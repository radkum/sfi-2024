use crate::{
    sha256_utils::{convert_sha256_to_string, Sha256},
    sig_set::{
        signature::SigBedet, sigset_serializer::SigSetSerializer, Description, SigId, SigSet,
    },
    SigSetError,
};
use common::hasher::member_to_hash;
use common_um::detection::DetectionReport;
use std::{
    collections::{BTreeMap, HashMap},
    io::{Read, Seek, SeekFrom},
};

type BedetSigId = u32;
type ImportInSigs = u32;

pub struct BedetSet {
    import_count: u32,
    sha_to_import_index: BTreeMap<Sha256, u32>,
    imports_in_sig: Vec<ImportInSigs>,
    sig_id_to_description: HashMap<BedetSigId, Description>,
    sig_id_to_imports: HashMap<BedetSigId, Vec<Sha256>>,
}

impl BedetSet {
    pub const SET_MAGIC_U32: u32 = 0x54453542; //B5ET
                                               //const BEDETSET_MAGIC: [u8; 4] = [0x42, 0x35, 0x45, 0x54]; //B5ET

    pub const PROPERTY_IMPORTS: &'static str = "imports";

    pub(crate) fn new_empty() -> Self {
        Self {
            import_count: 0,
            sha_to_import_index: Default::default(),
            imports_in_sig: Default::default(),
            sig_id_to_description: Default::default(),
            sig_id_to_imports: Default::default(),
        }
    }

    fn match_(&self, sha_vec: &Vec<Sha256>) -> Result<Option<SigBedet>, SigSetError> {
        //--------------ALGORITHM------------------
        // matching sha_vec with each signature has very low efficacy. There is better way
        // imports_in_sig field tell as which signatures has particular import. For example:
        //
        // 1) lets assume, "kernel32+sleep" after converted to sha belongs to "self.imports" on
        // first (zero index) position. Then if "kernel32+sleep" import appears in signatures
        // with id's 2,3,7,11, then first (zero index) value in "self.imports_to_sig" is
        // 1094, 0x446, 0b010001000110, because we fill "2,3,7,11" bits
        //
        // 2) next step is iterate by each import and if import exists in "imports_in_sig", then
        // clear value for import_id
        //
        // 3) then if some bit is 0 in each "imports_in_sig" value, then we found our matched signature
        // because each "import" hit clear for us one entry.
        // 4) How to find out each "sig" is hit? perform in loop bitwise or on each "import_to_sig"
        // then negate result, and then we know which sig is hit

        //todo: add algorithm example step by step

        let sig_count = self.sig_id_to_imports.len();
        log::trace!("{:?}", self.imports_in_sig);
        let mut imports_in_sig = self.imports_in_sig.clone();
        for sha256 in sha_vec {
            let Some(import_id) = self.sha_to_import_index.get(sha256) else {
                continue;
            };
            log::debug!(
                "self.imports_in_sig[*import_id as usize]: {:08b}",
                self.imports_in_sig[*import_id as usize]
            );
            // if some imports hit, then we remove it from array. At the end it tell us in which
            // signature all imports were hit

            imports_in_sig[*import_id as usize] = 0;
        }

        // we need calculate mask. If we have 5 signatures, then mask should be
        // 0x11111111111111111111111111100000, 5 first bits empty. So to get this in first step we get:
        // 0x00000000000000000000000000011111 and then negate it
        let mut shared_imports: u32 = (1 << sig_count) - 1;
        shared_imports = !shared_imports;

        for ids in imports_in_sig {
            shared_imports |= ids;
        }

        shared_imports = !shared_imports;

        if shared_imports == 0 {
            // no match
            return Ok(None);
        }
        //some signatures are matched. Take first signature matched
        //todo: add to signatures Priority field in future
        log::trace!("matched {} sigs", shared_imports.count_ones());

        let matched_sig = shared_imports.trailing_zeros();
        log::trace!("matched_sig {} id", matched_sig);
        log::trace!("matched_sig {:?} id", self.sig_id_to_description);

        let properties: SigBedet = serde_yaml::from_str(&self.sig_id_to_description[&matched_sig])?;
        return Ok(Some(properties));
    }

    pub(crate) fn append_signature(
        &mut self,
        imports: Vec<Sha256>,
        sig_id: BedetSigId,
        desc: Description,
    ) {
        self.sig_id_to_imports.insert(sig_id, imports.clone());

        for sha in imports {
            let import_mask = 1 << sig_id;
            if !self.sha_to_import_index.contains_key(&sha) {
                log::trace!("{}", self.import_count);
                self.sha_to_import_index.insert(sha, self.import_count);
                self.imports_in_sig.push(import_mask);
                self.import_count += 1;
            } else {
                let import_id = self.sha_to_import_index.get_mut(&sha).unwrap();
                let import_ids = self.imports_in_sig.get_mut(*import_id as usize).unwrap();
                *import_ids |= import_mask;
            }
        }
        self.sig_id_to_description.insert(sig_id, desc);
    }
}

impl SigSet for BedetSet {
    fn eval_event(&self, fields: Vec<Sha256>) -> Result<Option<DetectionReport>, SigSetError> {
        let sig_info = self.match_(&fields)?;
        let desc_and_info = sig_info.map(|sig| sig.into());
        Ok(desc_and_info)
    }

    fn from_signatures(path_to_dir: &str) -> Result<Self, SigSetError> {
        let paths = std::fs::read_dir(path_to_dir)?;
        let mut set = BedetSet::new_empty();

        let mut sig_id = 0;
        for entry_res in paths {
            let entry = entry_res?;
            //log::trace!("path: {:?}", &path);
            if entry.file_type()?.is_file() {
                let mut f = std::fs::File::open(entry.path())?;
                let properties: SigBedet = serde_yaml::from_reader(&f)?;
                log::info!("Properties: {:?}", properties);

                let event_type = properties.event_type;
                //todo: check if event type is valid

                // for s in properties.attributes.iter() {
                //     println!("{}+{}+{}", event_type, s.0, s.1);
                // }

                let imports: Vec<_> = properties
                    .attributes
                    .iter()
                    .map(|s| member_to_hash(event_type.as_ref(), s.0, s.1))
                    .collect();

                println!(
                    "{}",
                    imports
                        .iter()
                        .map(|sha| convert_sha256_to_string(sha).unwrap())
                        .collect::<Vec<_>>()
                        .join(", ")
                );

                f.seek(SeekFrom::Start(0))?;
                let mut data = Vec::new();
                f.read_to_end(&mut data)?;
                set.append_signature(imports, sig_id, String::from_utf8_lossy(&data).into());
                sig_id += 1;
            }
        }

        log::info!("set size: {}", sig_id);
        Ok(set)
    }

    fn to_set_serializer(&self) -> SigSetSerializer {
        let mut ser = SigSetSerializer::new_empty();
        for (sig_id, imports) in self.sig_id_to_imports.iter() {
            let mut desc = self.sig_id_to_description[&sig_id].clone();

            let mut v = vec![];
            let imports_len = imports.len() as u32;
            v.append(&mut imports_len.to_le_bytes().to_vec());
            for import in imports {
                v.append(&mut import.as_slice().to_vec());
            }
            unsafe {
                v.append(desc.as_mut_vec());
            }

            let mut sig_id_bytes = [0u32; 4];
            sig_id_bytes[0] = *sig_id;
            let sig_id = unsafe { *(sig_id_bytes.as_ptr() as *const SigId) };
            ser.serialize_signature(sig_id, v);
        }
        ser
    }
}