use crate::{
    sha256_utils,
    sha256_utils::{sha256_from_vec_of_vec, Sha256},
    sig_set::{
        signature::SigHeur, sigset_serializer::SigSetSerializer, Description, SigId, SigSet,
    },
    SigSetError,
};
use common::{detection::DetectionReport, redr};
use object::{Import, Object};
use std::{
    collections::{BTreeMap, HashMap},
    io::{Read, Seek, SeekFrom},
};

type HeurSigId = u32;
type ImportInSigs = u32;

pub struct HeurSet {
    import_count: u32,
    sha_to_import_index: BTreeMap<Sha256, u32>,
    imports_in_sig: Vec<ImportInSigs>,
    sig_id_to_description: HashMap<HeurSigId, Description>,
    sig_id_to_imports: HashMap<HeurSigId, Vec<Sha256>>,
}

impl HeurSet {
    pub const SET_MAGIC_U32: u32 = 0x54453548; //H5ET
                                               //const HEURSET_MAGIC: [u8; 4] = [0x48, 0x35, 0x45, 0x54]; //H5ET

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

    fn match_(&self, sha_vec: &Vec<Sha256>) -> Result<Option<SigHeur>, SigSetError> {
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

        //some signatures are matched. Take first signature matched
        //todo: add to signatures Priority field in future
        log::trace!("matched {} sigs", shared_imports.count_ones());

        let matched_sig = shared_imports.trailing_zeros();
        log::trace!("matched_sig {} id", matched_sig);
        log::trace!("matched_sig {:?} id", self.sig_id_to_description);

        let properties: SigHeur = serde_yaml::from_str(&self.sig_id_to_description[&matched_sig])?;
        return Ok(Some(properties));
    }

    pub(crate) fn append_signature(
        &mut self,
        imports: Vec<Sha256>,
        sig_id: HeurSigId,
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

fn get_characteristics(reader: &mut redr::FileReader) -> Result<Vec<Sha256>, SigSetError> {
    let mut buffer = Vec::new();
    let _binary_data = reader.read_to_end(&mut buffer)?;
    let file = object::File::parse(&*buffer)?;
    get_imports(file.imports()?)
}

fn get_imports(imports: Vec<Import>) -> Result<Vec<Sha256>, SigSetError> {
    const DELIMITER: u8 = b'+';

    fn import_to_sha(import: &Import) -> Result<Sha256, SigSetError> {
        #[cfg(debug_assertions)]
        log::debug!(
            "import: \"{}{}{}\"",
            String::from_utf8(import.library().to_vec())
                .unwrap()
                .to_lowercase(),
            DELIMITER as char,
            String::from_utf8(import.name().to_vec())
                .unwrap()
                .to_lowercase()
        );

        Ok(sha256_from_vec_of_vec(vec![
            import.library().to_vec(),
            vec![DELIMITER],
            import.name().to_vec(),
        ])?)
    }

    imports.iter().map(|i| import_to_sha(i)).collect()
}

impl SigSet for HeurSet {
    fn eval_file(
        &self,
        file: &mut redr::FileReader,
    ) -> Result<Option<DetectionReport>, SigSetError> {
        let imports_res = get_characteristics(file);
        if let Err(e) = imports_res {
            log::debug!("Not executable: {:?}", e);
            return Ok(None);
        }
        let imports = imports_res.unwrap();

        let sig_info = self.match_(&imports)?;
        let desc_and_info = sig_info.map(|sig| sig.into());
        Ok(desc_and_info)
    }

    fn from_signatures(path_to_dir: &str) -> Result<Self, SigSetError> {
        let paths = std::fs::read_dir(path_to_dir)?;
        let mut heurset = HeurSet::new_empty();

        let mut sig_id = 0;
        for entry_res in paths {
            let entry = entry_res?;
            //log::trace!("path: {:?}", &path);
            if entry.file_type()?.is_file() {
                let mut f = std::fs::File::open(entry.path())?;
                let properties: SigHeur = serde_yaml::from_reader(&f)?;
                log::info!("Properties: {:?}", properties);

                // let imports_str = properties.get(HeurSet::PROPERTY_IMPORTS).ok_or(
                //     SigSetError::NoSuchPropertyError(HeurSet::PROPERTY_IMPORTS.into()),
                // )?;

                let imports = properties
                    .imports
                    .iter()
                    .map(|s| {
                        sha256_utils::sha256_from_vec(s.to_lowercase().as_bytes().to_vec()).unwrap()
                    })
                    .collect();
                f.seek(SeekFrom::Start(0))?;
                let mut data = Vec::new();
                f.read_to_end(&mut data)?;
                heurset.append_signature(imports, sig_id, String::from_utf8_lossy(&data).into());
                sig_id += 1;
            }
        }

        log::info!("heurset size: {}", sig_id);
        Ok(heurset)
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
