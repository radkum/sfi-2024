use crate::{
    sha256_utils,
    sha256_utils::{Sha256},
    sig_set::{
        signature::SigDyn, sigset_serializer::SigSetSerializer, Description, SigId, SigSet,
    },
    SigSetError,
};
use common::{detection::DetectionReport, redr};
use std::{
    collections::{BTreeMap, HashMap},
    io::{Read, Seek, SeekFrom},
};
use crate::sha256_utils::sha256_from_vec;

type DynSigId = u32;
type ImportInSigs = u32;

pub struct DynSet {
    import_count: u32,
    sha_to_import_index: BTreeMap<Sha256, u32>,
    imports_in_sig: Vec<ImportInSigs>,
    sig_id_to_description: HashMap<DynSigId, Description>,
    sig_id_to_imports: HashMap<DynSigId, Vec<Sha256>>,
}

impl DynSet {
    pub const SET_MAGIC_U32: u32 = 0x54453544; //D5ET
                                               //const DYNSET_MAGIC: [u8; 4] = [0x44, 0x35, 0x45, 0x54]; //D5ET

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

    fn match_(&self, sha_vec: &Vec<Sha256>) -> Result<Option<SigDyn>, SigSetError> {
        //--------------ALGORITHM------------------
        // matching sha_vec with each signature has very low efficacy. There is better way
        // imports_in_sig field tell as which signatures has particular import. For example:
        // lets assume, "kernel32+sleep" after converted to sha belongs to "self.imports" on
        // first (zero index) position. Then if "kernel32+sleep" import appears in signatures
        // with id's 2,3,7,11, then first (zero index) value in "self.imports_to_sig" is
        // 1094, 0x446, 0b010001000110, because we fill "2,3,7,11" bits
        log::trace!("{:?}", self.sha_to_import_index.values());
        let mut shared_imports = u32::MAX;
        for sha256 in sha_vec {
            let Some(import_id) = self.sha_to_import_index.get(sha256) else {
                continue;
            };
            log::debug!(
                "self.imports_in_sig[*import_id as usize]: {}",
                self.imports_in_sig[*import_id as usize]
            );
            log::debug!("shared_imports: {}", shared_imports);

            shared_imports &= self.imports_in_sig[*import_id as usize];
        }

        if shared_imports == 0 {
            return Ok(None);
        }

        //some signatures are matched. Take first signature matched
        //todo: add to signatures Priority field in future
        log::trace!("matched {} sigs", shared_imports.count_ones());
        let first_matched_sig_bit = shared_imports.trailing_zeros();

        //convert from bit position to sig id
        let matched_sig = 1u32 >> first_matched_sig_bit;

        let properties: SigDyn = serde_yaml::from_str(&self.sig_id_to_description[&matched_sig])?;
        return Ok(Some(properties));
    }

    pub(crate) fn append_signature(
        &mut self,
        imports: Vec<Sha256>,
        sig_id: DynSigId,
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

    pub fn eval_api_calls(
          &self,
          calls: Vec<String>,
    ) -> Result<Option<DetectionReport>, SigSetError> {

        let api_calls_res = parse_api_calls(calls);
        //let api_calls_res = get_calls(variant.get_origin_file().borrow().path.as_path());
        if let Err(e) = api_calls_res {
            log::debug!("Failed to run sandbox: {:?}", e);
            return Ok(None);
        }
        let api_calls = api_calls_res.unwrap();

        let sig_info = self.match_(&api_calls)?;
        let desc_and_info = sig_info.map(|sig| sig.into());
        Ok(desc_and_info)
    }
}

fn parse_api_calls(imports: Vec<String>) -> Result<Vec<Sha256>, SigSetError> {

    fn api_call_to_sha(call: &String) -> Result<Sha256, SigSetError> {
        #[cfg(debug_assertions)]
        log::debug!(
            "call: \"{}\"",
            call,
        );

        Ok(sha256_from_vec(call.clone().into_bytes())?)
    }

    imports.iter().map(|i| api_call_to_sha(i)).collect()
}

impl SigSet for DynSet {
    fn eval_file(
        &self,
        _file: &mut redr::FileReader,
        _variant: &mut redr::FileScanInfo,
    ) -> Result<Option<DetectionReport>, SigSetError> {
        todo!()
    }

    fn from_signatures(path_to_dir: &str) -> Result<Self, SigSetError> {
        let paths = std::fs::read_dir(path_to_dir)?;
        let mut dynset = DynSet::new_empty();

        let mut sig_id = 0;
        for entry_res in paths {
            let entry = entry_res?;
            //log::trace!("path: {:?}", &path);
            if entry.file_type()?.is_file() {
                let mut f = std::fs::File::open(entry.path())?;
                let properties: SigDyn = serde_yaml::from_reader(&f)?;
                log::info!("Properties: {:?}", properties);

                let imports = properties
                    .calls
                    .iter()
                    .map(|s| sha256_utils::sha256_from_vec(s.as_bytes().to_vec()).unwrap())
                    .collect();
                f.seek(SeekFrom::Start(0))?;
                let mut data = Vec::new();
                f.read_to_end(&mut data)?;
                dynset.append_signature(imports, sig_id, String::from_utf8_lossy(&data).into());
                sig_id += 1;
            }
        }

        log::info!("dynset size: {}", sig_id);
        Ok(dynset)
    }

    fn to_sig_set(&self) -> SigSetSerializer {
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
