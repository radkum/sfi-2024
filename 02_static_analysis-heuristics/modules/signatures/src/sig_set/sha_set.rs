use crate::sha256_utils::{sha256_from_path, Sha256Buff};
use common::{detection::DetectionReport, redr};
use serde_yaml;
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    fs::DirEntry,
    io::{Read, Seek, SeekFrom},
};

use crate::{
    error::SigSetError,
    sha256_utils,
    sig_set::{signature::SigSha256, sigset_serializer::SigSetSerializer, Description, SigSetTrait},
};
use crate::sig_set::signature::{SigBase, SigId};

pub struct ShaSet {
    sha_list: BTreeSet<Sha256Buff>,
    sha_to_description: HashMap<Sha256Buff, Description>,
}

impl ShaSet {
    pub const SET_MAGIC_U32: u32 = 0x54453535; //55ET
                                               //const SHASET_MAGIC: [u8; 4] = [0x35, 0x35, 0x45, 0x54]; //55ET

    const PROPERTY_NAME: &'static str = "name";
    const PROPERTY_SHA256: &'static str = "sha256";
    const PROPERTY_DESC: &'static str = "description";

    pub(crate) fn new_empty() -> Self {
        Self {
            sha_list: Default::default(),
            sha_to_description: Default::default(),
        }
    }

    fn match_(&self, sha: &Sha256Buff) -> Result<Option<SigSha256>, SigSetError> {
        if self.sha_list.contains(sha) {
            let properties: SigSha256 = serde_yaml::from_str(&self.sha_to_description[sha]).unwrap();
            return Ok(Some(properties));
        }

        Ok(None)
    }

    pub fn from_dir(path_to_dir: &str) -> Result<ShaSet, SigSetError> {
        let paths = std::fs::read_dir(path_to_dir)?;

        let mut sha_set = ShaSet::new_empty();
        for entry_res in paths {
            let entry = entry_res?;
            //log::trace!("path: {:?}", &path);
            if entry.file_type()?.is_file() {
                let sha = sha256_from_path(entry.path().into_os_string().into_string()?.as_str())?;
                let sha_sig = SigSha256{ sig_base: SigBase { name: "".to_string(), description: Self::create_file_info(&entry, &sha)? }, sha256: "".to_string() };
                sha_set.append_signature(sha, sha_sig);
                log::trace!("path: {:?}", &entry);
            }
        }

        log::info!("shaset size: {}", sha_set.sha_list.len());
        Ok(sha_set)
    }

    fn create_file_info(path: &DirEntry, sha256: &Sha256Buff) -> Result<String, SigSetError> {
        Ok(format!(
            "{}: {}\n{}: {}\n{}: {:?}\n",
            Self::PROPERTY_NAME,
            path.file_name().into_string()?,
            Self::PROPERTY_SHA256,
            hex::encode_upper(&sha256),
            Self::PROPERTY_DESC,
            path.metadata()?
        ))
    }

    pub fn unpack_to_dir(&self, out_dir: &String) -> Result<usize, SigSetError> {
        let path = std::path::Path::new(&out_dir);
        for (sha, desc) in self.sha_to_description.iter() {
            let file_path = path.join(hex::encode_upper(&sha));
            std::fs::write(file_path, desc)?;
        }

        Ok(self.sha_to_description.len())
    }


}

impl SigSetTrait for ShaSet {
    type Sig = SigSha256;

    fn append_signature(&mut self, sig_id: SigId, sig_sha: Self::Sig) {
        self.sha_list.insert(sig_id);
        self.sha_to_description.insert(sig_id, sig_sha.sig_base.description);
    }

    fn eval_file(
        &self,
        file: &mut redr::FileReader,
    ) -> Result<Option<DetectionReport>, SigSetError> {
        let sha256 = crate::sha256_utils::sha256_from_file_pointer(file)?;

        let sig_info = self.match_(&sha256)?;
        let desc_and_info = sig_info.map(|sig| sig.into());
        Ok(desc_and_info)
    }

    fn new_empty() ->Self where Self: Sized {
        Self {
            sha_list: Default::default(),
            sha_to_description: Default::default()
        }
    }

    fn to_set_serializer(&self) -> SigSetSerializer {
        let mut ser = SigSetSerializer::new_empty();
        let sorted_map: BTreeMap<Sha256Buff, Description> =
            self.sha_to_description.clone().into_iter().collect();

        for (sha, desc) in sorted_map {
            ser.serialize_signature(sha, desc.into_bytes());
        }
        ser
    }
}
