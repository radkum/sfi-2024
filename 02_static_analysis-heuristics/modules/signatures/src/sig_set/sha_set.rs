use crate::sha256_utils::{sha256_from_path, Sha256};
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
    sig_set::{signature::SigSha256, sigset_serializer::SigSetSerializer, Description, SigSet},
};

pub struct ShaSet {
    sha_list: BTreeSet<Sha256>,
    sha_to_description: HashMap<Sha256, Description>,
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

    fn match_(&self, sha: &Sha256) -> Result<Option<SigSha256>, SigSetError> {
        if self.sha_list.contains(sha) {
            let properties: SigSha256 = serde_yaml::from_str(&self.sha_to_description[sha])?;
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
                sha_set.append_signature(sha, Self::create_file_info(&entry, &sha)?);
                log::trace!("path: {:?}", &entry);
            }
        }

        log::info!("mset size: {}", sha_set.sha_list.len());
        Ok(sha_set)
    }

    fn create_file_info(path: &DirEntry, sha256: &Sha256) -> Result<String, SigSetError> {
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

    pub(crate) fn append_signature(&mut self, sig_id: Sha256, desc: Description) {
        self.sha_list.insert(sig_id);
        self.sha_to_description.insert(sig_id, desc);
    }
}

impl SigSet for ShaSet {
    fn eval_file(
        &self,
        file: &mut redr::FileReader,
    ) -> Result<Option<DetectionReport>, SigSetError> {
        let sha256 = crate::sha256_utils::sha256_from_file_pointer(file)?;

        let sig_info = self.match_(&sha256)?;
        let desc_and_info = sig_info.map(|sig| sig.into());
        Ok(desc_and_info)
    }

    fn from_signatures(path_to_dir: &str) -> Result<Self, SigSetError> {
        let paths = std::fs::read_dir(path_to_dir)?;
        let mut sha_set = Self::new_empty();

        for entry_res in paths {
            let entry = entry_res?;
            //log::trace!("path: {:?}", &path);
            if entry.file_type()?.is_file() {
                let mut f = std::fs::File::open(entry.path())?;
                let properties: BTreeMap<String, String> = serde_yaml::from_reader(&f)?;
                log::info!("Properies: {:?}", properties);

                //let name = properties.get(Self::PROPERTY_NAME).ok_or(MsetError::NoSuchPropertyError(PROPERTY_NAME.into()))?;
                let sha256 = properties.get(Self::PROPERTY_SHA256).ok_or(
                    SigSetError::NoSuchPropertyError(Self::PROPERTY_SHA256.into()),
                )?;
                //let desc = properties.get(Self::PROPERTY_DESC).ok_or(MsetError::NoSuchPropertyError(PROPERTY_DESC.into()))?;

                f.seek(SeekFrom::Start(0))?;
                let mut data = Vec::new();
                f.read_to_end(&mut data)?;
                sha_set.append_signature(
                    sha256_utils::convert_string_to_sha256(sha256)?,
                    String::from_utf8_lossy(&data).into(),
                )
            }
        }

        log::info!("mset size: {}", sha_set.sha_list.len());
        Ok(sha_set)
    }

    fn to_sig_set(&self) -> SigSetSerializer {
        let mut ser = SigSetSerializer::new_empty();
        let sorted_map: BTreeMap<Sha256, Description> =
            self.sha_to_description.clone().into_iter().collect();

        for (sha, desc) in sorted_map {
            ser.serialize_signature(sha, desc.into_bytes());
        }
        ser
    }
}
