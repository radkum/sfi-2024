use crate::{sha256_utils::Sha256Buff, SigSetError};
use common::redr;
use serde::Deserialize;

pub mod heuristic_set;
pub mod sha_set;
mod signature;
pub mod sigset_deserializer;
pub mod sigset_serializer;

use crate::sig_set::{
    heuristic_set::HeurSet, sha_set::ShaSet, sigset_serializer::SigSetSerializer,
};
use common::detection::DetectionReport;
use serde::Serialize;
use crate::sig_set::signature::{SigId, SigTrait};

pub(crate) type Description = String;

#[derive(Debug, Serialize, Deserialize)]
struct SigSetHeader {
    magic: u32,
    checksum: Sha256Buff,
    elem_count: u32,
}

impl SigSetHeader {
    const MAGIC_LIST: [u32; 2] = [ShaSet::SET_MAGIC_U32, HeurSet::SET_MAGIC_U32];
    fn verify_magic(&self) -> Result<(), SigSetError> {
        if !Self::MAGIC_LIST.contains(&self.magic) {
            return Err(SigSetError::IncorrectMagicError {
                current: String::from_utf8_lossy(&self.magic.to_le_bytes()).into(),
            });
        }
        Ok(())
    }
}

pub trait SigSetTrait {
    type Sig: SigTrait;

    fn append_signature(&mut self, id: SigId, signature: Self::Sig);

    fn eval_file(
        &self,
        file: &mut redr::FileReader,
    ) -> Result<Option<DetectionReport>, SigSetError>;

    fn new_empty() -> Self
        where
            Self: Sized;

    fn from_signatures(path_to_dir: &str) -> Result<Self, SigSetError> {
        let paths = std::fs::read_dir(path_to_dir)?;
        let mut sig_set = Self::new_empty();

        let mut sig_id = 0;
        for entry_res in paths {
            let entry = entry_res?;
            //log::trace!("path: {:?}", &path);
            if entry.file_type()?.is_file() {
                let mut f = std::fs::File::open(entry.path())?;
                let sig: Self::Sig = serde_yaml::from_reader(&f).unwrap();
                log::info!("Properties: {:?}", properties);

                sig_set.append_signature(sig_id, sig);
                sig_id += 1;
            }
        }

        log::info!("heurset size: {}", sig_id);
        Ok(sig_set)
    }

    fn to_set_serializer(&self) -> SigSetSerializer;


}
