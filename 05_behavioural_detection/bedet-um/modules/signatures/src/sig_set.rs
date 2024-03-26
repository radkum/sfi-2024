use crate::{sha256_utils::Sha256, SigSetError};
use serde::Deserialize;

pub mod bedet_set;
mod signature;
pub mod sigset_deserializer;
pub mod sigset_serializer;

use crate::sig_set::{bedet_set::BedetSet, sigset_serializer::SigSetSerializer};
use common_um::detection::DetectionReport;
use serde::Serialize;

pub(crate) type Description = String;

#[derive(Debug, Serialize, Deserialize)]
struct SetHeader {
    magic: u32,
    checksum: Sha256,
    elem_count: u32,
}

impl SetHeader {
    fn verify_magic(&self) -> Result<(), SigSetError> {
        if self.magic != BedetSet::SET_MAGIC_U32 {
            return Err(SigSetError::IncorrectMagicError {
                current: String::from_utf8_lossy(&self.magic.to_le_bytes()).into(),
            });
        }
        Ok(())
    }
}

pub(crate) type SigId = [u8; 32];

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct SigHeader {
    id: SigId,
    size: u32,
    offset: u32,
}

#[derive(Debug)]
struct HeurSigHeader {
    id: u32,
    size: u32,
    offset: u32,
}

impl From<SigHeader> for HeurSigHeader {
    fn from(header: SigHeader) -> Self {
        Self {
            id: u32::from_le_bytes(header.id[0..4].try_into().unwrap()),
            size: header.size,
            offset: header.offset,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct Signature {
    header: SigHeader,
    data: Vec<u8>,
}

pub trait SigSet {
    //fn append_signature(&mut self, sha: SigIdType, desc: Description);
    fn eval_event(&self, file: Vec<Sha256>) -> Result<Option<DetectionReport>, SigSetError>;
    fn from_signatures(path_to_dir: &str) -> Result<Self, SigSetError>
    where
        Self: Sized;

    fn to_set_serializer(&self) -> SigSetSerializer;
}
