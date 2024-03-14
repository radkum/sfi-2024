use crate::{sha256_utils::Sha256, SigSetError};
use common::redr;
use serde::Deserialize;

pub mod sha_set;
mod signature;
pub mod sigset_deserializer;
pub mod sigset_serializer;

use crate::sig_set::sigset_serializer::SigSetSerializer;
use common::detection::DetectionReport;
use serde::Serialize;

pub(crate) type Description = String;

#[derive(Debug, Serialize, Deserialize)]
struct SetHeader {
    magic: u32,
    checksum: Sha256,
    elem_count: u32,
}

impl SetHeader {
    fn new(magic: u32, checksum: Sha256, elem_count: u32) -> Self {
        Self {
            magic,
            checksum,
            elem_count,
        }
    }

    fn verify_magic(&self, magic: u32) -> Result<(), SigSetError> {
        if self.magic != magic {
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

#[derive(Debug, Serialize, Deserialize)]
struct Signature {
    header: SigHeader,
    data: Vec<u8>,
}

pub trait SigSet {
    fn eval_file(
        &self,
        file: &mut redr::FileReader,
    ) -> Result<Option<DetectionReport>, SigSetError>;
    fn from_signatures(path_to_dir: &str) -> Result<Self, SigSetError>
    where
        Self: Sized;

    fn to_set_serializer(&self) -> SigSetSerializer;
}
