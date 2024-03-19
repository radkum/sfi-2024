use crate::{sha256_utils::Sha256, SigSetError};
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

pub(crate) type Description = String;

#[derive(Debug, Serialize, Deserialize)]
struct SetHeader {
    magic: u32,
    checksum: Sha256,
    elem_count: u32,
}

impl SetHeader {
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

pub(crate) type SigId = [u8; 32];

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct SigHeader {
    id: SigId,
    size: u32,
    offset: u32,
}

pub(crate) type ShaSigHeader = SigHeader;

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

// #[derive(Debug, Serialize, Deserialize)]
// struct SignatureHeader {
//     id: [u8;32],
//     size: u32,
//     offset: u32,
// }

#[derive(Debug, Serialize, Deserialize)]
struct Signature {
    header: SigHeader,
    data: Vec<u8>,
}

pub trait SigSet {
    //fn append_signature(&mut self, sha: SigIdType, desc: Description);
    fn eval_file(
        &self,
        file: &mut redr::FileReader,
    ) -> Result<Option<DetectionReport>, SigSetError>;
    fn from_signatures(path_to_dir: &str) -> Result<Self, SigSetError>
    where
        Self: Sized;

    fn to_set_serializer(&self) -> SigSetSerializer;
}
