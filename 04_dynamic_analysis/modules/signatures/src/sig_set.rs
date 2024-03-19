use crate::{DynSet, sha256_utils::Sha256, SigSetError};
use common::redr;
use serde::Deserialize;

pub mod heuristic_set;
pub mod sha_set;
mod signature;
pub mod sigset_deserializer;
pub mod sigset_serializer;
pub mod dynamic_set;

use crate::sig_set::{
    heuristic_set::HeurSet, sha_set::ShaSet, sigset_serializer::SigSetSerializer,
};
use common::detection::DetectionReport;
use serde::Serialize;

pub(crate) type Description = String;

#[derive(Debug, Serialize, Deserialize)]
struct SerializedSetHeader {
    magic: u32,
    checksum: Sha256,
    elem_count: u32,
}

impl SerializedSetHeader {
    const MAGIC_LIST: [u32; 3] = [ShaSet::SET_MAGIC_U32, HeurSet::SET_MAGIC_U32, DynSet::SET_MAGIC_U32];
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

pub(self) type DynSigHeader = HeurSigHeader;

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
        variant: &mut redr::FileScanInfo,
    ) -> Result<Option<DetectionReport>, SigSetError>;
    fn from_signatures(path_to_dir: &str) -> Result<Self, SigSetError>
    where
        Self: Sized;

    fn to_sig_set(&self) -> SigSetSerializer;
}
