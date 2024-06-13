use common::detection::DetectionReport;
use serde::{Deserialize, Serialize};
use crate::sha256_utils::Sha256Buff;

pub(crate) mod sha_sig;
pub(crate) mod heuristic_sig;

pub(crate) type SigId = u32;

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct SerSigHeader {
    pub(crate) id: SigId,
    pub(crate) size: u32,
    pub(crate) offset: u32,
}

#[derive(Debug, Serialize, Deserialize)]
struct SerSignature {
    header: SerSigHeader,
    data: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SigBase {
    pub name: String,
    pub description: String,
}

pub trait SigTrait {
    type SigDeserialized;
    fn deserialize_vec(data: vec<u8>) -> Self::SigDeserialized;
}
