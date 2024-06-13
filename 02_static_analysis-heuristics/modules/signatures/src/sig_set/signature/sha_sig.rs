use common::detection::DetectionReport;
use crate::sha256_utils::Sha256Buff;
use crate::sig_set::signature::{SigBase, SigTrait};
use crate::SigSetError;

#[derive(Debug, Serialize, Deserialize)]
pub struct SigSha {
    #[serde(flatten)]
    pub sig_base: SigBase,
    pub sha256: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SigShaDeserialized {
    pub sha: Sha256Buff,
    pub sig: SigSha,
}

impl From<SigSha> for DetectionReport {
    fn from(sig: SigSha) -> Self {
        Self {
            desc: sig.sig_base.description,
            cause: format!("Known sha: {:?}", sig.sha256),
        }
    }
}

impl SigTrait for SigSha {
    type SigDeserialized = SigShaDeserialized;

    fn deserialize_vec(data: Vec<u8>) -> Result<Self, SigSetError>  {
        // Ok(Self::SigDeserialized {
        //
        // })
        todo!()
    }
}