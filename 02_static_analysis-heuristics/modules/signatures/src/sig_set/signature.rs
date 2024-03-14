use common::detection::DetectionReport;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct SigBase {
    pub name: String,
    pub description: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SigSha256 {
    #[serde(flatten)]
    pub sig_base: SigBase,
    pub sha256: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SigHeur {
    #[serde(flatten)]
    pub sig_base: SigBase,
    pub imports: Vec<String>,
}

impl From<SigHeur> for DetectionReport {
    fn from(sig: SigHeur) -> Self {
        Self {
            desc: sig.sig_base.description,
            cause: format!("Used Imports: {:?}", sig.imports),
        }
    }
}

impl From<SigSha256> for DetectionReport {
    fn from(sig: SigSha256) -> Self {
        Self {
            desc: sig.sig_base.description,
            cause: format!("Known sha: {:?}", sig.sha256),
        }
    }
}
