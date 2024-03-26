use common_um::detection::DetectionReport;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Serialize, Deserialize)]
pub struct SigBase {
    pub name: String,
    pub description: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SigBedet {
    #[serde(flatten)]
    pub sig_base: SigBase,
    pub event_type: String,
    pub attributes: BTreeMap<String, String>,
}

impl From<SigBedet> for DetectionReport {
    fn from(sig: SigBedet) -> Self {
        Self {
            desc: sig.sig_base.description,
            cause: format!(
                "Detected Event: {}: {{ {:?} }}",
                sig.event_type, sig.attributes
            ),
        }
    }
}
