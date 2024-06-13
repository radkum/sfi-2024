use std::mem::size_of;
use common::detection::DetectionReport;
use crate::sha256_utils::Sha256Buff;
use crate::sig_set::signature::{SigBase, SigTrait};
use crate::{sha256_utils, SigSetError};

#[derive(Debug, Serialize, Deserialize)]
pub struct SigHeur {
    #[serde(flatten)]
    pub sig_base: SigBase,
    pub imports: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SigHeurDeserialized {
    #[serde(flatten)]
    pub imports: Vec<Sha256Buff>,
    pub sig: SigHeur,
}

impl SigTrait for SigHeur{
    type SigDeserialized = SigHeurDeserialized;

    fn deserialize_vec(data: vec<u8>) -> Result<Self::SigDeserialized, SigSetError> {
        let imports_count: u32 = bincode::serde::decode_from_slice(
            &data,
            bincode::config::standard(),
        )?
            .0;
        //log::debug!("imports_count: {:?}", imports_count);

        let mut curr_offset= size_of::<u32>();

        let mut imports_vec = vec![];
        //let signature_data = self.data[curr_offset..];
        for _i in 0..imports_count {
            let import: Sha256Buff = bincode::serde::decode_from_slice(
                &data[curr_offset..],
                bincode::config::legacy(),
            )?
                .0;
            imports_vec.push(import);
            curr_offset += size_of::<Sha256Buff>();
        }
        log::debug!("imports: {:?}", imports_vec);

        let sig: SigHeur = serde_yaml::from_slice(&data[curr_offset..]).unwrap();
        log::info!("Properties: {:?}", sig_heur);

        let imports = sig
            .imports
            .iter()
            .map(|s| sha256_utils::sha256_from_vec(s.as_bytes().to_vec()).unwrap())
            .collect();

        Ok(Self::SigDeserialized {
            imports,
            sig,
        })
    }
}

impl From<SigHeur> for DetectionReport {
    fn from(sig: SigHeur) -> Self {
        Self {
            desc: sig.sig_base.description,
            cause: format!("Used Imports: {:?}", sig.imports),
        }
    }
}