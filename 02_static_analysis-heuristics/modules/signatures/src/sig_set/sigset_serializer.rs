use crate::{
    sha256_utils::Sha256Buff,
    sig_set::{SetHeader, SerSigHeader, SigId},
    SigSetError,
};
use sha2::Digest;
use std::io::Write;
use crate::sig_set::signature::{SerSigHeader, SigId};
use crate::sig_set::SigSetHeader;

pub struct SigSetSerializer {
    sig_headers_vec: Vec<SerSigHeader>,
    curr_offset: u32,
    signatures: Vec<u8>,
}

impl SigSetSerializer {
    pub(crate) fn new_empty() -> Self {
        Self {
            sig_headers_vec: Vec::new(),
            curr_offset: 0,
            signatures: Vec::new(),
        }
    }
}

impl SigSetSerializer {
    pub(crate) fn serialize_signature(&mut self, id: SigId, mut data: Vec<u8>) {
        self.sig_headers_vec.push(SerSigHeader {
            id,
            size: data.len() as u32,
            offset: self.curr_offset,
        });

        self.signatures.append(&mut data);
        self.curr_offset = self.signatures.len() as u32;
    }

    pub fn serialize(&self, set_name: &str, magic: u32) -> Result<usize, SigSetError> {
        let mut file = std::fs::File::create(set_name)?;

        let mut checksum_buf = Sha256Buff::default();
        checksum_buf.copy_from_slice(&self.calculate_checksum()?);

        let set_header = SigSetHeader {
            magic,
            checksum: checksum_buf,
            elem_count: self.sig_headers_vec.len() as u32,
        };

        let header = bincode::serde::encode_to_vec(&set_header, bincode::config::legacy())?;
        file.write_all(&header)?;

        //write info about each sig
        for sig_header in &self.sig_headers_vec {
            let data = bincode::serde::encode_to_vec(&sig_header, bincode::config::legacy())?;
            file.write_all(&data)?;
        }

        //write signatures to file
        file.write_all(&self.signatures)?;
        Ok(self.sig_headers_vec.len())
    }

    fn calculate_checksum(&self) -> Result<Sha256Buff, SigSetError> {
        let mut hasher = sha2::Sha256::new();

        hasher.update(&(self.sig_headers_vec.len() as u32).to_le_bytes());

        for header in &self.sig_headers_vec {
            hasher.update(&bincode::serde::encode_to_vec(
                &header,
                bincode::config::legacy(),
            )?);
        }

        hasher.update(&self.signatures);
        Ok(hasher.finalize().into())
    }
}
