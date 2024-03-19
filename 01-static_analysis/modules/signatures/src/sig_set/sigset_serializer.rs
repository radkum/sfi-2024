use crate::{
    sha256_utils::Sha256,
    sig_set::{SetHeader, SigHeader, SigId},
    ShaSet, SigSetError,
};
use sha2::Digest;
use std::io::Write;

pub struct SigSetSerializer {
    sig_headers_vec: Vec<SigHeader>,
    curr_offset: u32,
    descriptions: Vec<u8>,
}

impl SigSetSerializer {
    pub(crate) fn new_empty() -> Self {
        Self {
            sig_headers_vec: Vec::new(),
            curr_offset: 0,
            descriptions: Vec::new(),
        }
    }
}

impl SigSetSerializer {
    pub(crate) fn serialize_signature(&mut self, id: SigId, mut data: Vec<u8>) {
        self.sig_headers_vec.push(SigHeader {
            id,
            size: data.len() as u32,
            offset: self.curr_offset,
        });

        self.descriptions.append(&mut data);
        self.curr_offset = self.descriptions.len() as u32;
    }

    // fn serialize_shaset(&self, set_name: &str) -> Result<(), SigSetError> {
    //     self.serialize(set_name, ShaSet::SET_MAGIC_U32)
    // }
    //
    // fn serialize_heurset(&self, set_name: &str) -> Result<(), SigSetError> {
    //     self.serialize(set_name, HeurSet::SET_MAGIC_U32)
    // }
    pub fn serialize_sha_set(&self, set_name: &str) -> Result<usize, SigSetError> {
        self.serialize(set_name, ShaSet::SET_MAGIC_U32)
    }

    pub fn serialize(&self, set_name: &str, magic: u32) -> Result<usize, SigSetError> {
        let mut file = std::fs::File::create(set_name)?;

        let mut checksum_buf = Sha256::default();
        checksum_buf.copy_from_slice(&self.calculate_checksum()?);

        let shaset_header = SetHeader::new(magic, checksum_buf, self.sig_headers_vec.len() as u32);

        let header = bincode::serde::encode_to_vec(&shaset_header, bincode::config::legacy())?;
        file.write_all(&header)?;

        //write info about each sig
        for header in &self.sig_headers_vec {
            let data = bincode::serde::encode_to_vec(&header, bincode::config::legacy())?;
            file.write_all(&data)?;
        }

        //write descriptions to file
        file.write_all(&self.descriptions)?;
        Ok(self.sig_headers_vec.len())
    }

    fn calculate_checksum(&self) -> Result<Sha256, SigSetError> {
        let mut hasher = sha2::Sha256::new();

        hasher.update(&(self.sig_headers_vec.len() as u32).to_le_bytes());

        for header in &self.sig_headers_vec {
            hasher.update(&bincode::serde::encode_to_vec(
                &header,
                bincode::config::legacy(),
            )?);
        }

        hasher.update(&self.descriptions);
        Ok(hasher.finalize().into())
    }
}
