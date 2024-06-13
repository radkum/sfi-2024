use crate::{
    sha256_utils::Sha256Buff,
    sig_set::{
        heuristic_set::HeurSet, sha_set::ShaSet, HeurSigHeader, SetHeader,
        ShaSigHeader, SerSigHeader, SigSetTrait,
    },
    SigSetError,
};
use sha2::Digest;
use std::{io::Read, mem::size_of};
use crate::sig_set::signature::{SerSigHeader, SigHeurSerialized, SigSha256, SigTrait};
use crate::sig_set::signature::sig_deserializer::SigDeserializer;
use crate::sig_set::SigSetHeader;

#[derive(Debug)]
pub(crate) struct SigSetDeserializer {
    ser_set_header: SigSetHeader,
    data: Vec<u8>,
}

impl SigSetDeserializer {
    const MAX_BUF_LEN: u64 = 0x400000;
    // 4 MB
    const HEADER_SIZE: usize = size_of::<SigSetHeader>();

    pub fn new(name: &str) -> Result<Self, SigSetError> {
        let mut file = std::fs::File::open(name)?;
        let metadata = file.metadata()?;

        if metadata.len() > Self::MAX_BUF_LEN {
            return Err(SigSetError::IncorrectFileSizeError {
                size: metadata.len(),
            });
        }

        let mut buffer = vec![0; metadata.len() as usize];
        let _ = file.read(&mut buffer)?;

        Self::new_with_buffer(buffer)
    }

    fn new_with_buffer(mut data: Vec<u8>) -> Result<Self, SigSetError> {
        if data.len() < Self::HEADER_SIZE {
            return Err(SigSetError::IncorrectFileSizeError {
                size: data.len() as u64,
            });
        }
        let set_header: SetHeader = bincode::serde::decode_from_slice(
            &data[..Self::HEADER_SIZE],
            bincode::config::legacy(),
        )?
        .0;

        set_header.verify_magic()?;
        data.drain(..Self::HEADER_SIZE);

        let reader = Self {
            ser_set_header: set_header,
            data,
        };
        reader.verify_checksum()?;

        Ok(reader)
    }

    fn verify_checksum(&self) -> Result<(), SigSetError> {
        let mut hasher = sha2::Sha256::new();
        hasher.update(&self.ser_set_header.elem_count.to_le_bytes());
        hasher.update(&self.data);
        let mut checksum_buf = Sha256Buff::default();
        checksum_buf.copy_from_slice(&hasher.finalize()[..]);
        if self.ser_set_header.checksum != checksum_buf {
            return Err(SigSetError::IncorrectChecksumError {
                current: hex::encode(checksum_buf),
                expected: hex::encode(self.ser_set_header.checksum),
            });
        }
        Ok(())
    }

    pub fn get_set_box(&self) -> Result<Box<dyn SigSetTrait>, SigSetError> {
        match self.ser_set_header.magic {
            HeurSet::SET_MAGIC_U32 => Ok(Box::new(self.get_set::<HeurSet>()?)),
            ShaSet::SET_MAGIC_U32 => Ok(Box::new(self.get_set::<ShaSet>()?)),
            _ => Err(SigSetError::IncorrectMagicError {
                current: String::from_utf8_lossy(&self.ser_set_header.magic.to_le_bytes()).into(),
            }),
        }
    }

    fn get_set<SigSet: SigSetTrait>(&self) -> Result<SigSet, SigSetError> {
        let elem_count = self.ser_set_header.elem_count as usize;
        let signature_header_size = size_of::<SerSigHeader>();
        let start_of_data = elem_count * signature_header_size;

        let mut signature_set = SigSet::new_empty();
        for i in 0..elem_count {
            let curr_header_offset = i * signature_header_size;

            let sig_header: SerSigHeader = bincode::serde::decode_from_slice(
                &self.data[curr_header_offset..],
                bincode::config::legacy(),
            )?
                .0;

            log::debug!("sig_header: {:?}", sig_header);

            if sig_header.size > Self::MAX_BUF_LEN as u32 {
                return Err(SigSetError::IncorrectSignatureSizeError {
                    size: sig_header.size,
                });
            }

            let start_offset = sig_header.offset as usize + start_of_data;
            let end_offset = start_offset + sig_header.size as usize;

            if end_offset > self.data.len() {
                return Err(SigSetError::IncorrectSignatureSizeError {
                    size: sig_header.size,
                });
            }

            let signature = SigSet::Sig::deserialize_vec(self.data[start_offset..end_offset].to_vec())?;

            signature_set.append_signature(sig_header.id, signature);
        }

        Ok(signature_set)
    }
}
