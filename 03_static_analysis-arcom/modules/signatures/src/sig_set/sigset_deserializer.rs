use crate::{
    sha256_utils,
    sha256_utils::Sha256,
    sig_set::{
        heuristic_set::HeurSet, sha_set::ShaSet, signature::SigHeur, HeurSigHeader,
        SerializedSetHeader, ShaSigHeader, SigHeader, SigSet,
    },
    SigSetError,
};
use sha3::Digest;
use std::{io::Read, mem::size_of};

#[derive(Debug)]
pub(crate) struct SigSetDeserializer {
    ser_set_header: SerializedSetHeader,
    data: Vec<u8>,
}

impl SigSetDeserializer {
    const MAX_BUF_LEN: u64 = 0x400000;
    // 4 MB
    const HEADER_SIZE: usize = size_of::<SerializedSetHeader>();

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
        let set_header: SerializedSetHeader = bincode::serde::decode_from_slice(
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
        let mut hasher = sha3::Sha3_256::new();
        hasher.update(&self.ser_set_header.elem_count.to_le_bytes());
        hasher.update(&self.data);
        let mut checksum_buf = Sha256::default();
        checksum_buf.copy_from_slice(&hasher.finalize()[..]);
        if self.ser_set_header.checksum != checksum_buf {
            return Err(SigSetError::IncorrectChecksumError {
                current: hex::encode(checksum_buf),
                expected: hex::encode(self.ser_set_header.checksum),
            });
        }
        Ok(())
    }

    pub fn get_set(&self) -> Result<Box<dyn SigSet>, SigSetError> {
        match self.ser_set_header.magic {
            HeurSet::SET_MAGIC_U32 => Ok(Box::new(self.get_heur_set()?)),
            ShaSet::SET_MAGIC_U32 => Ok(Box::new(self.get_sha_set()?)),
            _ => Err(SigSetError::IncorrectMagicError {
                current: String::from_utf8_lossy(&self.ser_set_header.magic.to_le_bytes()).into(),
            }),
        }
    }

    fn get_heur_set(&self) -> Result<HeurSet, SigSetError> {
        let elem_count = self.ser_set_header.elem_count as usize;
        let signature_header_size = size_of::<SigHeader>();
        let start_of_data = elem_count * signature_header_size;

        let mut heurset = HeurSet::new_empty();
        for i in 0..elem_count {
            let curr_header_offset = i * signature_header_size;

            let sig_header: SigHeader = bincode::serde::decode_from_slice(
                &self.data[curr_header_offset..],
                bincode::config::legacy(),
            )?
            .0;
            let sig_header: HeurSigHeader = sig_header.into();

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

            let mut curr_offset = start_offset;
            let imports_count: u32 = bincode::serde::decode_from_slice(
                &self.data[start_offset..],
                bincode::config::standard(),
            )?
            .0;
            log::debug!("imports_count: {:?}", imports_count);

            curr_offset += size_of::<u32>();

            let mut imports_vec = vec![];
            //let signature_data = self.data[curr_offset..];
            for _i in 0..imports_count {
                let import: Sha256 = bincode::serde::decode_from_slice(
                    &self.data[curr_offset..],
                    bincode::config::legacy(),
                )?
                .0;
                imports_vec.push(import);
                curr_offset += size_of::<Sha256>();
            }
            log::debug!("imports: {:?}", imports_vec);

            let sig_heur: SigHeur = serde_yaml::from_slice(&self.data[curr_offset..end_offset])?;
            log::info!("Properties: {:?}", sig_heur);

            let imports = sig_heur
                .imports
                .iter()
                .map(|s| sha256_utils::sha256_from_vec(s.as_bytes().to_vec()).unwrap())
                .collect();

            let description = String::from_utf8_lossy(&self.data[curr_offset..end_offset]);
            heurset.append_signature(imports, sig_header.id, description.into());
        }

        Ok(heurset)
    }

    pub(crate) fn get_sha_set(&self) -> Result<ShaSet, SigSetError> {
        let elem_count = self.ser_set_header.elem_count as usize;
        let signature_header_size = size_of::<SigHeader>();
        let start_of_data = elem_count * signature_header_size;

        let mut sha_set = ShaSet::new_empty();
        for i in 0..elem_count {
            let curr_header_offset = i * signature_header_size;

            let sig_header: SigHeader = bincode::serde::decode_from_slice(
                &self.data[curr_header_offset..],
                bincode::config::legacy(),
            )?
            .0;
            let sig_header: ShaSigHeader = sig_header.into();

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

            let signature_data = self.data[start_offset..end_offset].to_vec();
            let description = String::from_utf8_lossy(&signature_data);

            sha_set.append_signature(sig_header.id, description.into());
        }

        Ok(sha_set)
    }
}
