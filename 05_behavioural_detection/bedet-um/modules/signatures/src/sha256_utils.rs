use std::io;

use crate::SigSetError;
use sha2::Digest;

const SHA256_LEN: usize = 32;
pub type Sha256 = [u8; SHA256_LEN];

pub fn sha256_from_file_pointer(file: &mut impl io::Read) -> Result<Sha256, io::Error> {
    // Create a SHA-256 "hasher"
    let mut hasher = sha2::Sha256::new();

    // Read the file in 4KB chunks and feed them to the hasher
    let mut buffer = [0; 4096];
    loop {
        let bytes_read = file.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    let mut checksum_buf = Sha256::default();
    checksum_buf.copy_from_slice(&hasher.finalize()[..]);
    Ok(checksum_buf)
}

pub fn sha256_from_vec(v: Vec<u8>) -> Result<Sha256, io::Error> {
    let mut hasher = sha2::Sha256::new();
    hasher.update(v);

    let mut checksum_buf = Sha256::default();
    checksum_buf.copy_from_slice(&hasher.finalize()[..]);
    Ok(checksum_buf)
}

pub fn sha256_from_vec_of_vec(vec: Vec<Vec<u8>>) -> Result<Sha256, io::Error> {
    let mut hasher = sha2::Sha256::new();

    for v in vec {
        hasher.update(v);
    }

    let mut checksum_buf = Sha256::default();
    checksum_buf.copy_from_slice(&hasher.finalize()[..]);
    Ok(checksum_buf)
}

pub fn sha256_from_path(file_path: &str) -> Result<Sha256, io::Error> {
    let mut file = std::fs::File::open(file_path)?;
    sha256_from_file_pointer(&mut file)
}

pub fn convert_string_to_sha256(s: &str) -> Result<Sha256, SigSetError> {
    let mut sha = Sha256::default();
    let v = hex::decode(s)?;

    if v.len() != SHA256_LEN {
        log::trace!("v.len(): {}, expected: {}", v.len(), SHA256_LEN);
        return Err(SigSetError::IncorrectSignatureError {
            info: format!("Can't convert {s} to sha256"),
        });
    }
    sha.copy_from_slice(&v);
    Ok(sha)
}

pub fn convert_sha256_to_string(sha: &Sha256) -> Result<String, SigSetError> {
    Ok(hex::encode_upper(sha))
}
