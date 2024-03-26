use alloc::vec::Vec;
use core::mem;
use sha2::Digest;

const SHA256_LEN: usize = 32;
pub type Sha256 = [u8; SHA256_LEN];

pub fn sha256_from_vec(v: Vec<u8>) -> Sha256 {
    let mut hasher = sha2::Sha256::new();
    hasher.update(v);

    let mut checksum_buf = Sha256::default();
    checksum_buf.copy_from_slice(&hasher.finalize()[..]);
    checksum_buf
}

pub fn sha256_from_bytes(v: &[u8]) -> Sha256 {
    sha256_from_vec(v.to_vec())
}

#[allow(dead_code)]
pub fn sha256_from_vec_of_vec(vec: Vec<Vec<u8>>) -> Sha256 {
    let mut hasher = sha2::Sha256::new();

    for v in vec {
        hasher.update(v);
    }

    let mut checksum_buf = Sha256::default();
    checksum_buf.copy_from_slice(&hasher.finalize()[..]);
    checksum_buf
}

pub fn align(size: usize) -> u32 {
    //const ALIGNMENT: usize = mem::size_of::<usize>();
    const ALIGNMENT: usize = mem::size_of::<u32>();
    if size % ALIGNMENT == 0 {
        size as u32
    } else {
        (size + (ALIGNMENT - size % ALIGNMENT)) as u32
    }
}
