extern crate core;

pub mod error;
pub mod sha256_utils;
pub mod sig_set;

use crate::{
    error::SigSetError,
    sig_set::{sha_set::ShaSet, SigSetTrait},
};
pub use sha256_utils::sha256_from_file_pointer;
use sig_set::sigset_deserializer::SigSetDeserializer;

pub fn deserialize_set_from_path(set_path: &str) -> Result<Box<dyn SigSetTrait>, SigSetError> {
    let des = SigSetDeserializer::new(set_path)?;
    des.get_set_box()
}

pub fn deserialize_sha_set_from_path(set_path: &str) -> Result<ShaSet, SigSetError> {
    let des = SigSetDeserializer::new(set_path)?;
    des.get_sha_set()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
