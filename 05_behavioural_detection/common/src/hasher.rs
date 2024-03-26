use alloc::format;
use crate::utils::{Sha256, sha256_from_bytes};
use alloc::vec::Vec;

pub trait MemberHasher {
    const EVENT_NAME: &'static str;

    fn hash_members(&self) -> Vec<Sha256>;
}

pub fn member_to_hash<T: core::fmt::Display>(event_type: &str, attr_name: &str, attr_value: T) -> Sha256 {
    let attr = format!("{}+{}+{}", event_type, attr_name, attr_value);
    sha256_from_bytes(attr.as_bytes())
}