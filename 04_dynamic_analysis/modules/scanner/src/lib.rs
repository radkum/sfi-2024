mod api_calls;
pub(crate) mod error;
pub mod ffi;
pub(crate) mod scan;

pub use ffi::{scan_api_calls, scan_dir, scan_file, scan_path};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        assert_eq!(4, 4);
    }
}
