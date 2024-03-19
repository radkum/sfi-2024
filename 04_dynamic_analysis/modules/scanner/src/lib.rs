pub(crate) mod error;
pub(crate) mod scan;
pub mod ffi;
mod api_calls;

pub use ffi::scan_file;
pub use ffi::scan_dir;
pub use ffi::scan_path;
pub use ffi::scan_api_calls;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        assert_eq!(4, 4);
    }
}
