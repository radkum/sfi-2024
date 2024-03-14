pub mod error;
pub mod scan;

pub use scan::scan_files;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        assert_eq!(4, 4);
    }
}
