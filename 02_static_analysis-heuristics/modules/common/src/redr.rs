mod file_abstraction;
mod file_info;

pub use file_abstraction::FileReader;
pub use file_info::FileInfo;

pub type FileScanInfo = (FileReader, FileInfo);
