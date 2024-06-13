use crate::detection::DetectionReport;
use std::{cell::RefCell, path::PathBuf, rc::Rc};

pub type RcMut<T> = Rc<RefCell<T>>;

use crate::redr::FileInfo;

pub enum FileScanInfo {
    RealFile(RcMut<FileInfo>),
    EmbeddedFile {
        original_file: RcMut<FileInfo>,
        //original_file: FileInfo,
        name: String,
    },
}

impl FileScanInfo {
    pub fn get_malware_info(&self, detection_info: DetectionReport) -> String {
        match self {
            FileScanInfo::RealFile(file) => {
                let name: String = file.borrow().name.clone();
                let path: String = file.borrow().canonical_path.clone();

                format!(
                    //"\"{name}\" -> Malicious {{ path: \"{path}\", desc: \"{}\", cause: {} }}",
                    "\"{name}\" -> Malicious {{ desc: \"{}\", cause: {} }}",
                    detection_info.desc, detection_info.cause
                )
            },
            FileScanInfo::EmbeddedFile {
                original_file: file,
                name,
            } => {
                let original_name: String = file.borrow().name.clone();
                let path: String = file.borrow().canonical_path.clone();

                let sha256 = file
                    .borrow()
                    .sha256
                    .clone()
                    .unwrap_or("UNKNOWN".to_string());

                let cause = format!(
                    "EmbeddedFile: {{ name: {name}, desc: \"{}\", cause: {} }}",
                    detection_info.desc, detection_info.cause
                );
                format!(
                    "\"{original_name}\" -> Malicious {{ cause: {cause} }}"
                )
            },
        }
    }

    pub fn get_origin_file(&self) -> RcMut<FileInfo> {
        match self {
            FileScanInfo::RealFile(rc) => rc.clone(),
            FileScanInfo::EmbeddedFile {
                original_file,
                name: _name,
            } => original_file.clone(),
        }
    }

    pub fn get_name(&self) -> String {
        match self {
            FileScanInfo::RealFile(file) => {
                let name: String = file.borrow().name.clone();
                name.to_string()
            },
            FileScanInfo::EmbeddedFile {
                original_file: file,
                name,
            } => {
                let original_name: String = file.borrow().name.clone();
                name.to_string()
            },
        }
    }


    pub fn set_sha(&mut self, sha: String) {
        if let FileScanInfo::RealFile(rc) = self {
            rc.borrow_mut().sha256 = Some(sha);
        }
    }

    pub fn real_file(path: PathBuf) -> Self {
        Self::RealFile(Rc::new(RefCell::new(FileInfo::new(path))))
    }

    pub fn embedded_file(original_file: RcMut<FileInfo>, name: &str) -> Self {
        Self::EmbeddedFile {
            original_file,
            name: name.to_string(),
        }
    }
}
