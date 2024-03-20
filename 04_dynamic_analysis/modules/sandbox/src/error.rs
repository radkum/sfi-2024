use std::ffi::OsString;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum SandboxError {
    #[error("IoError: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Failed to perform sandbox. Reason '{reason}'")]
    PerformSandboxError { reason: String },
    #[error("Can't convert OsString to String. After to_string_lossy(): {0}")]
    OsStringError(String),
}

impl From<OsString> for SandboxError {
    fn from(arg: OsString) -> Self {
        Self::OsStringError(arg.to_string_lossy().into())
    }
}
