use crate::error::SandboxError;

#[link(name = "..\\Sandbox\\Sandbox")]
extern "C" {
    //unfortunately exported function in Sandbox.dll are in C++ mangling. Fortunately we can add lin_name attribute
    #[link_name = "?sandboxFile@@YAHPEADH0H@Z"]
    pub fn sandboxFile(path: *const u8) -> u32;
}

pub(crate) fn perform_sandboxing(path: &str) -> Result<(), SandboxError> {
    //println!("path: {path}");
    // let mut path_plus_null = String::from(
    //     "C:\\VSExclude\\sfi-2024\\04_dynamic_analysis\\maldir\\Wacatac_dynamic_detection.exe",
    // );
    //let binding = std::path::Path::new(path).canonicalize()?;
    //let path = binding.as_path().to_str().unwrap_or_default();

    let mut path_plus_null = String::from(path);
    path_plus_null.push('\0');
    let result = unsafe { sandboxFile(path_plus_null.as_ptr()) };
    //println!("sandbox res: {}", get_sandbox_result(result));

    if result != 0 {
        return Err(SandboxError::PerformSandboxError {
            reason: get_sandbox_result(result),
        });
    } else {
        Ok(())
    }
}

fn get_sandbox_result(res: u32) -> String {
    let s = match res {
        0 => "Success",
        1 => "InputPathIsNull",
        2 => "GivenFileNotExists",
        3 => "ReportDirAlreadyExists",
        4 => "FailedToPerformApiAnalysis",
        _ => "UNKNOWN",
    };
    String::from(s)
}
