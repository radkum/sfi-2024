use crate::error::SandboxError;

pub fn sandbox_path(target_path: &str) -> Result<Vec<String>, SandboxError>{
    let _path = std::path::Path::new(target_path);
    let v = vec!["BlockInput".to_string(), "Sleep".to_string(), "Beep".to_string(), "SeetCursorPos".to_string(), "ShellExecuteA".to_string(), "RegSetValueExA".to_string()];
    Ok(v)
}