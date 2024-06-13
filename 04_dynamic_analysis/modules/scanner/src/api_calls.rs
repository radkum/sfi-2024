use crate::error::ScanError;
use signatures::sig_set::dynamic_set::DynSet;
use ansi_term::Colour::Red;
use ansi_term::Colour::Green;
pub fn eval_api_calls(calls: Vec<String>, signatures: DynSet, file_name: String) -> Result<(), ScanError> {
    let _ = ansi_term::enable_ansi_support();
    if let Some(detection_info) = signatures.eval_api_calls(calls)? {
        //todo: do some action with detection info
        println!("{} - \"{}\",  {}", Red.paint("MALICIOUS"), file_name, detection_info);
        //println!("{}", detection_info);
    } else {
        println!("{} - \"{}\"", Green.paint("CLEAN"), file_name)
    }
    Ok(())
}
