use signatures::sig_set::dynamic_set::DynSet;
use crate::error::ScanError;

pub fn eval_api_calls(calls: Vec<String>, signatures: DynSet) -> Result<(), ScanError> {
    if let Some(detection_info) = signatures.eval_api_calls(calls)? {
        //todo: do some action with detection info
        println!("{}", detection_info);
    }
    Ok(())
}