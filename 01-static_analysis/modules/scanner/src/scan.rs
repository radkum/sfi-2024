use std::collections::VecDeque;

use crate::error::ScanError;
use common::redr;
use signatures::sig_set::{sha_set::ShaSet, SigSet};
use ansi_term::Colour::Green;
use ansi_term::Colour::Red;

const MAX_FILE_TO_SCAN: usize = 0x100;

pub fn scan_files(
    files_queue: &mut VecDeque<redr::FileScanInfo>,
    signatures: ShaSet,
) -> Result<(), ScanError> {
    let _ = ansi_term::enable_ansi_support();

    for i in 1..MAX_FILE_TO_SCAN + 1 {
        if let Some((mut reader, file_info)) = files_queue.pop_front() {
            log::debug!("Start scanning {i} file");

            if let Some(detection_info) = signatures.eval_file(&mut reader)? {
                //todo: do some action with detection info
                println!("{} - \"{}\",  {}", Red.paint("MALICIOUS"), file_info.name, detection_info);
                //break;
            } else {
                println!("{} - \"{}\"", Green.paint("CLEAN"), file_info.name);
            }
        } else {
            log::info!("No more files to scan");
            break;
        }
    }
    Ok(())
}
