use std::{
    collections::VecDeque,
    io::{Seek, SeekFrom::Start},
};

use crate::error::ScanError;
use common::redr;
use signatures::sig_set::SigSet;

const MAX_FILE_TO_SCAN: usize = 0x100;

pub fn scan_files(
    files_queue: &mut VecDeque<redr::FileScanInfo>,
    signatures_vec: Vec<Box<dyn SigSet>>,
) -> Result<(), ScanError> {
    for i in 1..MAX_FILE_TO_SCAN + 1 {
        if let Some((mut reader, file_info)) = files_queue.pop_front() {
            log::debug!("Start scanning {i} file");

            for signatures in &signatures_vec {
                //set file pointer to 0 to be sure we read from the file beginning
                reader.seek(Start(0))?;

                if let Some(detection_info) = signatures.eval_file(&mut reader)? {
                    //todo: do some action with detection info
                    println!("{}, {}", detection_info, file_info);
                    break;
                }
            }
        } else {
            log::info!("No more files to scan");
            break;
        }
    }
    Ok(())
}
