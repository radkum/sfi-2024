use std::{
    collections::VecDeque,
    io::{Seek, SeekFrom::Start},
};
use std::collections::{BTreeMap, BTreeSet};

use crate::error::ScanError;
use common::redr;
use signatures::sig_set::SigSet;
use ansi_term::Colour::Green;
use ansi_term::Colour::Red;

const MAX_FILE_TO_SCAN: usize = 0x100;

pub fn scan_files(
    files_queue: &mut VecDeque<redr::FileReaderAndInfo>,
    signatures_vec: Vec<Box<dyn SigSet>>,
) -> Result<(), ScanError> {
    let _ = ansi_term::enable_ansi_support();
    let mut set: BTreeMap<String, String> = BTreeMap::new();
    for i in 1..MAX_FILE_TO_SCAN + 1 {
        if let Some((mut reader, mut variant)) = files_queue.pop_front() {
            log::debug!("Start scanning {i} file");

            for signatures in &signatures_vec {
                //set file pointer to 0 to be sure we read from the file beginning
                reader.seek(Start(0))?;

                let detection = if let Some(detection_info) = signatures.eval_file(&mut reader, &mut variant)? {
                    //todo: do some action with detection info
                    format!("{} - {}", Red.paint("MALICIOUS"), variant.get_malware_info(detection_info))
                    //break;
                } else {
                    format!("{} - \"{}\"", Green.paint("CLEAN"), variant.get_name())
                };
                let name = variant.get_name();
                //println!("{}", &name);
                set.insert(name, detection);
            }

            //set file pointer to 0 to be sure we read from the file beginning
            reader.seek(Start(0))?;

            //unpack and add files to the scanning queue
            let res = arcom::unpack_file(reader, variant.get_origin_file(), files_queue);
            if let Err(e) = res {
                log::warn!("{e}");
            }
        } else {
            log::info!("No more files to scan");
            break;
        }
    }

    for (_, v) in set {
        println!("{v}");
    }
    Ok(())
}
