use std::{collections::VecDeque, fs::File, path::PathBuf};

use common::redr;
use signatures::sig_set::SigSetTrait;

pub(super) fn scan_path(
    target_path: &str,
    sha_sig_path: Option<String>,
    heur_sig_path: Option<String>,
) -> anyhow::Result<()> {
    let mut signatures_vec = vec![];
    if let Some(sha_sig_path) = sha_sig_path {
        let signatures = signatures::deserialize_set_from_path(sha_sig_path.as_str())?;
        signatures_vec.push(signatures)
    }
    if let Some(heur_sig_path) = heur_sig_path {
        let signatures = signatures::deserialize_set_from_path(heur_sig_path.as_str())?;
        signatures_vec.push(signatures)
    }

    if signatures_vec.is_empty() {
        //something wrong
        log::warn!("There is no signatures!!!");
        return Ok(());
    }

    let path = std::path::Path::new(target_path);

    if path.is_dir() {
        scan_dir(target_path, signatures_vec)?
    } else if path.is_file() {
        scan_file(target_path, signatures_vec)?
    } else {
        //other types are not supported
    }

    Ok(())
}

fn scan_file(file_path: &str, signatures: Vec<Box<dyn SigSetTrait>>) -> anyhow::Result<()> {
    log::debug!("scan_file: {}", file_path);
    let file = File::open(file_path)?;
    let file_info = redr::FileInfo::new(PathBuf::from(file_path));
    let file_to_scan = (redr::FileReader::from_file(file), file_info);

    let mut queue: VecDeque<(redr::FileReader, redr::FileInfo)> = VecDeque::from([file_to_scan]);
    scanner::scan_files(&mut queue, signatures)?;

    Ok(())
}

fn scan_dir(dir_path: &str, signatures: Vec<Box<dyn SigSetTrait>>) -> anyhow::Result<()> {
    log::debug!("scan_dir: {}", dir_path);

    let mut queue = VecDeque::new();
    let paths = std::fs::read_dir(dir_path)?;
    for entry_res in paths {
        let entry = entry_res?;
        log::trace!("dir entry: {:?}", entry);

        if entry.file_type()?.is_file() {
            let path = entry.path();
            let file = File::open(&path)?;
            queue.push_back((
                redr::FileReader::from_file(file),
                redr::FileInfo::new(path.to_path_buf()),
            ));
        }
    }
    scanner::scan_files(&mut queue, signatures)?;

    Ok(())
}
