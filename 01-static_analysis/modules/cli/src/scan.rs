use std::{collections::VecDeque, fs::File, path::PathBuf};

use common::redr;
use signatures::sig_set::sha_set::ShaSet;

pub(super) fn scan_path(target_path: &str, sha_sig_path: String) -> anyhow::Result<()> {
    let signatures = signatures::deserialize_sha_set_from_path(sha_sig_path.as_str())?;

    let path = std::path::Path::new(target_path);

    if path.is_dir() {
        scan_dir(target_path, signatures)?
    } else if path.is_file() {
        scan_file(target_path, signatures)?
    } else {
        //other types are not supported
    }

    Ok(())
}

fn scan_file(file_path: &str, signatures: ShaSet) -> anyhow::Result<()> {
    log::debug!("scan_file: {}", file_path);
    let file = File::open(file_path)?;
    let file_info = redr::FileInfo::new(PathBuf::from(file_path));
    let file_to_scan = (redr::FileReader::from_file(file), file_info);

    let mut queue: VecDeque<(redr::FileReader, redr::FileInfo)> = VecDeque::from([file_to_scan]);
    scanner::scan_files(&mut queue, signatures)?;

    Ok(())
}

fn scan_dir(dir_path: &str, signatures: ShaSet) -> anyhow::Result<()> {
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
