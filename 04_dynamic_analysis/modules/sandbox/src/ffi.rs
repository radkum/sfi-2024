use crate::{error::SandboxError, sandbox::perform_sandboxing};
use std::{collections::BTreeSet, fs::File, io, io::BufRead, path::Path};

const REPORTS_PATH: &str = "reports\\apiCallsReport.txt";

pub fn sandbox_path(target_path: &str) -> Result<Vec<String>, SandboxError> {
    perform_sandboxing(target_path)?;

    let lines = read_lines(REPORTS_PATH)?;
    let functions: Vec<_> = lines
        .into_iter()
        .map(|line| get_fn_name(line.unwrap_or_default()))
        .collect();
    let mut functions: BTreeSet<String> = functions.into_iter().collect();
    functions.remove(&String::from(""));
    //println!("fn calls: {:?}", &functions);
    log::trace!("fn calls: {:?}", &functions);
    Ok(functions.into_iter().collect())
    //Ok(vec!["BlockiInput".to_string(), "Sleep".to_string(), "ShellExecuteA".to_string(), "SetCursorPos".to_string()])
}

fn get_fn_name(fn_call: String) -> String {
    //println!("{fn_call:?}");
    let Some((call, _)) = fn_call.split_once("(") else {
        return String::new();
    };
    call.to_string()
}

fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
where
    P: AsRef<Path>,
{
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}
