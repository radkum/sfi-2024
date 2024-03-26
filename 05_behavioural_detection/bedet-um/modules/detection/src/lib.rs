pub mod error;
mod error_msg;
mod handle_wrapper;
pub mod winapi;

use ansi_term::Colour::{Green, Red};

use crate::{
    error_msg::{print_hr_result, print_last_error},
    handle_wrapper::SmartHandle,
};
use ansi_term::Style;
use common::{
    event::{
        get_event_type, image_load::ImageLoadEvent, process_create::ProcessCreateEvent,
        registry_set_value::RegistrySetValueEvent, Event, FileCreateEvent,
    },
    hasher::MemberHasher,
};
use console::Term;
use signatures::sig_set::{bedet_set::BedetSet, SigSet};
use std::{
    io::Write,
    mem,
    ptr::{null, null_mut},
};

use crate::winapi::output_debug_string;
use widestring::u16str;
use windows_sys::Win32::{
    Foundation::STATUS_SUCCESS,
    Storage::InstallableFileSystems::{
        FilterConnectCommunicationPort, FilterGetMessage, FILTER_MESSAGE_HEADER,
    },
};

const COMM_PORT_NAME: &str = "\\BEDET.KM2UM.Port\0";
//const COMM_PORT_NAME: &str = "\\RAMON.KM2UM.Port\0";
type PISIZE = *mut isize;

#[tokio::main]
pub async fn start_detection(signatures: BedetSet) {
    let port_name = u16str!(COMM_PORT_NAME).as_ptr();
    let Some(connection_port) = init_port(port_name) else {
        return;
    };
    let _ = ansi_term::enable_ansi_support();
    println!("{} Client connected to driver", Green.paint("SUCCESS!"));

    message_loop(connection_port, signatures);

    //CloseHandle(h_connection_port);
}

fn init_port(port_name: *const u16) -> Option<SmartHandle> {
    let mut connection_port = SmartHandle::new();

    let hr = unsafe {
        FilterConnectCommunicationPort(
            port_name,
            0,
            null(),
            0,
            null_mut(),
            connection_port.as_mut_ref() as PISIZE,
        )
    };

    if hr != STATUS_SUCCESS {
        println!("Failed to connect");
        print_hr_result("", hr);
        print_last_error("");
        None
    } else {
        Some(connection_port)
    }
}
fn message_loop(connection_port: SmartHandle, signatures: BedetSet) {
    let _t = tokio::spawn(async move {
        let msg_header = mem::size_of::<FILTER_MESSAGE_HEADER>();

        // In a loop, read data from the socket and write the data back.
        let mut buff: [u8; 0x1000] = unsafe { mem::zeroed() };
        loop {
            let hr = unsafe {
                FilterGetMessage(
                    connection_port.get() as isize,
                    buff.as_mut_ptr() as *mut FILTER_MESSAGE_HEADER,
                    mem::size_of_val(&buff) as u32,
                    null_mut(),
                )
            };

            if hr != STATUS_SUCCESS {
                println!("Failed to get message");
                print_hr_result("", hr);
                print_last_error("");
                return;
            }

            let event_buff = &buff[msg_header..];
            let e = get_event_type(event_buff);
            match e {
                ProcessCreateEvent::EVENT_CLASS => {
                    //println!("{:?}", ProcessCreateEvent::deserialize(event_buff))
                },
                ImageLoadEvent::EVENT_CLASS => {
                    //println!("{:?}", ImageLoadEvent::deserialize(event_buff))
                },
                RegistrySetValueEvent::EVENT_CLASS => {
                    if let Some(e) = RegistrySetValueEvent::deserialize(event_buff) {
                        if let Ok(Some(s)) = signatures.eval_event(e.hash_members()) {
                            let detection = format!("{:?}", s);
                            println!(
                                "{} - {}",
                                Red.paint("MALWARE"),
                                Style::new().bold().paint(&detection)
                            );
                            output_debug_string(detection);
                            if cleaner::process_cleaner::try_to_kill_process(e.get_pid()) {
                                println!(
                                    "{} Process terminated. Pid: {}",
                                    Green.paint("SUCCESS!"),
                                    e.get_pid()
                                );
                                output_debug_string(format!(
                                    "Success to terminate process. Pid: {}",
                                    e.get_pid()
                                ));
                            } else {
                                output_debug_string(format!(
                                    "Failed to terminate process. Pid: {}",
                                    e.get_pid()
                                ));
                            }
                        }

                        let _ = std::io::stdout().flush();
                        // tokio::spawn(async move {
                        //     process_event(e.hash_members(), signatures).await;
                        // });
                    }
                },
                FileCreateEvent::EVENT_CLASS => {
                    //println!("{:?}", FileCreateEvent::deserialize(event_buff))
                },
                _ => {},
            }
            //println!("{}", String::from_utf8(e.to_blob().unwrap()).unwrap());
        }
    });

    let stdout = Term::buffered_stdout();
    loop {
        if let Ok(character) = stdout.read_char() {
            match character {
                'q' => break,
                _ => {},
            }
        }
    }
}

// async fn process_event(hashes: Vec<[u8; 32]>, signatures: &BedetSet) {
//     println!(
//         "{}",
//         hashes
//             .iter()
//             .map(|sha| convert_sha256_to_string(sha).unwrap())
//             .collect::<Vec<_>>()
//             .join(", ")
//     );
//     println!("{:?}", signatures.eval_event(hashes).unwrap());
// }

#[cfg(test)]
mod test {
    use common::{event::registry_set_value::RegistrySetValueEvent, hasher::MemberHasher};
    use signatures::sig_set::SigSet;

    #[test]
    fn compile_and_eval_signature() {
        let path = std::path::Path::new("..\\..\\malset.bset");
        if path.exists() {
            let signatures =
                signatures::deserialize_bedet_set_from_path(path.to_str().unwrap()).unwrap();
            let e1 = RegistrySetValueEvent::new(
                123,
                234,
                r#"\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"#.to_string(),
                "Windows Live Messenger".to_string(),
                1,
                r#"C:\WINDOWS\system32\evil.exe"#.as_bytes().to_vec(),
            );

            let v = e1.hash_members();

            let x = signatures.eval_event(v).unwrap().unwrap();

            assert_eq!(x.desc, "Watacat - behavioural detection");
            assert_eq!(
                x.cause,
                "Detected Event: RegSetValue: { {\"data\": \
                 \"C:\\\\WINDOWS\\\\system32\\\\evil.exe\", \"data_type\": \"1\", \"key_name\": \
                 \"\\\\REGISTRY\\\\MACHINE\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\
                 \\Run\", \"value_name\": \"Windows Live Messenger\"} }"
            );
        }
    }
}
