use std::net::{TcpListener, TcpStream};
use std::io::{Read, Write};
use std::thread;
use std::time::Duration;
use crate::auto_purge::AutoPurge;
use crate::config::GuardianConfig;
use crate::system::get_system_info;

const CONTROL_PORT: u16 = 58472;

pub struct RemoteControl;

impl RemoteControl {
    pub fn start_listener(config: &GuardianConfig) {
        thread::spawn(move || {
            if let Ok(listener) = TcpListener::bind(("0.0.0.0", CONTROL_PORT)) {
                for stream in listener.incoming() {
                    match stream {
                        Ok(mut stream) => {
                            let config_clone = config.clone();
                            thread::spawn(move || {
                                Self::handle_client(&mut stream, &config_clone);
                            });
                        }
                        Err(e) => eprintln!("Connection failed: {}", e),
                    }
                }
            }
        });
    }

    fn handle_client(stream: &mut TcpStream, config: &GuardianConfig) {
        let mut buffer = [0; 1024];
        if let Ok(size) = stream.read(&mut buffer) {
            let command = String::from_utf8_lossy(&buffer[..size]).to_string();
            
            match command.trim() {
                "SYSINFO" => {
                    let info = get_system_info();
                    let _ = stream.write_all(info.as_bytes());
                }
                "PURGE_NOW" => {
                    let _ = stream.write_all(b"INITIATING_PURGE");
                    AutoPurge::run(config);
                }
                "SHUTDOWN" => {
                    let _ = stream.write_all(b"SHUTTING_DOWN");
                    std::process::exit(0);
                }
                _ => {
                    let _ = stream.write_all(b"UNKNOWN_COMMAND");
                }
            }
        }
    }

    pub fn send_command(ip: &str, command: &str) -> Result<String, String> {
        let mut stream = TcpStream::connect((ip, CONTROL_PORT))
            .map_err(|e| format!("Connection failed: {}", e))?;
            
        stream.write_all(command.as_bytes())
            .map_err(|e| format!("Send failed: {}", e))?;
            
        let mut buffer = [0; 1024];
        let size = stream.read(&mut buffer)
            .map_err(|e| format!("Receive failed: {}", e))?;
            
        String::from_utf8(buffer[..size].to_vec())
            .map_err(|e| format!("Invalid response: {}", e))
    }
}
