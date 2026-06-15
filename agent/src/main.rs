mod types;
mod parser;

#[cfg(target_os = "windows")]
mod win_capture;

#[cfg(target_os = "linux")]
mod linux_capture;

use crossbeam_channel::unbounded;
use std::thread;

fn main() {
    let (tx, rx) = unbounded();

    #[cfg(target_os = "windows")]
    win_capture::start_capture(tx);

    #[cfg(target_os = "linux")]
    linux_capture::start_capture(tx);

    println!("[*] Snffr agent started. Press Ctrl+C to stop.");

    let _parser_handle = thread::spawn(move || {
        while let Ok(data) = rx.recv() {
            if let Some(parsed) = parser::parse_packet(data) {
                println!(
                    "[{}] {} -> {} ({} bytes)",
                    parsed.protocol,
                    parsed.src_ip,
                    parsed.dst_ip,
                    parsed.length
                );
            }
        }
    });

    loop { std::thread::park(); }
}