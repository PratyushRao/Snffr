mod types;
mod parser;
mod responder;
mod ebpf_loader;

#[cfg(target_os = "windows")]
mod win_capture;

#[cfg(target_os = "linux")]
mod linux_capture;

pub mod snffr {
    tonic::include_proto!("snffr");
}

use snffr::sniffer_service_client::SnifferServiceClient;
use snffr::PacketReport;
use tokio_stream::wrappers::ReceiverStream;
use crossbeam_channel::unbounded;
use std::thread;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (tx, rx) = unbounded();

    #[cfg(target_os = "windows")]
    let _interface = win_capture::start_capture(tx);

    #[cfg(target_os = "linux")]
    let interface = linux_capture::start_capture(tx);

    // Try loading XDP program on Linux
    #[cfg(target_os = "linux")]
    {
        // this needs root/sudo.
        if !ebpf_loader::load_xdp(&interface) {
            println!("[!] Warning: Kernel-level XDP bypass could not be initialized. Operating in standard user-space capture mode.");
        }
    }

    println!("[*] Snffr agent started. Press Ctrl+C to stop.");

    // Graceful shutdown XDP drop
    #[cfg(target_os = "linux")]
    let interface_clone = interface.clone();
    
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.expect("failed to listen for event");
        println!("\n[*] Shutting down Agent...");
        #[cfg(target_os = "linux")]
        {
            ebpf_loader::unload_xdp(&interface_clone);
        }
        std::process::exit(0);
    });

    // send reports to the gRPC task
    let (tx_report, rx_report) = tokio::sync::mpsc::channel::<PacketReport>(1000);

    // Sync -> Bridge
    let _parser_handle = thread::spawn(move || {
        while let Ok(data) = rx.recv() {
            if let Some(parsed) = parser::parse_packet(data) {
                let report = PacketReport {
                    agent_id: "agent-01".into(),
                    src_ip: parsed.src_ip,
                    dst_ip: parsed.dst_ip,
                    src_port: parsed.src_port as u32,
                    dst_port: parsed.dst_port as u32,
                    protocol: parsed.protocol,
                    length: parsed.length,
                    payload_peek: parsed.payload_peek,
                    timestamp: Some(prost_types::Timestamp {
                        seconds: parsed.timestamp_sec,
                        nanos: (parsed.timestamp_usec * 1000) as i32,
                    }),
                };

                if let Err(e) = tx_report.blocking_send(report) {
                    eprintln!("Failed to send to gRPC task: {}", e);
                }
            }
        }
    });

    // gRPC Task: Consumer
    tokio::spawn(async move {
        println!("[*] Connecting to Manager at http://127.0.0.1:50051...");
        
        let mut client = match SnifferServiceClient::connect("http://127.0.0.1:50051").await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("[!] Connection failed: {}", e);
                return;
            }
        };

        let outbound_stream = ReceiverStream::new(rx_report);

        let response = match client.monitor(outbound_stream).await {
            Ok(res) => res,
            Err(e) => {
                eprintln!("[!] Monitor RPC failed: {}", e);
                return;
            }
        };

        let mut inbound_stream = response.into_inner();
        println!("[*] Connected to Manager. Monitoring traffic...");

        while let Ok(Some(command)) = inbound_stream.message().await {
            println!(
                "[!] ACTION RECEIVED: {:?} for IP: {} (Reason: {})",
                command.action(),
                command.target_ip,
                command.reason
            );
            
            responder::handle_command(command).await;
        }
    });

    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
    }
}
