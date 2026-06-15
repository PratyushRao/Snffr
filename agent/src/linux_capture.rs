use crate::types::PacketData;
use crossbeam_channel::Sender;
use pcap::{Capture, Device, Error};
use std::thread;

pub fn start_capture(tx: Sender<PacketData>) {
    thread::spawn(move || {
        println!("[*] Searching network interfaces...");

        let devices = Device::list().expect("Failed to fetch interfaces");

        if devices.is_empty() {
            panic!("No network adapters found");
        }

        let device = devices
            .into_iter()
            .find(|d| {
                !d.flags.is_loopback() && d.flags.is_up() && d.flags.is_running()
})
            .expect("No suitable active non-loopback adapter found");

        println!("[*] Starting capture on: {}", device.name);

        let mut cap = Capture::from_device(device)
            .unwrap()
            .promisc(true)
            .snaplen(65535)
            .timeout(1000)
            .open()
            .expect("Failed to open interface");

        cap.filter("tcp or udp or icmp", true)
            .expect("Failed to apply BPF filter");

        loop {
            match cap.next_packet() {
                Ok(packet) => {
                    let data = PacketData {
                        timestamp_sec: packet.header.ts.tv_sec,
                        timestamp_usec: packet.header.ts.tv_usec,
                        length: packet.header.len,
                        payload: packet.data.to_vec(),
                    };

                    if tx.send(data).is_err() {
                        eprintln!("Capture channel closed");
                        break;
                    }
                }
                Err(Error::TimeoutExpired) => { continue; }
                Err(e) => { eprintln!("Capture error: {:?}", e); }
            }
        }
    });
}
