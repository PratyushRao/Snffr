use std::process::Command;
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};

static XDP_ACTIVE: AtomicBool = AtomicBool::new(false);

pub fn set_xdp_active(active: bool) {
    XDP_ACTIVE.store(active, Ordering::SeqCst);
}

pub fn is_xdp_active() -> bool {
    XDP_ACTIVE.load(Ordering::SeqCst)
}

pub fn load_xdp(interface: &str) -> bool {
    println!("[*] Initializing Kernel-Level eBPF/XDP acceleration on device: {}", interface);

    // Clean up crashed run artefacts
    let _ = Command::new("bpftool").args(&["net", "detach", "xdp", "dev", interface]).status();
    let _ = Command::new("bpftool").args(&["net", "detach", "xdpgeneric", "dev", interface]).status();
    let _ = Command::new("rm").args(&["-f", "/sys/fs/bpf/snffr_prog", "/sys/fs/bpf/blocked_ips"]).status();

    // find where xdp_block.o is
    let mut bpf_obj = "src/ebpf/xdp_block.o".to_string();
    if !std::path::Path::new(&bpf_obj).exists() {
        bpf_obj = "agent/src/ebpf/xdp_block.o".to_string();
    }
    if !std::path::Path::new(&bpf_obj).exists() {
        bpf_obj = "xdp_block.o".to_string();
    }

    if !std::path::Path::new(&bpf_obj).exists() {
        eprintln!("[!] XDP filter object file not found. eBPF loading aborted.");
        return false;
    }

    println!("[*] Loading eBPF program: {}", bpf_obj);
    let load_status = Command::new("bpftool")
        .args(&[
            "prog", "load",
            &bpf_obj,
            "/sys/fs/bpf/snffr_prog",
            "type", "xdp",
            "pinmaps", "/sys/fs/bpf/"
        ])
        .status();

    match load_status {
        Ok(status) if status.success() => {
            println!("[+] eBPF program loaded and pinned to /sys/fs/bpf/snffr_prog");
        }
        _ => {
            eprintln!("[!] Failed to load eBPF program using bpftool. Fallback to standard iptables.");
            return false;
        }
    }

    //(try driver-level XDP first, fall back to xdpgeneric)
    println!("[*] Attaching XDP program to interface: {}", interface);
    let attach_xdp = Command::new("bpftool")
        .args(&["net", "attach", "xdp", "pinned", "/sys/fs/bpf/snffr_prog", "dev", interface])
        .status();

    let mut attached = false;
    if let Ok(status) = attach_xdp {
        if status.success() {
            println!("[+] Successfully attached native driver-level XDP program");
            attached = true;
        }
    }

    if !attached {
        println!("[*] Native driver-level XDP attachment failed. Trying generic XDP (xdpgeneric)...");
        let attach_generic = Command::new("bpftool")
            .args(&["net", "attach", "xdpgeneric", "pinned", "/sys/fs/bpf/snffr_prog", "dev", interface])
            .status();

        if let Ok(status) = attach_generic {
            if status.success() {
                println!("[+] Successfully attached generic-level XDP (xdpgeneric) program");
                attached = true;
            }
        }
    }

    if !attached {
        eprintln!("[!] Failed to attach XDP program to network interface");
        let _ = Command::new("rm").args(&["-f", "/sys/fs/bpf/snffr_prog", "/sys/fs/bpf/blocked_ips"]).status();
        return false;
    }

    println!("[+] eBPF/XDP Kernel-level filter active and running!");
    set_xdp_active(true);
    true
}

pub fn unload_xdp(interface: &str) {
    if !is_xdp_active() {
        return;
    }
    println!("[*] Unloading XDP program from interface: {}", interface);
    let _ = Command::new("bpftool").args(&["net", "detach", "xdp", "dev", interface]).status();
    let _ = Command::new("bpftool").args(&["net", "detach", "xdpgeneric", "dev", interface]).status();
    let _ = Command::new("rm").args(&["-f", "/sys/fs/bpf/snffr_prog", "/sys/fs/bpf/blocked_ips"]).status();
    set_xdp_active(false);
}

fn ip_to_hex_key(ip: &str) -> Option<String> {
    let ipv4 = Ipv4Addr::from_str(ip).ok()?;
    let octets = ipv4.octets();
    Some(format!("{:02x} {:02x} {:02x} {:02x}", octets[0], octets[1], octets[2], octets[3]))
}

pub fn block_ip(ip: &str) -> bool {
    let key = match ip_to_hex_key(ip) {
        Some(k) => k,
        None => return false,
    };

    println!("[*] Inserting block rule in kernel XDP map for IP: {} (Key: {})", ip, key);
    let parts: Vec<&str> = key.split_whitespace().collect();
    let status = Command::new("bpftool")
        .args(&[
            "map", "update",
            "pinned", "/sys/fs/bpf/blocked_ips",
            "key", parts[0], parts[1], parts[2], parts[3],
            "value", "01"
        ])
        .status();

    match status {
        Ok(s) if s.success() => true,
        _ => {
            eprintln!("[!] Failed to update XDP map for IP: {}", ip);
            false
        }
    }
}

pub fn unblock_ip(ip: &str) -> bool {
    let key = match ip_to_hex_key(ip) {
        Some(k) => k,
        None => return false,
    };

    println!("[*] Removing block rule from kernel XDP map for IP: {} (Key: {})", ip, key);
    let parts: Vec<&str> = key.split_whitespace().collect();
    let status = Command::new("bpftool")
        .args(&[
            "map", "delete",
            "pinned", "/sys/fs/bpf/blocked_ips",
            "key", parts[0], parts[1], parts[2], parts[3]
        ])
        .status();

    match status {
        Ok(s) if s.success() => true,
        _ => {
            eprintln!("[!] Failed to delete IP from XDP map: {}", ip);
            false
        }
    }
}
