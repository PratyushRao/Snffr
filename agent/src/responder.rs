use crate::snffr::ActionCommand;
use crate::snffr::action_command::ActionType;
use std::process::Command;
use tokio::time::{sleep, Duration};

pub async fn handle_command(cmd: ActionCommand) {
    match cmd.action() {
        ActionType::BLOCK => {
            block_ip(&cmd.target_ip, cmd.duration_seconds).await;
        }
        ActionType::RATE_LIMIT => {
            #[cfg(target_os = "linux")]
            rate_limit_ip_linux(&cmd.target_ip, cmd.duration_seconds, cmd.rate_limit_pps).await;
            
            #[cfg(target_os = "windows")]
            rate_limit_ip_windows(&cmd.target_ip, cmd.duration_seconds).await;
        }
        _ => println!("[?] Action {:?} not yet implemented", cmd.action()),
    }
}

async fn block_ip(ip: &str, duration: u32) {
    println!("[!] BLOCKING IP: {} for {}s", ip, duration);

    #[cfg(target_os = "linux")]
    {
        let _ = Command::new("iptables")
            .args(&["-A", "INPUT", "-s", ip, "-j", "DROP"])
            .status();

        if duration > 0 {
            let ip_clone = ip.to_string();
            tokio::spawn(async move {
                sleep(Duration::from_secs(duration as u64)).await;
                let _ = Command::new("iptables")
                    .args(&["-D", "INPUT", "-s", &ip_clone, "-j", "DROP"])
                    .status();
                println!("[*] Unblocked IP: {}", ip_clone);
            });
        }
    }

    #[cfg(target_os = "windows")]
    {
        let rule_name = format!("snffr-block-{}", ip);

        let _ = Command::new("netsh")
            .args(&[
                "advfirewall", "firewall", "add", "rule",
                &format!("name={}", rule_name),
                "dir=in", "action=block",
                &format!("remoteip={}", ip),
            ])
            .status();

        if duration > 0 {
            tokio::spawn(async move {
                sleep(Duration::from_secs(duration as u64)).await;
                let _ = Command::new("netsh")
                    .args(&["advfirewall", "firewall", "delete", "rule", &format!("name={}", rule_name)])
                    .status();
                println!("[*] Unblocked IP: {}", ip);
            });
        }
    }
}

#[cfg(target_os = "linux")]
async fn rate_limit_ip_linux(ip: &str, duration: u32, pps: u32) {
    let rate_str = format!("{}/s", pps);
    println!("[!] RATE LIMITING IP: {} for {}s (Limit: {})", ip, duration, rate_str);

    let _ = Command::new("iptables")
        .args(&["-A", "INPUT", "-s", ip, "-m", "limit", "--limit", &rate_str, "-j", "ACCEPT"])
        .status();

    let _ = Command::new("iptables")
        .args(&["-A", "INPUT", "-s", ip, "-j", "DROP"])
        .status();

    if duration > 0 {
        let ip_clone = ip.to_string();
        tokio::spawn(async move {
            sleep(Duration::from_secs(duration as u64)).await;
            let _ = Command::new("iptables")
                .args(&["-D", "INPUT", "-s", &ip_clone, "-m", "limit", "--limit", &rate_str, "-j", "ACCEPT"])
                .status();
            let _ = Command::new("iptables")
                .args(&["-D", "INPUT", "-s", &ip_clone, "-j", "DROP"])
                .status();
            println!("[*] Removed Rate Limit for IP: {}", ip_clone);
        });
    }
}

#[cfg(target_os = "windows")]
async fn rate_limit_ip_windows(ip: &str, duration: u32) {
    let policy_name = format!("snffr-throttle-{}", ip.replace(".", "-"));
    println!("[!] RATE LIMITING IP (Windows QoS): {} for {}s (Limit: 1Mbps)", ip, duration);

    let _ = Command::new("powershell")
        .args(&[
            "-Command",
            &format!(
                "New-NetQosPolicy -Name '{}' -IPDstAddrMatchCondition '{}' -ThrottleRateActionBitsPerSecond 1000000 -AppPathNameMatchCondition '*'",
                policy_name, ip
            )
        ])
        .status();

    if duration > 0 {
        let ip_clone = ip.to_string();
        tokio::spawn(async move {
            sleep(Duration::from_secs(duration as u64)).await;
            
            let _ = Command::new("powershell")
                .args(&["-Command", &format!("Remove-NetQosPolicy -Name '{}' -Confirm:$false", policy_name)])
                .status();
                
            println!("[*] Removed Windows Rate Limit for IP: {}", ip_clone);
        });
    }
}
