fn main() {
    tonic_build::configure()
        .compile_protos(&["../proto/snffr.proto"], &["../proto"])
        .expect("Failed to compile protos");

    #[cfg(target_os = "windows")]
    {
        println!(
            r"cargo:rustc-link-search=native=C:\npcap-sdk\Lib\x64"
        );
        println!("cargo:rustc-link-lib=wpcap");
        println!("cargo:rustc-link-lib=Packet");
    }

    // Linux Only: build the eBPF/XDP kernel program
    #[cfg(target_os = "linux")]
    {
        let status = std::process::Command::new("clang")
            .args(&[
                "-O2",
                "-target", "bpf",
                "-c", "src/ebpf/xdp_block.c",
                "-o", "src/ebpf/xdp_block.o"
            ])
            .status();
        if let Ok(s) = status {
            if !s.success() {
                println!("cargo:warning=Failed to compile eBPF/XDP program");
            } else {
                println!("cargo:warning=Successfully compiled eBPF/XDP filter program to src/ebpf/xdp_block.o");
            }
        } else {
            println!("cargo:warning=clang is not available to compile eBPF program");
        }
    }
}
