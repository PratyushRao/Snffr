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
}
