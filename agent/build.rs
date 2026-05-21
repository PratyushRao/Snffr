fn main() {
    println!(
        r"cargo:rustc-link-search=native=C:\Program Files\Npcap SDK\Lib\x64"
    );

    println!("cargo:rustc-link-lib=wpcap");
    println!("cargo:rustc-link-lib=Packet");
}