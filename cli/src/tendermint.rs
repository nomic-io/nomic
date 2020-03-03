use hex_literal::hex;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::prelude::*;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;
use zip::read::ZipArchive;
use log::{trace, info};

/// Download Tendermint binary unless we already have the correct version downloaded.

#[cfg(target_os = "macos")]
static TENDERMINT_BINARY_URL: &str = "https://github.com/tendermint/tendermint/releases/download/v0.32.8/tendermint_v0.32.8_darwin_amd64.zip";
#[cfg(all(target_os = "linux", target_arch="x86_64"))]
static TENDERMINT_BINARY_URL: &str = "https://github.com/tendermint/tendermint/releases/download/v0.32.8/tendermint_v0.32.8_linux_amd64.zip";
#[cfg(all(target_os = "linux", target_arch="arm"))]
static TENDERMINT_BINARY_URL: &str = "https://github.com/tendermint/tendermint/releases/download/v0.32.8/tendermint_v0.32.8_linux_arm.zip";

#[cfg(target_os = "macos")]
static TENDERMINT_ZIP_HASH: [u8; 32] =
    hex!("00577595c0672e287e651e55f6ca40eb780f93d415b5c48cfecafa9a12fd53b6");
#[cfg(all(target_os = "linux", target_arch="x86_64"))]
static TENDERMINT_ZIP_HASH: [u8; 32] =
    hex!("7b3bb2b156e624ff6792398fd8fcc422ea56a649c381e09a52491dab23906a4b");
    #[cfg(all(target_os = "linux", target_arch="arm"))]
static TENDERMINT_ZIP_HASH: [u8; 32] =
    hex!("dcaff3ad9e498bae0468e5b2763ede0a71121e94e6d409bcf9f72b1d5d6f8148");


fn verify_hash(tendermint_bytes: &Vec<u8>) {
    let mut hasher = Sha256::new();
    hasher.input(tendermint_bytes);
    let digest = hasher.result();
    let bytes = digest.as_slice();
    assert_eq!(
        bytes, TENDERMINT_ZIP_HASH,
        "Tendermint binary zip did not match expected hash"
    );
    info!("Confirmed correct Tendermint zip hash");
}

pub fn install(nomic_home: &PathBuf) {
    info!("Installing Tendermint to {}", nomic_home.to_str().unwrap());
    let mut buf: Vec<u8> = vec![];
    reqwest::blocking::get(TENDERMINT_BINARY_URL)
        .expect("Failed to download Tendermint zip file from GitHub")
        .copy_to(&mut buf)
        .expect("Failed to read bytes from zip file");

    info!("Downloaded Tendermint binary");
    verify_hash(&buf);
    let cursor = std::io::Cursor::new(buf);
    let mut zip = ZipArchive::new(cursor).expect("Invalid zip file contents");
    let mut tendermint_bytes = zip
        .by_name("tendermint")
        .expect("Tendermint binary not found in the downloaded zip file");
    let mut buf: Vec<u8> = vec![];
    std::io::copy(&mut tendermint_bytes, &mut buf).expect("Failed to buffer Tendermint binary");
    let tendermint_path = nomic_home.join("tendermint-v0.32.8");
    let mut f = fs::File::create(tendermint_path)
        .expect("Could not create Tendermint binary on file system");
    f.write_all(&mut buf)
        .expect("Failed to write Tendermint binary to file system");
    let mut perms = f.metadata().unwrap().permissions();
    perms.set_mode(0o777);
    f.set_permissions(perms)
        .expect("Failed to set Tendermint binary permissions");
}

pub fn start(nomic_home: &PathBuf) {
    let tendermint_path = nomic_home.join("tendermint-v0.32.8");
    Command::new(tendermint_path)
        .arg("node")
        .arg("--home")
        .arg(nomic_home.to_str().unwrap())
        .spawn()
        .expect("Failed to start Tendermint");
    info!("Spawned Tendermint child process");
}
