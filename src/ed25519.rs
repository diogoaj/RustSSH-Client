use std::convert::TryInto;
use std::fs::{self, File};
use std::io::{stdin, stdout, BufRead, Read, Write};
use std::net::IpAddr;
use std::path::PathBuf;

use base64::engine::general_purpose;
use base64::Engine;
use ed25519_dalek::Verifier;
use ring::digest;

fn read_hosts(ip: IpAddr, fingerprint: String) -> std::io::Result<bool> {
    let stdin = stdin();
    let mut stdout = stdout();
    let filename = &PathBuf::from("rust_known_hosts");
    let mut f = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .append(true)
        .read(true)
        .open(filename)
        .unwrap();

    let mut data = String::new();
    f.read_to_string(&mut data).expect("Unable to read file");

    let lines = data.split("\n");
    for line in lines {
        if line.contains(&fingerprint) {
            return Ok(true);
        }
    }

    println!("Host is not recognized!");
    println!("Fingerprint for ED25519 key is SHA256:{}", fingerprint);
    print!("Are you sure you want to continue connecting (yes/no)? ");
    stdout.flush()?;

    loop {
        let mut user_input = String::new();
        stdin.lock().read_line(&mut user_input).unwrap();
        match &user_input[..] {
            "yes\n" => {
                write_fingerprint(f, ip, fingerprint)?;
                println!("Host added.");
                return Ok(true);
            }
            "no\n" => {
                println!("Host could not be verified.");
                return Ok(false);
            }
            _ => {
                print!("Please type yes or no: ");
                stdout.flush()?;
            }
        }
    }
}

fn write_fingerprint(f: File, ip: IpAddr, fingerprint: String) -> std::io::Result<()> {
    write!(&f, "{}|{}", ip.to_string(), fingerprint)
}

pub fn host_key_fingerprint_check(ip: IpAddr, server_host_key: &Vec<u8>) -> bool {
    // Get SHA256 fingerprint
    let hash = digest::digest(&digest::SHA256, server_host_key.as_slice())
        .as_ref()
        .to_vec();
    let b64 = general_purpose::STANDARD.encode(hash);

    read_hosts(ip, b64).unwrap()
}

pub fn verify_server_signature(
    signature: &Vec<u8>,
    server_host_key: &Vec<u8>,
    hash_data: &Vec<u8>,
) -> bool {
    let mut signature_fixed_slice: [u8; 64] = [0; 64];
    signature_fixed_slice.copy_from_slice(signature.as_slice());

    let ed25519_signature = ed25519_dalek::Signature::from_bytes(&signature_fixed_slice);
    let server_host_key_slice: &[u8; 32] = server_host_key.as_slice().try_into().unwrap();
    let host_key_ed25519 = ed25519_dalek::VerifyingKey::from_bytes(server_host_key_slice).unwrap();

    host_key_ed25519
        .verify(hash_data.as_slice(), &ed25519_signature)
        .is_ok()
}
