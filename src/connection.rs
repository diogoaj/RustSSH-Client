use std::{io::prelude::*, net::SocketAddr};
use std::net::TcpStream;
use std::io::BufReader;
use std::io::BufWriter;
use std::net::IpAddr;
use std::str;

use rand::Rng;
use rand::rngs::OsRng;
use x25519_dalek::{EphemeralSecret, PublicKey};
use ed25519_dalek::*;
use ring::{digest, aead};
use core::convert::TryInto;
use std::convert::From;


mod numbers;
mod algorithms;


pub fn read_line(reader: &mut BufReader<&TcpStream>) -> std::io::Result<String> {
    let mut data = String::new();
    reader.read_line(&mut data)?;
    Ok(data)
}

pub fn write_line(writer: &mut BufWriter<&TcpStream>, line: &str) -> std::io::Result<()> {
    writer.write(&line.as_bytes())?;
    writer.flush()?;
    Ok(())
}

pub fn send_data(writer: &mut BufWriter<&TcpStream>, data: &mut Vec<u8>) -> std::io::Result<()> {
    let padding = 32 - (data.len() as u32 + 5) % 32;
    let data_len = ((data.len() + 1 + padding as usize) as u32).to_be_bytes().to_vec();

    let mut i = 0;
    for b in data_len.iter() {
        data.insert(i, *b);
        i += 1;
    }

    data.insert(i, padding as u8);
    data.append(&mut vec![0; padding as usize]);

    writer.write(data.as_slice())?;
    writer.flush()
}

pub fn make_hash(
    v_c: &mut Vec<u8>, 
    v_s: &mut Vec<u8>, 
    i_c: &mut Vec<u8>, 
    i_s: &mut Vec<u8>, 
    k_s: &mut Vec<u8>, 
    e: &mut Vec<u8>, 
    f: &mut Vec<u8>,
    k: &mut Vec<u8>) -> Vec<u8> {

        let mut hash_data: Vec<u8> = Vec::new();
        hash_data.append(v_c);
        hash_data.append(v_s);
        hash_data.append(i_c);
        hash_data.append(i_s);
        hash_data.append(k_s);
        hash_data.append(e);
        hash_data.append(f);
        hash_data.append(k);

        digest::digest(&digest::SHA256, hash_data.as_slice()).as_ref().to_vec()
    }


// Testing SSH handshake
// 1. Sending Client Identifier
// 2. Sending Algorithm List
// 3. Testing key exchange

pub fn run(host: IpAddr, port: u16) -> std::io::Result<()>{
    let socket = SocketAddr::new(host, port);
    let stream = TcpStream::connect(socket)?;

    let mut reader = BufReader::new(&stream);
    let mut writer = BufWriter::new(&stream);

    let server_protocol =  read_line(&mut reader)?;

    println!("Server version: {:?}", server_protocol.trim());

    let protocol_string = "SSH-2.0-Simple_Rust_Client_1.0\r\n";
    write_line(&mut writer, protocol_string)?;

    let mut received_kex: Vec<u8> = reader.fill_buf()?.to_vec();
    reader.consume(received_kex.len());

    let _size = &received_kex[0..4];
    let _pad = &received_kex[5];
    let _code = &received_kex[6];
    let _cookie = &received_kex[6..22];

    let mut server_algorithms: Vec<&str> = Vec::new();
    let mut i = 22;

    loop {
        let mut size_bytes: [u8; 4] = [0; 4];
        size_bytes.copy_from_slice(&received_kex[i..i+4]);
        let algo_size = u32::from_be_bytes(size_bytes);

        if algo_size == 0 { 
            break;
        }

        server_algorithms.push(str::from_utf8(&received_kex[i+4..i+4+algo_size as usize]).unwrap());

        i = i + 4 + algo_size as usize;   
    }

    let mut ciphers: Vec<u8> = Vec::new();
    let mut csprng = OsRng{};

    let cookie: [u8; 16] = csprng.gen();
  
    ciphers.push(numbers::Message::SSH_MSG_KEXINIT);
    ciphers.append(&mut cookie.to_vec());
    ciphers.append(&mut (algorithms::KEY_EXCHANGE_ALGORITHMS.len() as u32).to_be_bytes().to_vec());
    ciphers.append(&mut algorithms::KEY_EXCHANGE_ALGORITHMS.as_bytes().to_vec());
    ciphers.append(&mut (algorithms::PUBLIC_KEY_ALGORITHMS.len() as u32).to_be_bytes().to_vec());
    ciphers.append(&mut algorithms::PUBLIC_KEY_ALGORITHMS.as_bytes().to_vec());
    ciphers.append(&mut (algorithms::ENCRYPTION_ALGORITHMS.len() as u32).to_be_bytes().to_vec());
    ciphers.append(&mut algorithms::ENCRYPTION_ALGORITHMS.as_bytes().to_vec());
    ciphers.append(&mut (algorithms::ENCRYPTION_ALGORITHMS.len() as u32).to_be_bytes().to_vec());
    ciphers.append(&mut algorithms::ENCRYPTION_ALGORITHMS.as_bytes().to_vec());
    ciphers.append(&mut (algorithms::MAC_ALGORITHMS.len() as u32).to_be_bytes().to_vec());
    ciphers.append(&mut algorithms::MAC_ALGORITHMS.as_bytes().to_vec());
    ciphers.append(&mut (algorithms::MAC_ALGORITHMS.len() as u32).to_be_bytes().to_vec());
    ciphers.append(&mut algorithms::MAC_ALGORITHMS.as_bytes().to_vec());
    ciphers.append(&mut (algorithms::COMPRESSION_ALGORITHMS.len() as u32).to_be_bytes().to_vec());
    ciphers.append(&mut algorithms::COMPRESSION_ALGORITHMS.as_bytes().to_vec());
    ciphers.append(&mut (algorithms::COMPRESSION_ALGORITHMS.len() as u32).to_be_bytes().to_vec());
    ciphers.append(&mut algorithms::COMPRESSION_ALGORITHMS.as_bytes().to_vec());
    ciphers.append(&mut vec![0;13]);

    send_data(&mut writer, &mut ciphers)?;

    ///////////////////////////////////////

    let client_secret = EphemeralSecret::new(&mut csprng);
    let client_public = PublicKey::from(&client_secret);
    let pub_key = client_public.as_bytes();

    let mut key_exchange: Vec<u8> = Vec::new();
    key_exchange.push(numbers::Message::SSH_MSG_KEX_ECDH_INIT);
    key_exchange.append(&mut (pub_key.len() as u32).to_be_bytes().to_vec());
    key_exchange.append(&mut pub_key.to_vec());

    send_data(&mut writer, &mut key_exchange)?;

    ///////////////////////////////////////////////

    let mut received_ecdh: Vec<u8> = reader.fill_buf()?.to_vec();
    let _size = &received_ecdh[0..4];
    let _pad = &received_ecdh[5];
    let _code = &received_ecdh[6];

    let key_size = u32::from_be_bytes(received_ecdh[6..10].try_into().unwrap());
    let host_key = &received_ecdh[29..(10 + key_size) as usize];

    let host_key_ed25519 = ed25519_dalek::PublicKey::from_bytes(host_key).unwrap();

    let f = &received_ecdh[((14 + key_size) as usize)..((14 + 32 + key_size) as usize)];

    let index = (14 + 32 + key_size) as usize;
    let alg_size = &received_ecdh[index..index+4];
    let alg = &received_ecdh[index+4..index+4+11];
    let sig = &received_ecdh[index+4+19..index+4+11+72];

    let mut sig_fixed: [u8;64] = [0;64];
    sig_fixed.copy_from_slice(sig);
    let ed25519_signature = ed25519_dalek::Signature::new(sig_fixed);

    let f_fixed: [u8;32] = f.try_into().unwrap();

    let server_pub = PublicKey::from(f_fixed);
    let secret = client_secret.diffie_hellman(&server_pub);

    let mut v_c: Vec<u8> = Vec::new();
    v_c.append(&mut (30 as u32).to_be_bytes().to_vec());
    v_c.append(&mut "SSH-2.0-Simple_Rust_Client_1.0".as_bytes().to_vec());

    let mut v_s: Vec<u8> = Vec::new();
    v_s.append(&mut (39 as u32).to_be_bytes().to_vec());
    v_s.append(&mut "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1".as_bytes().to_vec());

    let mut k_s = received_ecdh[6..(10 + key_size) as usize].to_vec();

    let mut e: Vec<u8> = Vec::new();
    e.append(&mut (32 as u32).to_be_bytes().to_vec());
    e.append(&mut client_public.as_bytes().to_vec());

    let mut f: Vec<u8> = Vec::new();
    f.append(&mut (32 as u32).to_be_bytes().to_vec());
    f.append(&mut f_fixed.to_vec());

    let mut k: Vec<u8> = Vec::new();
    k.append(&mut (32 as u32).to_be_bytes().to_vec());
    k.append(&mut secret.as_bytes().to_vec());

    let mut ciphers_v2: Vec<u8> = Vec::new();
    ciphers_v2.append(&mut (174 as u32).to_be_bytes().to_vec());
    ciphers = ciphers[5..(ciphers.len() - 13)].to_vec();
    ciphers_v2.append(&mut ciphers);

    let mut kex_v2: Vec<u8> = Vec::new();
    kex_v2.append(&mut (1041 as u32).to_be_bytes().to_vec());
    received_kex = received_kex[5..(received_kex.len() - 10)].to_vec();
    kex_v2.append(&mut received_kex);
    

    let h = make_hash(&mut v_c, 
                               &mut v_s,
                          &mut ciphers_v2, 
                          &mut kex_v2, 
                               &mut k_s, 
                               &mut e, 
                               &mut f, 
                               &mut k);

    //println!("{:?}", h);

    println!("{:?}", host_key_ed25519.verify(h.as_slice(), &ed25519_signature).is_ok());

    Ok(())
}