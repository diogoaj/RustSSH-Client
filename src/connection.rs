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
    v_c: &str, 
    v_s: &str, 
    i_c: &mut Vec<u8>, 
    i_s: &mut Vec<u8>, 
    k_s: &mut Vec<u8>, 
    e: &mut Vec<u8>, 
    f: &mut Vec<u8>,
    k: &mut Vec<u8>) -> Vec<u8> {

        let mut hash_data: Vec<u8> = Vec::new();
        hash_data.append(&mut v_c.as_bytes().to_vec());
        hash_data.append(&mut v_s.as_bytes().to_vec());
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

    println!("Server version: {}", &read_line(&mut reader)?.trim());

    let protocol_string = "SSH-2.0-Simple_Rust_Client_1.0\r\n";
    write_line(&mut writer, protocol_string)?;

    let received: Vec<u8> = reader.fill_buf()?.to_vec();
    reader.consume(received.len());

    let _size = &received[0..4];
    let _pad = &received[5];
    let _code = &received[6];
    let _cookie = &received[6..22];

    let mut server_algorithms: Vec<&str> = Vec::new();
    let mut i = 22;

    loop {
        let mut size_bytes: [u8; 4] = [0; 4];
        size_bytes.copy_from_slice(&received[i..i+4]);
        let algo_size = u32::from_be_bytes(size_bytes);

        if algo_size == 0 { 
            break;
        }

        server_algorithms.push(str::from_utf8(&received[i+4..i+4+algo_size as usize]).unwrap());

        i = i + 4 + algo_size as usize;   
    }

    println!("Server algorithms: {:?}", server_algorithms);

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

    let alice_secret = EphemeralSecret::new(&mut csprng);
    let alice_public = PublicKey::from(&alice_secret);
    let pub_key = alice_public.as_bytes();

    let mut key_exchange: Vec<u8> = Vec::new();
    key_exchange.push(numbers::Message::SSH_MSG_KEX_ECDH_INIT);
    key_exchange.append(&mut (pub_key.len() as u32).to_be_bytes().to_vec());
    key_exchange.append(&mut alice_public.as_bytes().to_vec());

    send_data(&mut writer, &mut key_exchange)?;

    ///////////////////////////////////////////////

    let mut received_k: Vec<u8> = reader.fill_buf()?.to_vec();
    let _size = &received_k[0..4];
    let _pad = &received_k[5];
    let _code = &received_k[6];

    let key_size = u32::from_be_bytes(received_k[6..10].try_into().unwrap());

    let host_key = &received_k[10..(10 + key_size) as usize];

    //println!("{:?}", host_key.to_vec());

    let f = &received_k[((14 + key_size) as usize)..((14 + 32 + key_size) as usize)];
    println!("{:?}", f.len());

    let f_fixed: [u8;32] = f.try_into().unwrap();

    let server_pub = PublicKey::from(f_fixed);
    let secret = alice_secret.diffie_hellman(&server_pub);

    println!("{:?}", secret.as_bytes().to_vec());

    Ok(())
}