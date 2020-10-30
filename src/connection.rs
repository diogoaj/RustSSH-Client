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
use ring::{aead::chacha20_poly1305_openssh, digest, hmac};
use core::convert::TryInto;
use std::convert::From;

use aes_ctr::Aes256Ctr;
use aes_ctr::cipher::{
    generic_array::GenericArray,
    stream::{
        NewStreamCipher, SyncStreamCipher, SyncStreamCipherSeek
    }
};

use aes_ctr::cipher::generic_array::typenum::{U16, U32};

use crate::{numbers, algorithms};

struct Keys {
    initial_iv_client_to_server: [u8;32],
    initial_iv_server_to_client: [u8;32],
    encryption_key_client_to_server: [u8; 32],
    encryption_key_server_to_client: [u8; 32],
    integrity_key_client_to_server: [u8; 32],
    integrity_key_server_to_client: [u8; 32],
}

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

pub fn process_data(data: &mut Vec<u8>) {
    let mut padding = 8 - (data.len() as u32 + 5) % 8;

    if padding < 4{
        padding += 8
    }

    let data_len = ((data.len() + 1 + padding as usize) as u32).to_be_bytes().to_vec();

    let mut i = 0;
    for b in data_len.iter() {
        data.insert(i, *b);
        i += 1;
    }

    data.insert(i, padding as u8);
    data.append(&mut vec![0; padding as usize]);
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

        //println!("{:x?}", hash_data);

        digest::digest(&digest::SHA256, hash_data.as_slice()).as_ref().to_vec()
}


fn make_keys(secret: &mut Vec<u8>, exchange_hash: &mut Vec<u8>) -> Keys {

    let mut encryption_client: Vec<u8> = Vec::new();
    encryption_client.append(&mut secret.clone());
    encryption_client.append(&mut exchange_hash.clone());
    encryption_client.push(67);
    encryption_client.append(&mut exchange_hash.clone());

    let mut k1_client = 
        digest::digest(&digest::SHA256, encryption_client.as_slice()).as_ref().to_vec();

    let mut encryption_server: Vec<u8> = Vec::new();
    encryption_server.append(&mut secret.clone());
    encryption_server.append(&mut exchange_hash.clone());
    encryption_server.push(68);
    encryption_server.append(&mut exchange_hash.clone());

    let mut k1_server = 
        digest::digest(&digest::SHA256, encryption_server.as_slice()).as_ref().to_vec();

    let mut client_key_slice: [u8; 32] = [0;32];
    client_key_slice.copy_from_slice(k1_client.as_slice());
    let mut server_key_slice: [u8; 32] = [0;32];
    server_key_slice.copy_from_slice(k1_server.as_slice());

    let mut k1_client = 
        digest::digest(&digest::SHA256, encryption_client.as_slice()).as_ref().to_vec();

    let mut iv_client_to_server: [u8;32] = [0;32];
    let mut iv_client: Vec<u8> = Vec::new();
    iv_client.append(&mut secret.clone());
    iv_client.append(&mut exchange_hash.clone());
    iv_client.push(65);
    iv_client.append(&mut exchange_hash.clone());

    iv_client_to_server.copy_from_slice(digest::digest(&digest::SHA256, iv_client.as_slice()).as_ref());

    let mut iv_server_to_client: [u8;32] = [0;32];
    let mut iv_server: Vec<u8> = Vec::new();
    iv_server.append(&mut secret.clone());
    iv_server.append(&mut exchange_hash.clone());
    iv_server.push(66);
    iv_server.append(&mut exchange_hash.clone());
    
    iv_server_to_client.copy_from_slice(digest::digest(&digest::SHA256, iv_server.as_slice()).as_ref());


    let mut integrity_client_to_server: [u8;32] = [0;32];
    let mut integrity_client: Vec<u8> = Vec::new();
    integrity_client.append(&mut secret.clone());
    integrity_client.append(&mut exchange_hash.clone());
    integrity_client.push(69);
    integrity_client.append(&mut exchange_hash.clone());

    integrity_client_to_server.copy_from_slice(digest::digest(&digest::SHA256, integrity_client.as_slice()).as_ref());

    let mut integrity_server_to_client: [u8;32] = [0;32];
    let mut integrity_server: Vec<u8> = Vec::new();
    integrity_server.append(&mut secret.clone());
    integrity_server.append(&mut exchange_hash.clone());
    integrity_server.push(70);
    integrity_server.append(&mut exchange_hash.clone());
    
    integrity_server_to_client.copy_from_slice(digest::digest(&digest::SHA256, integrity_server.as_slice()).as_ref());

    Keys {
        initial_iv_client_to_server: iv_client_to_server,
        initial_iv_server_to_client: iv_server_to_client,
        encryption_key_client_to_server: client_key_slice,
        encryption_key_server_to_client: server_key_slice,
        integrity_key_client_to_server: integrity_client_to_server,
        integrity_key_server_to_client: integrity_server_to_client
    }
}


pub fn ssh_debug(host: IpAddr, port: u16) -> std::io::Result<()>{
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

    process_data(&mut ciphers);
    writer.write(ciphers.as_slice())?;
    writer.flush();

    ///////////////////////////////////////// Send KEXINIT response

    let client_secret = EphemeralSecret::new(&mut csprng);
    let client_public = PublicKey::from(&client_secret);
    let pub_key = client_public.as_bytes();

    let mut key_exchange: Vec<u8> = Vec::new();
    key_exchange.push(numbers::Message::SSH_MSG_KEX_ECDH_INIT);
    key_exchange.append(&mut (pub_key.len() as u32).to_be_bytes().to_vec());
    key_exchange.append(&mut pub_key.to_vec());

    process_data(&mut key_exchange);
    writer.write(key_exchange.as_slice())?;
    writer.flush();

    ////////////////////////////////// Generate Shared K

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


    ///////////////////////////// Create Exchange Hash

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

    // mpint logic
    let mut k: Vec<u8> = Vec::new();
    if secret.as_bytes()[0] & 128 == 128 {
        k.append(&mut 33u32.to_be_bytes().to_vec());
        k.push(0);
    } else {
        k.append(&mut 32u32.to_be_bytes().to_vec());
    };

    k.append(&mut secret.as_bytes().to_vec());

    let mut i_c: Vec<u8> = Vec::new();
    i_c.append(&mut (144 as u32).to_be_bytes().to_vec());
    ciphers = ciphers[5..(ciphers.len() - 11)].to_vec();
    i_c.append(&mut ciphers);

    let mut i_s: Vec<u8> = Vec::new();
    i_s.append(&mut (1041 as u32).to_be_bytes().to_vec());
    received_kex = received_kex[5..(received_kex.len() - 10)].to_vec();
    i_s.append(&mut received_kex);
    

    let mut exchange_hash = make_hash(&mut v_c, 
                                           &mut v_s,
                                           &mut i_c, 
                                           &mut i_s, 
                                           &mut k_s, 
                                           &mut e, 
                                           &mut f, 
                                           &mut k.clone());

    //println!("{:x?}", exchange_hash);

    // Host Key check was skipped - TODO
    // Checking server's signature
    println!("Signature Check: {:?}", host_key_ed25519.verify(exchange_hash.as_slice(), 
                                                              &ed25519_signature).is_ok());

    ///////////////////////////////// NEW_KEYS

    let mut new_keys: Vec<u8> = Vec::new();
    new_keys.push(numbers::Message::SSH_MSG_NEWKEYS);

    process_data(&mut new_keys);
    writer.write(new_keys.as_slice())?;
    writer.flush()?;

    /////////////////////////////////

    let keys = make_keys(&mut k, &mut exchange_hash);

    ////////////////////////////////

    let mut service_req: Vec<u8> = Vec::new();
    service_req.push(numbers::Message::SSH_MSG_SERVICE_REQUEST);  
    service_req.append(&mut (12 as u32).to_be_bytes().to_vec());
    service_req.append(&mut "ssh-userauth".as_bytes().to_vec());

    process_data(&mut service_req);

    let mut mac: Vec<u8> = Vec::new();
    mac.append(&mut (3 as u32).to_be_bytes().to_vec());
    mac.append(&mut service_req.clone());

    let key: &GenericArray<_, U32> = GenericArray::from_slice(keys.encryption_key_client_to_server.as_ref());
    let nonce: &GenericArray<_, U16> = GenericArray::from_slice(&keys.initial_iv_client_to_server[0..16]);

    let mut cipher = Aes256Ctr::new(&key, &nonce);

    cipher.apply_keystream(service_req.as_mut_slice());

    let int_key = hmac::Key::new(hmac::HMAC_SHA256, &keys.integrity_key_client_to_server);
    let tag = hmac::sign(&int_key, &mac.as_slice());

    println!("{:?}", service_req);

    service_req.append(&mut tag.as_ref().to_vec());

    writer.write(service_req.as_slice());
    writer.flush()?;

    
    Ok(())
}