
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

use crate::{constants, algorithms, crypto, session};


pub fn ssh_debug(host: IpAddr, port: u16) -> std::io::Result<()>{
    let mut session = session::Session::new(host, port).unwrap();

    let server_protocol =  session.read_line()?;

    println!("Server version: {:?}", server_protocol.trim());

    let mut protocol_string = constants::Strings::CLIENT_VERSION.to_string();
    protocol_string.push_str("\r\n");

    session.write_line(&protocol_string)?;

    let mut received_kex: Vec<u8> = session.read_from_server();

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
  
    ciphers.push(constants::Message::SSH_MSG_KEXINIT);
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

    session.pad_data(&mut ciphers);
    session.write_to_server(&ciphers);

    ///////////////////////////////////////// Send KEXINIT response

    let client_secret = EphemeralSecret::new(&mut csprng);
    let client_public = PublicKey::from(&client_secret);
    let pub_key = client_public.as_bytes();

    let mut key_exchange: Vec<u8> = Vec::new();
    key_exchange.push(constants::Message::SSH_MSG_KEX_ECDH_INIT);
    key_exchange.append(&mut (pub_key.len() as u32).to_be_bytes().to_vec());
    key_exchange.append(&mut pub_key.to_vec());

    session.pad_data(&mut key_exchange);
    session.write_to_server(&key_exchange);

    ////////////////////////////////// Generate Shared K

    let mut received_ecdh: Vec<u8> = session.read_from_server();

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
    v_c.append(&mut constants::Strings::CLIENT_VERSION.as_bytes().to_vec());

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
    

    let mut exchange_hash = crypto::make_hash(
        &digest::SHA256,
        &mut v_c, 
        &mut v_s, 
        &mut i_c, 
        &mut i_s, 
        &mut k_s, 
        &mut e, 
        &mut f, 
        &mut k.clone()
    );

    //println!("{:x?}", exchange_hash);

    // Host Key check was skipped - TODO
    // Checking server's signature
    println!("Signature Check: {:?}", host_key_ed25519.verify(exchange_hash.as_slice(), 
                                                              &ed25519_signature).is_ok());

    ///////////////////////////////// NEW_KEYS

    let mut new_keys: Vec<u8> = Vec::new();
    new_keys.push(constants::Message::SSH_MSG_NEWKEYS);

    session.pad_data(&mut new_keys);
    session.write_to_server(&new_keys);

    /////////////////////////////////

    let keys = crypto::Keys::new(&mut k, &mut exchange_hash);

    ////////////////////////////////

    let mut service_req: Vec<u8> = Vec::new();
    service_req.push(constants::Message::SSH_MSG_SERVICE_REQUEST);  
    service_req.append(&mut (12 as u32).to_be_bytes().to_vec());
    service_req.append(&mut constants::Strings::SSH_USERAUTH.as_bytes().to_vec());

    session.pad_data(&mut service_req);

    let mut mac: Vec<u8> = Vec::new();
    mac.append(&mut (3 as u32).to_be_bytes().to_vec());
    mac.append(&mut service_req.clone());

    let key: &GenericArray<_, U32> = GenericArray::from_slice(&keys.encryption_key_client_to_server);
    let nonce: &GenericArray<_, U16> = GenericArray::from_slice(&keys.initial_iv_client_to_server[0..16]);

    let mut cipher = Aes256Ctr::new(&key, &nonce);

    cipher.apply_keystream(service_req.as_mut_slice());

    let int_key = hmac::Key::new(hmac::HMAC_SHA256, &keys.integrity_key_client_to_server);
    let tag = hmac::sign(&int_key, &mac.as_slice());


    service_req.append(&mut tag.as_ref().to_vec());

    session.write_to_server(&service_req);

    /////////////////// Decryption example

    let mut dec_response: Vec<u8> = session.read_from_server();

    println!("{:x?}", dec_response);

    let key: &GenericArray<_, U32> = GenericArray::from_slice(&keys.encryption_key_server_to_client);
    let nonce: &GenericArray<_, U16> = GenericArray::from_slice(&keys.initial_iv_server_to_client[0..16]);
    let mut cipher = Aes256Ctr::new(&key, &nonce);

    cipher.apply_keystream(dec_response.as_mut_slice()); 

    println!("{:x?}", dec_response);

    Ok(())
}