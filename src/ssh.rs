use std::net::IpAddr;
use std::str;
use rand::Rng;
use ed25519_dalek::*;
use ring::{aead::chacha20_poly1305_openssh, digest};
use core::convert::TryInto;

use crate::{constants, algorithms, crypto, session::Session, kex};

pub struct SSH{
    client_session: Session,
    ciphers: Vec<u8>,
    received_ciphers: Vec<u8>,
    server_host_key: Vec<u8>,
    server_signature: Vec<u8>, 
}

impl SSH {
    pub fn new(host: IpAddr, port: u16) -> SSH {
        SSH { 
            client_session: Session::new(host, port).unwrap(),
            ciphers: Vec::new(),
            received_ciphers: Vec::new(),
            server_host_key: Vec::new(),
            server_signature: Vec::new()
        }
    }

    fn protocol_string_exchange(&mut self, client_protocol_string: &str) -> String{
        let mut protocol_string = client_protocol_string.to_string();
        protocol_string.push_str("\r\n");

        self.client_session.write_line(&protocol_string).unwrap();
        self.client_session.read_line().unwrap()
    }

    fn algorithm_exchange(&mut self) {
        let received_ciphers: Vec<u8> = self.client_session.read_from_server();
        
        let _size = &received_ciphers[0..4];
        let _pad = &received_ciphers[5];
        let _code = &received_ciphers[6];
        let _cookie = &received_ciphers[6..22];

        let mut server_algorithms: Vec<&str> = Vec::new();
        let mut i = 22;

        for _ in 0..8 {
            let mut size_bytes: [u8; 4] = [0; 4];
            size_bytes.copy_from_slice(&received_ciphers[i..i+4]);
            let algo_size = u32::from_be_bytes(size_bytes);
            server_algorithms.push(str::from_utf8(&received_ciphers[i+4..i+4+algo_size as usize]).unwrap());
            i = i + 4 + algo_size as usize;   
        }

        println!("[+] Server offers: {:?}", server_algorithms);

        let mut ciphers: Vec<u8> = Vec::new();
        let cookie: [u8; 16] = self.client_session.csprng.gen();

        ciphers.push(constants::Message::SSH_MSG_KEXINIT);
        ciphers.append(&mut cookie.to_vec());

        println!("[+] Client offers: {:?}", algorithms::ALGORITHMS.to_vec());

        for algorithm in algorithms::ALGORITHMS.to_vec() {
            ciphers.append(&mut (algorithm.len() as u32).to_be_bytes().to_vec());
            ciphers.append(&mut (algorithm.as_bytes().to_vec()));
        }

        ciphers.append(&mut vec![0;13]); // Last bytes - 0000 0000 0000 0

        self.client_session.pad_data(&mut ciphers, false);
        self.client_session.write_to_server(&ciphers).unwrap();

        self.ciphers = ciphers;
        self.received_ciphers = received_ciphers;
    }

    fn key_exchange(&mut self) -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>){
        let kex = kex::Kex::new(&mut self.client_session);
        let mut client_public_key = kex.generate_public_key();
        let e = &client_public_key.clone()[1..];

        self.client_session.pad_data(&mut client_public_key, false);
        self.client_session.write_to_server(&client_public_key).unwrap();

        let received_ecdh: Vec<u8> = self.client_session.read_from_server();

        let (_size, received_ecdh) = received_ecdh.split_at(4);
        let (_pad, received_ecdh) = received_ecdh.split_at(1);
        let (_code, received_ecdh) = received_ecdh.split_at(1);

        let (key_size_slice, received_ecdh) = received_ecdh.split_at(4);
        //let key_size = u32::from_be_bytes(key_size_slice.try_into().unwrap());

        let (key_algorithm_size_slice, received_ecdh) = received_ecdh.split_at(4);
        let key_algorithm_size = u32::from_be_bytes(key_algorithm_size_slice.try_into().unwrap());

        let (key_name, received_ecdh) = received_ecdh.split_at(key_algorithm_size as usize);

        println!("[+] Host Key Algorithm: {}", str::from_utf8(key_name).unwrap());

        let (host_key_size_slice, received_ecdh) = received_ecdh.split_at(4);
        let host_key_size = u32::from_be_bytes(host_key_size_slice.try_into().unwrap());

        let (host_key, received_ecdh) = received_ecdh.split_at(host_key_size as usize);

        self.server_host_key = host_key.to_vec();

        let k_s = [
            key_size_slice, 
            key_algorithm_size_slice, 
            key_name, 
            host_key_size_slice, 
            host_key]
            .concat();

        let (f_size_slice, received_ecdh) = received_ecdh.split_at(4);
        let f_size = u32::from_be_bytes(f_size_slice.try_into().unwrap());
        let (f, received_ecdh) = received_ecdh.split_at(f_size as usize);
        let f: [u8;32] = f.try_into().unwrap();
        
        let (signature_length, received_ecdh) = received_ecdh.split_at(4);
        let signature_length = u32::from_be_bytes(signature_length.try_into().unwrap());

        let (signature_data, _) = received_ecdh.split_at(signature_length as usize);
        
        let (signature_algo_size, signature_data) = signature_data.split_at(4);
        let signature_algo_size = u32::from_be_bytes(signature_algo_size.try_into().unwrap());

        let (signature_algorithm, signature_data) = signature_data.split_at(signature_algo_size as usize);
        
        println!("[+] Signature Algorithm: {}", str::from_utf8(signature_algorithm).unwrap());

        let (signature_size, signature_data) = signature_data.split_at(4);
        let signature_size = u32::from_be_bytes(signature_size.try_into().unwrap());

        let (signature, _) = signature_data.split_at(signature_size as usize);

        self.server_signature = signature.to_vec();

        let secret = kex.generate_shared_secret(f);

        let f = [f_size_slice, f.as_ref()].concat();

        (k_s, e.to_vec(), f, self.client_session.mpint(secret.as_bytes()))
    }
    
    fn new_keys_message(&mut self){
        let mut new_keys: Vec<u8> = Vec::new();
        new_keys.push(constants::Message::SSH_MSG_NEWKEYS);

        self.client_session.pad_data(&mut new_keys, false);
        self.client_session.write_to_server(&new_keys).unwrap();
    }


    pub fn ssh_debug(&mut self) -> std::io::Result<()>{
        // Protocol String Exchange 
        let server_protocol_string = self.protocol_string_exchange(constants::Strings::CLIENT_VERSION);
        println!("[+] Server version: {}", server_protocol_string.trim());

        // Algorithm Exchange 
        self.algorithm_exchange();

        // Key Exchange 
        let (mut k_s, mut e, mut f, mut k) = self.key_exchange();

        // Make Session ID 
        self.client_session.make_session_id(
            &digest::SHA256, 
            server_protocol_string, 
            &mut self.ciphers, 
            &mut self.received_ciphers, 
            &mut k_s,
            &mut e, 
            &mut f, 
            &mut k.clone());

        // Host Key Check - TODO 

        // Check Server Signature 
        let mut signature_fixed_slice: [u8;64] = [0;64];
        signature_fixed_slice.copy_from_slice(self.server_signature.as_slice());
        let ed25519_signature = ed25519_dalek::Signature::new(signature_fixed_slice);
        let host_key_ed25519 = ed25519_dalek::PublicKey::from_bytes(self.server_host_key.as_slice()).unwrap();

        println!("[+] Server's signature OK?: {:?}", 
        host_key_ed25519.verify(self.client_session.session_id.as_slice(),  &ed25519_signature).is_ok());
        
        // NEW_KEYS 
        self.new_keys_message();
 
        // Derive Keys 
        let keys = crypto::Keys::new(&digest::SHA256, &mut k, &mut self.client_session.session_id);

        // SERVICE REQUEST 
        let mut service_req: Vec<u8> = Vec::new();
        service_req.push(constants::Message::SSH_MSG_SERVICE_REQUEST);  
        service_req.append(&mut (constants::Strings::SSH_USERAUTH.len() as u32).to_be_bytes().to_vec());
        service_req.append(&mut constants::Strings::SSH_USERAUTH.as_bytes().to_vec());

        self.client_session.pad_data(&mut service_req, true);

        let session_keys = crypto::SessionKeys::new(keys);

        session_keys.seal_packet_and_write_to_server(&mut self.client_session, &mut service_req);

        println!("{:x?}", session_keys.unseal_incoming_packet(&mut self.client_session));
  

        Ok(())
    }
}