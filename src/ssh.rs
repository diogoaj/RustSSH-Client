use std::net::IpAddr;
use std::str;
use rand::Rng;
use x25519_dalek::{EphemeralSecret, PublicKey};
use ed25519_dalek::*;
use ring::{aead::chacha20_poly1305_openssh, digest};
use core::convert::TryInto;

use crate::{constants, algorithms, crypto, session::Session, kex};

pub struct SSH{
    client_session: Session,
    ciphers: Vec<u8>,
    received_ciphers: Vec<u8>
}

impl SSH {
    pub fn new(host: IpAddr, port: u16) -> SSH {
        SSH { 
            client_session: Session::new(host, port).unwrap(),
            ciphers: Vec::new(),
            received_ciphers: Vec::new()
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

        for algorithm in algorithms::ALGORITHMS.to_vec() {
            ciphers.append(&mut (algorithm.len() as u32).to_be_bytes().to_vec());
            ciphers.append(&mut (algorithm.as_bytes().to_vec()));
        }

        ciphers.append(&mut vec![0;13]); // Last bytes 

        self.client_session.pad_data(&mut ciphers, false);
        self.client_session.write_to_server(&ciphers).unwrap();

        self.ciphers = ciphers;
        self.received_ciphers = received_ciphers;
    }

    fn kex() {

    }

    pub fn ssh_debug(&mut self) -> std::io::Result<()>{
        let server_protocol_string = self.protocol_string_exchange(constants::Strings::CLIENT_VERSION);
        println!("[+] Server version: {}", server_protocol_string.trim());

        self.algorithm_exchange();

        let kex = kex::Kex::new(&mut self.client_session);
        kex.send_client_public_key(&mut self.client_session);
        
        ////////////////////////////////// Generate Shared K

        let mut received_ecdh: Vec<u8> = self.client_session.read_from_server();

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
        let secret = kex.private_key.diffie_hellman(&server_pub);
        

        ///////////////////////////// Create Exchange Hash

        let mut v_c: Vec<u8> = Vec::new();
        v_c.append(&mut (30 as u32).to_be_bytes().to_vec());
        v_c.append(&mut constants::Strings::CLIENT_VERSION.as_bytes().to_vec());

        let mut v_s: Vec<u8> = Vec::new();
        v_s.append(&mut (39 as u32).to_be_bytes().to_vec());
        v_s.append(&mut server_protocol_string.trim().as_bytes().to_vec());

        let mut k_s = received_ecdh[6..(10 + key_size) as usize].to_vec();

        let mut e: Vec<u8> = Vec::new();
        e.append(&mut (32 as u32).to_be_bytes().to_vec());
        let client_public = PublicKey::from(&kex.private_key);
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
        self.ciphers = self.ciphers[5..(self.ciphers.len() - self.ciphers[4] as usize)].to_vec();
        i_c.append(&mut (self.ciphers.len() as u32).to_be_bytes().to_vec());
        i_c.append(&mut self.ciphers);

        let mut i_s: Vec<u8> = Vec::new();
        self.received_ciphers = self.received_ciphers[5..(self.received_ciphers.len() - self.received_ciphers[4] as usize)].to_vec();
        i_s.append(&mut (self.received_ciphers.len() as u32).to_be_bytes().to_vec());
        i_s.append(&mut self.received_ciphers);
        

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

        self.client_session.pad_data(&mut new_keys, false);
        self.client_session.write_to_server(&new_keys);

        /////////////////////////////////

        let keys = crypto::Keys::new(&digest::SHA256, &mut k, &mut exchange_hash);

        ////////////////////////////////

        let mut service_req: Vec<u8> = Vec::new();
        service_req.push(constants::Message::SSH_MSG_SERVICE_REQUEST);  
        service_req.append(&mut (constants::Strings::SSH_USERAUTH.len() as u32).to_be_bytes().to_vec());
        service_req.append(&mut constants::Strings::SSH_USERAUTH.as_bytes().to_vec());

        self.client_session.pad_data(&mut service_req, true);

        let mut sealing_key_data: [u8;64] = [0;64];
        let mut opening_key_data: [u8;64] = [0;64];
        let mut tag: [u8;16] = [0;16];
        sealing_key_data.copy_from_slice(keys.encryption_key_client_to_server.as_slice());
        opening_key_data.copy_from_slice(keys.encryption_key_server_to_client.as_slice());
        let sealing_key = chacha20_poly1305_openssh::SealingKey::new(&sealing_key_data);
        let opening_key = chacha20_poly1305_openssh::OpeningKey::new(&opening_key_data);
        sealing_key.seal_in_place(self.client_session.sequence_number, &mut service_req, &mut tag);

        service_req.append(&mut tag.to_vec());
        
        self.client_session.write_to_server(&service_req);
        

        let mut dec_response = self.client_session.read_from_server();

        let mut tag: [u8;16] = [0;16];
        tag.copy_from_slice(&dec_response[28..]);

        let mut dec_response_length: [u8;4] = [0;4];
        dec_response_length.copy_from_slice(&dec_response[0..4]);

        let mut dec_response_length = 
        u32::from_be_bytes(opening_key.decrypt_packet_length(self.client_session.sequence_number-1, dec_response_length));

        let mut response_dec = 
        opening_key.open_in_place(self.client_session.sequence_number-1, &mut dec_response[0..28], &mut tag).unwrap();
        
        println!("{:?}", response_dec);
        
        Ok(())
    }
}