use std::{sync::Mutex, io::Write, io::stdin, io::stdout, net::IpAddr, process::exit, str, sync::mpsc, thread};
use core::convert::TryInto;
use rand::Rng;

use ed25519_dalek::*;
use ring::digest;

use termion::input::TermRead;

use crate::{constants, algorithms, crypto, session::Session, kex, terminal};

pub struct SSH{
    username: String,
    client_session: Session,
    ciphers: Vec<u8>,
    received_ciphers: Vec<u8>,
    server_host_key: Vec<u8>,
    server_signature: Vec<u8>, 
    session_keys: Option<crypto::SessionKeys>
}

impl SSH {
    pub fn new(username: String, host: IpAddr, port: u16) -> SSH {
        SSH { 
            username,
            client_session: Session::new(host, port).unwrap(),
            ciphers: Vec::new(),
            received_ciphers: Vec::new(),
            server_host_key: Vec::new(),
            server_signature: Vec::new(),
            session_keys: None
        }
    }

    fn get_password(&self) -> String {
        let stdout = stdout();
        let mut stdout = stdout.lock();
        let stdin = stdin();
        let mut stdin = stdin.lock();

        println!("[+] Password authentication");
        stdout.write_all(b"password: ").unwrap();
        stdout.flush().unwrap();
        let password = stdin.read_passwd(&mut stdout).unwrap().unwrap();
        stdout.write_all(b"\n").unwrap();

        password
    }

    fn protocol_string_exchange(&mut self, client_protocol_string: &str) -> String{
        let mut protocol_string = client_protocol_string.to_string();
        protocol_string.push_str("\r\n");

        self.client_session.write_line(&protocol_string).unwrap();
        self.client_session.read_line().unwrap()
    }

    fn algorithm_exchange(&mut self, received_ciphers: Vec<u8>) {
        //let _cookie = &received_ciphers[6..22];

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

        self.client_session.pad_data(&mut ciphers);
        self.client_session.write_to_server(&ciphers).unwrap();

        self.ciphers = ciphers;
        self.received_ciphers = received_ciphers;
    }

    fn key_exchange(&mut self) -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>){
        let kex = kex::Kex::new(&mut self.client_session);
        let mut client_public_key = kex.generate_public_key();
        let e = &client_public_key.clone()[1..];

        self.client_session.pad_data(&mut client_public_key);
        self.client_session.write_to_server(&client_public_key).unwrap();

        let mut received_ecdh: Vec<u8> = self.client_session.read_from_server();
        loop {
            if received_ecdh.len() != 0 {break;}
            received_ecdh = self.client_session.read_from_server();
        }

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

        self.client_session.pad_data(&mut new_keys);
        self.client_session.write_to_server(&new_keys).unwrap();

        self.client_session.encrypted = true;
    }

    fn service_request_message(&mut self){
        let mut service_request: Vec<u8> = Vec::new();
        service_request.push(constants::Message::SSH_MSG_SERVICE_REQUEST);  
        service_request.append(&mut (constants::Strings::SSH_USERAUTH.len() as u32).to_be_bytes().to_vec());
        service_request.append(&mut constants::Strings::SSH_USERAUTH.as_bytes().to_vec());

        self.client_session.pad_data(&mut service_request);
        self.session_keys.as_ref().unwrap().seal_packet(&mut self.client_session, &mut service_request);
        self.client_session.write_to_server(&mut service_request).unwrap();
    }

    fn authentication_request(&mut self, session_keys: &crypto::SessionKeys, username: String){
        let mut auth_request: Vec<u8> = Vec::new();
        auth_request.push(constants::Message::SSH_MSG_USERAUTH_REQUEST);  
        auth_request.append(&mut (username.len() as u32).to_be_bytes().to_vec());
        auth_request.append(&mut username.as_bytes().to_vec());
        auth_request.append(&mut (constants::Strings::SSH_CONNECTION.len() as u32).to_be_bytes().to_vec());
        auth_request.append(&mut constants::Strings::SSH_CONNECTION.as_bytes().to_vec());
        auth_request.append(&mut (4 as u32).to_be_bytes().to_vec());
        auth_request.append(&mut "none".as_bytes().to_vec());

        self.client_session.pad_data(&mut auth_request);

        session_keys.seal_packet(&mut self.client_session, &mut auth_request);
    }

    fn password_authentication(&mut self, username: String, password: String){
        let mut password_auth: Vec<u8> = Vec::new();
        password_auth.push(constants::Message::SSH_MSG_USERAUTH_REQUEST);  
        password_auth.append(&mut (username.len() as u32).to_be_bytes().to_vec());
        password_auth.append(&mut username.as_bytes().to_vec());
        password_auth.append(&mut (constants::Strings::SSH_CONNECTION.len() as u32).to_be_bytes().to_vec());
        password_auth.append(&mut constants::Strings::SSH_CONNECTION.as_bytes().to_vec());
        password_auth.append(&mut (constants::Strings::PASSWORD.len() as u32).to_be_bytes().to_vec());
        password_auth.append(&mut constants::Strings::PASSWORD.as_bytes().to_vec());
        password_auth.push(0);
        password_auth.append(&mut (password.len() as u32).to_be_bytes().to_vec());
        password_auth.append(&mut password.as_bytes().to_vec());

        self.client_session.pad_data(&mut password_auth);
        self.session_keys.as_ref().unwrap().seal_packet(&mut self.client_session, &mut password_auth);
        self.client_session.write_to_server(&mut password_auth).unwrap();
    }

    fn open_channel(&mut self) {
        let mut open_request: Vec<u8> = Vec::new();
        open_request.push(constants::Message::SSH_MSG_CHANNEL_OPEN);
        open_request.append(&mut (constants::Strings::SESSION.len() as u32).to_be_bytes().to_vec());
        open_request.append(&mut constants::Strings::SESSION.as_bytes().to_vec());
        open_request.append(&mut (1 as u32).to_be_bytes().to_vec());
        open_request.append(&mut (1048576 as u32).to_be_bytes().to_vec());
        open_request.append(&mut (16384 as u32).to_be_bytes().to_vec());

        self.client_session.pad_data(&mut open_request);
        self.session_keys.as_ref().unwrap().seal_packet(&mut self.client_session, &mut open_request);
        self.client_session.write_to_server(&mut open_request).unwrap();
    }

    fn channel_request_pty(&mut self){
        let mut channel_request: Vec<u8> = Vec::new();
        channel_request.push(constants::Message::SSH_MSG_CHANNEL_REQUEST);
        channel_request.append(&mut (0 as u32).to_be_bytes().to_vec());
        channel_request.append(&mut (7 as u32).to_be_bytes().to_vec());
        channel_request.append(&mut "pty-req".as_bytes().to_vec());
        channel_request.push(0);
        channel_request.append(&mut (14 as u32).to_be_bytes().to_vec());
        channel_request.append(&mut "xterm-256color".as_bytes().to_vec());
        channel_request.append(&mut (0x7e as u32).to_be_bytes().to_vec());
        channel_request.append(&mut (0x1e as u32).to_be_bytes().to_vec());
        channel_request.append(&mut (0 as u32).to_be_bytes().to_vec());
        channel_request.append(&mut (0 as u32).to_be_bytes().to_vec());
        channel_request.append(&mut (11 as u32).to_be_bytes().to_vec());
        channel_request.push(0x81);
        channel_request.append(&mut (38400 as u32).to_be_bytes().to_vec());
        channel_request.push(0x80);
        channel_request.append(&mut (38400 as u32).to_be_bytes().to_vec());
        channel_request.push(0);

        self.client_session.pad_data(&mut channel_request);
        self.session_keys.as_ref().unwrap().seal_packet(&mut self.client_session, &mut channel_request);
        self.client_session.write_to_server(&mut channel_request).unwrap();
    }

    fn channel_request_shell(&mut self) {
        let mut channel_request: Vec<u8> = Vec::new();
        channel_request.push(constants::Message::SSH_MSG_CHANNEL_REQUEST);
        channel_request.append(&mut (0 as u32).to_be_bytes().to_vec());
        channel_request.append(&mut (constants::Strings::SHELL.len() as u32).to_be_bytes().to_vec());
        channel_request.append(&mut constants::Strings::SHELL.as_bytes().to_vec());
        channel_request.push(1);

        self.client_session.pad_data(&mut channel_request);
        self.session_keys.as_ref().unwrap().seal_packet(&mut self.client_session, &mut channel_request);
        self.client_session.write_to_server(&mut channel_request).unwrap();
    }

    // Handle INTERACTIVE SESSION 
    fn handle_key(&mut self, key: u8) {
        let mut command: Vec<u8> = Vec::new();
        command.push(constants::Message::SSH_MSG_CHANNEL_DATA);
        command.append(&mut (0 as u32).to_be_bytes().to_vec());
        command.append(&mut (1 as u32).to_be_bytes().to_vec());
        command.push(key);
    
        self.client_session.pad_data(&mut command);
        self.session_keys.as_ref().unwrap().seal_packet(&mut self.client_session, &mut command);
        self.client_session.write_to_server(&mut command).unwrap();

    }

    pub fn ssh_protocol(&mut self) -> std::io::Result<()>{
        let (tx, rx) = mpsc::channel();
        let mut terminal_launched = false;

        // Protocol String Exchange 
        let server_protocol_string = self.protocol_string_exchange(constants::Strings::CLIENT_VERSION);
        println!("[+] Server version: {}", server_protocol_string.trim());

        // Main loop
        loop {
            let mut queue: Vec<Vec<u8>> = Vec::new();
            let data = self.client_session.read_from_server();
            if data.len() > 0 {
                queue.push(data);

                // Decrypt packets if session is encrypted
                if self.client_session.encrypted {
                    queue = self.session_keys.as_ref().unwrap().unseal_packets(
                        &mut self.client_session, 
                        &mut queue[0]);
                }
            } else {
                let result = rx.try_recv();
                match result {
                    Ok(ch) => self.handle_key(ch),
                    Err(e) => (),
                }
            }
            
            for packet in queue {
                let (_, data_no_size) = packet.split_at(4);
                let (padding, data_no_size) = data_no_size.split_at(1);
                let (code, data_no_size) = data_no_size.split_at(1);

                match code[0] {
                    constants::Message::SSH_MSG_KEXINIT => {
                        //println!("[+] Received Code {}", constants::Message::SSH_MSG_KEXINIT);
                        self.algorithm_exchange(packet.to_vec());
                        let (mut k_s, mut e, mut f, mut k) = self.key_exchange();

                        // Make Session ID 
                        self.client_session.make_session_id(
                            &digest::SHA256, 
                            server_protocol_string.clone(), 
                            &mut self.ciphers, 
                            &mut self.received_ciphers, 
                            &mut k_s,
                            &mut e, 
                            &mut f, 
                            &mut k.clone());
                            
                        let mut signature_fixed_slice: [u8;64] = [0;64];
                        signature_fixed_slice.copy_from_slice(self.server_signature.as_slice());
                        let ed25519_signature = ed25519_dalek::Signature::new(signature_fixed_slice);
                        let host_key_ed25519 = ed25519_dalek::PublicKey::from_bytes(self.server_host_key.as_slice()).unwrap();

                        println!("[+] Server's signature OK?: {:?}", host_key_ed25519.verify(self.client_session.session_id.as_slice(),  &ed25519_signature).is_ok());
                        self.new_keys_message();
                        
                        let keys = crypto::Keys::new(&digest::SHA256, &mut k, &mut self.client_session.session_id);
                        let session_keys = crypto::SessionKeys::new(keys);
                        self.session_keys = Some(session_keys);
                        self.service_request_message();
                        }
                    constants::Message::SSH_MSG_SERVICE_ACCEPT => {
                        //println!("[+] Received Code: {}", constants::Message::SSH_MSG_SERVICE_ACCEPT);
                        let (size, data_no_size) = data_no_size.split_at(4);
                        let size = u32::from_be_bytes(size.try_into().unwrap());
                        println!("{}", str::from_utf8(&data_no_size[..size as usize]).unwrap());
                        let password = self.get_password();
                        self.password_authentication(self.username.clone(), password);
                    }
                    constants::Message::SSH_MSG_USERAUTH_SUCCESS => {
                        //println!("[+] Received Code: {}", constants::Message::SSH_MSG_USERAUTH_SUCCESS);
                        println!("[+] Authentication succeded");
                        self.open_channel();
                    }
                    constants::Message::SSH_MSG_GLOBAL_REQUEST => {
                        // Handle host key check upon receiving -> hostkeys-00@openssh.com
                        // Ignore for now
                        //println!("[+] Received Code: {}", constants::Message::SSH_MSG_GLOBAL_REQUEST);
                    }
                    constants::Message::SSH_MSG_CHANNEL_OPEN_CONFIRMATION => {
                        //println!("[+] Received Code: {}", constants::Message::SSH_MSG_CHANNEL_OPEN_CONFIRMATION);
                        //let (size, data_no_size) = data_no_size.split_at(4);
                        //let size = u32::from_be_bytes(size.try_into().unwrap());
                        //let (recipient_channel, data_no_size) = data_no_size.split_at(4);
                        //let (sender_channel, data_no_size) = data_no_size.split_at(4);
                        //let (initial_window_size, data_no_size) = data_no_size.split_at(4);
                        //let (maximum_window_size, data_no_size) = data_no_size.split_at(4);
                        self.channel_request_pty();
                        self.channel_request_shell();
                    }
                    constants::Message::SSH_MSG_CHANNEL_OPEN_FAILURE => {
                        //println!("[+] Received Code: {}", constants::Message::SSH_MSG_CHANNEL_OPEN_FAILURE);
                        println!("[+] Channel open failed, exiting.");
                        exit(1);
                    }
                    constants::Message::SSH_MSG_CHANNEL_SUCCESS => {
                        //println!("[+] Received Code: {}", constants::Message::SSH_MSG_CHANNEL_SUCCESS);
                        println!("Channel open succeeded.");
                        //let (size, data_no_size) = data_no_size.split_at(4);
                        //let size = u32::from_be_bytes(size.try_into().unwrap());
                        //let (recipient_channel, data_no_size) = data_no_size.split_at(4);
                        terminal_launched = true;
                    }
                    constants::Message::SSH_MSG_CHANNEL_WINDOW_ADJUST => {
                        // Figure this out later
                        //println!("[+] Received Code: {}", constants::Message::SSH_MSG_CHANNEL_WINDOW_ADJUST);
                    }
                    constants::Message::SSH_MSG_CHANNEL_DATA => {
                        //println!("[+] Received Code: {}", constants::Message::SSH_MSG_CHANNEL_DATA);
                        let (recipient_channel, data_no_size) = data_no_size.split_at(4);
                        let (data_size, data_no_size) = data_no_size.split_at(4);
                        let data_size = u32::from_be_bytes(data_size.try_into().unwrap());
                        let to_print = str::from_utf8(&data_no_size[..data_size as usize]).unwrap();

                        if terminal_launched == true {
                            let clone = tx.clone();
                            thread::spawn(move ||{
                                let mut terminal = terminal::Terminal::new(Mutex::new(clone));
                                if terminal.handle_command() == 1 { 
                                    exit(1); 
                                } 
                            });    
                            terminal_launched = false;
                        }

                        print!("{}", to_print);
                        stdout().flush().unwrap();
                    }
                    _ => println!("Could not recognize this message!"),
                }
            }
        }  
        Ok(())
    }
}