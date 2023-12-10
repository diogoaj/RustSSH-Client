use core::convert::TryInto;
use rand::Rng;
use std::{
    io::stdin, io::stdout, io::Write, net::IpAddr, process::exit, str, sync::mpsc,
    sync::mpsc::Receiver, thread,
};

use ring::digest;

use termion::input::TermRead;

use crate::{algorithms, constants, crypto, ed25519, kex, session::Session, terminal};

pub struct SSH {
    host: IpAddr,
    username: String,
    client_session: Session,
    ciphers: Vec<u8>,
    received_ciphers: Vec<u8>,
    server_host_key: Vec<u8>,
    server_signature: Vec<u8>,
    kex_keys: Option<kex::Kex>,
}

impl SSH {
    pub fn new(username: String, host: IpAddr, port: u16) -> SSH {
        SSH {
            host,
            username,
            client_session: Session::new(host, port).unwrap(),
            ciphers: Vec::new(),
            received_ciphers: Vec::new(),
            server_host_key: Vec::new(),
            server_signature: Vec::new(),
            kex_keys: None,
        }
    }

    fn get_password(&self) -> String {
        let stdout = stdout();
        let mut stdout = stdout.lock();
        let stdin = stdin();
        let mut stdin = stdin.lock();

        stdout.write_all(b"password: ").unwrap();
        stdout.flush().unwrap();
        let password = stdin.read_passwd(&mut stdout).unwrap().unwrap();
        stdout.write_all(b"\n").unwrap();

        password
    }

    fn protocol_string_exchange(&mut self, client_protocol_string: &str) -> String {
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
            size_bytes.copy_from_slice(&received_ciphers[i..i + 4]);
            let algo_size = u32::from_be_bytes(size_bytes);
            server_algorithms.push(
                str::from_utf8(&received_ciphers[i + 4..i + 4 + algo_size as usize]).unwrap(),
            );
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

        ciphers.append(&mut vec![0; 13]); // Last bytes - 0000 0000 0000 0

        self.client_session.write_to_server(&mut ciphers).unwrap();

        self.ciphers = ciphers;
        self.received_ciphers = received_ciphers;
    }

    fn send_public_key(&mut self) {
        self.kex_keys = Some(kex::Kex::new(&mut self.client_session));
        let mut client_public_key = self
            .kex_keys
            .as_ref()
            .unwrap()
            .public_key
            .as_bytes()
            .to_vec();

        let mut key_exchange: Vec<u8> = Vec::new();
        key_exchange.push(constants::Message::SSH_MSG_KEX_ECDH_INIT);
        key_exchange.append(&mut (client_public_key.len() as u32).to_be_bytes().to_vec());
        key_exchange.append(&mut client_public_key);

        self.client_session
            .write_to_server(&mut key_exchange)
            .unwrap();
    }

    fn key_exchange(&mut self, received_ecdh: Vec<u8>) -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
        let mut e = Vec::new();
        let pub_key = self.kex_keys.as_ref().unwrap().public_key.as_bytes();
        e.append(&mut (pub_key.len() as u32).to_be_bytes().to_vec());
        e.append(&mut pub_key.to_vec());

        let (key_size_slice, received_ecdh) = received_ecdh.split_at(4);

        let (key_algorithm_size_slice, received_ecdh) = received_ecdh.split_at(4);
        let key_algorithm_size = u32::from_be_bytes(key_algorithm_size_slice.try_into().unwrap());

        let (key_name, received_ecdh) = received_ecdh.split_at(key_algorithm_size as usize);

        //println!("[+] Host Key Algorithm: {}", str::from_utf8(key_name).unwrap());

        let (host_key_size_slice, received_ecdh) = received_ecdh.split_at(4);
        let host_key_size = u32::from_be_bytes(host_key_size_slice.try_into().unwrap());

        let (host_key, received_ecdh) = received_ecdh.split_at(host_key_size as usize);

        self.server_host_key = host_key.to_vec();

        if ed25519::host_key_fingerprint_check(
            self.host,
            &[
                key_algorithm_size_slice,
                key_name,
                host_key_size_slice,
                host_key,
            ]
            .concat(),
        ) == false
        {
            exit(1);
        }

        let k_s = [
            key_size_slice,
            key_algorithm_size_slice,
            key_name,
            host_key_size_slice,
            host_key,
        ]
        .concat();

        let (f_size_slice, received_ecdh) = received_ecdh.split_at(4);
        let f_size = u32::from_be_bytes(f_size_slice.try_into().unwrap());
        let (f, received_ecdh) = received_ecdh.split_at(f_size as usize);
        let f: [u8; 32] = f.try_into().unwrap();

        let (signature_length, received_ecdh) = received_ecdh.split_at(4);
        let signature_length = u32::from_be_bytes(signature_length.try_into().unwrap());

        let (signature_data, _) = received_ecdh.split_at(signature_length as usize);

        let (signature_algo_size, signature_data) = signature_data.split_at(4);
        let signature_algo_size = u32::from_be_bytes(signature_algo_size.try_into().unwrap());

        let (_, signature_data) = signature_data.split_at(signature_algo_size as usize);

        //println!("[+] Signature Algorithm: {}", str::from_utf8(signature_algorithm).unwrap());

        let (signature_size, signature_data) = signature_data.split_at(4);
        let signature_size = u32::from_be_bytes(signature_size.try_into().unwrap());

        let (signature, _) = signature_data.split_at(signature_size as usize);

        self.server_signature = signature.to_vec();

        let secret = self.kex_keys.as_ref().unwrap().generate_shared_secret(f);

        let f = [f_size_slice, f.as_ref()].concat();

        (
            k_s,
            e.to_vec(),
            f,
            self.client_session.mpint(secret.as_bytes()),
        )
    }

    fn new_keys_message(&mut self) {
        let mut new_keys: Vec<u8> = Vec::new();
        new_keys.push(constants::Message::SSH_MSG_NEWKEYS);

        self.client_session.write_to_server(&mut new_keys).unwrap();
        self.client_session.encrypted = true;
    }

    fn service_request_message(&mut self) {
        let mut service_request: Vec<u8> = Vec::new();
        service_request.push(constants::Message::SSH_MSG_SERVICE_REQUEST);
        service_request.append(
            &mut (constants::Strings::SSH_USERAUTH.len() as u32)
                .to_be_bytes()
                .to_vec(),
        );
        service_request.append(&mut constants::Strings::SSH_USERAUTH.as_bytes().to_vec());

        self.client_session
            .write_to_server(&mut service_request)
            .unwrap();
    }

    fn password_authentication(&mut self, username: String, password: String) {
        let mut password_auth: Vec<u8> = Vec::new();
        password_auth.push(constants::Message::SSH_MSG_USERAUTH_REQUEST);
        password_auth.append(&mut (username.len() as u32).to_be_bytes().to_vec());
        password_auth.append(&mut username.as_bytes().to_vec());
        password_auth.append(
            &mut (constants::Strings::SSH_CONNECTION.len() as u32)
                .to_be_bytes()
                .to_vec(),
        );
        password_auth.append(&mut constants::Strings::SSH_CONNECTION.as_bytes().to_vec());
        password_auth.append(
            &mut (constants::Strings::PASSWORD.len() as u32)
                .to_be_bytes()
                .to_vec(),
        );
        password_auth.append(&mut constants::Strings::PASSWORD.as_bytes().to_vec());
        password_auth.push(0);
        password_auth.append(&mut (password.len() as u32).to_be_bytes().to_vec());
        password_auth.append(&mut password.as_bytes().to_vec());

        self.client_session
            .write_to_server(&mut password_auth)
            .unwrap();
    }

    fn open_channel(&mut self) {
        let mut open_request: Vec<u8> = Vec::new();
        open_request.push(constants::Message::SSH_MSG_CHANNEL_OPEN);
        open_request.append(
            &mut (constants::Strings::SESSION.len() as u32)
                .to_be_bytes()
                .to_vec(),
        );
        open_request.append(&mut constants::Strings::SESSION.as_bytes().to_vec());
        open_request.append(&mut (1 as u32).to_be_bytes().to_vec());
        open_request.append(
            &mut (self.client_session.client_window_size as u32)
                .to_be_bytes()
                .to_vec(),
        );
        open_request.append(&mut constants::Size::MAX_PACKET_SIZE.to_be_bytes().to_vec());

        self.client_session
            .write_to_server(&mut open_request)
            .unwrap();
    }

    fn channel_request_pty(&mut self) {
        let terminal_size = terminal::get_terminal_size().unwrap();

        let mut channel_request: Vec<u8> = Vec::new();
        channel_request.push(constants::Message::SSH_MSG_CHANNEL_REQUEST);
        channel_request.append(&mut (0 as u32).to_be_bytes().to_vec());
        channel_request.append(
            &mut (constants::Strings::PTY_REQ.len() as u32)
                .to_be_bytes()
                .to_vec(),
        );
        channel_request.append(&mut constants::Strings::PTY_REQ.as_bytes().to_vec());
        channel_request.push(0);
        channel_request.append(
            &mut (constants::Strings::XTERM_VAR.len() as u32)
                .to_be_bytes()
                .to_vec(),
        );
        channel_request.append(&mut constants::Strings::XTERM_VAR.as_bytes().to_vec());
        channel_request.append(&mut (terminal_size.0 as u32).to_be_bytes().to_vec());
        channel_request.append(&mut (terminal_size.1 as u32).to_be_bytes().to_vec());
        channel_request.append(&mut (0 as u32).to_be_bytes().to_vec());
        channel_request.append(&mut (0 as u32).to_be_bytes().to_vec());
        channel_request.append(&mut (11 as u32).to_be_bytes().to_vec());
        channel_request.push(0x81);
        channel_request.append(&mut (38400 as u32).to_be_bytes().to_vec());
        channel_request.push(0x80);
        channel_request.append(&mut (38400 as u32).to_be_bytes().to_vec());
        channel_request.push(0);

        self.client_session
            .write_to_server(&mut channel_request)
            .unwrap();
    }

    fn channel_request_shell(&mut self) {
        let mut channel_request: Vec<u8> = Vec::new();
        channel_request.push(constants::Message::SSH_MSG_CHANNEL_REQUEST);
        channel_request.append(&mut (0 as u32).to_be_bytes().to_vec());
        channel_request.append(
            &mut (constants::Strings::SHELL.len() as u32)
                .to_be_bytes()
                .to_vec(),
        );
        channel_request.append(&mut constants::Strings::SHELL.as_bytes().to_vec());
        channel_request.push(1);

        self.client_session
            .write_to_server(&mut channel_request)
            .unwrap();
    }

    fn window_adjust(&mut self) {
        let mut window_adjust: Vec<u8> = Vec::new();
        window_adjust.push(constants::Message::SSH_MSG_CHANNEL_WINDOW_ADJUST);
        window_adjust.append(&mut (0 as u32).to_be_bytes().to_vec());
        window_adjust.append(
            &mut self
                .client_session
                .client_window_size
                .to_be_bytes()
                .to_vec(),
        );

        self.client_session
            .write_to_server(&mut window_adjust)
            .unwrap();
    }

    fn handle_key(&mut self, mut key: Vec<u8>) {
        let mut command: Vec<u8> = Vec::new();
        command.push(constants::Message::SSH_MSG_CHANNEL_DATA);
        command.append(&mut (0 as u32).to_be_bytes().to_vec());
        command.append(&mut (key.len() as u32).to_be_bytes().to_vec());
        command.append(&mut key);

        self.client_session.write_to_server(&mut command).unwrap();
    }

    fn get_key(&mut self, rx: &Receiver<Vec<u8>>) {
        let result = rx.try_recv();
        match result {
            Ok(vec) => self.handle_key(vec),
            Err(_) => (),
        }
    }

    fn close_channel(&mut self) {
        let mut close: Vec<u8> = Vec::new();
        close.push(constants::Message::SSH_MSG_CHANNEL_CLOSE);
        close.append(&mut (0 as u32).to_be_bytes().to_vec());

        self.client_session.write_to_server(&mut close).unwrap();
    }

    pub fn ssh_protocol(&mut self) -> std::io::Result<()> {
        let (tx, rx) = mpsc::channel();
        let mut terminal_launched = false;

        // Protocol String Exchange
        let server_protocol_string =
            self.protocol_string_exchange(constants::Strings::CLIENT_VERSION);
        println!("[+] Server version: {}", server_protocol_string.trim());

        loop {
            // If no data is read then queue is empty
            let mut queue = Vec::new();

            if let Ok(server_data) = self.client_session.read_from_server() {
                queue = self.client_session.process_data(server_data);
            }

            // Adjust window
            if self.client_session.data_received >= self.client_session.client_window_size {
                self.client_session.data_received = 0;
                self.window_adjust();
            }

            // Process key strokes
            self.get_key(&rx);

            for packet in queue {
                let (_, data_no_size) = packet.split_at(4);
                let (_padding, data_no_size) = data_no_size.split_at(1);
                let (code, data_no_size) = data_no_size.split_at(1);

                // Process each packet by matching the message code
                match code[0] {
                    constants::Message::SSH_MSG_KEXINIT => {
                        println!("[+] Received Code {}", constants::Message::SSH_MSG_KEXINIT);
                        // Algorithm exchange
                        // TODO - Check if client and server algorithms match
                        self.algorithm_exchange(packet);
                        self.send_public_key();
                    }
                    constants::Message::SSH_MSG_KEX_ECDH_REPLY => {
                        let (mut k_s, mut e, mut f, mut k) =
                            self.key_exchange(data_no_size.to_vec());

                        // Make Session ID
                        // TODO - Change this when implementing rekey
                        // Note: Rekey should be triggered every 1GB or every hour
                        self.client_session.make_session_id(
                            &digest::SHA256,
                            server_protocol_string.clone(),
                            &mut self.ciphers,
                            &mut self.received_ciphers,
                            &mut k_s,
                            &mut e,
                            &mut f,
                            &mut k.clone(),
                        );

                        let verification = ed25519::verify_server_signature(
                            &self.server_signature,
                            &self.server_host_key,
                            &self.client_session.session_id,
                        );

                        if verification == false {
                            println!("Server's signature does not match!");
                            exit(1);
                        }

                        let mut session_id = self.client_session.session_id.clone();

                        let keys = crypto::Keys::new(
                            &digest::SHA256,
                            &mut k,
                            &mut self.client_session.session_id,
                            &mut session_id,
                        );

                        let session_keys = crypto::SessionKeys::new(keys);
                        self.client_session.session_keys = Some(session_keys);

                        self.new_keys_message();

                        // Request authentication
                        self.service_request_message();
                    }
                    constants::Message::SSH_MSG_SERVICE_ACCEPT => {
                        println!(
                            "[+] Received Code: {}",
                            constants::Message::SSH_MSG_SERVICE_ACCEPT
                        );
                        //let (size, data_no_size) = data_no_size.split_at(4);
                        //let size = u32::from_be_bytes(size.try_into().unwrap());
                        //println!("{}", str::from_utf8(&data_no_size[..size as usize]).unwrap());
                        // Password authentication
                        // TODO - Implement other types of authentication (keys)
                        let password = self.get_password();
                        self.password_authentication(self.username.clone(), password);
                    }
                    constants::Message::SSH_MSG_USERAUTH_FAILURE => {
                        println!("[+] Authentication failed!");
                        println!("Try again.");
                        let password = self.get_password();
                        self.password_authentication(self.username.clone(), password);
                    }
                    constants::Message::SSH_MSG_USERAUTH_SUCCESS => {
                        println!(
                            "[+] Received Code: {}",
                            constants::Message::SSH_MSG_USERAUTH_SUCCESS
                        );
                        println!("[+] Authentication succeeded.");
                        self.open_channel();
                    }
                    constants::Message::SSH_MSG_GLOBAL_REQUEST => {
                        // TODO - Handle host key check upon receiving -> hostkeys-00@openssh.com
                        // Ignore for now
                        println!(
                            "[+] Received Code: {}",
                            constants::Message::SSH_MSG_GLOBAL_REQUEST
                        );
                    }
                    constants::Message::SSH_MSG_CHANNEL_OPEN_CONFIRMATION => {
                        //println!("[+] Received Code: {}", constants::Message::SSH_MSG_CHANNEL_OPEN_CONFIRMATION);
                        //let (size, data_no_size) = data_no_size.split_at(4);
                        //let size = u32::from_be_bytes(size.try_into().unwrap());
                        //let (recipient_channel, data_no_size) = data_no_size.split_at(4);
                        //let (sender_channel, data_no_size) = data_no_size.split_at(4);
                        //let (initial_window_size, data_no_size) = data_no_size.split_at(4);
                        //let (maximum_window_size, data_no_size) = data_no_size.split_at(4);

                        // Request pseudo terminal / shell
                        self.channel_request_pty();
                        self.channel_request_shell();
                        terminal_launched = true;
                    }
                    constants::Message::SSH_MSG_CHANNEL_OPEN_FAILURE => {
                        //println!("[+] Received Code: {}", constants::Message::SSH_MSG_CHANNEL_OPEN_FAILURE);
                        //println!("[+] Channel open failed, exiting.");
                        exit(1);
                    }
                    constants::Message::SSH_MSG_CHANNEL_SUCCESS => {
                        //println!("[+] Received Code: {}", constants::Message::SSH_MSG_CHANNEL_SUCCESS);
                        //println!("[+] Channel open succeeded.");
                        //let (size, data_no_size) = data_no_size.split_at(4);
                        //let size = u32::from_be_bytes(size.try_into().unwrap());
                        //let (recipient_channel, data_no_size) = data_no_size.split_at(4);
                    }
                    constants::Message::SSH_MSG_CHANNEL_WINDOW_ADJUST => {
                        //println!("[+] Received Code: {}", constants::Message::SSH_MSG_CHANNEL_WINDOW_ADJUST);
                        let (_recipient_channel, data_no_size) = data_no_size.split_at(4);
                        let (window_bytes, _) = data_no_size.split_at(4);

                        let mut window_slice = [0u8; 4];
                        window_slice.copy_from_slice(window_bytes);

                        self.client_session.server_window_size = u32::from_be_bytes(window_slice);
                    }
                    constants::Message::SSH_MSG_CHANNEL_DATA => {
                        //println!("[+] Received Code: {}", constants::Message::SSH_MSG_CHANNEL_DATA);
                        let (_recipient_channel, data_no_size) = data_no_size.split_at(4);
                        let (data_size, data_no_size) = data_no_size.split_at(4);
                        let data_size = u32::from_be_bytes(data_size.try_into().unwrap());

                        // Launch thread that processes key strokes
                        if terminal_launched == true {
                            let clone = tx.clone();
                            thread::spawn(move || {
                                let mut terminal = terminal::Terminal::new(clone);
                                terminal.handle_command();
                            });
                            terminal_launched = false;
                        }

                        // Print data received to screen
                        stdout()
                            .write_all(&data_no_size[..data_size as usize])
                            .unwrap();
                        stdout().flush().unwrap();
                    }
                    constants::Message::SSH_MSG_CHANNEL_EOF => {
                        //println!("[+] Received Code: {}", constants::Message::SSH_MSG_CHANNEL_EOF);
                        //println!("Server will not send more data!");
                    }
                    constants::Message::SSH_MSG_CHANNEL_REQUEST => {
                        //println!("[+] Received Code: {}", constants::Message::SSH_MSG_CHANNEL_REQUEST);
                    }
                    constants::Message::SSH_MSG_IGNORE => {
                        //println!("[+] Received Code: {}", constants::Message::SSH_MSG_IGNORE);
                    }
                    constants::Message::SSH_MSG_CHANNEL_CLOSE => {
                        // Issue close channel packet
                        self.close_channel();
                        println!("Connection closed.");
                        exit(0);
                    }
                    constants::Message::SSH_MSG_DISCONNECT => {
                        //println!("[+] Received Code: {}", constants::Message::SSH_MSG_DISCONNECT);
                        println!("Server disconnected...");
                        exit(1);
                    }
                    _ => {
                        println!("Could not recognize this message -> {}", code[0]);
                        exit(1);
                    }
                }
            }
        }
    }
}
