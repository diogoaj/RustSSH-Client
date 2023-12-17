use rand::rngs::OsRng;
use ring::digest;
use std::io::{prelude::*, BufReader, BufWriter, Result};
use std::net::{IpAddr, SocketAddr, TcpStream};

use crate::{constants, crypto};

trait BaseState {
    fn process_incoming_packet(&mut self, received_data: &mut Vec<u8>) -> Vec<u8>;
    fn process_outgoing_packet(&mut self, data: &mut Vec<u8>);
    fn get_padding(&self, data: &Vec<u8>) -> u32;
    fn get_client_sequence_number(&self) -> u32;
    fn get_server_sequence_number(&self) -> u32;
}

struct EncryptedState {
    client_sequence_number: u32,
    server_sequence_number: u32,
    session_keys: crypto::SessionKeys,
}

impl BaseState for EncryptedState {
    fn process_incoming_packet(&mut self, received_data: &mut Vec<u8>) -> Vec<u8> {
        self.server_sequence_number += 1;
        let packet = self.decrypt_packet(received_data);
        let packet_size = packet.len() + 16;

        received_data.drain(..packet_size);
        packet
    }

    fn process_outgoing_packet(&mut self, data: &mut Vec<u8>) {
        self.encrypt_packet(data);
        self.client_sequence_number += 1;
    }

    fn get_padding(&self, data: &Vec<u8>) -> u32 {
        8 - (data.len() as u32 + 1) % 8
    }

    fn get_client_sequence_number(&self) -> u32 {
        self.client_sequence_number
    }

    fn get_server_sequence_number(&self) -> u32 {
        self.server_sequence_number
    }
}

impl EncryptedState {
    fn encrypt_packet(&mut self, packet: &mut Vec<u8>) {
        self.session_keys
            .seal_packet(self.client_sequence_number, packet);
    }

    fn decrypt_packet_length(&mut self, enc_length: [u8; 4]) -> [u8; 4] {
        self.session_keys
            .decrypt_length(self.server_sequence_number, enc_length)
    }

    fn decrypt_packet(&mut self, packet: &mut Vec<u8>) -> Vec<u8> {
        let mut encrypted_length_slice = [0u8; 4];
        encrypted_length_slice.copy_from_slice(&packet[0..4]);

        let decrypted_length_slice = self.decrypt_packet_length(encrypted_length_slice);

        let vec = self.session_keys.unseal_packet(
            self.server_sequence_number,
            &encrypted_length_slice,
            &decrypted_length_slice,
            &mut packet[4..].to_vec(),
        );

        vec
    }
}

struct PlaintextState {
    client_sequence_number: u32,
    server_sequence_number: u32,
}

impl BaseState for PlaintextState {
    fn process_incoming_packet(&mut self, received_data: &mut Vec<u8>) -> Vec<u8> {
        self.server_sequence_number += 1;
        let packet = received_data.clone();
        let packet_size = received_data.len();

        received_data.drain(..packet_size);
        packet
    }

    fn process_outgoing_packet(&mut self, _data: &mut Vec<u8>) {
        self.client_sequence_number += 1;
    }

    fn get_padding(&self, data: &Vec<u8>) -> u32 {
        16 - (data.len() as u32 + 4 + 1) % 16
    }

    fn get_client_sequence_number(&self) -> u32 {
        self.client_sequence_number
    }

    fn get_server_sequence_number(&self) -> u32 {
        self.server_sequence_number
    }
}

pub struct Session {
    reader: BufReader<TcpStream>,
    writer: BufWriter<TcpStream>,
    pub csprng: OsRng,
    pub session_id: Vec<u8>,
    pub data_received: u32,
    pub data_sent: u32,
    pub total_data_transmitted: u32,
    pub client_window_size: u32,
    pub server_window_size: u32,
    encrypted_state: Box<dyn BaseState>,
}

impl Session {
    pub fn new(host: IpAddr, port: u16) -> Result<Self> {
        let socket = SocketAddr::new(host, port);
        let stream = match TcpStream::connect(socket) {
            Ok(stream) => stream,
            Err(e) => panic!("{}: Couldn't connect to {} at port {}", e, host, port),
        };
        stream.set_nonblocking(true).unwrap();
        Ok(Session {
            reader: BufReader::new(stream.try_clone()?),
            writer: BufWriter::new(stream),
            csprng: OsRng {},
            session_id: Vec::new(),
            data_received: 0,
            data_sent: 0,
            total_data_transmitted: 0,
            client_window_size: 1048576,
            server_window_size: 0,
            encrypted_state: Box::new(PlaintextState {
                client_sequence_number: 0,
                server_sequence_number: 0,
            }),
        })
    }

    pub fn set_encrypted_state(&mut self, session_keys: crypto::SessionKeys) {
        self.encrypted_state = Box::new(EncryptedState {
            client_sequence_number: self.encrypted_state.get_client_sequence_number(),
            server_sequence_number: self.encrypted_state.get_server_sequence_number(),
            session_keys,
        })
    }

    pub fn write_line(&mut self, line: &str) -> Result<()> {
        self.writer.get_mut().write(&line.as_bytes())?;
        self.writer.get_mut().flush()?;
        Ok(())
    }

    pub fn write_to_server(&mut self, data: &mut Vec<u8>) -> Result<()> {
        self.pad_data(data, self.encrypted_state.get_padding(data));
        self.encrypted_state.process_outgoing_packet(data);
        self.writer.get_mut().write(data.as_slice())?;
        self.writer.get_mut().flush()
    }

    pub fn read_line(&mut self) -> Result<String> {
        let mut data = String::new();

        loop {
            match self.reader.read_line(&mut data) {
                Ok(_) => break,
                Err(_) => continue,
            }
        }
        Ok(data)
    }

    pub fn read_from_server(&mut self) -> Result<Vec<u8>> {
        let mut received_data = Vec::new();
        let read_bytes = {
            let bytes = self.reader.fill_buf()?;
            received_data.extend_from_slice(bytes);
            bytes.len()
        };

        self.reader.consume(read_bytes);

        return Ok(received_data);
    }

    pub fn process_data(&mut self, mut received_data: Vec<u8>) -> Vec<Vec<u8>> {
        let mut packets: Vec<Vec<u8>> = Vec::new();
        while received_data.len() != 0 {
            let packet = self
                .encrypted_state
                .process_incoming_packet(&mut received_data);
            packets.push(packet);
        }
        return packets;
    }


    pub fn make_session_id(
        &mut self,
        algorithm: &'static digest::Algorithm,
        server_protocol_string: String,
        ciphers: &mut Vec<u8>,
        received_ciphers: &mut Vec<u8>,
        k_s: &mut Vec<u8>,
        e: &mut Vec<u8>,
        f: &mut Vec<u8>,
        k: &mut Vec<u8>,
    ) {
        let mut v_c: Vec<u8> = Vec::new();
        v_c.append(
            &mut (constants::Strings::CLIENT_VERSION.len() as u32)
                .to_be_bytes()
                .to_vec(),
        );
        v_c.append(&mut constants::Strings::CLIENT_VERSION.as_bytes().to_vec());

        let mut v_s: Vec<u8> = Vec::new();
        v_s.append(
            &mut (server_protocol_string.trim().len() as u32)
                .to_be_bytes()
                .to_vec(),
        );
        v_s.append(&mut server_protocol_string.trim().as_bytes().to_vec());

        let mut ciphers_no_size = ciphers[5..(ciphers.len() - ciphers[4] as usize)].to_vec();
        let mut i_c: Vec<u8> = Vec::new();
        i_c.append(&mut (ciphers_no_size.len() as u32).to_be_bytes().to_vec());
        i_c.append(&mut ciphers_no_size);

        let mut received_ciphers_no_size =
            received_ciphers[5..(received_ciphers.len() - received_ciphers[4] as usize)].to_vec();
        let mut i_s: Vec<u8> = Vec::new();
        i_s.append(
            &mut (received_ciphers_no_size.len() as u32)
                .to_be_bytes()
                .to_vec(),
        );
        i_s.append(&mut received_ciphers_no_size);

        self.session_id = crypto::make_hash(
            algorithm, &mut v_c, &mut v_s, &mut i_c, &mut i_s, k_s, e, f, k,
        );
    }

    pub fn mpint(&self, int: &[u8]) -> Vec<u8> {
        let mut int_vec: Vec<u8> = Vec::new();
        if int[0] & 128 == 128 {
            int_vec.append(&mut 33u32.to_be_bytes().to_vec());
            int_vec.push(0);
        } else {
            int_vec.append(&mut 32u32.to_be_bytes().to_vec());
        };

        int_vec.append(&mut int.to_vec());
        int_vec
    }

    fn pad_data(&self, data: &mut Vec<u8>, mut padding: u32) {
        if padding < 4 {
            padding += 8
        };

        data.append(&mut vec![0; padding as usize]);

        let data_len = ((data.len() + 1 as usize) as u32).to_be_bytes().to_vec();
        let mut i = 0;
        for b in data_len.iter() {
            data.insert(i, *b);
            i += 1;
        }
        data.insert(i, padding as u8);
    }
}
