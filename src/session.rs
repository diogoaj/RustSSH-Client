use std::{cell::Cell, net::{SocketAddr, TcpStream, IpAddr}};
use std::io::{BufReader, BufWriter, Result, prelude::*};
use ring::digest;
use rand::rngs::OsRng;

use crate::{constants, crypto};

pub struct Session {
    reader: Cell<BufReader<TcpStream>>,
    writer: Cell<BufWriter<TcpStream>>,
    pub csprng: OsRng, 
    pub client_sequence_number: u32,
    pub server_sequence_number: u32,
    pub session_id: Vec<u8>,
    pub data_received: u32,
    pub data_sent: u32,
    pub total_data_transmitted: u32,
    pub client_window_size: u32,
    pub server_window_size: u32,
    pub encrypted: bool,
    pub session_keys: Option<crypto::SessionKeys>
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
            reader: Cell::new(BufReader::new(stream.try_clone()?)),
            writer: Cell::new(BufWriter::new(stream)),
            csprng: OsRng{},
            client_sequence_number: 0,
            server_sequence_number: 0,
            session_id: Vec::new(),
            data_received: 0,
            data_sent: 0,
            total_data_transmitted: 0,
            client_window_size: 1048576,
            server_window_size: 0,
            encrypted: false,
            session_keys: None,

        })
    }

    pub fn read_line(&mut self) -> Result<String> {
        let mut data = String::new();

        loop {
            match self.reader.get_mut().read_line(&mut data) {
                Ok(_) => break,
                Err(_) => continue,
            }
        }
        Ok(data)
    }

    pub fn write_line(&mut self, line: &str) -> Result<()> {
        self.writer.get_mut().write(&line.as_bytes())?;
        self.writer.get_mut().flush()?;
        Ok(())
    }

    pub fn read_from_server(&mut self) -> Vec<Vec<u8>> {
        let mut buf = [0u8;constants::Size::MAX_PACKET_SIZE as usize];
        let result = self.reader.get_mut().read(&mut buf);

        if result.is_ok() && self.encrypted == false {
            self.server_sequence_number += 1;
            let received_data = buf[..result.unwrap()].to_vec();

            let mut packet = Vec::new();
            packet.push(received_data);
            return packet;

        } else if result.is_ok() && self.encrypted == true {
            self.server_sequence_number += 1;
            let mut received_data = buf[..result.unwrap()].to_vec();

            let mut decrypted_packets: Vec<Vec<u8>> = Vec::new();

            while received_data.len() != 0 {
                let mut enc_length_slice = [0u8;4];
                enc_length_slice.copy_from_slice(&received_data[0..4]);
    
                let dec_length_slice = self.decrypt_packet_length(enc_length_slice);
                let dec_length = u32::from_be_bytes(dec_length_slice);

                if received_data.len() >= (dec_length + 20) as usize {
                    decrypted_packets.push(self.decrypt_packet(&mut received_data[..(dec_length+20) as usize].to_vec()));
                    received_data.drain(..(dec_length+20) as usize);
                    self.data_received += dec_length+20;
                    self.server_sequence_number += 1;
                }
                
                if received_data.len() == 0 {self.server_sequence_number -= 1; return decrypted_packets; }

                let mut buf = [0u8;constants::Size::MAX_PACKET_SIZE as usize];
                match self.reader.get_mut().read(&mut buf) {
                    Ok(size) => {
                        received_data.append(&mut buf[..size].to_vec());
                    } 
                    Err(_) => continue,
                }
            }
            self.server_sequence_number -= 1;
            return decrypted_packets;
        }
        Vec::new()
    }

    pub fn write_to_server(&mut self, data: &Vec<u8>) -> Result<()> {
        self.writer.get_mut().write(data.as_slice())?;
        self.client_sequence_number += 1;
        self.writer.get_mut().flush()
    }
    
    pub fn decrypt_packet_length(&mut self, enc_length: [u8;4]) -> [u8;4] {
        self.session_keys.as_mut().unwrap().decrypt_length(self.server_sequence_number, enc_length)
    }

    pub fn encrypt_packet(&mut self, packet: &mut Vec<u8>) {
        self.session_keys.as_mut().unwrap().seal_packet(self.client_sequence_number, packet);
    }

    pub fn decrypt_packet(&mut self, packet: &mut Vec<u8>) -> Vec<u8> {
        let vec = self.session_keys.as_mut().unwrap().unseal_packet(self.server_sequence_number, packet);
        vec
    }

    pub fn pad_data(&self, data: &mut Vec<u8>) {
        let mut padding = match self.encrypted {
            true => 8 - (data.len() as u32 + 1) % 8,
            false => 16 - (data.len() as u32 + 5) % 16
        };

        if padding < 4 { padding += 8 };

        data.append(&mut vec![0; padding as usize]);
    
        let data_len = ((data.len() + 1 as usize) as u32).to_be_bytes().to_vec();
    
        let mut i = 0;
        for b in data_len.iter() {
            data.insert(i, *b);
            i += 1;
        }
    
        data.insert(i, padding as u8);
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
        k: &mut Vec<u8>) {

        let mut v_c: Vec<u8> = Vec::new();
        v_c.append(&mut (constants::Strings::CLIENT_VERSION.len() as u32).to_be_bytes().to_vec());
        v_c.append(&mut constants::Strings::CLIENT_VERSION.as_bytes().to_vec());
        
        let mut v_s: Vec<u8> = Vec::new();
        v_s.append(&mut (server_protocol_string.trim().len() as u32).to_be_bytes().to_vec());
        v_s.append(&mut server_protocol_string.trim().as_bytes().to_vec());

        let mut ciphers_no_size = ciphers[5..(ciphers.len() - ciphers[4] as usize)].to_vec();
        let mut i_c: Vec<u8> = Vec::new();
        i_c.append(&mut (ciphers_no_size.len() as u32).to_be_bytes().to_vec());
        i_c.append(&mut ciphers_no_size);

        let mut received_ciphers_no_size = received_ciphers[5..(received_ciphers.len() - received_ciphers[4] as usize)].to_vec();
        let mut i_s: Vec<u8> = Vec::new();
        i_s.append(&mut (received_ciphers_no_size.len() as u32).to_be_bytes().to_vec());
        i_s.append(&mut received_ciphers_no_size);
        
        self.session_id = crypto::make_hash(
            algorithm,
            &mut v_c, 
            &mut v_s, 
            &mut i_c, 
            &mut i_s, 
            k_s, 
            e, 
            f,
            k,
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
}