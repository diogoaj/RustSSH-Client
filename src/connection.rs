use std::{io::prelude::*, net::SocketAddr};
use std::net::TcpStream;
use std::io::BufReader;
use std::io::BufWriter;
use std::net::IpAddr;
use std::str;

mod algorithms;

pub fn read_line(reader: &mut BufReader<&TcpStream>) -> std::io::Result<String> {
    let mut data = String::new();
    reader.read_line(&mut data)?;
    Ok(data)
}

pub fn write_line(writer: &mut BufWriter<&TcpStream>, line: &str) -> std::io::Result<()>{
    writer.write(&line.as_bytes())?;
    writer.flush()?;
    Ok(())
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

    write_line(&mut writer, "SSH-2.0-Simple_Rust_Client_1.0\r\n")?;

    let received: Vec<u8> = reader.fill_buf()?.to_vec();
    let size = &received[0..4];
    let pad = &received[5];
    let code = &received[6];
    let cookie = &received[6..22];

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

    ciphers.push(20);
    ciphers.append(&mut vec![0x69,0x45,0x32,0x50,0xc5,0x59,0x60,0x52,0x1c,0xf9,0xd5,0xc6,0x38,0x47,0xa8,0x50]);
    ciphers.append(&mut (algorithms::KEY_EXCHANGE_ALGORITHM.len() as u32).to_be_bytes().to_vec());
    ciphers.append(&mut algorithms::KEY_EXCHANGE_ALGORITHM.as_bytes().to_vec());
    ciphers.append(&mut (algorithms::PUBLIC_KEY_ALGORITHM.len() as u32).to_be_bytes().to_vec());
    ciphers.append(&mut algorithms::PUBLIC_KEY_ALGORITHM.as_bytes().to_vec());
    ciphers.append(&mut (algorithms::ENCRYPTION_ALGORITHM.len() as u32).to_be_bytes().to_vec());
    ciphers.append(&mut algorithms::ENCRYPTION_ALGORITHM.as_bytes().to_vec());
    ciphers.append(&mut (algorithms::ENCRYPTION_ALGORITHM.len() as u32).to_be_bytes().to_vec());
    ciphers.append(&mut algorithms::ENCRYPTION_ALGORITHM.as_bytes().to_vec());
    ciphers.append(&mut (algorithms::MAC_ALGORITHM.len() as u32).to_be_bytes().to_vec());
    ciphers.append(&mut algorithms::MAC_ALGORITHM.as_bytes().to_vec());
    ciphers.append(&mut (algorithms::MAC_ALGORITHM.len() as u32).to_be_bytes().to_vec());
    ciphers.append(&mut algorithms::MAC_ALGORITHM.as_bytes().to_vec());
    ciphers.append(&mut (algorithms::COMPRESSION_ALGORITHM.len() as u32).to_be_bytes().to_vec());
    ciphers.append(&mut algorithms::COMPRESSION_ALGORITHM.as_bytes().to_vec());
    ciphers.append(&mut (algorithms::COMPRESSION_ALGORITHM.len() as u32).to_be_bytes().to_vec());
    ciphers.append(&mut algorithms::COMPRESSION_ALGORITHM.as_bytes().to_vec());
    ciphers.append(&mut vec![0;13]);

    let padding = 16 - (ciphers.len() as u32 + 5) % 16;

    let cipher_list_len = ((ciphers.len() + 1 + padding as usize) as u32).to_be_bytes().to_vec();

    let mut i = 0;
    for b in cipher_list_len.iter() {
        ciphers.insert(i, *b);
        i += 1;
    }

    ciphers.insert(i, padding as u8);
    ciphers.append(&mut vec![0; padding as usize]);

    writer.write(ciphers.as_slice())?;
    writer.flush()?;

    ///////////////////////////////////////

    // let mut key_exchange: Vec<u8> = Vec::new();

    // key_exchange.push(30);
    // key_exchange.append(&mut 32_u32.to_be_bytes().to_vec());
    // key_exchange.append(&mut vec![0x69,0x45,0x32,0x50,0xc5,0x59,0x60,0x52,0x1c,0xf9,0xd5,0xc6,0x38,0x47,0xa8,0x50,0x69,0x45,0x32,0x50,0xc5,0x59,0x60,0x52,0x1c,0xf9,0xd5,0xc6,0x38,0x47,0xa8,0x50]);

    // let padding = 8 - (key_exchange.len() as u32 + 5) % 8;
    // let key_exchange_len = ((key_exchange.len() + 1 + padding as usize) as u32).to_be_bytes().to_vec();    

    // let mut j = 0;
    // for b in key_exchange_len.iter() {
    //     key_exchange.insert(j, *b);
    //     j += 1;
    // }

    // key_exchange.insert(j, padding as u8);
    // key_exchange.append(&mut vec![0; padding as usize]);

    // writer.write(key_exchange.as_slice())?;

    Ok(())
}