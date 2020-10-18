use std::{io::prelude::*, net::SocketAddr};
use std::net::TcpStream;
use std::io::BufReader;
use std::io::BufWriter;
use std::net::IpAddr;
use std::str;

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

pub fn run(host: IpAddr, port: u16) -> std::io::Result<()>{
    let socket = SocketAddr::new(host, port);
    let stream = TcpStream::connect(socket)?;

    let mut reader = BufReader::new(&stream);
    let mut writer = BufWriter::new(&stream);

    println!("Server version: {}", &read_line(&mut reader)?.trim());

    write_line(&mut writer, "SSH-2.0-Simple_Rust_Client_1.0\r\n")?;

    let size = read_line(&mut reader)?;
    let mut packet_size: [u8; 4] = [0; 4];
    packet_size.copy_from_slice(size.trim().as_bytes());

    println!("Size of incoming connection: {:?}", u32::from_be_bytes(packet_size));

    let received: Vec<u8> = reader.fill_buf()?.to_vec();
    let cookie = &received[1..17];

    let mut server_algorithms: Vec<&str> = Vec::new();
    let mut i = 17;

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

    Ok(())
}