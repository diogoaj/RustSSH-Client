use std::io::prelude::*;
use std::net::TcpStream;
use std::io::BufReader;
use std::io::BufWriter;

fn main() -> std::io::Result<()> {
    let stream = TcpStream::connect("192.168.1.187:22")?;

    let mut reader = BufReader::new(&stream);
    let mut writer = BufWriter::new(&stream);

    let mut data = String::new();
    reader.read_line(&mut data)?;
    println!("{:?}", &data);

    // SSH-2.0-Simple_Rust_Client_1.0
    let buf: [u8; 32] = [83, 83, 72, 45, 50, 46, 48, 45, 83, 105, 109, 112, 108, 101, 95, 82, 117, 115, 116, 95, 67, 108, 105, 101, 110, 116, 95, 49, 46, 48, 13, 10];
    writer.write(&buf)?;
    writer.flush()?;

    let mut data2 = Vec::new();
    reader.read_until(0x00, &mut data2)?;
    println!("{:?}", &data2);
    Ok(())
}