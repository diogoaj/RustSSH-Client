use std::{cell::Cell, net::{SocketAddr, TcpStream, IpAddr}};
use std::io::{BufReader, BufWriter, Result, prelude::*};

pub struct Session {
    reader: Cell<BufReader<TcpStream>>,
    writer: Cell<BufWriter<TcpStream>>,
    pub sequence_number: u32,
    pub session_id: Vec<u8>
}

impl Session {
    pub fn new(host: IpAddr, port: u16) -> Result<Self> {
        let socket = SocketAddr::new(host, port);
        let stream = TcpStream::connect(socket).unwrap();
        Ok(Session {
            reader: Cell::new(BufReader::new(stream.try_clone()?)),
            writer: Cell::new(BufWriter::new(stream)),
            sequence_number: 0,
            session_id: Vec::new(),
        })
    }

    pub fn read_line(&mut self) -> Result<String> {
        let r = self.reader.get_mut();
        let mut data = String::new();

        r.read_line(&mut data)?;
        Ok(data)
    }

    pub fn write_line(&mut self, line: &str) -> Result<()> {
        let w = self.writer.get_mut();

        w.write(&line.as_bytes())?;
        w.flush()?;
        Ok(())
    }

    pub fn read_from_server(&mut self) -> Vec<u8> {
        let r = self.reader.get_mut();
        let mut received_data: Vec<u8> = r.fill_buf().unwrap().to_vec();

        r.consume(received_data.len());
        received_data
    }

    pub fn write_to_server(&mut self, data: &Vec<u8>) -> Result<()> {
        let w = self.writer.get_mut();

        w.write(data.as_slice())?;
        self.sequence_number += 1;
        w.flush()
    }

    pub fn pad_data(&self, data: &mut Vec<u8>) {
        let mut padding = 8 - (data.len() as u32 + 5) % 8;
        if padding < 4 { padding += 8 }
    
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