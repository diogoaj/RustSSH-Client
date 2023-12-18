use std::convert::TryInto;

#[derive(Debug)]

pub struct Packet {
    pub length: u32,
    pub padding_length: u8,
    pub payload: Vec<u8>,
    pub random_padding: Vec<u8>,
    pub mac: Vec<u8>,
}

impl Packet {
    pub fn new(data: &mut Vec<u8>) -> Self {
        let packet_length: [u8; 4] = data[..4].try_into().unwrap();
        let length = u32::from_be_bytes(packet_length);

        let packet_without_length: &[u8] = &data[4..(length + 4) as usize];
        let padding_length: u8 = packet_without_length[0];

        let payload: &[u8] = &packet_without_length[1..(length - padding_length as u32) as usize];
        let packet_ending: &[u8] =
            &packet_without_length[(length - padding_length as u32) as usize..];

        let random_padding: &[u8] = &packet_ending[..padding_length as usize];
        let mac: &[u8] = &packet_ending[padding_length as usize..];
        Packet {
            length,
            padding_length,
            payload: payload.to_vec(),
            random_padding: random_padding.to_vec(),
            mac: mac.to_vec(),
        }
    }

    pub fn to_vec(&mut self) -> Vec<u8> {
        let mut vec = Vec::new();

        vec.append(&mut self.length.to_be_bytes().to_vec().clone());
        vec.append(&mut self.padding_length.to_be_bytes().to_vec().clone());
        vec.append(&mut self.payload.clone());
        vec.append(&mut self.random_padding.clone());
        vec.append(&mut self.mac.clone());

        vec
    }
}
