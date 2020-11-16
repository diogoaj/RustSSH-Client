pub struct Packet {
    packet_length: u32,
    padding: u8,
    payload: &[u8],
    random_padding: &[u8],
    mac: &[u8]
}


impl Packet {
}