pub fn mpint(int: &[u8]) -> Vec<u8> {
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
