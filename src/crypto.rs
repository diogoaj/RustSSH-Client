use ring::{aead::chacha20_poly1305_openssh, digest, hmac};
pub struct Keys {
    pub initial_iv_client_to_server: [u8;32],
    pub initial_iv_server_to_client: [u8;32],
    pub encryption_key_client_to_server :[u8;32],
    pub encryption_key_server_to_client: [u8;32],
    pub integrity_key_client_to_server: [u8;32],
    pub integrity_key_server_to_client: [u8;32],
}

impl Keys {
    pub fn new(secret: &mut Vec<u8>, exchange_hash: &mut Vec<u8>) -> Keys {
        let mut encryption_client: Vec<u8> = Vec::new();
        encryption_client.append(&mut secret.clone());
        encryption_client.append(&mut exchange_hash.clone());
        encryption_client.push(67);
        encryption_client.append(&mut exchange_hash.clone());
    
        let mut k1_client = 
            digest::digest(&digest::SHA256, encryption_client.as_slice()).as_ref().to_vec();
    
        let mut encryption_server: Vec<u8> = Vec::new();
        encryption_server.append(&mut secret.clone());
        encryption_server.append(&mut exchange_hash.clone());
        encryption_server.push(68);
        encryption_server.append(&mut exchange_hash.clone());
    
        let mut k1_server = 
            digest::digest(&digest::SHA256, encryption_server.as_slice()).as_ref().to_vec();
    
        let mut client_key_slice: [u8; 32] = [0;32];
        client_key_slice.copy_from_slice(k1_client.as_slice());
        let mut server_key_slice: [u8; 32] = [0;32];
        server_key_slice.copy_from_slice(k1_server.as_slice());
    
        let mut k1_client = 
            digest::digest(&digest::SHA256, encryption_client.as_slice()).as_ref().to_vec();
    
        let mut iv_client_to_server: [u8;32] = [0;32];
        let mut iv_client: Vec<u8> = Vec::new();
        iv_client.append(&mut secret.clone());
        iv_client.append(&mut exchange_hash.clone());
        iv_client.push(65);
        iv_client.append(&mut exchange_hash.clone());
    
        iv_client_to_server.copy_from_slice(digest::digest(&digest::SHA256, iv_client.as_slice()).as_ref());
    
        let mut iv_server_to_client: [u8;32] = [0;32];
        let mut iv_server: Vec<u8> = Vec::new();
        iv_server.append(&mut secret.clone());
        iv_server.append(&mut exchange_hash.clone());
        iv_server.push(66);
        iv_server.append(&mut exchange_hash.clone());
        
        iv_server_to_client.copy_from_slice(digest::digest(&digest::SHA256, iv_server.as_slice()).as_ref());
    
    
        let mut integrity_client_to_server: [u8;32] = [0;32];
        let mut integrity_client: Vec<u8> = Vec::new();
        integrity_client.append(&mut secret.clone());
        integrity_client.append(&mut exchange_hash.clone());
        integrity_client.push(69);
        integrity_client.append(&mut exchange_hash.clone());
    
        integrity_client_to_server.copy_from_slice(digest::digest(&digest::SHA256, integrity_client.as_slice()).as_ref());
    
        let mut integrity_server_to_client: [u8;32] = [0;32];
        let mut integrity_server: Vec<u8> = Vec::new();
        integrity_server.append(&mut secret.clone());
        integrity_server.append(&mut exchange_hash.clone());
        integrity_server.push(70);
        integrity_server.append(&mut exchange_hash.clone());
        
        integrity_server_to_client.copy_from_slice(digest::digest(&digest::SHA256, integrity_server.as_slice()).as_ref());
    
        Keys {
            initial_iv_client_to_server: iv_client_to_server,
            initial_iv_server_to_client: iv_server_to_client,
            encryption_key_client_to_server: client_key_slice,
            encryption_key_server_to_client: server_key_slice,
            integrity_key_client_to_server: integrity_client_to_server,
            integrity_key_server_to_client: integrity_server_to_client
        }      
    } 

    fn create_key(algorithm: &'static digest::Algorithm, k: Vec<u8>, h: Vec<u8>, key_char: u8, session_id: Vec<u8>) -> Vec<u8> {
        let mut key: Vec<u8> = Vec::new();
        key.append(&mut k.clone());
        key.append(&mut h.clone());
        key.push(key_char);
        key.append(&mut session_id.clone());
    
        digest::digest(algorithm, key.as_slice()).as_ref().to_vec()
    }
}  

pub fn make_hash(
    algorithm: &'static digest::Algorithm,
    v_c: &mut Vec<u8>, 
    v_s: &mut Vec<u8>, 
    i_c: &mut Vec<u8>, 
    i_s: &mut Vec<u8>, 
    k_s: &mut Vec<u8>, 
    e: &mut Vec<u8>, 
    f: &mut Vec<u8>,
    k: &mut Vec<u8>) -> Vec<u8> {

        let mut hash_data: Vec<u8> = Vec::new();
        hash_data.append(v_c);
        hash_data.append(v_s);
        hash_data.append(i_c);
        hash_data.append(i_s);
        hash_data.append(k_s);
        hash_data.append(e);
        hash_data.append(f);
        hash_data.append(k);

        //println!("{:x?}", hash_data);

        digest::digest(algorithm, hash_data.as_slice()).as_ref().to_vec()
}




