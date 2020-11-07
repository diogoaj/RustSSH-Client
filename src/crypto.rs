use ring::{aead::chacha20_poly1305_openssh, digest};
use crate::session::Session;

pub struct SessionKeys {
    pub client_key: chacha20_poly1305_openssh::SealingKey,
    pub server_key: chacha20_poly1305_openssh::OpeningKey
}

impl SessionKeys {
    pub fn new(keys: Keys) -> SessionKeys{
        let mut sealing_key_data: [u8;64] = [0;64];
        let mut opening_key_data: [u8;64] = [0;64];
        sealing_key_data.copy_from_slice(keys.encryption_key_client_to_server.as_slice());
        opening_key_data.copy_from_slice(keys.encryption_key_server_to_client.as_slice());

        SessionKeys {
            client_key: chacha20_poly1305_openssh::SealingKey::new(&sealing_key_data),
            server_key: chacha20_poly1305_openssh::OpeningKey::new(&opening_key_data),
        }
    }

    pub fn seal_packet_and_write_to_server(&self, client_session: &mut Session, packet: &mut Vec<u8>){
        let mut tag: [u8;16] = [0;16];
        self.client_key.seal_in_place(client_session.sequence_number, packet, &mut tag);

        packet.append(&mut tag.to_vec());
        client_session.write_to_server(&packet).unwrap();
    }

    pub fn unseal_incoming_packet(&self, client_session: &mut Session) -> Vec<u8>{
        let mut enc_respnse = client_session.read_from_server();

        let mut tag: [u8;16] = [0;16];
        tag.copy_from_slice(&enc_respnse[(enc_respnse.len() - 16) as usize..]);

        let mut enc_response_len: [u8;4] = [0;4];
        enc_response_len.copy_from_slice(&enc_respnse[0..4]);

        let dec_response_len = u32::from_be_bytes(
            self.server_key.decrypt_packet_length(
                client_session.sequence_number-1, 
                enc_response_len)
            );

        let dec_response = self.server_key.open_in_place(
            client_session.sequence_number-1, 
            &mut enc_respnse[0..(dec_response_len+4) as usize], 
            &mut tag).unwrap();

        dec_response.to_vec()
    }
}

pub struct Keys {
    pub initial_iv_client_to_server: Vec<u8>,
    pub initial_iv_server_to_client: Vec<u8>,
    pub encryption_key_client_to_server: Vec<u8>,
    pub encryption_key_server_to_client: Vec<u8>,
    pub integrity_key_client_to_server: Vec<u8>,
    pub integrity_key_server_to_client: Vec<u8>,
}

impl Keys {
    pub fn new(algorithm: &'static digest::Algorithm, k: &mut Vec<u8>, h: &mut Vec<u8>) -> Keys {
        let mut keys: Vec<Vec<u8>> = Vec::new();

        for index in 65..71 {
            keys.push(Keys::derive_key(algorithm, k, h, index, &mut h.clone()));
        }
    
        let mut keys = Keys {
            initial_iv_client_to_server: keys[0].clone(),
            initial_iv_server_to_client: keys[1].clone(),
            encryption_key_client_to_server: keys[2].clone(),
            encryption_key_server_to_client: keys[3].clone(),
            integrity_key_client_to_server: keys[4].clone(),
            integrity_key_server_to_client: keys[5].clone()
        };

        keys.extend_keys(algorithm, k, h);

        keys
    } 

    pub fn rekey(&mut self, algorithm: &'static digest::Algorithm, k: &mut Vec<u8>, h: &mut Vec<u8>, session_id: &mut Vec<u8>) {
        let mut keys: Vec<Vec<u8>> = Vec::new();

        for index in 65..71 {
            keys.push(Keys::derive_key(algorithm, k, h, index, session_id));
        }

        self.initial_iv_client_to_server = keys[0].clone();
        self.initial_iv_server_to_client = keys[1].clone();
        self.encryption_key_client_to_server = keys[2].clone();
        self.encryption_key_server_to_client = keys[3].clone();
        self.integrity_key_client_to_server = keys[4].clone();
        self.integrity_key_server_to_client = keys[5].clone();

        self.extend_keys(algorithm, k, h);
    }

    fn derive_key(algorithm: &'static digest::Algorithm, k: &mut Vec<u8>, h: &mut Vec<u8>, key_char: u8, session_id: &mut Vec<u8>) -> Vec<u8> {
        let mut key: Vec<u8> = Vec::new();
        key.append(&mut k.clone());
        key.append(&mut h.clone());
        key.push(key_char);
        key.append(&mut session_id.clone());
    
        digest::digest(algorithm, key.as_slice()).as_ref().to_vec()
    }

    fn extend_key(&self, algorithm: &'static digest::Algorithm, k: &mut Vec<u8>, h: &mut Vec<u8>, key: Vec<u8>) -> Vec<u8>{
        let mut hash: Vec<u8> = Vec::new();
        hash.append(&mut k.clone());
        hash.append(&mut h.clone());
        hash.append(&mut key.clone());

        digest::digest(algorithm, hash.as_slice()).as_ref().to_vec()
    }

    fn extend_keys(&mut self, algorithm: &'static digest::Algorithm, k: &mut Vec<u8>, h: &mut Vec<u8>) {
        self.initial_iv_client_to_server.append(&mut self.extend_key(algorithm, k, h, self.initial_iv_client_to_server.clone()));
        self.initial_iv_server_to_client.append(&mut self.extend_key(algorithm, k, h, self.initial_iv_server_to_client.clone()));
        self.encryption_key_client_to_server.append(&mut self.extend_key(algorithm, k, h, self.encryption_key_client_to_server.clone()));
        self.encryption_key_server_to_client.append(&mut self.extend_key(algorithm, k, h, self.encryption_key_server_to_client.clone()));
        self.integrity_key_client_to_server.append(&mut self.extend_key(algorithm, k, h, self.integrity_key_client_to_server.clone()));
        self.integrity_key_server_to_client.append(&mut self.extend_key(algorithm, k, h, self.integrity_key_server_to_client.clone()));
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




