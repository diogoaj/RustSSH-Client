use ring::{aead::chacha20_poly1305_openssh, digest};

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

    pub fn seal_packet(&mut self, sequence_number: u32, packet: &mut Vec<u8>) -> Vec<u8>{
        let mut tag: [u8;16] = [0;16];
        self.client_key.seal_in_place(sequence_number, packet, &mut tag);

        packet.append(&mut tag.to_vec());
        packet.clone()
    }

    pub fn decrypt_length(&mut self, sequence_number: u32, enc_length: [u8;4]) -> [u8;4] {
        self.server_key.decrypt_packet_length(
            sequence_number, 
            enc_length)
    }

    pub fn unseal_packet(&mut self, sequence_number: u32, packet: &mut Vec<u8>) -> Vec<u8> {
        let enc_response = packet.as_mut_slice();
     
        //println!("Encrypted packet: {:x?}", enc_response);
        
        let (enc_response_len_slice, enc_response) = enc_response.split_at_mut(4);

        let mut enc_response_len: [u8;4] = [0;4];
        enc_response_len.copy_from_slice(enc_response_len_slice);

        let dec_response_len_slice = self.decrypt_length(sequence_number, enc_response_len);
        let dec_response_len = u32::from_be_bytes(dec_response_len_slice);

        let (enc_payload, enc_response) = enc_response.split_at_mut(dec_response_len as usize);
        let (tag_slice,  _) = enc_response.split_at_mut(16);

        let mut tag: [u8;16] = [0;16];
        tag.copy_from_slice(tag_slice);

        let mut ciphertext_in = [enc_response_len_slice, enc_payload].concat();
        let ciphertext_in = ciphertext_in.as_mut_slice();

        let dec_response = self.server_key.open_in_place(
            sequence_number, 
            ciphertext_in, 
            &mut tag).unwrap();

        //println!("Decrypted packet: {:?}", dec_response);

        [dec_response_len_slice.as_ref(), dec_response].concat()
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
    pub fn new(algorithm: &'static digest::Algorithm, k: &mut Vec<u8>, h: &mut Vec<u8>, session_id: &mut Vec<u8>) -> Keys {
        let mut keys: Vec<Vec<u8>> = Vec::new();

        for index in 65..71 {
            keys.push(Keys::derive_key(algorithm, k, h, index, session_id));
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

    #[allow(dead_code)] // For now
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

        digest::digest(algorithm, hash_data.as_slice()).as_ref().to_vec()
}




