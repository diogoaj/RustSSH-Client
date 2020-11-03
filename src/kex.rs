use crate::{session::Session, constants};

use x25519_dalek::{StaticSecret, EphemeralSecret, PublicKey};
use ed25519_dalek::*;
use std::convert::From;

pub struct Kex {
   pub private_key: StaticSecret,
}

impl Kex{
    pub fn new(client: &mut Session) -> Kex {
        let private_key = StaticSecret::new(&mut client.csprng);
        Kex {
            private_key,
        }
    }

    pub fn x25519_kex(self, client: &mut Session) -> Vec<u8>{
        self.send_client_public_key(client);
        self.generate_shared_secret(client)
    }

    pub fn send_client_public_key(&self, client: &mut Session) {
        let public_key = PublicKey::from(&self.private_key);
        let pub_key = public_key.as_bytes();

        let mut key_exchange: Vec<u8> = Vec::new();
        key_exchange.push(constants::Message::SSH_MSG_KEX_ECDH_INIT);
        key_exchange.append(&mut (pub_key.len() as u32).to_be_bytes().to_vec());
        key_exchange.append(&mut pub_key.to_vec());

        client.pad_data(&mut key_exchange, false);
        client.write_to_server(&key_exchange);
    }

    fn generate_shared_secret(self, client: &mut Session) -> Vec<u8>{
       Vec::new()
    }
}