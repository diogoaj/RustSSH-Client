use crate::{session::Session, constants};

use x25519_dalek::{StaticSecret, SharedSecret, PublicKey};
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

    // TODO - Refactor this
    pub fn generate_public_key(&self) -> Vec<u8>{
        let public_key = PublicKey::from(&self.private_key);
        let pub_key = public_key.as_bytes();

        let mut key_exchange: Vec<u8> = Vec::new();
        key_exchange.push(constants::Message::SSH_MSG_KEX_ECDH_INIT);
        key_exchange.append(&mut (pub_key.len() as u32).to_be_bytes().to_vec());
        key_exchange.append(&mut pub_key.to_vec());

        key_exchange
 
    }

    pub fn generate_shared_secret(&self, f: [u8;32]) -> SharedSecret{
        let server_pub = PublicKey::from(f);
        self.private_key.diffie_hellman(&server_pub)
    }
}