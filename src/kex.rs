use crate::session::Session;

use std::convert::From;
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};

pub struct Kex {
    pub private_key: StaticSecret,
    pub public_key: PublicKey,
}

impl Kex {
    pub fn new(client: &mut Session) -> Kex {
        let private_key = StaticSecret::random_from_rng(&mut client.csprng);
        let public_key = PublicKey::from(&private_key);
        Kex {
            private_key,
            public_key,
        }
    }

    pub fn generate_shared_secret(&self, f: [u8; 32]) -> SharedSecret {
        let server_pub = PublicKey::from(f);
        self.private_key.diffie_hellman(&server_pub)
    }
}
