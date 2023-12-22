use rand::rngs::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};

pub trait Kex {
    fn generate_shared_key(&self, f: &[u8]) -> Vec<u8>;
    fn get_public_key(&self) -> Vec<u8>;
}

pub fn try_match(s: &str) -> Option<Box<dyn Kex>> {
    match s {
        "curve25519-sha256" => Some(Box::new(Curve25519::new())),
        _ => None,
    }
}

// curve25519-sha256
pub struct Curve25519 {
    private_key: StaticSecret,
    public_key: PublicKey,
}

impl Curve25519 {
    pub fn new() -> Self {
        let private_key = StaticSecret::random_from_rng(OsRng {});
        let public_key = PublicKey::from(&private_key);
        Self {
            private_key,
            public_key,
        }
    }
}

impl Kex for Curve25519 {
    fn generate_shared_key(&self, f: &[u8]) -> Vec<u8> {
        let mut server_pub_slice = [0u8; 32];
        server_pub_slice.copy_from_slice(f);

        let server_pub = PublicKey::from(server_pub_slice);
        self.private_key
            .diffie_hellman(&server_pub)
            .as_bytes()
            .to_vec()
    }

    fn get_public_key(&self) -> Vec<u8> {
        self.public_key.as_bytes().to_vec()
    }
}
