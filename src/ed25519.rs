use ed25519_dalek::*;
struct Ed25519 {
    pub host_key: PublicKey
}

impl Ed25519 {
    pub fn new(key_material: &[u8]) -> Ed25519{
        Ed25519 { host_key: PublicKey::from_bytes(key_material).unwrap() }
    }

    pub fn verify_signature(&self, exchange_hash: &[u8], signature: Signature) -> bool {
        self.host_key.verify(exchange_hash, &signature).is_ok()
    }
}