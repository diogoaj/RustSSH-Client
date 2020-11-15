// Algorithms accepted by the client

pub const ALGORITHMS: [&str;8] = [KEY_EXCHANGE_ALGORITHMS, 
                                  PUBLIC_KEY_ALGORITHMS, 
                                  ENCRYPTION_ALGORITHMS, 
                                  ENCRYPTION_ALGORITHMS,
                                  MAC_ALGORITHMS,
                                  MAC_ALGORITHMS,
                                  COMPRESSION_ALGORITHMS,
                                  COMPRESSION_ALGORITHMS];

// Key Exchange Method Names
pub const KEY_EXCHANGE_ALGORITHMS: &str = "curve25519-sha256";

// Public Key Algorithm Names
pub const PUBLIC_KEY_ALGORITHMS: &str = "ssh-ed25519";

// Encryption Algorithm Names
pub const ENCRYPTION_ALGORITHMS: &str = "chacha20-poly1305@openssh.com";

// MAC Algorithm Names
pub const MAC_ALGORITHMS: &str = "none";

// Compression Algorithm Names
pub const COMPRESSION_ALGORITHMS: &str = "none";