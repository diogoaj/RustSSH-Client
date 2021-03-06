# RustSSH - Client

Client implementation of the SSH2 protocol in the Rust language.

> :warning: **Warning**: This project was created for learning purposes and it's very incomplete.

### Usage:
```
./rustssh_client <username> <ip> <port> 
```

### Algorithms Available:
| Key Exchange      | Public Key  | Encryption                     | MAC | Compression |
|-------------------|-------------|--------------------------------|-----|-------------|
| curve25519-sha256 | ssh-ed25519 | chacha20-poly1305\@openssh.com | -   | -           |

### Authentication Methods:
- password

### TODO
- [ ] Key Re-Exchange
- [ ] Algorithm exchange checks
- [ ] Public key fingerprint check
- [ ] Public key authentication
- [ ] Implement other algorithms
- [ ] Detect Terminal window changes
- [ ] Handle other keyboard keys
- [ ] Other protocol related features