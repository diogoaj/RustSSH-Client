use std::net::IpAddr;

use clap::Parser;

mod algorithms;
mod constants;
mod crypto;
mod ed25519;
mod kex;
mod session;
mod ssh;
mod terminal;

#[derive(Parser)]
struct Opts {
    username: String,
    ip: IpAddr,
    port: u16,
}

fn main() -> std::io::Result<()> {
    let opts: Opts = Opts::parse();
    let mut ssh_client = ssh::SSH::new(opts.username, opts.ip, opts.port);

    ssh_client.ssh_protocol()
}
