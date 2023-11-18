use clap::Clap;
use std::net::IpAddr;

mod algorithms;
mod constants;
mod crypto;
mod ed25519;
mod kex;
mod session;
mod ssh;
mod terminal;

#[derive(Clap)]
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
