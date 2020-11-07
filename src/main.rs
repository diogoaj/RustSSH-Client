use clap::Clap;
use std::net::IpAddr;

mod algorithms;
mod constants;
mod ssh;
mod crypto;
mod session;
mod kex;

#[derive(Clap)]
struct Opts {
    ip: IpAddr,
    port: u16,
}

fn main() -> std::io::Result<()>{
    let opts: Opts = Opts::parse();
    let mut ssh_client = ssh::SSH::new(opts.ip, opts.port);

    ssh_client.ssh_protocol()
}