use clap::Clap;
use std::net::IpAddr;

mod algorithms;
mod numbers;
mod connection;

#[derive(Clap)]
struct Opts {
    ip: IpAddr,
    port: u16,
}

fn main() -> std::io::Result<()>{
    let opts: Opts = Opts::parse();

    connection::ssh_debug(opts.ip, opts.port)
}