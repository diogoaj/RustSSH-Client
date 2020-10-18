use clap::Clap;
use std::net::IpAddr;

mod connection;

#[derive(Clap)]
struct Opts {
    ip: IpAddr,
    port: u16,
}

fn main() -> std::io::Result<()>{
    let opts: Opts = Opts::parse();

    connection::run(opts.ip, opts.port)
}