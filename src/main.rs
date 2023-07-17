use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use std::net::IpAddr;

mod tcp;
mod udp;
mod util;

/// A program to send muffins from one computer to another.
#[derive(Parser, Debug)]
#[command(version, about)]
struct Cli {
    /// Transport to use.
    #[arg(short, long, value_enum, default_value_t = Transport::TCP)]
    transport: Transport,

    /// Port to use.
    #[arg(short, long, default_value_t = 4747)]
    port: u16,

    /// Scope to use for IPv6 targets
    #[arg(short, long, default_value_t = 0)]
    scope: u32,

    /// How big an individual send bufer is in bytes.
    #[arg(short, long, default_value_t = 64000)]
    buffer_size: usize,

    /// How big of a TCP backlog to keep.
    #[arg(long, default_value_t = 128)]
    backlog: i32,

    #[command(subcommand)]
    kind: Participant,
}

#[derive(Debug, Subcommand)]
enum Participant {
    Client(Client),
    Server(Server),
}

#[derive(Parser, Debug)]
struct Client {
    /// IP address of server
    server: IpAddr,

    /// Determine test duration in terms of time or data.
    #[arg(short, long, value_enum, default_value_t = Mode::Time)]
    mode: Mode,

    /// How long the test should run. Interpretation depends on mode. Time
    /// values are in seconds. Data values are in buffer writes.
    #[arg(short, long, default_value_t = 10)]
    duration: u64,
}

#[derive(Parser, Debug)]
struct Server {
    /// IP address to listen on
    listen: IpAddr,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum Transport {
    TCP,
    UDP,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum Mode {
    Time,
    Data,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum Kind {
    Client,
    Server,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.transport {
        Transport::TCP => tcp::run(&cli),
        Transport::UDP => udp::run(&cli),
    }
}
