use anyhow::{Result, bail};
use clap::{Parser, Subcommand, ValueEnum};
use std::net::{IpAddr, Ipv4Addr};

mod tcp;
mod udp;
mod util;

/// A program to send muffins from one computer to another.
#[derive(Parser, Debug)]
#[command(version, about)]
struct Cli {
    /// Transport to use.
    #[arg(short, long, value_enum, default_value_t = Transport::Tcp)]
    transport: Transport,

    /// Port to use.
    #[arg(short, long, default_value_t = 4747)]
    port: u16,

    /// Scope (zone index) to use for IPv6 targets. Also used as the outgoing
    /// `IPV6_MULTICAST_IF` interface index when the destination/listen address
    /// is an IPv6 multicast address.
    #[arg(short, long, default_value_t = 0)]
    scope: u32,

    /// How big an individual send buffer is in bytes.
    #[arg(short, long, default_value_t = 64000)]
    buffer_size: usize,

    /// How big of a TCP backlog to keep.
    #[arg(long, default_value_t = 128)]
    backlog: i32,

    /// Multicast TTL (IPv4) or hop limit (IPv6). Applied only when the
    /// destination address is a multicast address.
    #[arg(long, default_value_t = 64)]
    multicast_ttl: u32,

    /// Enable `IP_MULTICAST_LOOP` / `IPV6_MULTICAST_LOOP`. Disabled by
    /// default to avoid the sender seeing its own traffic on hosts that
    /// also act as receivers.
    #[arg(long)]
    multicast_loop: bool,

    /// Outgoing `IP_MULTICAST_IF` for IPv4 multicast, expressed as the
    /// IPv4 address bound to the desired interface. For IPv6 use
    /// `--scope` (numeric ifindex) instead. When omitted the kernel selects
    /// the interface from its routing table, which may surprise on
    /// multi-homed hosts.
    #[arg(long)]
    multicast_iface: Option<Ipv4Addr>,

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
    /// IP address of the server, or multicast group address when sending
    /// multicast traffic.
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
    /// IP address to listen on. When this is a multicast address the
    /// receiver binds the wildcard address (`0.0.0.0` for IPv4, `[::]` for
    /// IPv6) on `--port`, sets `SO_REUSEADDR`, and joins the multicast
    /// group on the interface selected by `--multicast-iface` (IPv4) or
    /// `--scope` (IPv6).
    listen: IpAddr,

    /// Wallclock duration (seconds) for UDP receivers. When unset the
    /// receiver runs until interrupted, matching the prior behavior. TCP
    /// servers ignore this field.
    #[arg(short, long)]
    duration: Option<u64>,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum Transport {
    Tcp,
    Udp,
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

    // TCP cannot carry multicast. Reject early so callers (e.g. commtest)
    // get a clear error rather than a silent unicast send to a multicast
    // address.
    if matches!(cli.transport, Transport::Tcp) {
        let mcast = match cli.kind {
            Participant::Client(ref c) => c.server.is_multicast(),
            Participant::Server(ref s) => s.listen.is_multicast(),
        };
        if mcast {
            bail!("multicast is only supported with `--transport udp`");
        }
    }

    match cli.transport {
        Transport::Tcp => tcp::run(&cli),
        Transport::Udp => udp::run(&cli),
    }
}
