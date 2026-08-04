use anyhow::{Result, bail};
use clap::error::ErrorKind;
use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

mod ssm;
mod tcp;
mod udp;
mod util;

use util::InterfaceSelector;

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

    /// Scope (zone index) to use for IPv6 unicast targets. For multicast
    /// use `--multicast-iface` instead.
    #[arg(short, long, default_value_t = 0)]
    scope: u32,

    /// How big an individual send buffer is in bytes.
    #[arg(short, long, default_value_t = 64000)]
    buffer_size: usize,

    /// How big of a TCP backlog to keep.
    #[arg(long, default_value_t = 128)]
    backlog: i32,

    /// TTL (IPv4) or hop limit (IPv6) for outgoing datagrams. For multicast
    /// destinations this sets `IP_MULTICAST_TTL` / `IPV6_MULTICAST_HOPS`;
    /// otherwise, it sets `IP_TTL` / `IPV6_UNICAST_HOPS`. The on-wire field
    /// is 8 bits in both IPv4 and IPv6.
    #[arg(long, default_value_t = 64)]
    ttl: u8,

    /// Enable `IP_MULTICAST_LOOP` / `IPV6_MULTICAST_LOOP`. Disabled by
    /// default to avoid the sender seeing its own traffic on hosts that
    /// also act as receivers.
    #[arg(long)]
    multicast_loop: bool,

    /// Interface to pin multicast traffic to.
    ///
    /// This accepts either an interface name (e.g. `net0`) or an IP address
    /// bound to the interface. The group's address family selects what the
    /// selector resolves to: the interface's IPv4 address for `IP_MULTICAST_IF`
    /// and the IPv4 joins, or its interface index for `IPV6_MULTICAST_IF`, the
    /// IPv6 joins, and, for interface- and link-local groups, the bind
    /// scope. When omitted the kernel selects the
    /// interface from its routing table, which may not choose the intended
    /// interface on hosts with multiple network interfaces.
    #[arg(long)]
    multicast_iface: Option<InterfaceSelector>,

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
    /// receiver binds directly to the group on `--port`, sets `SO_REUSEADDR`
    /// (so multiple receivers can co-bind), and joins the group on the
    /// interface selected by `--multicast-iface`.
    listen: IpAddr,

    /// Wallclock duration (seconds) for UDP receivers. When unset the
    /// receiver runs until interrupted. TCP servers ignore this field.
    #[arg(short, long)]
    duration: Option<u64>,

    /// Source addresses for [source-specific multicast][rfc4607] (SSM).
    /// Repeatable: pass `--multicast-source` once per source. With one
    /// source it's a `(S, G)` join. With N sources it's a
    /// `({S1, S2, ...}, G)` INCLUDE filter. The kernel filters incoming
    /// datagrams to only those sourced from one of these addresses
    /// (`IP_ADD_SOURCE_MEMBERSHIP` per source on IPv4, `setsourcefilter`
    /// with the full slist on IPv6). Each must be a unicast address with
    /// family matching `listen`, and `listen` must be a multicast address.
    ///
    /// [rfc4607]: https://datatracker.ietf.org/doc/html/rfc4607
    #[arg(long, value_parser = parse_unicast_ipaddr)]
    multicast_source: Vec<IpAddr>,
}

/// Reject obviously-non-unicast addresses (multicast, unspecified, loopback)
/// and non-routable sources (broadcast, link-local) at clap parse time so SSM
/// misconfiguration surfaces as a CLI error rather than an opaque kernel
/// `EADDRNOTAVAIL` after socket setup.
///
/// This matches the source checks Dendrite applies at group creation
/// (i.e., `dpd/src/mcast/validate.rs`).
fn parse_unicast_ipaddr(s: &str) -> Result<IpAddr, String> {
    let addr: IpAddr = s
        .parse()
        .map_err(|e: std::net::AddrParseError| e.to_string())?;
    if addr.is_multicast() || addr.is_unspecified() || addr.is_loopback() {
        return Err(format!("must be a unicast address (got `{addr}`)"));
    }
    let non_routable = match addr {
        IpAddr::V4(v4) => v4.is_broadcast() || v4.is_link_local(),
        IpAddr::V6(v6) => v6.is_unicast_link_local(),
    };
    if non_routable {
        return Err(format!(
            "must be a routable source address, not broadcast or link-local \
             (got `{addr}`)"
        ));
    }
    Ok(addr)
}

impl Server {
    fn validate(
        &self,
        cli: &Cli,
        cmd: &mut clap::Command,
    ) -> Result<(), clap::Error> {
        // Match the control plane's admission rules for SSM destinations
        // (reserved 232.0.0.0/24, non-allocatable IPv6 group IDs, unusable
        // scopes). The rack never programs such a group, so a join would
        // yield a silent zero-delivery reception.
        if ssm::is_ssm_multicast(self.listen)
            && let Err(msg) = ssm::validate_ssm_destination(self.listen)
        {
            return Err(cmd.error(ErrorKind::ValueValidation, msg));
        }
        if self.multicast_source.is_empty() {
            // An any-source (*, G) join on an SSM-range group receives no
            // traffic. SSM defines no shared (*, G) tree: the host rules
            // (RFC 4607 §4.1) reject a source-less join to an SSM destination,
            // and Nexus only ever programs an SSM-range group as an (S, G)
            // channel. The fabric forwards via a control-plane subscription
            // rather than by snooping the guest's join, so a source-less join
            // installs no usable reception state and yields a silent
            // zero-delivery receive indistinguishable from a network
            // regression.
            //
            // We reject it so that the mismatch surfaces as a CLI error.
            if ssm::is_ssm_multicast(self.listen) {
                return Err(cmd.error(
                    ErrorKind::MissingRequiredArgument,
                    format!(
                        "`listen` {} is in the source-specific multicast (SSM) \
                         range (232.0.0.0/8, ff3x::/32) but no sources were \
                         supplied; an any-source join is undeliverable. Pass \
                         `--multicast-source` for an INCLUDE-mode (S, G) join",
                        self.listen
                    ),
                ));
            }
            return Ok(());
        }
        if !self.listen.is_multicast() {
            return Err(cmd.error(
                ErrorKind::ValueValidation,
                format!(
                    "`--multicast-source` requires `listen` to be a multicast \
                     address (got `{}`)",
                    self.listen
                ),
            ));
        }
        for source in &self.multicast_source {
            if source.is_ipv4() != self.listen.is_ipv4() {
                return Err(cmd.error(
                    ErrorKind::ValueValidation,
                    format!(
                        "`--multicast-source` family must match the `listen` \
                         address family (got `{source}` vs listen `{}`)",
                        self.listen
                    ),
                ));
            }
        }
        // SSM joins must be pinned to a specific interface. With a
        // kernel-picked interface (`INADDR_ANY` for v4, `ifindex = 0` for
        // v6) the join can silently land on an interface where the source
        // isn't reachable and deliver no traffic, which looks identical
        // to a real network regression in CI.
        if cli.multicast_iface.is_none() {
            return Err(cmd.error(
                ErrorKind::MissingRequiredArgument,
                "`--multicast-source` requires `--multicast-iface` to pin \
                 the SSM join to a specific interface",
            ));
        }
        Ok(())
    }

    /// IPv4 SSM sources. `validate` guarantees that, when `listen` is v4
    /// and a multicast address, every configured source is also v4, so this
    /// never silently drops a v6 source meant for the v4 path.
    pub(crate) fn multicast_source_v4(&self) -> Vec<Ipv4Addr> {
        self.multicast_source
            .iter()
            .filter_map(|source| match source {
                IpAddr::V4(addr) => Some(*addr),
                IpAddr::V6(_) => None,
            })
            .collect()
    }

    /// IPv6 SSM sources. See [`Self::multicast_source_v4`] for the
    /// corresponding invariant.
    pub(crate) fn multicast_source_v6(&self) -> Vec<Ipv6Addr> {
        self.multicast_source
            .iter()
            .filter_map(|source| match source {
                IpAddr::V6(addr) => Some(*addr),
                IpAddr::V4(_) => None,
            })
            .collect()
    }
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

    if let Participant::Server(ref server) = cli.kind
        && let Err(e) = server.validate(&cli, &mut Cli::command())
    {
        e.exit();
    }

    match cli.transport {
        Transport::Tcp => tcp::run(&cli),
        Transport::Udp => udp::run(&cli),
    }
}
