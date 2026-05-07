use crate::util::{SEQ_LEN, buffer, get_seq, put_seq, show_speed};
use crate::{Cli, Client, Participant, Server};
use anyhow::{Context, Result};
use socket2::{Domain, Protocol, Socket, Type};
use std::io::Read;
use std::net::{
    IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6,
};
use std::num::NonZeroU32;
use std::time::{Duration, Instant};

pub(crate) fn run(cli: &Cli) -> Result<()> {
    match cli.kind {
        Participant::Client(ref client) => run_client(cli, client),
        Participant::Server(ref server) => run_server(cli, server),
    }
}

fn run_client(cli: &Cli, client: &Client) -> Result<()> {
    let is_mcast = client.server.is_multicast();

    let (s, sa) = match client.server {
        IpAddr::V4(addr) => {
            let sa = SocketAddrV4::new(addr, cli.port);
            let s =
                Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
            if is_mcast {
                s.set_multicast_ttl_v4(cli.multicast_ttl)
                    .context("set IP_MULTICAST_TTL")?;
                s.set_multicast_loop_v4(cli.multicast_loop)
                    .context("set IP_MULTICAST_LOOP")?;
                if let Some(iface) = cli.multicast_iface {
                    s.set_multicast_if_v4(&iface)
                        .context("set IP_MULTICAST_IF")?;
                }
            }
            (s, SocketAddr::V4(sa))
        }
        IpAddr::V6(addr) => {
            let sa = SocketAddrV6::new(addr, cli.port, 0, cli.scope);
            let s =
                Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
            if is_mcast {
                s.set_multicast_hops_v6(cli.multicast_ttl)
                    .context("set IPV6_MULTICAST_HOPS")?;
                s.set_multicast_loop_v6(cli.multicast_loop)
                    .context("set IPV6_MULTICAST_LOOP")?;
                // ifindex 0 means "kernel picks". Cross-platform behavior of
                // explicit 0 is inconsistent, so skip the call entirely.
                if let Some(idx) = NonZeroU32::new(cli.scope) {
                    s.set_multicast_if_v6(idx.get())
                        .context("set IPV6_MULTICAST_IF")?;
                }
            }
            (s, SocketAddr::V6(sa))
        }
    };
    let sa = sa.into();

    let mut buf = buffer(cli.buffer_size);

    let start = Instant::now();
    let mut interval = 0;
    let mut interval_sent = 0;
    let mut total = 0;
    let mut count = 0;
    let mut seq: u64 = 0;
    loop {
        if is_mcast {
            put_seq(&mut buf, seq);
            seq = seq.wrapping_add(1);
        }
        let n = s.send_to(&buf, &sa)?;

        interval_sent += n * 8;
        let t = Instant::now();
        let d = t.duration_since(start);
        let ds = d.as_secs();
        if ds > interval {
            interval = ds;
            total += interval_sent;
            print!("[{}] ", count);
            count += 1;
            show_speed(interval_sent as f64);
            interval_sent = 0;
        }
        if ds >= client.duration {
            break;
        }
    }

    println!("------");
    show_speed(total as f64 / client.duration as f64);

    Ok(())
}

fn run_server(cli: &Cli, server: &Server) -> Result<()> {
    let is_mcast = server.listen.is_multicast();

    let s = match server.listen {
        IpAddr::V4(addr) => {
            let s =
                Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
            if is_mcast {
                s.set_reuse_address(true).context("SO_REUSEADDR")?;
                let bind = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, cli.port);
                s.bind(&bind.into())?;
                let iface =
                    cli.multicast_iface.unwrap_or(Ipv4Addr::UNSPECIFIED);
                s.join_multicast_v4(&addr, &iface)
                    .context("IP_ADD_MEMBERSHIP")?;
            } else {
                let sa = SocketAddrV4::new(addr, cli.port);
                s.bind(&sa.into())?;
            }
            s
        }
        IpAddr::V6(addr) => {
            let s =
                Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
            if is_mcast {
                s.set_reuse_address(true).context("SO_REUSEADDR")?;
                let bind =
                    SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, cli.port, 0, 0);
                s.bind(&bind.into())?;
                s.join_multicast_v6(&addr, cli.scope)
                    .context("IPV6_ADD_MEMBERSHIP")?;
            } else {
                let sa = SocketAddrV6::new(addr, cli.port, 0, cli.scope);
                s.bind(&sa.into())?;
            }
            s
        }
    };

    // When `--duration` is set, install a short read timeout so the recv
    // loop wakes up periodically and can observe the wallclock deadline
    // even if no datagrams are arriving.
    if server.duration.is_some() {
        s.set_read_timeout(Some(Duration::from_millis(500)))
            .context("SO_RCVTIMEO")?;
    }

    let mut interval = 0;
    let mut interval_sent = 0;
    let mut count = 0;
    let start = Instant::now();
    let deadline = server.duration.map(|d| start + Duration::from_secs(d));

    let mut rx_count: u64 = 0;
    let mut loss_count: u64 = 0;
    let mut next_expected: Option<u64> = None;
    let mut total_bits: u64 = 0;

    let mut buf = vec![0u8; cli.buffer_size];

    loop {
        if let Some(deadline) = deadline
            && Instant::now() >= deadline
        {
            break;
        }

        // Read::read on `&Socket` calls into the same `recv` syscall as
        // `recv_from`, but returns a `&[u8]`-shaped result. The source address
        // is discarded either way.
        let n = match Read::read(&mut &s, &mut buf) {
            Ok(n) => n,
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::TimedOut
                ) =>
            {
                continue;
            }
            Err(e) => return Err(e.into()),
        };

        rx_count += 1;
        interval_sent += n * 8;
        total_bits += (n * 8) as u64;

        if is_mcast
            && n >= SEQ_LEN
            && let Some(seq) = get_seq(&buf[..n])
        {
            let expected = next_expected.unwrap_or(seq);
            if seq > expected {
                loss_count += seq - expected;
            }
            next_expected = Some(expected.max(seq.wrapping_add(1)));
        }

        let t = Instant::now();
        let d = t.duration_since(start);
        let ds = d.as_secs();
        if ds > interval {
            interval = ds;
            print!("[{}] ", count);
            count += 1;
            show_speed(interval_sent as f64);
            interval_sent = 0;
        }
    }

    let elapsed = Instant::now().duration_since(start).as_secs_f64();
    let bps = if elapsed > 0.0 {
        total_bits as f64 / elapsed
    } else {
        0.0
    };

    // Machine-readable summary so commtest can parse the result without
    // scraping `show_speed` output.
    println!("{{\"rx\":{rx_count},\"loss\":{loss_count},\"bps\":{bps:.3}}}");

    if rx_count == 0 {
        anyhow::bail!("received zero datagrams");
    }
    Ok(())
}
