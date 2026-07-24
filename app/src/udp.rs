use crate::ssm::join_ssm_v6;
use crate::util::{SEQ_LEN, buffer, get_seq, put_seq, show_speed};
use crate::{Cli, Client, Participant, Server};
use anyhow::{Context, Result};
use socket2::{Domain, Protocol, Socket, Type};
use std::io::{self, Read};
use std::net::{
    IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6,
};
use std::num::NonZeroU32;
use std::os::fd::AsRawFd;
use std::time::{Duration, Instant};

/// `setsockopt` with a single-byte value. The IPv4 multicast options
/// `IP_MULTICAST_TTL` and `IP_MULTICAST_LOOP` are specified by illumos as
/// `uchar_t` and the kernel rejects 4-byte payloads with `EINVAL`.
///
/// socket2 (version 0.6) sets these via a `c_int`, so we drop to a raw
/// `setsockopt` with the correct wire size.
fn setsockopt_u8(
    socket: &Socket,
    level: libc::c_int,
    name: libc::c_int,
    value: u8,
) -> io::Result<()> {
    let ret = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            level,
            name,
            std::ptr::from_ref(&value).cast::<libc::c_void>(),
            std::mem::size_of::<u8>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn set_ip_multicast_ttl_v4(socket: &Socket, ttl: u8) -> io::Result<()> {
    setsockopt_u8(socket, libc::IPPROTO_IP, libc::IP_MULTICAST_TTL, ttl)
}

fn set_ip_multicast_loop_v4(socket: &Socket, enable: bool) -> io::Result<()> {
    setsockopt_u8(
        socket,
        libc::IPPROTO_IP,
        libc::IP_MULTICAST_LOOP,
        u8::from(enable),
    )
}

/// The `sin6_scope_id` to use for a multicast `group` pinned to `ifindex`.
///
/// Scope identifiers disambiguate link-scoped addresses (RFC 4007), so
/// only interface-local (`ffx1::`) and link-local (`ffx2::`) groups carry
/// the ifindex in the socket address. Wider-scope groups are already
/// pinned by `IPV6_MULTICAST_IF` or the join, and the kernel may reject a
/// nonzero scope on them, so the scope stays 0.
fn v6_multicast_scope_id(group: Ipv6Addr, ifindex: u32) -> u32 {
    if matches!(group.segments()[0] & 0x000f, 1 | 2) {
        ifindex
    } else {
        0
    }
}

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
                set_ip_multicast_ttl_v4(&s, cli.ttl)
                    .context("set IP_MULTICAST_TTL")?;
                set_ip_multicast_loop_v4(&s, cli.multicast_loop)
                    .context("set IP_MULTICAST_LOOP")?;
                if let Some(iface) = &cli.multicast_iface {
                    s.set_multicast_if_v4(&iface.v4_addr()?)
                        .context("set IP_MULTICAST_IF")?;
                }
            } else {
                s.set_ttl_v4(u32::from(cli.ttl)).context("set IP_TTL")?;
            }
            (s, SocketAddr::V4(sa))
        }
        IpAddr::V6(addr) => {
            let s =
                Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
            let scope_id = if is_mcast {
                s.set_multicast_hops_v6(u32::from(cli.ttl))
                    .context("set IPV6_MULTICAST_HOPS")?;
                s.set_multicast_loop_v6(cli.multicast_loop)
                    .context("set IPV6_MULTICAST_LOOP")?;
                let ifindex = match &cli.multicast_iface {
                    Some(iface) => iface.index()?,
                    None => 0,
                };
                // ifindex 0 means "kernel picks". Cross-platform behavior of
                // explicit 0 is inconsistent, so skip the call entirely.
                if let Some(idx) = NonZeroU32::new(ifindex) {
                    s.set_multicast_if_v6(idx.get())
                        .context("set IPV6_MULTICAST_IF")?;
                }
                v6_multicast_scope_id(addr, ifindex)
            } else {
                s.set_unicast_hops_v6(u32::from(cli.ttl))
                    .context("set IPV6_UNICAST_HOPS")?;
                cli.scope
            };
            let sa = SocketAddrV6::new(addr, cli.port, 0, scope_id);
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
        put_seq(&mut buf, seq);
        seq = seq.wrapping_add(1);
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

/// Join `socket` to the IPv4 multicast `group` on `iface`. With `sources`
/// non-empty it's an SSM include-mode join, one
/// `IP_ADD_SOURCE_MEMBERSHIP` per source. Otherwise it's an any-source
/// `(*, G)` join via `IP_ADD_MEMBERSHIP`.
fn join_v4(
    socket: &Socket,
    group: Ipv4Addr,
    iface: Ipv4Addr,
    sources: &[Ipv4Addr],
) -> Result<()> {
    if sources.is_empty() {
        return socket
            .join_multicast_v4(&group, &iface)
            .context("IP_ADD_MEMBERSHIP");
    }
    for source in sources {
        // socket2's `join_ssm_v4` signature is (source, group, interface).
        // Swapping them lands the multicast address in `imr_sourceaddr` and
        // the kernel rejects the join with `EINVAL`.
        socket
            .join_ssm_v4(source, &group, &iface)
            .context("IP_ADD_SOURCE_MEMBERSHIP")?;
    }
    Ok(())
}

/// Join `socket` to the IPv6 multicast `group` on `ifindex`. With `sources`
/// non-empty it's an SSM include-mode join via `setsourcefilter` (one call
/// with the full slist). Otherwise it's an any-source `(*, G)` join via
/// `IPV6_ADD_MEMBERSHIP`.
fn join_v6(
    socket: &Socket,
    group: Ipv6Addr,
    ifindex: u32,
    sources: &[Ipv6Addr],
) -> Result<()> {
    if sources.is_empty() {
        return socket
            .join_multicast_v6(&group, ifindex)
            .context("IPV6_ADD_MEMBERSHIP");
    }
    join_ssm_v6(socket, &group, sources, ifindex).context("setsourcefilter")
}

fn run_server(cli: &Cli, server: &Server) -> Result<()> {
    let is_mcast = server.listen.is_multicast();

    let s = match server.listen {
        IpAddr::V4(addr) => {
            let s =
                Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
            // Bind directly to the group address for multicast so the socket
            // only receives datagrams sent to that group.
            //
            // Note: `SO_REUSEADDR` lets multiple receivers co-bind to the same
            // group/port.
            let sa = SocketAddrV4::new(addr, cli.port);
            if is_mcast {
                s.set_reuse_address(true).context("SO_REUSEADDR")?;
            }
            s.bind(&sa.into())?;
            if is_mcast {
                let iface = match &cli.multicast_iface {
                    Some(iface) => iface.v4_addr()?,
                    None => Ipv4Addr::UNSPECIFIED,
                };
                join_v4(&s, addr, iface, &server.multicast_source_v4())?;
            }
            s
        }
        IpAddr::V6(addr) => {
            let s =
                Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;

            let ifindex = if is_mcast {
                match &cli.multicast_iface {
                    Some(iface) => iface.index()?,
                    None => 0,
                }
            } else {
                0
            };

            let scope_id = if is_mcast {
                v6_multicast_scope_id(addr, ifindex)
            } else {
                cli.scope
            };

            let sa = SocketAddrV6::new(addr, cli.port, 0, scope_id);
            if is_mcast {
                s.set_reuse_address(true).context("SO_REUSEADDR")?;
            }
            s.bind(&sa.into())?;
            if is_mcast {
                join_v6(&s, addr, ifindex, &server.multicast_source_v6())?;
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

    let mut rx_count: u64 = 0;
    let mut loss_count: u64 = 0;
    // `out_of_order_count` covers any datagram whose sequence is below the
    // running high-water mark. With only a sequence prefix the receiver
    // cannot distinguish a reordered delivery from a duplicate, so both
    // land in this bucket.
    let mut out_of_order_count: u64 = 0;
    let mut next_expected: Option<u64> = None;
    let mut total_bits: u64 = 0;

    let mut buf = vec![0u8; cli.buffer_size];

    loop {
        if let Some(duration_secs) = server.duration
            && start.elapsed().as_secs() >= duration_secs
        {
            break;
        }

        // The source address is unused here. `Read::read` on `&Socket` routes
        // through the same `recv` syscall as `recv_from` but operates on a
        // plain `&mut [u8]`, avoiding the `MaybeUninit<u8>` buffer that
        // socket2's typed datagram APIs require.
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

        // The sender's sequence is a `u64` counter starting at 0. At line
        // rate that's hundreds of years to wrap, so the receiver makes no
        // attempt to detect or compensate for wraparound. `wrapping_add` is
        // used purely to avoid an overflow panic on adversarial inputs.
        if n >= SEQ_LEN
            && let Some(seq) = get_seq(&buf[..n])
        {
            let expected = next_expected.unwrap_or(seq);
            if seq > expected {
                loss_count += seq - expected;
            } else if seq < expected {
                out_of_order_count += 1;
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
    println!(
        "{{\"rx\":{rx_count},\"loss\":{loss_count},\"out_of_order\":{out_of_order_count},\"bps\":{bps:.3}}}"
    );

    if rx_count == 0 {
        anyhow::bail!("received zero datagrams");
    }
    Ok(())
}
