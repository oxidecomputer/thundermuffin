//! Source-specific multicast (SSM) support: group classification and joins
//! not covered by `socket2`.
//!
//! `socket2` exposes `Socket::join_ssm_v4` for IPv4 SSM joins via
//! `IP_ADD_SOURCE_MEMBERSHIP`, but has no IPv6 equivalent in any current
//! release. For IPv6 we drop to POSIX [`setsourcefilter(3SOCKET)`]
//! (RFC 3678), which lives in `libsocket` on illumos and `libc` on Linux.
//!
//! [`setsourcefilter(3SOCKET)`]: https://illumos.org/man/3SOCKET/setsourcefilter

use socket2::Socket;
use std::net::{IpAddr, Ipv6Addr};
use std::os::fd::AsRawFd;

/// Whether `addr` is in the source-specific multicast (SSM) range:
/// `232.0.0.0/8` for IPv4 and `ff30::/12` for IPv6 (flags nibble `3`,
/// referring to any scope), per [RFC 4607][rfc4607] §1. An SSM group builds no
/// shared `(*, G)` tree, so it is reachable only through an INCLUDE-mode
/// `(S, G)` join.
///
/// The ranges mirror Nexus's canonical `is_ssm_address`, so a probe's in-zone
/// join classifies a group the same way the control plane does when it
/// programs the group's forwarding tables.
///
/// [rfc4607]: https://datatracker.ietf.org/doc/html/rfc4607
pub fn is_ssm_multicast(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => v4.octets()[0] == 232,
        IpAddr::V6(v6) => {
            let octets = v6.octets();
            octets[0] == 0xff && octets[1] >> 4 == 0x3
        }
    }
}

// RFC 3678 / POSIX include-mode source filter. Standardized as `1` on every
// platform that exposes `setsourcefilter`.
const MCAST_INCLUDE: u32 = 1;

unsafe extern "C" {
    fn setsourcefilter(
        socket: libc::c_int,
        interface: u32,
        group: *const libc::sockaddr,
        grouplen: libc::socklen_t,
        fmode: u32,
        numsrc: u32,
        slist: *const libc::sockaddr_storage,
    ) -> libc::c_int;
}

/// Join `socket` to the IPv6 source-specific multicast group `group` on
/// interface `ifindex`, with INCLUDE-mode filter listing `sources`. With
/// one entry it's a `(S, G)` join; with N it's a `({S1, ..., Sn}, G)`
/// channel. Caller must pass a non-empty slice (the empty-sources case
/// is the any-source `IPV6_ADD_MEMBERSHIP` join, handled elsewhere).
pub fn join_ssm_v6(
    socket: &Socket,
    group: &Ipv6Addr,
    sources: &[Ipv6Addr],
    ifindex: u32,
) -> std::io::Result<()> {
    // Construct a `sockaddr_in6` with only family + address populated. All
    // other fields (port, flowinfo, scope, platform-specific extras) are
    // explicitly zeroed.
    let make_in6 = |addr: &Ipv6Addr| -> libc::sockaddr_in6 {
        libc::sockaddr_in6 {
            sin6_family: libc::AF_INET6 as libc::sa_family_t,
            sin6_port: 0,
            sin6_flowinfo: 0,
            sin6_addr: libc::in6_addr {
                s6_addr: addr.octets(),
            },
            sin6_scope_id: 0,
            #[cfg(any(target_os = "illumos", target_os = "solaris"))]
            __sin6_src_id: 0,
        }
    };

    let group_sa = make_in6(group);

    // Build the slist as a `Vec<sockaddr_storage>`. `sockaddr_storage` is
    // sized and aligned to hold any sockaddr family, so a `sockaddr_in6`
    // lands at offset 0 with correct alignment. `ptr::write` only
    // overwrites the leading `size_of::<sockaddr_in6>()` bytes per slot;
    // trailing bytes stay zero-initialized.
    let slist: Vec<libc::sockaddr_storage> = sources
        .iter()
        .map(|source| {
            let mut storage: libc::sockaddr_storage =
                unsafe { std::mem::zeroed() };
            unsafe {
                std::ptr::write(
                    &mut storage as *mut _ as *mut libc::sockaddr_in6,
                    make_in6(source),
                );
            }
            storage
        })
        .collect();

    // `setsourcefilter` is an FFI call. The pointers reference valid sockaddr
    // structures of the indicated lengths and live for the duration of the
    // call. `numsrc` is taken from `slist.len()` so both arguments unambiguously
    // refer to the same buffer.
    let ret = unsafe {
        setsourcefilter(
            socket.as_raw_fd(),
            ifindex,
            &group_sa as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
            MCAST_INCLUDE,
            slist.len() as u32,
            slist.as_ptr(),
        )
    };
    if ret < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssm_classification_matches_rfc4607_ranges() {
        // IPv4: only 232.0.0.0/8 is SSM. The adjacent ASM and link-local
        // ranges are not.
        assert!(is_ssm_multicast("232.0.0.1".parse().unwrap()));
        assert!(is_ssm_multicast("232.255.255.255".parse().unwrap()));
        assert!(!is_ssm_multicast("231.255.255.255".parse().unwrap()));
        assert!(!is_ssm_multicast("233.0.0.1".parse().unwrap()));
        assert!(!is_ssm_multicast("239.1.2.3".parse().unwrap()));
        assert!(!is_ssm_multicast("224.0.0.1".parse().unwrap()));

        // IPv6: ff30::/12 (flags nibble 3) is SSM at every scope. Other
        // multicast flag/scope combinations are not.
        assert!(is_ssm_multicast("ff3e::1".parse().unwrap()));
        assert!(is_ssm_multicast("ff35::1234".parse().unwrap()));
        assert!(!is_ssm_multicast("ff0e::1".parse().unwrap()));
        assert!(!is_ssm_multicast("ff02::1".parse().unwrap()));
    }
}
