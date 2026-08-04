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
/// `232.0.0.0/8` for IPv4 and `ff3x::/32` for IPv6, per
/// [RFC 4607][rfc4607] §1. The IPv6 space is sixteen disjoint /32 blocks,
/// not the broader `ff30::/12` prefix. An SSM group builds no shared `(*, G)`
/// tree, so it is reachable only through an INCLUDE-mode `(S, G)` join.
///
/// This mirrors Nexus's canonical `is_ssm_address`, so a probe's in-zone join
/// classifies a group the same way the control plane does when it programs the
/// group's forwarding tables.
///
/// [rfc4607]: https://datatracker.ietf.org/doc/html/rfc4607
// TODO: move SSM classification and the RFC 4607 admission checks (see
// `validate_ssm_destination`) into oxnet alongside a multicast address
// type, so this crate, Nexus's `is_ssm_address`, Dendrite's validation,
// and other consumers share one implementation.
pub fn is_ssm_multicast(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => v4.octets()[0] == 232,
        IpAddr::V6(v6) => {
            let segments = v6.segments();
            segments[0] & 0xfff0 == 0xff30 && segments[1] == 0
        }
    }
}

/// Validate an SSM destination against the allocation rules the Oxide
/// control plane enforces at pool admission and group creation (Nexus's
/// `validate_multicast_range` and Dendrite's `dpd/src/mcast/validate.rs`).
/// The caller classifies `addr` as SSM via [`is_ssm_multicast`] first.
///
/// The control plane never programs these groups, so a join would install
/// kernel state that can receive nothing and surface as a silent
/// zero-delivery run. For IPv4, [RFC 4607 §4.3][rfc4607-43] reserves
/// 232.0.0.0 and holds 232.0.0.1 through 232.0.0.255 for IANA, excluding
/// the whole first /24. For IPv6, only `ff3x::/96` group IDs of
/// 0x80000000 and above are dynamically allocatable ([RFC 4607 §1][rfc4607-1]
/// and [§4.3][rfc4607-43]), and the scope nibble must be usable for
/// inter-sled delivery ([RFC 7346 §2][rfc7346-2]).
///
/// [rfc4607-1]: https://www.rfc-editor.org/rfc/rfc4607#section-1
/// [rfc4607-43]: https://www.rfc-editor.org/rfc/rfc4607#section-4.3
/// [rfc7346-2]: https://www.rfc-editor.org/rfc/rfc7346#section-2
pub fn validate_ssm_destination(addr: IpAddr) -> Result<(), String> {
    match addr {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            if octets[1] == 0 && octets[2] == 0 {
                return Err(format!(
                    "{v4} is in the reserved IPv4 SSM subnet \
                     (232.0.0.0/24, RFC 4607)"
                ));
            }
        }
        IpAddr::V6(v6) => {
            let segments = v6.segments();
            let scope = segments[0] & 0x000f;
            if !matches!(scope, 0x4 | 0x5 | 0x8 | 0xe) {
                return Err(format!(
                    "{v6} has an unusable multicast scope nibble \
                     ({scope:x}); usable scopes are admin-local (4), \
                     site-local (5), organization-local (8), and global (e)"
                ));
            }
            let within_prefix = segments[2] == 0
                && segments[3] == 0
                && segments[4] == 0
                && segments[5] == 0;
            let group_id =
                (u32::from(segments[6]) << 16) | u32::from(segments[7]);
            if !within_prefix || group_id < 0x8000_0000 {
                return Err(format!(
                    "{v6} is not a dynamically allocatable IPv6 SSM address \
                     (ff3x::8000:0 through ff3x::ffff:ffff per RFC 4607)"
                ));
            }
        }
    }
    Ok(())
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

        // IPv6: ff3x::/32 is SSM at every scope. Other multicast flag/scope
        // combinations and the ASM gaps inside ff30::/12 are not.
        assert!(is_ssm_multicast("ff3e::1".parse().unwrap()));
        assert!(is_ssm_multicast("ff35::1234".parse().unwrap()));
        // RFC 4607 reserves the full /32 for possible future use of the
        // network-prefix field.
        assert!(is_ssm_multicast("ff3e:0:1234::1".parse().unwrap()));
        assert!(!is_ssm_multicast("ff3e:20:1234::1".parse().unwrap()));
        assert!(!is_ssm_multicast("ff0e::1".parse().unwrap()));
        assert!(!is_ssm_multicast("ff02::1".parse().unwrap()));
    }

    #[test]
    fn ssm_destination_validation_matches_control_plane_rules() {
        // IPv4: the reserved first /24 (RFC 4607 §4.3) is unusable, the
        // rest of 232/8 is fine.
        assert!(
            validate_ssm_destination("232.0.0.1".parse().unwrap()).is_err()
        );
        assert!(validate_ssm_destination("232.0.1.1".parse().unwrap()).is_ok());

        // IPv6: only ff3x::/96 group IDs of 0x80000000 and above are
        // dynamically allocatable.
        assert!(
            validate_ssm_destination("ff3e::8000:1".parse().unwrap()).is_ok()
        );
        assert!(validate_ssm_destination("ff3e::1".parse().unwrap()).is_err());
        assert!(
            validate_ssm_destination("ff3e::4000:1".parse().unwrap()).is_err()
        );
        assert!(
            validate_ssm_destination("ff3e:0:1234::8000:1".parse().unwrap())
                .is_err()
        );

        // IPv6: unusable and unassigned scope nibbles are rejected even
        // with allocatable group IDs, usable scopes pass.
        for scoped in [
            "ff31::8000:1",
            "ff32::8000:1",
            "ff33::8000:1",
            "ff36::8000:1",
            "ff3d::8000:1",
            "ff3f::8000:1",
        ] {
            assert!(
                validate_ssm_destination(scoped.parse().unwrap()).is_err(),
                "{scoped} should be rejected for its scope"
            );
        }
        assert!(
            validate_ssm_destination("ff35::8000:1".parse().unwrap()).is_ok()
        );
    }
}
