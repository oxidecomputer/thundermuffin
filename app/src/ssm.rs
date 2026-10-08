//! Source-specific multicast (SSM) support, including group classification and
//! joins not covered by `socket2`.
//!
//! `socket2` exposes `Socket::join_ssm_v4` for IPv4 SSM joins via
//! `IP_ADD_SOURCE_MEMBERSHIP`, but has no IPv6 equivalent in any current
//! release. For IPv6 we drop to POSIX [`setsourcefilter(3SOCKET)`]
//! (RFC 3678), which lives in `libsocket` on illumos and `libc` on Linux.
//!
//! [`setsourcefilter(3SOCKET)`]: https://illumos.org/man/3SOCKET/setsourcefilter

use socket2::Socket;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::AsRawFd;

const IPV4_SSM_FIRST_OCTET: u8 = 232;
const IPV4_SSM_RESERVED_NULL: Ipv4Addr = Ipv4Addr::new(232, 0, 0, 0);
const IPV6_SSM_NULL_GROUP_ID: u32 = 0x4000_0000;
const IPV6_SCOPE_MASK: u16 = 0x000f;
const IPV6_SCOPE_RESERVED_ZERO: u16 = 0x0;
const IPV6_SCOPE_INTERFACE_LOCAL: u16 = 0x1;
const IPV6_SCOPE_LINK_LOCAL: u16 = 0x2;
const IPV6_PREFIX_BASED_PLEN_MASK: u16 = 0x00ff;

// Checks R, P, and T in the flags nibble (SSM wants 0, 1, 1 per RFC 7371
// §4.1.2). X and scope are masked off.
const IPV6_SSM_PREFIX: u16 = 0xff30;
const IPV6_SSM_PREFIX_MASK: u16 = 0xff70;

const fn ipv6_segments_are_ssm(segments: [u16; 8]) -> bool {
    segments[0] & IPV6_SSM_PREFIX_MASK == IPV6_SSM_PREFIX
        && segments[1] & IPV6_PREFIX_BASED_PLEN_MASK == 0
}

/// Whether `addr` is a source-specific multicast (SSM) group.
///
/// IPv4: anywhere in `232.0.0.0/8` ([RFC 4607] §1). IPv6: P and T set, R
/// clear (so `ff3x` or `ffbx`), with a zero prefix length. Reserved bits are
/// ignored ([RFC 7371] §4.1.1, §4.1.2, [RFC 3956] §3).
///
/// [RFC 3956]: https://www.rfc-editor.org/rfc/rfc3956.html
/// [RFC 4607]: https://www.rfc-editor.org/rfc/rfc4607.html
/// [RFC 7371]: https://www.rfc-editor.org/rfc/rfc7371.html
// TODO: move SSM classification and the RFC 4607 admission checks (see
// `validate_ssm_destination`) into oxnet alongside multicast address types.
// This crate, Nexus's `is_ssm_address`, and Dendrite's validation could then
// share one implementation.
pub fn is_ssm_multicast(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => v4.octets()[0] == IPV4_SSM_FIRST_OCTET,
        IpAddr::V6(v6) => ipv6_segments_are_ssm(v6.segments()),
    }
}

/// Reject the SSM null addresses `232.0.0.0` and `ff3x::4000:0`
/// ([RFC 4607] §4.3) and IPv6 scopes 0 through 2 ([RFC 4291] §2.7).
///
/// Callers must check [`is_ssm_multicast`] first.
///
/// [RFC 4291]: https://www.rfc-editor.org/rfc/rfc4291.html
/// [RFC 4607]: https://www.rfc-editor.org/rfc/rfc4607.html
pub fn validate_ssm_destination(addr: IpAddr) -> Result<(), String> {
    match addr {
        IpAddr::V4(v4) => {
            if v4 == IPV4_SSM_RESERVED_NULL {
                return Err(format!(
                    "{v4} is the reserved IPv4 SSM null address \
                     (RFC 4607 §4.3)"
                ));
            }
        }
        IpAddr::V6(v6) => {
            let segments = v6.segments();
            let scope = segments[0] & IPV6_SCOPE_MASK;
            match scope {
                IPV6_SCOPE_RESERVED_ZERO => {
                    return Err(format!(
                        "{v6} has the reserved multicast scope 0 \
                         (RFC 4291 §2.7)"
                    ));
                }
                IPV6_SCOPE_INTERFACE_LOCAL | IPV6_SCOPE_LINK_LOCAL => {
                    return Err(format!(
                        "{v6} has an interface- or link-local multicast \
                         scope ({scope:x}) that cannot be forwarded \
                         (RFC 4291 §2.7)"
                    ));
                }
                _ => {}
            }

            let within_prefix =
                segments[2..6].iter().all(|segment| *segment == 0);
            let group_id =
                (u32::from(segments[6]) << 16) | u32::from(segments[7]);

            if within_prefix && group_id == IPV6_SSM_NULL_GROUP_ID {
                return Err(format!(
                    "{v6} is the reserved IPv6 SSM null address \
                     (ff3x::4000:0, RFC 4607 §4.3)"
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

        // IPv6: ff3x::/32 and ffbx::/32 are SSM at every scope, reserved bits
        // aside. Other flag combinations and nonzero prefix lengths
        // (RFC 3306 ASM) are not.
        assert!(is_ssm_multicast("ff3e::1".parse().unwrap()));
        assert!(is_ssm_multicast("ff35::1234".parse().unwrap()));

        // RFC 4607 reserves the full /32 for possible future use of the
        // network-prefix field.
        assert!(is_ssm_multicast("ff3e:0:1234::1".parse().unwrap()));
        assert!(!is_ssm_multicast("ff3e:20:1234::1".parse().unwrap()));
        assert!(!is_ssm_multicast("ff0e::1".parse().unwrap()));
        assert!(!is_ssm_multicast("ff02::1".parse().unwrap()));
        assert!(is_ssm_multicast("ffbe::1".parse().unwrap()));
        assert!(is_ssm_multicast("ff3e:1200::1".parse().unwrap()));
        assert!(!is_ssm_multicast("ff7e:120:1234::1".parse().unwrap()));
        assert!(!is_ssm_multicast("ff1e::1".parse().unwrap()));
    }

    #[test]
    fn ssm_destination_validation() {
        assert!(
            validate_ssm_destination("232.0.0.0".parse().unwrap()).is_err()
        );
        for accepted in ["232.0.0.1", "232.0.0.255", "232.0.1.1"] {
            assert!(
                validate_ssm_destination(accepted.parse().unwrap()).is_ok(),
                "{accepted} should be accepted"
            );
        }

        for rejected in ["ff3e::4000:0", "ffbe::4000:0"] {
            assert!(
                validate_ssm_destination(rejected.parse().unwrap()).is_err(),
                "{rejected} should be rejected"
            );
        }
        for accepted in [
            "ff3e::1",
            "ff3e::4000:1",
            "ff3e::8000:1",
            "ff3e::f000:1",
            "ff3e:0:1234::4000:0",
        ] {
            assert!(
                validate_ssm_destination(accepted.parse().unwrap()).is_ok(),
                "{accepted} should be accepted"
            );
        }

        for scoped in ["ff30::8000:1", "ff31::8000:1", "ff32::8000:1"] {
            assert!(
                validate_ssm_destination(scoped.parse().unwrap()).is_err(),
                "{scoped} should be rejected for its scope"
            );
        }
        for scoped in [
            "ff33::8000:1",
            "ff34::8000:1",
            "ff35::8000:1",
            "ff36::8000:1",
            "ff38::8000:1",
            "ff3d::8000:1",
            "ff3e::8000:1",
            "ff3f::8000:1",
        ] {
            assert!(
                validate_ssm_destination(scoped.parse().unwrap()).is_ok(),
                "{scoped} should be accepted for its scope"
            );
        }
    }
}
