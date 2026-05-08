//! Source-specific multicast (SSM) functionality that isn't covered by `socket2`.
//!
//! `socket2` exposes `Socket::join_ssm_v4` for IPv4 SSM joins via
//! `IP_ADD_SOURCE_MEMBERSHIP`, but has no IPv6 equivalent in any current
//! release. For IPv6 we drop to POSIX [`setsourcefilter(3SOCKET)`]
//! (RFC 3678), which lives in `libsocket` on illumos and `libc` on Linux.
//!
//! [`setsourcefilter(3SOCKET)`]: https://illumos.org/man/3SOCKET/setsourcefilter

use socket2::Socket;
use std::net::Ipv6Addr;
use std::os::fd::AsRawFd;

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
    // other fields (port, flowinfo, scope, platform-specific extras) stay
    // zeroed-out.
    let make_in6 = |addr: &Ipv6Addr| -> libc::sockaddr_in6 {
        // All-zero is a valid bit pattern for `sockaddr_in6`.
        let mut sa: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
        sa.sin6_family = libc::AF_INET6 as libc::sa_family_t;
        sa.sin6_addr.s6_addr = addr.octets();
        sa
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
    // call. `numsrc = sources.len()` matches the `slist` length (each entry
    // is one `sockaddr_in6` written into a `sockaddr_storage`).
    let ret = unsafe {
        setsourcefilter(
            socket.as_raw_fd(),
            ifindex,
            &group_sa as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
            MCAST_INCLUDE,
            sources.len() as u32,
            slist.as_ptr(),
        )
    };
    if ret < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}
