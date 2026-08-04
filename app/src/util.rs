use anyhow::{Context, Result, anyhow, bail};
use std::convert::Infallible;
use std::ffi::{CStr, CString};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::{io, iter, ptr};

const MUFFIN: &[u8] = b"muffin ";

/// Length of the big-endian `u64` sequence-number prefix that precedes the
/// muffin payload when sequence tracking is enabled.
pub const SEQ_LEN: usize = 8;

pub fn show_speed(mut s: f64) {
    if s > 1024.0 {
        s /= 1024.0;
        if s > 1000.0 {
            s /= 1000.0;
            if s > 1000.0 {
                s /= 1000.0;
                println!("{:.3} gbps", s);
            } else {
                println!("{:.3} mbps", s);
            }
        } else {
            println!("{:.3} kbps", s);
        }
    } else {
        println!("{:.3} bps", s);
    }
}

/// Build a send buffer of `size` bytes. The first [`SEQ_LEN`] bytes are
/// reserved for the sequence-number prefix (rewritten on each send) when
/// sequence tracking is enabled. The rest of the buffer is filled with the
/// repeating `muffin` filler so wire dumps stay recognizable.
pub fn buffer(size: usize) -> Vec<u8> {
    let mut buf = vec![0u8; size];
    for i in 0..buf.len() {
        buf[i] = MUFFIN[i % MUFFIN.len()];
    }
    buf
}

/// Write the big-endian sequence-number prefix into the first [`SEQ_LEN`]
/// bytes of `buf`. Caller must ensure `buf.len() >= SEQ_LEN`.
pub fn put_seq(buf: &mut [u8], seq: u64) {
    buf[..SEQ_LEN].copy_from_slice(&seq.to_be_bytes());
}

/// Read the big-endian sequence-number prefix from the first [`SEQ_LEN`]
/// bytes of `buf`, returning `None` if the slice is too short.
pub fn get_seq(buf: &[u8]) -> Option<u64> {
    if buf.len() < SEQ_LEN {
        return None;
    }
    let mut bytes = [0u8; SEQ_LEN];
    bytes.copy_from_slice(&buf[..SEQ_LEN]);
    Some(u64::from_be_bytes(bytes))
}

/// The interface selector for pinning multicast traffic.
///
/// This is either an interface name (e.g. `net0`) or an IP address bound to the
/// interface.
///
/// The group's address family decides what the selector resolves to. An
/// IPv4 group needs the interface's IPv4 address (`IP_MULTICAST_IF` and
/// the joins take an address). An IPv6 group needs the interface index
/// (`IPV6_MULTICAST_IF` and the joins take an ifindex).
///
/// An address selector that appears on multiple interfaces (an IPv6
/// link-local address, notably) resolves to the first matching entry.
/// Prefer the name form when the address is ambiguous.
#[derive(Clone, Debug)]
pub enum InterfaceSelector {
    Name(String),
    Addr(IpAddr),
}

impl FromStr for InterfaceSelector {
    type Err = Infallible;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Ok(input
            .parse::<IpAddr>()
            .map_or_else(|_| Self::Name(input.to_string()), Self::Addr))
    }
}

impl InterfaceSelector {
    /// The interface's IPv4 address, for `IP_MULTICAST_IF` and the IPv4
    /// joins.
    ///
    /// A selector that already is an IPv4 address is returned as-is,
    /// preserving the semantics of passing an arbitrary `IP_MULTICAST_IF`
    /// value.
    ///
    /// # Errors
    ///
    /// Fails when the interface list cannot be read, or no interface
    /// matches the selector, or the matched interface has no IPv4
    /// address.
    pub fn v4_addr(&self) -> Result<Ipv4Addr> {
        match self {
            Self::Addr(IpAddr::V4(addr)) => Ok(*addr),
            Self::Addr(addr @ IpAddr::V6(_)) => {
                let ifaddrs = IfAddrs::load()?;
                let name = owner_name(&ifaddrs, *addr)?;
                v4_addr_of(&ifaddrs, &name).with_context(|| {
                    format!("selector `{addr}` resolved to interface `{name}`")
                })
            }
            Self::Name(name) => v4_addr_of(&IfAddrs::load()?, name),
        }
    }

    /// The interface's index, for `IPV6_MULTICAST_IF`, the IPv6 joins,
    /// and the bind scope of interface- and link-local groups.
    ///
    /// # Errors
    ///
    /// Fails when no interface matches the selector.
    pub fn index(&self) -> Result<u32> {
        match self {
            Self::Name(name) => ifname_to_index(name),
            Self::Addr(addr) => {
                ifname_to_index(&owner_name(&IfAddrs::load()?, *addr)?)
            }
        }
    }
}

/// Resolve an interface name to its index via [`if_nametoindex(3SOCKET)`].
///
/// [`if_nametoindex(3SOCKET)`]: https://illumos.org/man/3SOCKET/if_nametoindex
fn ifname_to_index(name: &str) -> Result<u32> {
    if name.is_empty() {
        bail!("interface name is empty");
    }
    let cname = CString::new(name).context("interface name contains NUL")?;
    // SAFETY: `cname` is a valid NUL-terminated string for the duration of
    // the call.
    let index = unsafe { libc::if_nametoindex(cname.as_ptr()) };
    if index == 0 {
        let error = io::Error::last_os_error();
        bail!("no interface named `{name}`: {error}");
    }
    Ok(index)
}

/// Owned [`getifaddrs(3SOCKET)`] list, freed on drop.
///
/// [`getifaddrs(3SOCKET)`]: https://illumos.org/man/3SOCKET/getifaddrs
struct IfAddrs {
    head: *mut libc::ifaddrs,
}

impl IfAddrs {
    fn load() -> Result<Self> {
        let mut head = ptr::null_mut();
        // SAFETY: `getifaddrs` allocates a list into `head` on success.
        // The list is freed exactly once (on drop).
        if unsafe { libc::getifaddrs(&mut head) } != 0 {
            return Err(io::Error::last_os_error()).context("getifaddrs");
        }
        Ok(Self { head })
    }

    /// Iterate the entries. Borrowed entries stay live until `self`
    /// drops.
    fn iter(&self) -> impl Iterator<Item = &libc::ifaddrs> {
        // SAFETY: the entries form a null-terminated linked list owned by
        // `self`, and `as_ref` turns exactly the null tail into `None`.
        iter::successors(unsafe { self.head.as_ref() }, |entry| unsafe {
            entry.ifa_next.as_ref()
        })
    }
}

impl Drop for IfAddrs {
    fn drop(&mut self) {
        // SAFETY: `head` came from a successful `getifaddrs` in `load`
        // and is freed only here.
        unsafe { libc::freeifaddrs(self.head) };
    }
}

fn entry_name(entry: &libc::ifaddrs) -> Option<&str> {
    // SAFETY: `ifa_name` is a NUL-terminated string owned by the list.
    unsafe { CStr::from_ptr(entry.ifa_name) }.to_str().ok()
}

/// Whether the entry belongs to interface `name` or not. On illumos, addresses
/// live on logical interfaces (`name:1`, `name:2`), so those count too.
fn entry_matches(entry: &libc::ifaddrs, name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    entry_name(entry).is_some_and(|entry_name| {
        entry_name == name
            || entry_name
                .strip_prefix(name)
                .is_some_and(|rest| rest.starts_with(':'))
    })
}

fn entry_addr(entry: &libc::ifaddrs) -> Option<IpAddr> {
    if entry.ifa_addr.is_null() {
        return None;
    }

    // SAFETY: `ifa_addr` is non-null and only reinterpreted as the
    // sockaddr type its family indicates. `getifaddrs` allocates each
    // sockaddr with the alignment that concrete type requires.
    unsafe {
        match i32::from((*entry.ifa_addr).sa_family) {
            libc::AF_INET => {
                let sin = &*(entry.ifa_addr as *const libc::sockaddr_in);
                Some(IpAddr::V4(Ipv4Addr::from(u32::from_be(
                    sin.sin_addr.s_addr,
                ))))
            }
            libc::AF_INET6 => {
                let sin6 = &*(entry.ifa_addr as *const libc::sockaddr_in6);
                Some(IpAddr::V6(Ipv6Addr::from(sin6.sin6_addr.s6_addr)))
            }
            _ => None,
        }
    }
}

/// The base name of the interface `addr` is bound to, with any illumos
/// logical-interface suffix (`:1`) stripped so it resolves with
/// `if_nametoindex`.
fn owner_name(ifaddrs: &IfAddrs, addr: IpAddr) -> Result<String> {
    ifaddrs
        .iter()
        .find(|entry| entry_addr(entry) == Some(addr))
        .and_then(entry_name)
        .and_then(|name| name.split(':').next())
        .filter(|base| !base.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| anyhow!("no interface has address `{addr}`"))
}

/// The first IPv4 address bound to interface `name`.
fn v4_addr_of(ifaddrs: &IfAddrs, name: &str) -> Result<Ipv4Addr> {
    ifaddrs
        .iter()
        .filter(|entry| entry_matches(entry, name))
        .find_map(|entry| match entry_addr(entry) {
            Some(IpAddr::V4(addr)) => Some(addr),
            _ => None,
        })
        .ok_or_else(|| anyhow!("interface `{name}` has no IPv4 address"))
}
