use anyhow::{Context, Result, bail};
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
                let name = ifaddrs.owner_name(*addr)?;
                ifaddrs.v4_addr(&name).with_context(|| {
                    format!("selector `{addr}` resolved to interface `{name}`")
                })
            }
            Self::Name(name) => IfAddrs::load()?.v4_addr(name),
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
                ifname_to_index(&IfAddrs::load()?.owner_name(*addr)?)
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
    let idx = unsafe { libc::if_nametoindex(cname.as_ptr()) };
    if idx == 0 {
        let error = io::Error::last_os_error();
        bail!("no interface named `{name}`: {error}");
    }
    Ok(idx)
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
    fn iter(&self) -> impl Iterator<Item = IfAddr<'_>> {
        // SAFETY: the entries form a null-terminated linked list owned by
        // `self`, and `as_ref` turns exactly the null tail into `None`.
        iter::successors(unsafe { self.head.as_ref() }, |entry| unsafe {
            entry.ifa_next.as_ref()
        })
        .map(IfAddr)
    }

    /// The base name of the interface `addr` is bound to, with any illumos
    /// logical-interface suffix (`:1`) stripped so `if_nametoindex` can
    /// resolve it.
    fn owner_name(&self, addr: IpAddr) -> Result<String> {
        self.iter()
            .find(|entry| entry.addr() == Some(addr))
            .and_then(IfAddr::name)
            .map(base_ifname)
            .filter(|base| !base.is_empty())
            .map(str::to_owned)
            .with_context(|| format!("no interface has address `{addr}`"))
    }

    /// The first IPv4 address bound to interface `name`.
    fn v4_addr(&self, name: &str) -> Result<Ipv4Addr> {
        self.iter()
            .filter(|entry| entry.matches(name))
            .find_map(|entry| match entry.addr() {
                Some(IpAddr::V4(addr)) => Some(addr),
                _ => None,
            })
            .with_context(|| format!("interface `{name}` has no IPv4 address"))
    }
}

impl Drop for IfAddrs {
    fn drop(&mut self) {
        // SAFETY: `head` came from a successful `getifaddrs` in `load`
        // and is freed only here.
        unsafe { libc::freeifaddrs(self.head) };
    }
}

/// Borrowed entry of an [`IfAddrs`] list, valid while the list lives.
#[derive(Clone, Copy)]
struct IfAddr<'a>(&'a libc::ifaddrs);

impl<'a> IfAddr<'a> {
    fn name(self) -> Option<&'a str> {
        // SAFETY: `ifa_name` is a NUL-terminated string owned by the list.
        unsafe { CStr::from_ptr(self.0.ifa_name) }.to_str().ok()
    }

    fn matches(self, name: &str) -> bool {
        self.name()
            .is_some_and(|entry_name| ifname_matches(entry_name, name))
    }

    fn addr(self) -> Option<IpAddr> {
        let sockaddr = self.0.ifa_addr;
        if sockaddr.is_null() {
            return None;
        }

        // SAFETY: `ifa_addr` is non-null and only reinterpreted as the
        // sockaddr type its family indicates. `getifaddrs` allocates each
        // sockaddr with the alignment that concrete type requires.
        unsafe {
            match i32::from((*sockaddr).sa_family) {
                libc::AF_INET => {
                    let sin = &*(sockaddr as *const libc::sockaddr_in);
                    Some(IpAddr::V4(Ipv4Addr::from(u32::from_be(
                        sin.sin_addr.s_addr,
                    ))))
                }
                libc::AF_INET6 => {
                    let sin6 = &*(sockaddr as *const libc::sockaddr_in6);
                    Some(IpAddr::V6(Ipv6Addr::from(sin6.sin6_addr.s6_addr)))
                }
                _ => None,
            }
        }
    }
}

/// The interface an illumos logical interface name belongs to, e.g. `net0`
/// for `net0:1`.
fn base_ifname(name: &str) -> &str {
    name.split_once(':').map_or(name, |(base, _)| base)
}

/// Whether `entry_name` belongs to interface `name`. On illumos, addresses
/// live on logical interfaces (`name:1`, `name:2`), which count as matches
/// too.
fn ifname_matches(entry_name: &str, name: &str) -> bool {
    !name.is_empty()
        && (entry_name == name
            || entry_name
                .strip_prefix(name)
                .is_some_and(|rest| rest.starts_with(':')))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_ifname_strips_logical_suffix() {
        assert_eq!(base_ifname("net0"), "net0");
        assert_eq!(base_ifname("net0:1"), "net0");
        assert_eq!(base_ifname(":1"), "");
    }

    #[test]
    fn ifname_matches_base_and_logical_interfaces() {
        assert!(ifname_matches("net0", "net0"));
        assert!(ifname_matches("net0:1", "net0"));
        assert!(ifname_matches("net0:1", "net0:1"));
        assert!(!ifname_matches("net01", "net0"));
        assert!(!ifname_matches("net0", "net0:1"));
        assert!(!ifname_matches("net0", ""));
    }

    #[test]
    fn ifaddrs_resolves_loopback() {
        let ifaddrs = IfAddrs::load().unwrap();
        let name = ifaddrs.owner_name(IpAddr::V4(Ipv4Addr::LOCALHOST)).unwrap();

        assert!(!name.contains(':'), "`{name}` kept a logical suffix");
        assert!(ifname_to_index(&name).is_ok());
        assert!(ifaddrs.v4_addr(&name).unwrap().is_loopback());

        assert!(ifaddrs.owner_name("192.0.2.255".parse().unwrap()).is_err());
        assert!(ifaddrs.v4_addr("thundermuffin0").is_err());
    }
}
