use ispf::WireSize;
use libc::{self, c_int, c_void, socklen_t, IPPROTO_IPV6};
use serde::{Deserialize, Serialize};
use socket2::Socket;
use std::os::fd::AsRawFd;

const IPV6_DSTOPTS: c_int = 0xf;

#[derive(Debug, Serialize, Deserialize)]
pub struct DstOpts {
    pub next: u8,
    #[serde(with = "ispf::vec_lv8b")]
    pub options: Vec<Opt>,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Opt {
    Pad0(u8),
    Str(StrOpt),
}

impl WireSize for Opt {
    fn wire_size(&self) -> usize {
        match self {
            Opt::Pad0(_) => 1,
            Opt::Str(o) => o.wire_size(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StrOpt {
    pub typ: u8,
    #[serde(with = "ispf::str_lv8")]
    pub content: String,
}

impl WireSize for StrOpt {
    fn wire_size(&self) -> usize {
        2 + self.content.len()
    }
}

impl StrOpt {
    pub fn pad(n: u8) -> Self {
        assert!(n >= 2);
        Self {
            typ: 0x1,
            content: "\0".repeat(usize::from(n) - 2),
        }
    }
    pub fn text(s: &str) -> Self {
        Self {
            typ: 0x1e,
            content: String::from(s),
        }
    }
}

pub fn set_dstopt(s: &Socket, opts: &DstOpts) {
    let mut data = ispf::to_bytes_be(opts).unwrap();
    data[1] += 2;
    //println!("blen {}", data[1]);
    data[1] = if data[1] == 8 { 0 } else { (data[1] / 8) - 1 };
    //println!("plen {}", data[1]);
    let sk = s.as_raw_fd();
    unsafe {
        if libc::setsockopt(
            sk,
            IPPROTO_IPV6,
            IPV6_DSTOPTS,
            data.as_ptr() as *const c_void,
            data.len() as socklen_t,
        ) != 0
        {
            panic!(
                "failed to set destination options sockopt {:?}",
                std::io::Error::last_os_error()
            );
        }
    }
}
