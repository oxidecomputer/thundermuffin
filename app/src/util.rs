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
