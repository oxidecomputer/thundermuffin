const MUFFIN: &[u8] = b"muffin ";

pub fn format_speed(mut s: f64) -> String {
    if s <= 1024.0 {
        return format!("{:.3} bps", s);
    }
    s /= 1024.0;
    if s <= 1024.0 {
        return format!("{:.3} kbps", s);
    }
    s /= 1024.0;
    if s <= 1024.0 {
        return format!("{:.3} mbps", s);
    }
    s /= 1024.0;
    format!("{:.3} gbps", s)
}

pub fn buffer(size: usize) -> Vec<u8> {
    let mut buf = vec![0u8; size];
    for i in 0..buf.len() {
        buf[i] = MUFFIN[i % MUFFIN.len()];
    }
    buf
}
