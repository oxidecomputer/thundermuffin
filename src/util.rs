const MUFFIN: &[u8] = b"muffin ";

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

pub fn buffer(size: usize) -> Vec<u8> {
    let mut buf = vec![0u8; size];
    for i in 0..buf.len() {
        buf[i] = MUFFIN[i % MUFFIN.len()];
    }
    buf
}
