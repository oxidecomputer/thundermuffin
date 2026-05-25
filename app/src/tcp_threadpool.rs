use crate::util::{buffer, format_speed};
use crate::{Cli, Client, Participant, Server};
use anyhow::Result;
use mio::{Events, Interest, Poll, Token};
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

fn is_peer_closed(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::BrokenPipe
    )
}

fn cpus() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}

fn make_addr(ip: IpAddr, port: u16, scope: u32) -> SocketAddr {
    match ip {
        IpAddr::V4(a) => SocketAddr::V4(SocketAddrV4::new(a, port)),
        IpAddr::V6(a) => {
            SocketAddr::V6(SocketAddrV6::new(a, port, 0, scope))
        }
    }
}

pub(crate) fn run(cli: &Cli) -> Result<()> {
    match cli.kind {
        Participant::Client(ref client) => run_client(cli, client),
        Participant::Server(ref server) => run_server(cli, server),
    }
}

fn run_client(cli: &Cli, client: &Client) -> Result<()> {
    let n = cpus();
    let total_parallel = client.parallel;
    if total_parallel == 0 {
        return Ok(());
    }
    let per_thread = total_parallel / n;
    let remainder = total_parallel % n;

    let grand_bits = Arc::new(AtomicUsize::new(0));
    let connected = Arc::new(AtomicUsize::new(0));
    let duration = client.duration;
    let start = Instant::now();
    let addr = make_addr(client.server, cli.port, cli.scope);

    let r_bits = grand_bits.clone();
    let r_conn = connected.clone();
    let reporter = thread::spawn(move || {
        run_reporter_client(r_bits, r_conn, duration, start);
    });

    let mut handles = Vec::new();
    let mut base_id = 0;
    for thread_id in 0..n {
        let count = per_thread + if thread_id < remainder { 1 } else { 0 };
        if count == 0 {
            break;
        }
        let buffer_size = cli.buffer_size;
        let bits = grand_bits.clone();
        let conn = connected.clone();
        let stream_base = base_id;
        base_id += count;
        handles.push(thread::spawn(move || -> Result<()> {
            run_client_worker(
                stream_base,
                count,
                addr,
                buffer_size,
                duration,
                start,
                bits,
                conn,
            )
        }));
    }

    for h in handles {
        h.join().unwrap()?;
    }
    let _ = reporter.join();

    let total = grand_bits.load(Ordering::Relaxed);
    println!("------");
    println!("{}", format_speed(total as f64 / duration as f64));

    Ok(())
}

fn run_reporter_client(
    grand_bits: Arc<AtomicUsize>,
    connected: Arc<AtomicUsize>,
    duration: u64,
    start: Instant,
) {
    let mut last: usize = 0;
    for c in 0..duration {
        let target = start + Duration::from_secs(c + 1);
        let now = Instant::now();
        if target > now {
            thread::sleep(target - now);
        }
        let current = grand_bits.load(Ordering::Relaxed);
        let bits = current.wrapping_sub(last);
        last = current;
        let conn = connected.load(Ordering::Relaxed);
        println!(
            "[sum][{}] {} conn={}",
            c,
            format_speed(bits as f64),
            conn
        );
    }
}

struct Conn {
    stream: mio::net::TcpStream,
    active: bool,
}

fn run_client_worker(
    base_id: usize,
    count: usize,
    addr: SocketAddr,
    buffer_size: usize,
    duration: u64,
    start: Instant,
    grand_bits: Arc<AtomicUsize>,
    connected: Arc<AtomicUsize>,
) -> Result<()> {
    let total_duration = Duration::from_secs(duration);
    let buf = buffer(buffer_size);
    let mut poll = Poll::new()?;
    let mut events = Events::with_capacity(1024);
    let mut conns: HashMap<Token, Conn> = HashMap::with_capacity(count);

    for i in 0..count {
        let token = Token(i);
        let mut stream = mio::net::TcpStream::connect(addr)?;
        poll.registry()
            .register(&mut stream, token, Interest::WRITABLE)?;
        conns.insert(token, Conn { stream, active: false });
    }

    loop {
        let elapsed = start.elapsed();
        if elapsed >= total_duration {
            break;
        }
        let remaining = total_duration - elapsed;

        poll.poll(&mut events, Some(remaining))?;
        let mut to_drop: Vec<Token> = Vec::new();
        let mut to_reconnect: Vec<Token> = Vec::new();
        for event in &events {
            let token = event.token();

            let connect_err = {
                let conn = match conns.get_mut(&token) {
                    Some(c) => c,
                    None => continue,
                };
                if !conn.active {
                    match conn.stream.take_error() {
                        Ok(None) => {
                            let _ = conn.stream.set_nodelay(true);
                            conn.active = true;
                            connected.fetch_add(1, Ordering::Relaxed);
                            None
                        }
                        Ok(Some(e)) | Err(e) => Some(e),
                    }
                } else {
                    None
                }
            };

            if let Some(e) = connect_err {
                eprintln!(
                    "[{}] connect failed: {}",
                    base_id + token.0,
                    e
                );
                to_drop.push(token);
                continue;
            }

            let conn = conns.get_mut(&token).unwrap();
            loop {
                match conn.stream.write(&buf) {
                    Ok(0) => {
                        to_reconnect.push(token);
                        break;
                    }
                    Ok(n) => {
                        grand_bits.fetch_add(n * 8, Ordering::Relaxed);
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) if is_peer_closed(&e) => {
                        eprintln!(
                            "[{}] peer closed: {}",
                            base_id + token.0,
                            e
                        );
                        to_reconnect.push(token);
                        break;
                    }
                    Err(e) => return Err(e.into()),
                }
            }
        }

        for token in to_drop {
            if let Some(mut conn) = conns.remove(&token) {
                let _ = poll.registry().deregister(&mut conn.stream);
                if conn.active {
                    connected.fetch_sub(1, Ordering::Relaxed);
                }
            }
        }

        for token in to_reconnect {
            if let Some(mut conn) = conns.remove(&token) {
                let _ = poll.registry().deregister(&mut conn.stream);
                if conn.active {
                    connected.fetch_sub(1, Ordering::Relaxed);
                }
            }
            if start.elapsed() < total_duration {
                match mio::net::TcpStream::connect(addr) {
                    Ok(mut new_stream) => {
                        poll.registry().register(
                            &mut new_stream,
                            token,
                            Interest::WRITABLE,
                        )?;
                        conns.insert(
                            token,
                            Conn { stream: new_stream, active: false },
                        );
                    }
                    Err(e) => {
                        eprintln!(
                            "[{}] reconnect failed: {}",
                            base_id + token.0,
                            e
                        );
                    }
                }
            }
        }
    }

    let still_active = conns.values().filter(|c| c.active).count();
    if still_active > 0 {
        connected.fetch_sub(still_active, Ordering::Relaxed);
    }

    Ok(())
}

fn run_server(cli: &Cli, server: &Server) -> Result<()> {
    let n = cpus();
    let grand_bits = Arc::new(AtomicUsize::new(0));
    let connected = Arc::new(AtomicUsize::new(0));

    let r_bits = grand_bits.clone();
    let r_conn = connected.clone();
    thread::spawn(move || {
        run_reporter_server(r_bits, r_conn);
    });

    let mut handles = Vec::new();
    for _ in 0..n {
        let listen = server.listen;
        let port = cli.port;
        let scope = cli.scope;
        let backlog = cli.backlog;
        let buffer_size = cli.buffer_size;
        let bits = grand_bits.clone();
        let conn = connected.clone();
        handles.push(thread::spawn(move || -> Result<()> {
            run_server_worker(
                listen,
                port,
                scope,
                backlog,
                buffer_size,
                bits,
                conn,
            )
        }));
    }

    for h in handles {
        h.join().unwrap()?;
    }
    Ok(())
}

fn run_reporter_server(
    grand_bits: Arc<AtomicUsize>,
    connected: Arc<AtomicUsize>,
) {
    let start = Instant::now();
    let mut count: u64 = 0;
    let mut last: usize = 0;
    let mut tick: u64 = 1;
    loop {
        let target = start + Duration::from_secs(tick);
        let now = Instant::now();
        if target > now {
            thread::sleep(target - now);
        }
        tick += 1;
        let current = grand_bits.load(Ordering::Relaxed);
        let bits = current.wrapping_sub(last);
        last = current;
        let conn = connected.load(Ordering::Relaxed);
        if bits == 0 && conn == 0 {
            continue;
        }
        println!("[{}] {} conn={}", count, format_speed(bits as f64), conn);
        count += 1;
    }
}

fn make_listener(
    ip: IpAddr,
    port: u16,
    scope: u32,
    backlog: i32,
) -> Result<mio::net::TcpListener> {
    let (domain, addr) = match ip {
        IpAddr::V4(a) => (
            Domain::IPV4,
            SocketAddr::V4(SocketAddrV4::new(a, port)),
        ),
        IpAddr::V6(a) => (
            Domain::IPV6,
            SocketAddr::V6(SocketAddrV6::new(a, port, 0, scope)),
        ),
    };
    let sock = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    sock.set_reuse_address(true)?;
    sock.set_reuse_port(true)?;
    sock.set_nonblocking(true)?;
    sock.bind(&addr.into())?;
    sock.listen(backlog)?;
    let std_listener: std::net::TcpListener = sock.into();
    Ok(mio::net::TcpListener::from_std(std_listener))
}

fn run_server_worker(
    listen: IpAddr,
    port: u16,
    scope: u32,
    backlog: i32,
    buffer_size: usize,
    grand_bits: Arc<AtomicUsize>,
    connected: Arc<AtomicUsize>,
) -> Result<()> {
    let mut listener = make_listener(listen, port, scope, backlog)?;
    let mut poll = Poll::new()?;
    let mut events = Events::with_capacity(1024);

    const LISTENER: Token = Token(0);
    poll.registry()
        .register(&mut listener, LISTENER, Interest::READABLE)?;

    let mut conns: HashMap<Token, mio::net::TcpStream> = HashMap::new();
    let mut next_token: usize = 1;
    let mut buf = vec![0u8; buffer_size];

    loop {
        poll.poll(&mut events, None)?;
        let mut to_remove: Vec<Token> = Vec::new();
        for event in &events {
            match event.token() {
                LISTENER => loop {
                    match listener.accept() {
                        Ok((mut stream, _)) => {
                            let tok = Token(next_token);
                            next_token = next_token.wrapping_add(1);
                            if next_token == 0 {
                                next_token = 1;
                            }
                            let _ = stream.set_nodelay(true);
                            poll.registry().register(
                                &mut stream,
                                tok,
                                Interest::READABLE,
                            )?;
                            conns.insert(tok, stream);
                            connected.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(e)
                            if e.kind() == io::ErrorKind::WouldBlock =>
                        {
                            break;
                        }
                        Err(_) => break,
                    }
                },
                tok => {
                    if let Some(stream) = conns.get_mut(&tok) {
                        loop {
                            match stream.read(&mut buf) {
                                Ok(0) => {
                                    to_remove.push(tok);
                                    break;
                                }
                                Ok(n) => {
                                    grand_bits.fetch_add(
                                        n * 8,
                                        Ordering::Relaxed,
                                    );
                                }
                                Err(e)
                                    if e.kind() == io::ErrorKind::WouldBlock =>
                                {
                                    break;
                                }
                                Err(_) => {
                                    to_remove.push(tok);
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }
        for tok in to_remove {
            if let Some(mut stream) = conns.remove(&tok) {
                let _ = poll.registry().deregister(&mut stream);
                connected.fetch_sub(1, Ordering::Relaxed);
            }
        }
    }
}
