use crate::util::{buffer, format_speed};
use crate::{Cli, Client, Participant, Server};
use anyhow::Result;
use std::io;
use std::net::{IpAddr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream};

fn is_peer_closed(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::BrokenPipe
    )
}

struct ConnGuard(Arc<AtomicUsize>);
impl Drop for ConnGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

pub(crate) fn run(cli: &Cli) -> Result<()> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(async {
        match cli.kind {
            Participant::Client(ref client) => run_client(cli, client).await,
            Participant::Server(ref server) => run_server(cli, server).await,
        }
    })
}

async fn run_client(cli: &Cli, client: &Client) -> Result<()> {
    let server = client.server;
    let port = cli.port;
    let scope = cli.scope;
    let buffer_size = cli.buffer_size;
    let duration = client.duration;

    let show_stream_rates = client.parallel <= 8;
    let sum_bits = Arc::new(AtomicUsize::new(0));
    let connected = Arc::new(AtomicUsize::new(0));

    let ticker_bits = sum_bits.clone();
    let ticker_conn = connected.clone();
    let ticker = tokio::spawn(async move {
        let mut t = tokio::time::interval(Duration::from_secs(1));
        t.tick().await;
        for c in 0..duration {
            t.tick().await;
            let bits = ticker_bits.swap(0, Ordering::Relaxed);
            let conn = ticker_conn.load(Ordering::Relaxed);
            println!(
                "[sum][{}] {} conn={}",
                c,
                format_speed(bits as f64),
                conn
            );
        }
    });

    let mut handles = Vec::with_capacity(client.parallel);
    for id in 0..client.parallel {
        let bits = sum_bits.clone();
        let conn = connected.clone();
        handles.push(tokio::spawn(async move {
            run_one_client(
                id,
                server,
                port,
                scope,
                buffer_size,
                duration,
                show_stream_rates,
                bits,
                conn,
            )
            .await
        }));
    }

    let mut total = 0;
    for h in handles {
        total += h.await??;
    }
    let _ = ticker.await;

    println!("------");
    println!("{}", format_speed(total as f64 / duration as f64));

    Ok(())
}

async fn run_one_client(
    id: usize,
    server: IpAddr,
    port: u16,
    scope: u32,
    buffer_size: usize,
    duration: u64,
    show_stream_rates: bool,
    sum_bits: Arc<AtomicUsize>,
    connected: Arc<AtomicUsize>,
) -> Result<usize> {
    let addr: SocketAddr = match server {
        IpAddr::V4(a) => SocketAddr::V4(SocketAddrV4::new(a, port)),
        IpAddr::V6(a) => SocketAddr::V6(SocketAddrV6::new(a, port, 0, scope)),
    };

    let buf = buffer(buffer_size);
    let total_duration = Duration::from_secs(duration);

    let start = std::time::Instant::now();
    let mut interval = 0;
    let mut interval_sent = 0;
    let mut total = 0;
    let mut count = 0;

    'outer: loop {
        let elapsed = start.elapsed();
        if elapsed >= total_duration {
            break;
        }
        let remaining = total_duration - elapsed;

        let mut stream = match tokio::time::timeout(
            remaining,
            TcpStream::connect(addr),
        )
        .await
        {
            Err(_) => break,
            Ok(Err(e)) => {
                eprintln!("[{}] connect failed: {}", id, e);
                break;
            }
            Ok(Ok(s)) => s,
        };

        connected.fetch_add(1, Ordering::Relaxed);
        let _guard = ConnGuard(connected.clone());

        let mut retry = false;
        loop {
            let n = match stream.write(&buf).await {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if is_peer_closed(&e) => {
                    eprintln!("[{}] peer closed: {}", id, e);
                    retry = true;
                    break;
                }
                Err(e) => return Err(e.into()),
            };

            let bits = n * 8;
            interval_sent += bits;
            sum_bits.fetch_add(bits, Ordering::Relaxed);
            let t = std::time::Instant::now();
            let d = t.duration_since(start);
            let ds = d.as_secs();
            if ds > interval {
                interval = ds;
                total += interval_sent;
                if show_stream_rates {
                    println!(
                        "[{}][{}] {}",
                        id,
                        count,
                        format_speed(interval_sent as f64)
                    );
                }
                count += 1;
                interval_sent = 0;
            }
            if ds >= duration {
                break 'outer;
            }
        }

        if !retry {
            break;
        }
    }

    Ok(total)
}

async fn run_server(cli: &Cli, server: &Server) -> Result<()> {
    let listener = match server.listen {
        IpAddr::V4(addr) => {
            let s = TcpSocket::new_v4()?;
            s.bind(SocketAddr::V4(SocketAddrV4::new(addr, cli.port)))?;
            s.listen(cli.backlog as u32)?
        }
        IpAddr::V6(addr) => {
            let s = TcpSocket::new_v6()?;
            s.bind(SocketAddr::V6(SocketAddrV6::new(
                addr, cli.port, 0, cli.scope,
            )))?;
            s.listen(cli.backlog as u32)?
        }
    };

    let sum_bits = Arc::new(AtomicUsize::new(0));
    let connected = Arc::new(AtomicUsize::new(0));

    let reporter_bits = sum_bits.clone();
    let reporter_conn = connected.clone();
    tokio::spawn(async move {
        let mut t = tokio::time::interval(Duration::from_secs(1));
        t.tick().await;
        let mut count = 0;
        loop {
            t.tick().await;
            let bits = reporter_bits.swap(0, Ordering::Relaxed);
            let conn = reporter_conn.load(Ordering::Relaxed);
            if bits == 0 && conn == 0 {
                continue;
            }
            println!(
                "[{}] {} conn={}",
                count,
                format_speed(bits as f64),
                conn
            );
            count += 1;
        }
    });

    loop {
        let (mut stream, _sa) = listener.accept().await?;
        stream.set_nodelay(true)?;
        let sz = cli.buffer_size;
        let bits = sum_bits.clone();
        let conn = connected.clone();
        conn.fetch_add(1, Ordering::Relaxed);
        tokio::spawn(async move {
            let _conn_guard = ConnGuard(conn);
            let mut buf = vec![0u8; sz];
            loop {
                let r = match stream.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(r) => r,
                    Err(_) => break,
                };
                bits.fetch_add(r * 8, Ordering::Relaxed);
            }
        });
    }
}
