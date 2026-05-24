use crate::util::{buffer, format_speed};
use crate::{Cli, Client, Participant, Server};
use anyhow::Result;
use std::net::{IpAddr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;

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

    let ticker_bits = sum_bits.clone();
    let ticker = tokio::spawn(async move {
        let mut t = tokio::time::interval(Duration::from_secs(1));
        t.tick().await;
        for c in 0..duration {
            t.tick().await;
            let bits = ticker_bits.swap(0, Ordering::Relaxed);
            println!("[sum][{}] {}", c, format_speed(bits as f64));
        }
    });

    let mut handles = Vec::with_capacity(client.parallel);
    for id in 0..client.parallel {
        let bits = sum_bits.clone();
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
) -> Result<usize> {
    let (socket, dest) = match server {
        IpAddr::V4(addr) => {
            let s = UdpSocket::bind("0.0.0.0:0").await?;
            (s, SocketAddr::V4(SocketAddrV4::new(addr, port)))
        }
        IpAddr::V6(addr) => {
            let s = UdpSocket::bind("[::]:0").await?;
            (s, SocketAddr::V6(SocketAddrV6::new(addr, port, 0, scope)))
        }
    };

    let buf = buffer(buffer_size);

    let start = std::time::Instant::now();
    let mut interval = 0;
    let mut interval_sent = 0;
    let mut total = 0;
    let mut count = 0;
    loop {
        let n = socket.send_to(&buf, dest).await?;

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
            break;
        }
    }

    Ok(total)
}

async fn run_server(cli: &Cli, server: &Server) -> Result<()> {
    let socket = match server.listen {
        IpAddr::V4(addr) => {
            UdpSocket::bind(SocketAddrV4::new(addr, cli.port)).await?
        }
        IpAddr::V6(addr) => {
            UdpSocket::bind(SocketAddrV6::new(addr, cli.port, 0, cli.scope))
                .await?
        }
    };

    let mut buf = vec![0u8; cli.buffer_size];
    let mut interval = 0;
    let mut interval_sent = 0;
    let mut count = 0;
    let start = std::time::Instant::now();

    loop {
        let (n, _) = socket.recv_from(&mut buf).await?;
        interval_sent += n * 8;
        let t = std::time::Instant::now();
        let d = t.duration_since(start);
        let ds = d.as_secs();
        if ds > interval {
            interval = ds;
            println!("[{}] {}", count, format_speed(interval_sent as f64));
            count += 1;
            interval_sent = 0;
        }
    }
}
