use crate::util::{buffer, show_speed};
use crate::{Cli, Client, Participant, Server};
use anyhow::Result;
use socket2::{Domain, Protocol, Socket, Type};
use std::mem::MaybeUninit;
use std::net::{IpAddr, SocketAddr, SocketAddrV4, SocketAddrV6};

pub(crate) fn run(cli: &Cli) -> Result<()> {
    match cli.kind {
        Participant::Client(ref client) => run_client(cli, client),
        Participant::Server(ref server) => run_server(cli, server),
    }
}

fn run_client(cli: &Cli, client: &Client) -> Result<()> {
    let (s, sa) = match client.server {
        IpAddr::V4(addr) => {
            let sa = SocketAddrV4::new(addr, cli.port);
            let s =
                Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
            (s, SocketAddr::V4(sa))
        }
        IpAddr::V6(addr) => {
            let sa = SocketAddrV6::new(addr, cli.port, 0, cli.scope);
            let s =
                Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
            (s, SocketAddr::V6(sa))
        }
    };
    let sa = sa.into();

    let buf = buffer(cli.buffer_size);

    let start = std::time::Instant::now();
    let mut interval = 0;
    let mut interval_sent = 0;
    //let mut perf = Vec::new();
    let mut total = 0;
    let mut count = 0;
    loop {
        let n = s.send_to(&buf, &sa)?;

        interval_sent += n * 8;
        let t = std::time::Instant::now();
        let d = t.duration_since(start);
        let ds = d.as_secs();
        if ds > interval {
            //perf.push(interval_sent);
            interval = ds;
            total += interval_sent;
            print!("[{}] ", count);
            count += 1;
            show_speed(interval_sent as f64);
            interval_sent = 0;
        }
        if ds >= client.duration {
            break;
        }
    }

    println!("------");
    show_speed(total as f64 / client.duration as f64);

    Ok(())
}

fn run_server(cli: &Cli, server: &Server) -> Result<()> {
    let s = match server.listen {
        IpAddr::V4(addr) => {
            let sa = SocketAddrV4::new(addr, cli.port);
            let s =
                Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
            s.bind(&sa.into())?;
            s
        }
        IpAddr::V6(addr) => {
            let sa = SocketAddrV6::new(addr, cli.port, 0, cli.scope);
            let s =
                Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
            s.bind(&sa.into())?;
            s
        }
    };

    let mut interval = 0;
    let mut interval_sent = 0;
    //let mut perf = Vec::new();
    #[allow(unused_variables)]
    let mut total = 0;
    let mut count = 0;
    let start = std::time::Instant::now();

    loop {
        let sz = cli.buffer_size;
        let mut buf = vec![MaybeUninit::<u8>::uninit(); sz];
        let (n, _) = s.recv_from(&mut buf)?;
        interval_sent += n * 8;
        let t = std::time::Instant::now();
        let d = t.duration_since(start);
        let ds = d.as_secs();
        if ds > interval {
            interval = ds;
            total += interval_sent;
            print!("[{}] ", count);
            count += 1;
            show_speed(interval_sent as f64);
            interval_sent = 0;
        }
    }
}
