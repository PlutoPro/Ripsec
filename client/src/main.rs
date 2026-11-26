//! Command line client.

use ripsec_client::connection::{self, Event};
use ripsec_client::profile::Profile;
use ripsec_client::tunnel::{Connected, Counters, Options};
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

const USAGE: &str = "\
Usage: ripsec-client <command> <profile> [options]

The profile is the strongSwan file (ripsec.conf) downloaded from the portal.

Commands:
  connect   connect and carry traffic until interrupted (needs administrator rights)
  check     do the handshake and disconnect, without touching the network settings

Options:
  --server HOST    connect to this server instead of the one in the profile
  --port PORT      server's UDP port for NAT traversal (default: the profile's, or 4500)
  --route CIDR     send only this network through the tunnel; may be repeated";

struct Arguments {
    connect: bool,
    profile: Profile,
    options: Options,
}

fn arguments(mut args: impl Iterator<Item = String>) -> Result<Arguments, String> {
    let connect = match args.next().as_deref() {
        Some("connect") => true,
        Some("check") => false,
        _ => return Err(USAGE.into()),
    };
    let path = args.next().ok_or(USAGE)?;
    let text = std::fs::read_to_string(&path).map_err(|e| format!("{path}: {e}"))?;
    let profile = Profile::parse(&text).map_err(|e| format!("{path}: {e}"))?;
    let mut options = Options { server: None, port: None, routes: Vec::new() };
    while let Some(name) = args.next() {
        let value = args.next().ok_or_else(|| format!("{name} needs a value\n\n{USAGE}"))?;
        match name.as_str() {
            "--server" => options.server = Some(value),
            "--port" => options.port = Some(value.parse().map_err(|_| format!("invalid port {value}"))?),
            "--route" => options.routes.push(value.parse()?),
            _ => return Err(format!("unknown option {name}\n\n{USAGE}")),
        }
    }
    Ok(Arguments { connect, profile, options })
}

fn run(args: Arguments) -> Result<(), String> {
    let stop = Arc::new(AtomicBool::new(false));
    if !args.connect {
        let connected =
            Connected::handshake(&args.profile, &args.options, &stop).map_err(|e| e.to_string())?;
        let routes: Vec<String> = connected.routes().iter().map(ToString::to_string).collect();
        println!(
            "handshake succeeded with post-quantum key exchange: address {}, routes {}",
            connected.address(),
            routes.join(", ")
        );
        connected.disconnect();
        return Ok(());
    }

    let flag = stop.clone();
    ctrlc::set_handler(move || flag.store(true, Ordering::Relaxed)).map_err(|e| e.to_string())?;
    let counters = Counters::default();
    let mut on = |event: Event| match event {
        Event::Connecting => {}
        Event::Up { address, routes } => {
            let routes: Vec<String> = routes.iter().map(ToString::to_string).collect();
            println!("connected: address {address}, routing {}", routes.join(", "));
            if routes.iter().any(|r| r == "0.0.0.0/0") {
                println!("note: IPv6 traffic is not carried and goes outside the VPN");
            }
        }
        Event::Lost => println!("the server stopped responding; reconnecting"),
        Event::Renewing => println!("renewing the connection for fresh keys"),
        Event::Unreachable { retry_in } => {
            println!("cannot reach the server; retrying in {}s", retry_in.as_secs());
        }
    };
    let result = connection::run(&args.profile, &args.options, &stop, &counters, &mut on);
    let received = counters.bytes_in.load(Ordering::Relaxed);
    let sent = counters.bytes_out.load(Ordering::Relaxed);
    println!("disconnected after {sent} bytes sent and {received} received");
    result
}

fn main() -> ExitCode {
    match arguments(std::env::args().skip(1)).and_then(run) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}
