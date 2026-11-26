//! Command line client.

use ripsec_client::ike;
use ripsec_client::profile::Profile;
use ripsec_client::tunnel::{Connected, Counters, Ended, Options};
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

const USAGE: &str = "\
Usage: ripsec-client <command> <profile> [options]

The profile is the strongSwan file (ripsec.conf) downloaded from the portal.

Commands:
  connect   connect and carry traffic until interrupted (needs administrator rights)
  check     do the handshake and disconnect, without touching the network settings

Options:
  --server HOST    connect to this server instead of the one in the profile
  --port PORT      server's UDP port for NAT traversal (default 4500)
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
    let mut options = Options { server: None, port: 4500, routes: Vec::new() };
    while let Some(name) = args.next() {
        let value = args.next().ok_or_else(|| format!("{name} needs a value\n\n{USAGE}"))?;
        match name.as_str() {
            "--server" => options.server = Some(value),
            "--port" => options.port = value.parse().map_err(|_| format!("invalid port {value}"))?,
            "--route" => options.routes.push(value.parse()?),
            _ => return Err(format!("unknown option {name}\n\n{USAGE}")),
        }
    }
    Ok(Arguments { connect, profile, options })
}

fn run(args: Arguments) -> Result<(), String> {
    if !args.connect {
        let connected = Connected::handshake(&args.profile, &args.options).map_err(|e| e.to_string())?;
        let routes: Vec<String> = connected.routes().iter().map(ToString::to_string).collect();
        println!(
            "handshake succeeded with post-quantum key exchange: address {}, routes {}",
            connected.address(),
            routes.join(", ")
        );
        connected.disconnect();
        return Ok(());
    }

    let stop = Arc::new(AtomicBool::new(false));
    let flag = stop.clone();
    ctrlc::set_handler(move || flag.store(true, Ordering::Relaxed)).map_err(|e| e.to_string())?;

    let mut backoff = Duration::from_secs(1);
    let mut connected_before = false;
    while !stop.load(Ordering::Relaxed) {
        let counters = Counters::default();
        match Connected::handshake(&args.profile, &args.options) {
            Ok(connected) => {
                let address = connected.address();
                let ended = connected.run(&args.options, &stop, &counters, |routes| {
                    let routes: Vec<String> = routes.iter().map(ToString::to_string).collect();
                    println!("connected: address {address}, routing {}", routes.join(", "));
                    if routes.iter().any(|r| r == "0.0.0.0/0") {
                        println!("note: IPv6 traffic is not carried and goes outside the VPN");
                    }
                })?;
                connected_before = true;
                backoff = Duration::from_secs(1);
                let received = counters.bytes_in.load(Ordering::Relaxed);
                let sent = counters.bytes_out.load(Ordering::Relaxed);
                println!("disconnected after {sent} bytes sent and {received} received");
                match ended {
                    Ended::Stopped => return Ok(()),
                    Ended::ClosedByServer => return Err("the server closed the connection".into()),
                    Ended::Lost => println!("the server stopped responding; reconnecting"),
                    Ended::Expired => println!("renewing the connection for fresh keys"),
                }
            }
            // A first attempt that fails is reported; later ones keep trying.
            Err(ike::Error::NoResponse | ike::Error::Io(_)) if connected_before => {
                println!("cannot reach the server; retrying in {}s", backoff.as_secs());
                let until = std::time::Instant::now() + backoff;
                while std::time::Instant::now() < until && !stop.load(Ordering::Relaxed) {
                    std::thread::sleep(Duration::from_millis(100));
                }
                backoff = (backoff * 2).min(Duration::from_secs(60));
            }
            Err(e) => return Err(e.to_string()),
        }
    }
    Ok(())
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
