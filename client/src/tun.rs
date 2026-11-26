//! The virtual network interface and the routes that lead into it.

use ripsec_proto::net::Cidr;
use std::net::Ipv4Addr;
use std::process::Command;

/// Leaves room for the outer IP, UDP and ESP headers on an ordinary 1500 byte path.
pub const MTU: usize = 1360;

pub struct Settings {
    pub address: Ipv4Addr,
    pub routes: Vec<Cidr>,
    pub dns: Vec<Ipv4Addr>,
    /// Packets to the server itself must never be routed into the tunnel.
    pub server: Ipv4Addr,
}

impl Settings {
    /// "Everything" is added as two halves, which win over the default route without
    /// replacing it.
    fn expanded_routes(&self) -> Vec<Cidr> {
        let half = |addr: [u8; 4]| Cidr::new(addr.into(), 1);
        self.routes
            .iter()
            .flat_map(|r| {
                if r.prefix == 0 {
                    [half([0, 0, 0, 0]), half([128, 0, 0, 0])].into_iter().flatten().collect()
                } else {
                    vec![*r]
                }
            })
            .collect()
    }

    /// Whether some route would capture the packets that carry the tunnel.
    fn captures_server(&self) -> bool {
        let server = u32::from(self.server);
        !self.server.is_loopback() && self.routes.iter().any(|r| r.first() <= server && server <= r.last())
    }
}

fn command(program: &str, args: &[&str]) -> Result<String, String> {
    let output =
        Command::new(program).args(args).output().map_err(|e| format!("cannot run {program}: {e}"))?;
    let text = |bytes: &[u8]| String::from_utf8_lossy(bytes).trim().to_string();
    if output.status.success() {
        Ok(text(&output.stdout))
    } else {
        let detail = [text(&output.stderr), text(&output.stdout)].join(" ");
        Err(format!("{program} {}: {}", args.join(" "), detail.trim()))
    }
}

#[cfg(target_os = "linux")]
pub use linux::Tun;
#[cfg(windows)]
pub use windows::Tun;

#[cfg(target_os = "linux")]
mod linux {
    use super::{MTU, Settings, command};
    use std::fs::{File, OpenOptions};
    use std::io::{self, Read, Write};
    use std::os::fd::AsRawFd;

    const TUNSETIFF: libc::c_ulong = 0x4004_54ca;
    const NAME: &str = "ripsec0";

    /// The interface, and with it every route into it, disappears when this is dropped.
    pub struct Tun {
        file: File,
        /// The route that keeps the server reachable, to be removed again.
        server_route: Option<String>,
    }

    impl Tun {
        pub fn open(settings: &Settings) -> Result<Tun, String> {
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .open("/dev/net/tun")
                .map_err(|e| format!("/dev/net/tun: {e} (root is required)"))?;
            // SAFETY: ifreq is plain data, and TUNSETIFF reads the name and flags from it.
            let result = unsafe {
                let mut request: libc::ifreq = std::mem::zeroed();
                for (to, from) in request.ifr_name.iter_mut().zip(NAME.bytes()) {
                    *to = from as libc::c_char;
                }
                request.ifr_ifru.ifru_flags = (libc::IFF_TUN | libc::IFF_NO_PI) as libc::c_short;
                libc::ioctl(file.as_raw_fd(), TUNSETIFF as _, &request)
            };
            if result < 0 {
                return Err(format!(
                    "cannot create {NAME}: {} (root is required)",
                    io::Error::last_os_error()
                ));
            }
            let mut tun = Tun { file, server_route: None };
            tun.configure(settings)?;
            Ok(tun)
        }

        fn configure(&mut self, settings: &Settings) -> Result<(), String> {
            let address = format!("{}/32", settings.address);
            command("ip", &["address", "add", &address, "dev", NAME])?;
            command("ip", &["link", "set", NAME, "mtu", &MTU.to_string(), "up"])?;

            if settings.captures_server() {
                // Pin the path the server is reached by now, before the tunnel takes over.
                let server = settings.server.to_string();
                let current = command("ip", &["-4", "route", "get", &server])?;
                let words: Vec<&str> = current.split_whitespace().collect();
                let after = |key| words.iter().position(|w| *w == key).and_then(|i| words.get(i + 1));
                let host = format!("{server}/32");
                let mut args = vec!["route", "add", &host];
                if let Some(via) = after("via") {
                    args.extend(["via", via]);
                }
                let device = after("dev").ok_or("cannot find the route to the server")?;
                args.extend(["dev", device]);
                // An existing host route already does the job and is not ours to remove.
                if command("ip", &args).is_ok() {
                    self.server_route = Some(host);
                }
            }
            for route in settings.expanded_routes() {
                command("ip", &["route", "add", &route.to_string(), "dev", NAME])?;
            }
            if !settings.dns.is_empty() {
                let servers: Vec<String> = settings.dns.iter().map(ToString::to_string).collect();
                let mut args = vec!["dns", NAME];
                args.extend(servers.iter().map(String::as_str));
                let everything = settings.routes.iter().any(|r| r.prefix == 0);
                let result = command("resolvectl", &args).and_then(|_| {
                    if everything {
                        command("resolvectl", &["domain", NAME, "~."])
                    } else {
                        Ok(String::new())
                    }
                });
                if let Err(e) = result {
                    eprintln!("warning: DNS was not changed ({e})");
                }
            }
            Ok(())
        }

        /// Returns `None` when nothing arrived for a moment.
        pub fn recv(&self, buffer: &mut [u8]) -> io::Result<Option<usize>> {
            let mut poll = libc::pollfd { fd: self.file.as_raw_fd(), events: libc::POLLIN, revents: 0 };
            // SAFETY: one valid pollfd, and its count.
            match unsafe { libc::poll(&mut poll, 1, 200) } {
                0 => Ok(None),
                n if n < 0 => {
                    let error = io::Error::last_os_error();
                    if error.kind() == io::ErrorKind::Interrupted { Ok(None) } else { Err(error) }
                }
                _ => (&self.file).read(buffer).map(Some),
            }
        }

        pub fn send(&self, packet: &[u8]) -> io::Result<()> {
            (&self.file).write(packet).map(|_| ())
        }

        /// `recv` already returns regularly, so there is nothing to interrupt.
        pub fn stop(&self) {}
    }

    impl Drop for Tun {
        fn drop(&mut self) {
            if let Some(route) = &self.server_route
                && let Err(e) = command("ip", &["route", "del", route])
            {
                eprintln!("warning: {e}");
            }
        }
    }
}

#[cfg(windows)]
mod windows {
    use super::{MTU, Settings, command};
    use std::io;
    use std::sync::Arc;

    const NAME: &str = "Ripsec";

    pub struct Tun {
        session: Arc<wintun::Session>,
        server_route: Option<Vec<String>>,
        _adapter: Arc<wintun::Adapter>,
    }

    /// Windows tools by full path, since this process runs elevated.
    fn system(relative: &str) -> String {
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
        format!(r"{root}\System32\{relative}")
    }

    fn netsh(args: &[&str]) -> Result<String, String> {
        command(&system("netsh.exe"), args)
    }

    impl Tun {
        pub fn open(settings: &Settings) -> Result<Tun, String> {
            // Only ever load the driver library from next to this program.
            let dll = std::env::current_exe().map_err(|e| e.to_string())?.with_file_name("wintun.dll");
            if !dll.is_file() {
                return Err(format!("{} is missing. Download it from https://www.wintun.net", dll.display()));
            }
            // SAFETY: loading a library runs its initialisers; this is the one the user installed.
            let library = unsafe { wintun::load_from_path(&dll) }.map_err(|e| e.to_string())?;
            let admin = "(run from an administrator prompt)";
            let adapter = wintun::Adapter::create(&library, NAME, NAME, None)
                .map_err(|e| format!("cannot create the adapter: {e} {admin}"))?;
            let session = adapter
                .start_session(wintun::MAX_RING_CAPACITY)
                .map_err(|e| format!("cannot start the adapter: {e}"))?;
            let mut tun = Tun { session: Arc::new(session), server_route: None, _adapter: adapter };
            tun.configure(settings)?;
            Ok(tun)
        }

        fn configure(&mut self, settings: &Settings) -> Result<(), String> {
            let name = format!("name={NAME}");
            let address = settings.address.to_string();
            netsh(&["interface", "ipv4", "set", "address", &name, "static", &address, "255.255.255.255"])?;
            let mtu = format!("mtu={MTU}");
            netsh(&["interface", "ipv4", "set", "subinterface", NAME, &mtu, "store=active"])?;

            if settings.captures_server() {
                let script = format!(
                    "$r = Find-NetRoute -RemoteIPAddress {} | Select-Object -Last 1; \
                     \"$($r.InterfaceIndex) $($r.NextHop)\"",
                    settings.server
                );
                let found = command(
                    &system(r"WindowsPowerShell\v1.0\powershell.exe"),
                    &["-NoProfile", "-NonInteractive", "-Command", &script],
                )?;
                let (interface, next_hop) =
                    found.split_once(' ').ok_or("cannot find the route to the server")?;
                let route = vec![
                    format!("prefix={}/32", settings.server),
                    format!("interface={}", interface.trim()),
                    format!("nexthop={}", next_hop.trim()),
                ];
                let mut args = vec!["interface", "ipv4", "add", "route"];
                args.extend(route.iter().map(String::as_str));
                args.push("store=active");
                if netsh(&args).is_ok() {
                    self.server_route = Some(route);
                }
            }
            for route in settings.expanded_routes() {
                let prefix = format!("prefix={route}");
                let interface = format!("interface={NAME}");
                netsh(&[
                    "interface",
                    "ipv4",
                    "add",
                    "route",
                    &prefix,
                    &interface,
                    "metric=1",
                    "store=active",
                ])?;
            }
            if let Some(dns) = settings.dns.first() {
                let address = format!("address={dns}");
                if let Err(e) = netsh(&[
                    "interface",
                    "ipv4",
                    "set",
                    "dnsservers",
                    &name,
                    "static",
                    &address,
                    "primary",
                    "validate=no",
                ]) {
                    eprintln!("warning: DNS was not changed ({e})");
                }
            }
            Ok(())
        }

        /// Blocks until a packet arrives or [`Tun::stop`] is called.
        pub fn recv(&self, buffer: &mut [u8]) -> io::Result<Option<usize>> {
            match self.session.receive_blocking() {
                Ok(packet) => {
                    let bytes = packet.bytes();
                    let Some(target) = buffer.get_mut(..bytes.len()) else { return Ok(None) };
                    target.copy_from_slice(bytes);
                    Ok(Some(bytes.len()))
                }
                Err(e) => Err(io::Error::other(e.to_string())),
            }
        }

        pub fn send(&self, packet: &[u8]) -> io::Result<()> {
            let length = u16::try_from(packet.len()).map_err(io::Error::other)?;
            let mut out =
                self.session.allocate_send_packet(length).map_err(|e| io::Error::other(e.to_string()))?;
            out.bytes_mut().copy_from_slice(packet);
            self.session.send_packet(out);
            Ok(())
        }

        /// Unblocks `recv`.
        pub fn stop(&self) {
            let _ = self.session.shutdown();
        }
    }

    impl Drop for Tun {
        fn drop(&mut self) {
            // Routes into the adapter go with it; the one to the server does not.
            if let Some(route) = &self.server_route {
                let mut args = vec!["interface", "ipv4", "delete", "route"];
                args.extend(route.iter().map(String::as_str));
                if let Err(e) = netsh(&args) {
                    eprintln!("warning: {e}");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings(routes: &[&str], server: [u8; 4]) -> Settings {
        Settings {
            address: Ipv4Addr::new(10, 99, 0, 2),
            routes: routes.iter().map(|r| r.parse().unwrap()).collect(),
            dns: vec![],
            server: server.into(),
        }
    }

    #[test]
    fn full_tunnel_keeps_the_server_outside() {
        let s = settings(&["0.0.0.0/0"], [203, 0, 113, 5]);
        let routes: Vec<String> = s.expanded_routes().iter().map(Cidr::to_string).collect();
        assert_eq!(routes, ["0.0.0.0/1", "128.0.0.0/1"]);
        assert!(s.captures_server());
        assert!(!settings(&["10.0.0.0/8"], [203, 0, 113, 5]).captures_server());
        assert!(!settings(&["0.0.0.0/0"], [127, 0, 0, 1]).captures_server());
    }
}
