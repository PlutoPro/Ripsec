//! UDP sockets and the event loop that drives the IKE engine. The loop is Linux only,
//! because ESP is handled by its kernel.

use crate::ike::SessionInfo;
use tokio::sync::oneshot;

/// Requests from the web portal to the IKE engine.
pub enum Command {
    Sessions(oneshot::Sender<Vec<SessionInfo>>),
    Disconnect(u64),
}

#[cfg(target_os = "linux")]
pub use linux::run;

#[cfg(target_os = "linux")]
mod linux {
    use super::Command;
    use crate::dataplane::{Dataplane, UDP_ENCAP_ESPINUDP};
    use crate::ike::{Engine, Outgoing};
    use std::io;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::os::fd::AsRawFd;
    use std::time::{Duration, Instant};
    use tokio::net::UdpSocket;
    use tokio::signal::unix::{SignalKind, signal};
    use tokio::sync::mpsc;

    /// Marks IKE messages on port 4500, distinguishing them from ESP packets.
    const NON_ESP: [u8; 4] = [0; 4];

    /// Lets the kernel pick ESP-in-UDP packets off the socket and decrypt them.
    fn enable_udp_encap(socket: &UdpSocket) -> io::Result<()> {
        let value: libc::c_int = UDP_ENCAP_ESPINUDP.into();
        // SAFETY: `value` outlives the call and the length matches its type.
        let rc = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::IPPROTO_UDP,
                libc::UDP_ENCAP,
                std::ptr::from_ref(&value).cast(),
                size_of_val(&value) as libc::socklen_t,
            )
        };
        if rc == 0 { Ok(()) } else { Err(io::Error::last_os_error()) }
    }

    struct Sockets {
        ike: UdpSocket,
        natt: UdpSocket,
    }

    impl Sockets {
        async fn send(&self, messages: Vec<Outgoing>) {
            for m in messages {
                let result = if m.local_port == 4500 {
                    self.natt.send_to(&[&NON_ESP[..], &m.data].concat(), m.to).await
                } else {
                    self.ike.send_to(&m.data, m.to).await
                };
                if let Err(e) = result {
                    eprintln!("{}: send failed: {e}", m.to);
                }
            }
        }
    }

    pub async fn run<D: Dataplane>(
        mut engine: Engine<D>,
        ip: Ipv4Addr,
        mut commands: mpsc::Receiver<Command>,
    ) -> io::Result<()> {
        let sockets =
            Sockets { ike: UdpSocket::bind((ip, 500)).await?, natt: UdpSocket::bind((ip, 4500)).await? };
        enable_udp_encap(&sockets.natt)?;
        eprintln!("IKEv2 listening on {ip} ports 500 and 4500");

        let mut terminate = signal(SignalKind::terminate())?;
        let mut interrupt = signal(SignalKind::interrupt())?;
        let mut timer = tokio::time::interval(Duration::from_secs(1));
        let mut small = vec![0u8; 8192];
        let mut natt = vec![0u8; 8192];
        loop {
            let out = tokio::select! {
                received = sockets.ike.recv_from(&mut small) => match received {
                    Ok((n, SocketAddr::V4(from))) => engine.handle(&small[..n], from, 500),
                    Ok(_) => Vec::new(),
                    Err(e) => { eprintln!("receive failed: {e}"); Vec::new() }
                },
                received = sockets.natt.recv_from(&mut natt) => match received {
                    // One byte datagrams are NAT keepalives.
                    Ok((n, SocketAddr::V4(from))) if n > 4 && natt[..4] == NON_ESP => {
                        engine.handle(&natt[4..n], from, 4500)
                    }
                    Ok(_) => Vec::new(),
                    Err(e) => { eprintln!("receive failed: {e}"); Vec::new() }
                },
                _ = timer.tick() => engine.tick(Instant::now()),
                Some(command) = commands.recv() => match command {
                    Command::Sessions(reply) => {
                        let _ = reply.send(engine.sessions());
                        Vec::new()
                    }
                    Command::Disconnect(id) => engine.disconnect(id),
                },
                _ = terminate.recv() => break,
                _ = interrupt.recv() => break,
            };
            sockets.send(out).await;
        }
        eprintln!("shutting down: removing SAs");
        sockets.send(engine.shutdown()).await;
        Ok(())
    }
}
