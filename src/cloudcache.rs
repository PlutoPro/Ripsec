//! Client for the Cloud Cache TCP API.
//!
//! TLS 1.3 only, offering only the hybrid post-quantum group `X25519MLKEM768`, trusting only the
//! configured CA. Errors are classified by whether a command may have taken effect. Tokens,
//! keys' values and secrets never appear in error messages.

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_REPLY: usize = 8 * 1024;

#[derive(Debug, PartialEq)]
pub enum Reply {
    Ok,
    Nil,
    Value(String),
    Pong,
}

#[derive(Debug, PartialEq)]
pub enum Failure {
    /// Nothing happened. Try again later.
    Retry(String),
    /// A write may or may not have been applied. Resend until acknowledged.
    Unknown(String),
    /// The access token was refused.
    Unauthorized,
    /// Something is misconfigured, or this client sent something invalid. Retrying will not help.
    Fatal(String),
}

pub struct Token {
    pub value: String,
    pub lifetime: Duration,
}

pub type TokenSource = Box<dyn FnMut() -> Result<Token, String> + Send>;

pub struct Settings {
    /// `host:port`. The host is also the name the server certificate must carry.
    pub address: String,
    pub organization_id: String,
    pub read_timeout: Duration,
}

pub fn tls_config(ca_file: &Path) -> Result<Arc<ClientConfig>, String> {
    let error = |e: String| format!("CA certificate {}: {e}", ca_file.display());
    let mut roots = RootCertStore::empty();
    for cert in CertificateDer::pem_file_iter(ca_file).map_err(|e| error(e.to_string()))? {
        roots.add(cert.map_err(|e| error(e.to_string()))?).map_err(|e| error(e.to_string()))?;
    }
    if roots.is_empty() {
        return Err(error("no certificate found".into()));
    }
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    // The server would accept classical groups, so the guarantee has to come from us.
    provider.kx_groups = vec![rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768];
    let config = ClientConfig::builder_with_provider(provider.into())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| e.to_string())?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

struct Connection {
    stream: StreamOwned<ClientConnection, TcpStream>,
}

impl Connection {
    fn open(settings: &Settings, tls: Arc<ClientConfig>) -> io::Result<Connection> {
        let host = settings.address.rsplit_once(':').map_or(settings.address.as_str(), |(h, _)| h);
        let name = ServerName::try_from(host.trim_matches(['[', ']']).to_string())
            .map_err(|_| io::Error::other("invalid server name"))?;
        let mut last = io::Error::other("address did not resolve");
        for address in settings.address.to_socket_addrs()? {
            match TcpStream::connect_timeout(&address, CONNECT_TIMEOUT) {
                Ok(socket) => {
                    socket.set_read_timeout(Some(settings.read_timeout))?;
                    socket.set_write_timeout(Some(settings.read_timeout))?;
                    socket.set_nodelay(true)?;
                    let tls = ClientConnection::new(tls, name).map_err(io::Error::other)?;
                    let mut stream = StreamOwned::new(tls, socket);
                    // Finish the handshake now, so no command is "sent" to an unverified server.
                    while stream.conn.is_handshaking() {
                        stream.conn.complete_io(&mut stream.sock)?;
                    }
                    return Ok(Connection { stream });
                }
                Err(e) => last = e,
            }
        }
        Err(last)
    }

    /// Sends one line and reads one line.
    fn exchange(&mut self, line: &str) -> io::Result<String> {
        self.stream.write_all(format!("{line}\n").as_bytes())?;
        self.stream.flush()?;
        let mut reply = Vec::new();
        let mut chunk = [0u8; 1024];
        while !reply.contains(&b'\n') {
            let n = self.stream.read(&mut chunk)?;
            if n == 0 || reply.len() + n > MAX_REPLY {
                return Err(io::Error::other("connection closed or reply too long"));
            }
            reply.extend_from_slice(&chunk[..n]);
        }
        let end = reply.iter().position(|b| *b == b'\n').unwrap_or(reply.len());
        let text = String::from_utf8(reply[..end].to_vec()).map_err(|_| io::Error::other("not UTF-8"))?;
        Ok(text.trim_end_matches('\r').to_string())
    }
}

/// One authenticated connection, re-established as needed.
pub struct Client {
    settings: Settings,
    tls: Arc<ClientConfig>,
    tokens: TokenSource,
    connection: Option<Connection>,
    /// When to authenticate again, before the current token expires.
    renew_at: Instant,
    pub last_used: Instant,
}

enum Outcome {
    Done(Reply),
    Failed(Failure),
    /// The command was not run because the session needs a new token.
    Reauthenticate,
}

/// Interprets one reply line of the Cloud Cache protocol.
fn classify(line: &str) -> (Outcome, bool) {
    // The second value says whether the connection must be dropped.
    let fail = |f| (Outcome::Failed(f), false);
    match line {
        "OK" => (Outcome::Done(Reply::Ok), false),
        "NIL" => (Outcome::Done(Reply::Nil), false),
        "PONG" => (Outcome::Done(Reply::Pong), false),
        _ if line.starts_with("VALUE ") => (Outcome::Done(Reply::Value(line[6..].to_string())), false),
        _ if line == "BYE" || line.starts_with("BYE ") => {
            (Outcome::Failed(Failure::Unknown("server closed the connection".into())), true)
        }
        _ if line.starts_with("ERR cluster unavailable; the write may") => {
            fail(Failure::Unknown("cluster could not confirm the write".into()))
        }
        "ERR cluster unavailable" => fail(Failure::Retry("cluster unavailable".into())),
        "ERR auth unavailable" => fail(Failure::Retry("Cloud Cache cannot reach Keycloak".into())),
        _ if line.starts_with("ERR token expired") || line.starts_with("ERR not authenticated") => {
            (Outcome::Reauthenticate, false)
        }
        "ERR unauthorized" => (Outcome::Failed(Failure::Unauthorized), true),
        _ if line.starts_with("ERR ") => fail(Failure::Fatal(line.chars().take(120).collect())),
        // Anything else means we have lost track of which reply belongs to which command.
        _ => (Outcome::Failed(Failure::Unknown("unexpected reply".into())), true),
    }
}

impl Client {
    pub fn new(settings: Settings, tls: Arc<ClientConfig>, tokens: TokenSource) -> Client {
        let now = Instant::now();
        Client { settings, tls, tokens, connection: None, renew_at: now, last_used: now }
    }

    pub fn disconnect(&mut self) {
        self.connection = None;
    }

    pub fn connected(&self) -> bool {
        self.connection.is_some()
    }

    #[cfg(test)]
    fn key_exchange_group(&self) -> Option<rustls::NamedGroup> {
        self.connection.as_ref()?.stream.conn.negotiated_key_exchange_group().map(|g| g.name())
    }

    /// Connects and authenticates if needed. Any failure here means no command was sent.
    fn ensure_session(&mut self) -> Result<(), Failure> {
        if self.connection.is_some() && Instant::now() < self.renew_at {
            return Ok(());
        }
        let token = (self.tokens)().map_err(Failure::Retry)?;
        if !token.value.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(Failure::Fatal("token endpoint returned a malformed token".into()));
        }
        if self.connection.is_none() {
            let connection = Connection::open(&self.settings, self.tls.clone())
                .map_err(|e| Failure::Retry(format!("connect: {e}")))?;
            self.connection = Some(connection);
        }
        let Some(connection) = &mut self.connection else { unreachable!("just connected") };
        let reply = connection.exchange(&format!("AUTH {}", token.value));
        let failure = match reply {
            Err(e) => Failure::Retry(format!("sign in: {e}")),
            Ok(line) => {
                let mut words = line.split(' ');
                if words.next() == Some("OK") {
                    // `OK <user> <org_id>`: refuse to touch any other organization's keys.
                    if words.nth(1) == Some(self.settings.organization_id.as_str()) {
                        self.renew_at = Instant::now() + token.lifetime.mul_f32(0.8);
                        return Ok(());
                    }
                    Failure::Fatal("signed in to an unexpected organization".into())
                } else {
                    match classify(&line).0 {
                        Outcome::Failed(Failure::Unknown(why)) => Failure::Retry(why),
                        Outcome::Failed(f) => f,
                        _ => Failure::Retry("unexpected reply to AUTH".into()),
                    }
                }
            }
        };
        self.disconnect();
        Err(failure)
    }

    /// Runs one command. `Unknown` is only returned once the command may have reached the server.
    pub fn command(&mut self, line: &str) -> Result<Reply, Failure> {
        // A newline in a key or value would start a second command.
        if line.contains(['\n', '\r', '\0']) {
            return Err(Failure::Fatal("command contains a line break".into()));
        }
        for _ in 0..2 {
            self.ensure_session()?;
            let Some(connection) = &mut self.connection else { unreachable!("session ensured") };
            let reply = connection.exchange(line);
            self.last_used = Instant::now();
            let (outcome, drop_connection) = match reply {
                // Includes read timeouts. Dropping the connection keeps a late reply from being
                // read as the answer to the next command.
                Err(e) => (Outcome::Failed(Failure::Unknown(format!("connection lost: {}", e.kind()))), true),
                Ok(text) => classify(&text),
            };
            if drop_connection {
                self.disconnect();
            }
            match outcome {
                Outcome::Done(reply) => return Ok(reply),
                Outcome::Failed(f) => return Err(f),
                Outcome::Reauthenticate => self.renew_at = Instant::now(),
            }
        }
        Err(Failure::Retry("session keeps expiring".into()))
    }
}

#[cfg(test)]
mod tests;
