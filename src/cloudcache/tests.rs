//! The client against a scripted TLS server.

use super::*;
use rcgen::{CertificateParams, KeyPair};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ServerConfig, ServerConnection};
use std::io::{BufRead, BufReader};
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;

const ORG: &str = "00000000-0000-4000-8000-000000000001";

/// What the fake server does with the next line it receives.
#[derive(Clone)]
enum Step {
    Say(String),
    /// Reply, then close, like an unsolicited BYE.
    SayAndClose(String),
    /// Close without replying.
    Drop,
    /// Never reply.
    Stall,
}

fn say(text: &str) -> Step {
    Step::Say(text.to_string())
}

fn signed_in() -> Step {
    say(&format!("OK service-account-ripsec-gateway {ORG}"))
}

struct Server {
    port: u16,
    ca_file: PathBuf,
    received: Arc<Mutex<Vec<String>>>,
}

fn certificate(names: &[&str]) -> (rcgen::Certificate, KeyPair) {
    let key = KeyPair::generate().unwrap();
    let names: Vec<String> = names.iter().map(|n| n.to_string()).collect();
    (CertificateParams::new(names).unwrap().self_signed(&key).unwrap(), key)
}

fn write_ca(pem: &str) -> PathBuf {
    let path = std::env::temp_dir()
        .join(format!("ripsec-ca-{}.pem", u64::from_ne_bytes(crate::ike::crypto::random())));
    std::fs::write(&path, pem).unwrap();
    path
}

/// Serves connections, consuming the script across them.
fn server(names: &[&str], script: Vec<Step>) -> Server {
    let (cert, key) = certificate(names);
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let config = Arc::new(
        ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert.der().clone()], key)
            .unwrap(),
    );
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let received = Arc::new(Mutex::new(Vec::new()));
    let log = received.clone();
    let script = Arc::new(Mutex::new(std::collections::VecDeque::from(script)));
    thread::spawn(move || {
        for socket in listener.incoming().flatten() {
            let (config, log, script) = (config.clone(), log.clone(), script.clone());
            thread::spawn(move || {
                let tls = ServerConnection::new(config).unwrap();
                let mut reader = BufReader::new(StreamOwned::new(tls, socket));
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 {
                        return;
                    }
                    log.lock().unwrap().push(line.trim_end().to_string());
                    let step = script.lock().unwrap().pop_front();
                    let out = reader.get_mut();
                    match step {
                        Some(Step::Say(text)) => {
                            let _ = out.write_all(format!("{text}\n").as_bytes());
                        }
                        Some(Step::SayAndClose(text)) => {
                            let _ = out.write_all(format!("{text}\n").as_bytes());
                            return;
                        }
                        Some(Step::Stall) => thread::sleep(Duration::from_secs(2)),
                        Some(Step::Drop) | None => return,
                    }
                }
            });
        }
    });
    Server { port, ca_file: write_ca(&cert.pem()), received }
}

fn client(server: &Server, host: &str, ca_file: &Path) -> Client {
    let mut count = 0;
    Client::new(
        Settings {
            address: format!("{host}:{}", server.port),
            organization_id: ORG.into(),
            read_timeout: Duration::from_millis(500),
        },
        tls_config(ca_file).unwrap(),
        Box::new(move || {
            count += 1;
            Ok(Token { value: format!("token-{count}"), lifetime: Duration::from_secs(300) })
        }),
    )
}

fn connected(script: Vec<Step>) -> (Server, Client) {
    let s = server(&["localhost"], script);
    let c = client(&s, "localhost", &s.ca_file);
    (s, c)
}

#[test]
fn commands_run_over_hybrid_post_quantum_tls() {
    let (s, mut c) =
        connected(vec![signed_in(), say("OK"), say("OK"), say("VALUE v1:abc"), say("NIL"), say("PONG")]);
    assert_eq!(c.command("SETEX k 60 v1:abc"), Ok(Reply::Ok));
    assert_eq!(c.key_exchange_group(), Some(rustls::NamedGroup::X25519MLKEM768));
    assert_eq!(c.command("SET k v1:abc"), Ok(Reply::Ok));
    assert_eq!(c.command("GET k"), Ok(Reply::Value("v1:abc".into())));
    assert_eq!(c.command("DEL k"), Ok(Reply::Nil));
    assert_eq!(c.command("PING"), Ok(Reply::Pong));
    assert_eq!(s.received.lock().unwrap()[0], "AUTH token-1");
}

#[test]
fn untrusted_certificate_and_wrong_name_are_refused() {
    let s = server(&["localhost"], vec![signed_in()]);
    let other_ca = write_ca(&certificate(&["localhost"]).0.pem());
    assert!(matches!(client(&s, "localhost", &other_ca).command("PING"), Err(Failure::Retry(_))));
    // The certificate is for "localhost", not for the address.
    assert!(matches!(client(&s, "127.0.0.1", &s.ca_file).command("PING"), Err(Failure::Retry(_))));
    assert!(s.received.lock().unwrap().is_empty(), "no token may reach an unverified server");
}

#[test]
fn wrong_organization_is_refused() {
    let (s, mut c) = connected(vec![say("OK service-account-ripsec-gateway some-other-org"), say("OK")]);
    assert!(matches!(c.command("SET k v"), Err(Failure::Fatal(_))));
    assert!(!c.connected());
    assert_eq!(s.received.lock().unwrap().len(), 1, "nothing may be sent after a wrong org");
}

#[test]
fn errors_are_never_read_as_missing_or_success() {
    let (_s, mut c) = connected(vec![
        signed_in(),
        say("ERR cluster unavailable"),
        say("ERR cluster unavailable; the write may or may not have been applied"),
        say("ERR forbidden"),
        say("ERR something new"),
        say("ERR auth unavailable"),
        say("gibberish"),
    ]);
    assert!(matches!(c.command("GET k"), Err(Failure::Retry(_))));
    assert!(matches!(c.command("SET k v"), Err(Failure::Unknown(_))));
    assert!(matches!(c.command("SET k v"), Err(Failure::Fatal(_))));
    assert!(matches!(c.command("GET k"), Err(Failure::Fatal(_))));
    assert!(matches!(c.command("GET k"), Err(Failure::Retry(_))));
    assert!(matches!(c.command("GET k"), Err(Failure::Unknown(_))));
    assert!(!c.connected());
}

#[test]
fn expired_token_signs_in_again_and_resends() {
    let (s, mut c) =
        connected(vec![signed_in(), say("ERR token expired; send AUTH <token>"), signed_in(), say("OK")]);
    assert_eq!(c.command("SET k v"), Ok(Reply::Ok));
    assert_eq!(*s.received.lock().unwrap(), ["AUTH token-1", "SET k v", "AUTH token-2", "SET k v"]);
}

#[test]
fn bye_drop_and_timeout_leave_a_write_unresolved() {
    for step in [Step::SayAndClose("BYE shutting down".into()), Step::Drop, Step::Stall] {
        let (_s, mut c) = connected(vec![signed_in(), step, signed_in(), say("OK")]);
        assert!(matches!(c.command("SET k v"), Err(Failure::Unknown(_))));
        assert!(!c.connected(), "a late reply must not answer the next command");
        assert_eq!(c.command("SET k v"), Ok(Reply::Ok));
    }
}

#[test]
fn line_breaks_cannot_smuggle_commands() {
    let (s, mut c) = connected(vec![signed_in()]);
    assert!(matches!(c.command("SET k v\nDEL other"), Err(Failure::Fatal(_))));
    assert!(s.received.lock().unwrap().is_empty());
}
