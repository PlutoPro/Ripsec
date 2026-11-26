//! Server configuration, read from a TOML file.

use crate::net::Cidr;
use serde::Deserialize;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::path::PathBuf;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Raw {
    /// Local IPv4 address for IKE, or "auto" to use the default route's address.
    listen: String,
    /// Hostname or address clients connect to. Used in generated profiles.
    public_address: String,
    server_id: String,
    pool: String,
    #[serde(default)]
    dns: Vec<Ipv4Addr>,
    #[serde(default = "everything")]
    local_subnets: Vec<String>,
    #[serde(default = "yes")]
    require_post_quantum: bool,
    #[serde(default = "data_dir")]
    data_dir: PathBuf,
    /// Encrypts stored secrets. Default: `<data_dir>/master.key`, created on first start.
    master_key_file: Option<PathBuf>,
    web: Web,
    oidc: Oidc,
    cloud_cache: Option<RawCloudCache>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCloudCache {
    address: String,
    ca_file: PathBuf,
    token_url: String,
    token_ca_file: Option<PathBuf>,
    #[serde(default = "gateway_client")]
    client_id: String,
    client_secret_file: Option<PathBuf>,
    organization_id: String,
    #[serde(default = "refresh_seconds")]
    refresh_seconds: u64,
}

fn gateway_client() -> String {
    "ripsec-gateway".into()
}
fn refresh_seconds() -> u64 {
    60
}

/// Settings for keeping device secrets in Cloud Cache.
pub struct CloudCache {
    pub address: String,
    pub ca_file: PathBuf,
    pub token_url: String,
    pub token_ca_file: Option<PathBuf>,
    pub client_id: String,
    pub client_secret: String,
    pub organization_id: String,
    pub refresh_seconds: u64,
}

const CLOUD_CACHE_SECRET_ENV: &str = "RIPSEC_CLOUD_CACHE_CLIENT_SECRET";

/// The client secret comes from the environment or a file, never from the config itself.
fn cloud_cache(raw: RawCloudCache) -> Result<CloudCache, String> {
    if !secure_url(&raw.token_url) {
        return Err("cloud_cache.token_url must use https".into());
    }
    if raw.address.rsplit_once(':').and_then(|(_, port)| port.parse::<u16>().ok()).is_none() {
        return Err("cloud_cache.address must be host:port".into());
    }
    let client_secret = match (std::env::var(CLOUD_CACHE_SECRET_ENV), &raw.client_secret_file) {
        (Ok(secret), _) => secret,
        (Err(_), Some(path)) => {
            std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?
        }
        (Err(_), None) => {
            return Err(format!("set {CLOUD_CACHE_SECRET_ENV} or cloud_cache.client_secret_file"));
        }
    };
    Ok(CloudCache {
        address: raw.address,
        ca_file: raw.ca_file,
        token_url: raw.token_url,
        token_ca_file: raw.token_ca_file,
        client_id: raw.client_id,
        client_secret: client_secret.trim().to_string(),
        organization_id: raw.organization_id,
        refresh_seconds: raw.refresh_seconds,
    })
}

fn everything() -> Vec<String> {
    vec!["0.0.0.0/0".into()]
}
fn yes() -> bool {
    true
}
fn data_dir() -> PathBuf {
    "/var/lib/ripsec".into()
}

#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Web {
    pub listen: SocketAddr,
    /// URL users type into the browser, without a trailing slash.
    pub public_url: String,
    #[serde(default)]
    pub allow_insecure_http: bool,
}

#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Oidc {
    pub issuer: String,
    /// Where the server fetches discovery from, if different from the issuer.
    pub discovery_url: Option<String>,
    pub client_id: String,
    /// May instead be given in the RIPSEC_OIDC_CLIENT_SECRET environment variable.
    pub client_secret: Option<String>,
    #[serde(default = "scopes")]
    pub scopes: String,
    /// Dot separated path to the claim listing the user's roles or groups.
    #[serde(default = "roles_claim")]
    pub roles_claim: String,
    #[serde(default = "admin_role")]
    pub admin_role: String,
    /// If set, only holders of this role (or the admin role) may use the portal.
    pub user_role: Option<String>,
    #[serde(default = "ttl")]
    pub credential_ttl_days: u64,
    #[serde(default = "max_devices")]
    pub max_devices_per_user: usize,
}

fn scopes() -> String {
    "openid profile email".into()
}
fn roles_claim() -> String {
    "roles".into()
}
fn admin_role() -> String {
    "vpn-admin".into()
}
fn ttl() -> u64 {
    7
}
fn max_devices() -> usize {
    5
}

/// Settings the IKE engine needs.
#[derive(Clone)]
pub struct Vpn {
    pub local_ip: Ipv4Addr,
    pub public_address: String,
    pub server_id: String,
    pub pool: Cidr,
    pub dns: Vec<Ipv4Addr>,
    pub local_subnets: Vec<Cidr>,
    pub require_pq: bool,
}

pub struct Config {
    pub vpn: Vpn,
    pub web: Web,
    pub oidc: Oidc,
    pub data_dir: PathBuf,
    pub master_key_file: PathBuf,
    pub cloud_cache: Option<CloudCache>,
}

fn default_route_ip() -> Result<Ipv4Addr, String> {
    // Connecting a UDP socket selects a source address without sending anything.
    let socket = UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
    socket.connect("192.0.2.1:9").map_err(|e| e.to_string())?;
    match socket.local_addr().map_err(|e| e.to_string())?.ip() {
        std::net::IpAddr::V4(ip) => Ok(ip),
        ip => Err(format!("unexpected local address {ip}")),
    }
}

fn secure_url(url: &str) -> bool {
    url.starts_with("https://")
        || ["http://localhost", "http://127.0.0.1"]
            .iter()
            .any(|p| url.strip_prefix(p).is_some_and(|r| r.is_empty() || r.starts_with([':', '/'])))
}

pub fn parse(text: &str) -> Result<Config, String> {
    let mut raw: Raw = toml::from_str(text).map_err(|e| e.to_string())?;
    let local_ip = match raw.listen.as_str() {
        "auto" => default_route_ip()?,
        s => s.parse().map_err(|_| format!("listen: not an IPv4 address: {s}"))?,
    };
    if local_ip.is_unspecified() {
        return Err("listen must be a specific address or \"auto\"".into());
    }
    let pool: Cidr = raw.pool.parse()?;
    if !(16..=30).contains(&pool.prefix) {
        return Err("pool must be between /16 and /30".into());
    }
    let local_subnets = raw.local_subnets.iter().map(|s| s.parse()).collect::<Result<Vec<_>, _>>()?;
    // Profiles embed these, so keep them free of markup and shell metacharacters.
    for (key, value) in [("server_id", &raw.server_id), ("public_address", &raw.public_address)] {
        if value.is_empty() || !value.chars().all(|c| c.is_ascii_alphanumeric() || ".-_@".contains(c)) {
            return Err(format!("{key} may only contain letters, digits and . - _ @"));
        }
    }
    raw.web.public_url.truncate(raw.web.public_url.trim_end_matches('/').len());
    if !raw.web.allow_insecure_http {
        for url in [&raw.web.public_url, &raw.oidc.issuer] {
            if !secure_url(url) {
                return Err(format!("{url} must use https (or set web.allow_insecure_http)"));
            }
        }
    }
    if let Ok(secret) = std::env::var("RIPSEC_OIDC_CLIENT_SECRET") {
        raw.oidc.client_secret = Some(secret);
    }
    Ok(Config {
        vpn: Vpn {
            local_ip,
            public_address: raw.public_address,
            server_id: raw.server_id,
            pool,
            dns: raw.dns,
            local_subnets,
            require_pq: raw.require_post_quantum,
        },
        web: raw.web,
        oidc: raw.oidc,
        master_key_file: raw.master_key_file.unwrap_or_else(|| raw.data_dir.join("master.key")),
        data_dir: raw.data_dir,
        cloud_cache: raw.cloud_cache.map(cloud_cache).transpose()?,
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn example_config_is_valid() {
        let text = include_str!("../deploy/ripsec.example.toml");
        let c = super::parse(text).unwrap();
        assert!(c.vpn.require_pq);
    }

    #[test]
    fn plain_http_is_only_allowed_on_loopback() {
        assert!(super::secure_url("http://localhost:8080/realms/x"));
        assert!(!super::secure_url("http://localhost.evil.example"));
        assert!(!super::secure_url("http://vpn.example.com"));
    }
}
