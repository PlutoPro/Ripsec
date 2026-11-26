//! Self-service portal and admin API.

mod oidc;
mod profiles;

use crate::config::{Config, Vpn};
use crate::net::Cidr;
use crate::secrets;
use crate::server::Command;
use crate::store::{Device, Store, now};
use axum::extract::{FromRequestParts, Path, Query, Request, State};
use axum::http::header::{CONTENT_TYPE, COOKIE, LOCATION, SET_COOKIE};
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{AppendHeaders, IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, oneshot};

/// Kept short so that a user disabled at the provider soon loses portal access.
const SESSION_LIFETIME: Duration = Duration::from_secs(3600);
const LOGIN_LIFETIME: Duration = Duration::from_secs(600);
const MAX_PENDING: usize = 1000;
const SESSION_COOKIE: &str = "ripsec_session";
const LOGIN_COOKIE: &str = "ripsec_login";

#[derive(Clone)]
struct User {
    subject: String,
    name: String,
    admin: bool,
    expires: Instant,
}

struct Login {
    nonce: String,
    verifier: String,
    started: Instant,
}

struct App {
    oidc: oidc::Client,
    vpn: Vpn,
    public_url: String,
    store: Arc<Mutex<Store>>,
    engine: mpsc::Sender<Command>,
    /// Set when device secrets are kept in Cloud Cache.
    cache: Option<secrets::Handle>,
    users: Mutex<HashMap<String, User>>,
    logins: Mutex<HashMap<String, Login>>,
}

type Shared = Arc<App>;

struct Failure(StatusCode, String);

impl IntoResponse for Failure {
    fn into_response(self) -> Response {
        (self.0, Json(json!({ "error": self.1 }))).into_response()
    }
}

fn fail(status: StatusCode, message: &str) -> Failure {
    Failure(status, message.to_string())
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn cookie<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get_all(COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find_map(|(k, v)| (k == name).then_some(v))
}

impl App {
    fn set_cookie(&self, name: &str, value: &str, max_age: u64) -> String {
        let secure = if self.public_url.starts_with("https://") { "; Secure" } else { "" };
        format!("{name}={value}; Path=/; Max-Age={max_age}; HttpOnly; SameSite=Lax{secure}")
    }
}

impl FromRequestParts<Shared> for User {
    type Rejection = Failure;

    async fn from_request_parts(parts: &mut Parts, app: &Shared) -> Result<User, Failure> {
        cookie(&parts.headers, SESSION_COOKIE)
            .and_then(|id| lock(&app.users).get(id).cloned())
            .filter(|u| u.expires > Instant::now())
            .ok_or_else(|| fail(StatusCode::UNAUTHORIZED, "sign in required"))
    }
}

async fn guard(request: Request, next: Next) -> Response {
    // Cross-site pages cannot add this header without a CORS preflight, which we never grant.
    let reads = matches!(*request.method(), Method::GET | Method::HEAD);
    if !reads && !request.headers().contains_key("x-ripsec") {
        return fail(StatusCode::FORBIDDEN, "missing x-ripsec header").into_response();
    }
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    for (name, value) in [
        ("content-security-policy", "default-src 'self'; frame-ancestors 'none'; base-uri 'none'"),
        ("x-content-type-options", "nosniff"),
        ("referrer-policy", "no-referrer"),
        ("cache-control", "no-store"),
    ] {
        headers.insert(name, HeaderValue::from_static(value));
    }
    response
}

async fn login(State(app): State<Shared>) -> Result<Response, Failure> {
    let (state, nonce, verifier) = (oidc::token(), oidc::token(), oidc::token());
    let url = {
        let (app, state, nonce, verifier) = (app.clone(), state.clone(), nonce.clone(), verifier.clone());
        tokio::task::spawn_blocking(move || app.oidc.authorization_url(&state, &nonce, &verifier))
            .await
            .map_err(|_| fail(StatusCode::INTERNAL_SERVER_ERROR, "internal error"))?
            .map_err(|e| {
                eprintln!("sign in unavailable: {e}");
                fail(StatusCode::BAD_GATEWAY, "identity provider unavailable")
            })?
    };
    {
        let mut logins = lock(&app.logins);
        logins.retain(|_, l| l.started.elapsed() < LOGIN_LIFETIME);
        if logins.len() >= MAX_PENDING {
            return Err(fail(StatusCode::TOO_MANY_REQUESTS, "too many sign ins in progress"));
        }
        logins.insert(state.clone(), Login { nonce, verifier, started: Instant::now() });
    }
    let headers = [(SET_COOKIE, app.set_cookie(LOGIN_COOKIE, &state, 600)), (LOCATION, url)];
    Ok((StatusCode::SEE_OTHER, headers).into_response())
}

#[derive(Deserialize)]
struct Callback {
    code: Option<String>,
    state: Option<String>,
}

async fn callback(
    State(app): State<Shared>,
    Query(query): Query<Callback>,
    headers: HeaderMap,
) -> Result<Response, Failure> {
    let bad = || fail(StatusCode::BAD_REQUEST, "sign in failed, please try again");
    let (Some(code), Some(state)) = (query.code, query.state) else { return Err(bad()) };
    // The state must belong to this browser, which blocks login CSRF.
    if cookie(&headers, LOGIN_COOKIE) != Some(state.as_str()) {
        return Err(bad());
    }
    let login =
        lock(&app.logins).remove(&state).filter(|l| l.started.elapsed() < LOGIN_LIFETIME).ok_or_else(bad)?;
    let worker = app.clone();
    let identity =
        tokio::task::spawn_blocking(move || worker.oidc.redeem(&code, &login.verifier, &login.nonce))
            .await
            .map_err(|_| bad())?
            .map_err(|e| {
                eprintln!("sign in rejected: {e}");
                bad()
            })?;

    let config = &app.oidc.config;
    let admin = identity.roles.contains(&config.admin_role);
    if config.user_role.as_ref().is_some_and(|r| !admin && !identity.roles.contains(r)) {
        return Err(fail(StatusCode::FORBIDDEN, "your account is not allowed to use this VPN"));
    }
    let session = oidc::token();
    {
        let mut users = lock(&app.users);
        users.retain(|_, u| u.expires > Instant::now());
        users.insert(
            session.clone(),
            User {
                subject: identity.subject,
                name: identity.name,
                admin,
                expires: Instant::now() + SESSION_LIFETIME,
            },
        );
    }
    let cookies = AppendHeaders([
        (SET_COOKIE, app.set_cookie(SESSION_COOKIE, &session, SESSION_LIFETIME.as_secs())),
        (SET_COOKIE, app.set_cookie(LOGIN_COOKIE, "", 0)),
    ]);
    Ok((StatusCode::SEE_OTHER, cookies, [(LOCATION, app.public_url.clone() + "/")]).into_response())
}

async fn logout(State(app): State<Shared>, headers: HeaderMap) -> Response {
    if let Some(id) = cookie(&headers, SESSION_COOKIE) {
        lock(&app.users).remove(id);
    }
    let end = app.oidc.provider().ok().and_then(|p| p.end_session_endpoint.clone());
    ([(SET_COOKIE, app.set_cookie(SESSION_COOKIE, "", 0))], Json(json!({ "provider_logout": end })))
        .into_response()
}

async fn me(State(app): State<Shared>, user: User) -> Json<Value> {
    Json(json!({
        "name": user.name,
        "admin": user.admin,
        "require_post_quantum": app.vpn.require_pq,
        "server": app.vpn.public_address,
        "credential_ttl_days": app.oidc.config.credential_ttl_days,
    }))
}

/// A device as shown to users. The secret is never included.
#[derive(Serialize)]
struct DeviceView {
    id: String,
    name: String,
    owner_name: String,
    mine: bool,
    remote_subnets: Vec<String>,
    created: u64,
    expires: Option<u64>,
    active: bool,
}

fn view(d: &Device, user: &User) -> DeviceView {
    DeviceView {
        id: d.id.clone(),
        name: d.name.clone(),
        owner_name: d.owner_name.clone(),
        mine: d.owner == user.subject,
        remote_subnets: d.remote_subnets.clone(),
        created: d.created,
        expires: d.expires,
        active: d.active(),
    }
}

async fn devices(State(app): State<Shared>, user: User) -> Json<Vec<DeviceView>> {
    let store = lock(&app.store);
    Json(
        store
            .devices
            .iter()
            .filter(|d| user.admin || d.owner == user.subject)
            .map(|d| view(d, &user))
            .collect(),
    )
}

#[derive(Deserialize)]
struct NewDevice {
    name: String,
    #[serde(default)]
    remote_subnets: Vec<String>,
}

fn expiry(app: &App) -> u64 {
    now() + app.oidc.config.credential_ttl_days * 86_400
}

async fn enrol(
    State(app): State<Shared>,
    user: User,
    Json(request): Json<NewDevice>,
) -> Result<Json<Value>, Failure> {
    let name = request.name.trim();
    if name.is_empty() || name.chars().count() > 64 || name.chars().any(char::is_control) {
        return Err(fail(StatusCode::BAD_REQUEST, "name must be 1 to 64 characters"));
    }
    let site = !request.remote_subnets.is_empty();
    if site && !user.admin {
        return Err(fail(StatusCode::FORBIDDEN, "only administrators can add sites"));
    }
    let subnets = request
        .remote_subnets
        .iter()
        .map(|s| s.parse::<Cidr>())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| Failure(StatusCode::BAD_REQUEST, e))?;
    // A site must not capture the whole internet, the client pool or the gateway itself.
    let gateway = Cidr::host(app.vpn.local_ip);
    if subnets.iter().any(|n| n.prefix < 8 || n.overlaps(&app.vpn.pool) || n.overlaps(&gateway)) {
        return Err(fail(StatusCode::BAD_REQUEST, "subnet is too broad or overlaps the VPN itself"));
    }

    let over_limit = |store: &Store| {
        let owned = |d: &&Device| d.owner == user.subject && d.remote_subnets.is_empty();
        !site && store.devices.iter().filter(owned).count() >= app.oidc.config.max_devices_per_user
    };
    let limit = || fail(StatusCode::CONFLICT, "device limit reached, remove one first");
    let conflict = |e: std::io::Error| Failure(StatusCode::CONFLICT, e.to_string());
    let expires = (!site).then(|| expiry(&app));
    let device = {
        let store = lock(&app.store);
        if over_limit(&store) {
            return Err(limit());
        }
        store.new_device(name, &user.subject, &user.name, &subnets, expires).map_err(conflict)?
    };
    // The secret must be safely stored before the device exists and the user is given it.
    if let Some(cache) = &app.cache
        && let Err(why) = cache.store(&device).await
    {
        abandon(&app, &device.id);
        eprintln!("cannot enrol {}: {why}", device.id);
        return Err(fail(StatusCode::SERVICE_UNAVAILABLE, "secret store unavailable, try again later"));
    }
    let inserted = {
        let mut store = lock(&app.store);
        // Checked again: other requests may have run while we waited.
        if over_limit(&store) { Err(limit()) } else { store.insert(device.clone()).map_err(conflict) }
    };
    if let Err(failure) = inserted {
        abandon(&app, &device.id);
        return Err(failure);
    }
    eprintln!("{} enrolled {} ({})", user.name, device.name, device.id);
    Ok(Json(json!({
        "device": view(&device, &user),
        "secret": device.secret,
        "server_address": app.vpn.public_address,
        "server_id": app.vpn.server_id,
        "apple": (!site).then(|| profiles::apple(&app.vpn, &device)),
        "strongswan": profiles::strongswan(&app.vpn, &device),
    })))
}

/// Deletes whatever may have been stored for a device that was never created.
fn abandon(app: &App, id: &str) {
    if let Err(e) = lock(&app.store).queue_revocation(id) {
        eprintln!("cannot save revocations: {e}");
    }
}

/// Finds a device the user may manage.
fn owned(store: &Store, id: &str, user: &User) -> Result<Device, Failure> {
    store
        .devices
        .iter()
        .find(|d| d.id == id && (user.admin || d.owner == user.subject))
        .cloned()
        .ok_or_else(|| fail(StatusCode::NOT_FOUND, "no such device"))
}

fn storage_error(e: std::io::Error) -> Failure {
    eprintln!("cannot save devices: {e}");
    fail(StatusCode::INTERNAL_SERVER_ERROR, "could not save")
}

/// Extends a credential. Only its owner can, which requires a recent sign in.
async fn renew(State(app): State<Shared>, user: User, Path(id): Path<String>) -> Result<StatusCode, Failure> {
    let mut device = owned(&lock(&app.store), &id, &user)?;
    if device.owner != user.subject || !device.remote_subnets.is_empty() {
        return Err(fail(StatusCode::FORBIDDEN, "only the owner can renew a device"));
    }
    let expires = Some(expiry(&app));
    if let Some(cache) = &app.cache {
        if device.secret.is_empty() {
            return Err(fail(StatusCode::CONFLICT, "secret unavailable, enrol the device again"));
        }
        device.expires = expires;
        cache.store(&device).await.map_err(|why| {
            eprintln!("cannot renew {id}: {why}");
            fail(StatusCode::SERVICE_UNAVAILABLE, "secret store unavailable, try again later")
        })?;
    }
    let mut store = lock(&app.store);
    // It may have been revoked while we waited; that deletion is queued after our write.
    owned(&store, &id, &user)?;
    store.set_expiry(&id, expires).map_err(storage_error)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn revoke(
    State(app): State<Shared>,
    user: User,
    Path(id): Path<String>,
) -> Result<StatusCode, Failure> {
    let mut store = lock(&app.store);
    owned(&store, &id, &user)?;
    store.remove(&id).map_err(storage_error)?;
    eprintln!("{} revoked {id}", user.name);
    // The engine notices within a second and drops the session.
    Ok(StatusCode::NO_CONTENT)
}

async fn query_sessions(app: &App, user: &User) -> Result<Vec<crate::ike::SessionInfo>, Failure> {
    let gone = || fail(StatusCode::SERVICE_UNAVAILABLE, "VPN engine unavailable");
    let (reply, answer) = oneshot::channel();
    app.engine.send(Command::Sessions(reply)).await.map_err(|_| gone())?;
    let mut sessions = answer.await.map_err(|_| gone())?;
    sessions.retain(|s| user.admin || s.owner == user.subject);
    Ok(sessions)
}

async fn sessions(State(app): State<Shared>, user: User) -> Result<Response, Failure> {
    Ok(Json(query_sessions(&app, &user).await?).into_response())
}

async fn disconnect(
    State(app): State<Shared>,
    user: User,
    Path(id): Path<String>,
) -> Result<StatusCode, Failure> {
    let missing = || fail(StatusCode::NOT_FOUND, "no such session");
    if !query_sessions(&app, &user).await?.iter().any(|s| s.id == id) {
        return Err(missing());
    }
    let spi = u64::from_str_radix(&id, 16).map_err(|_| missing())?;
    let _ = app.engine.send(Command::Disconnect(spi)).await;
    Ok(StatusCode::NO_CONTENT)
}

fn asset(kind: &'static str, body: &'static str) -> Response {
    ([(CONTENT_TYPE, kind)], body).into_response()
}

pub fn router(
    config: &Config,
    store: Arc<Mutex<Store>>,
    engine: mpsc::Sender<Command>,
    cache: Option<secrets::Handle>,
) -> Router {
    let app = Arc::new(App {
        oidc: oidc::Client::new(config.oidc.clone(), &config.web.public_url),
        vpn: config.vpn.clone(),
        public_url: config.web.public_url.clone(),
        store,
        engine,
        cache,
        users: Mutex::default(),
        logins: Mutex::default(),
    });
    Router::new()
        .route("/", get(async || asset("text/html; charset=utf-8", include_str!("static/index.html"))))
        .route("/app.js", get(async || asset("text/javascript", include_str!("static/app.js"))))
        .route("/style.css", get(async || asset("text/css", include_str!("static/style.css"))))
        .route("/auth/login", get(login))
        .route("/auth/callback", get(callback))
        .route("/auth/logout", post(logout))
        .route("/api/me", get(me))
        .route("/api/devices", get(devices).post(enrol))
        .route("/api/devices/{id}", delete(revoke))
        .route("/api/devices/{id}/renew", post(renew))
        .route("/api/sessions", get(sessions))
        .route("/api/sessions/{id}", delete(disconnect))
        .layer(middleware::from_fn(guard))
        .with_state(app)
}
