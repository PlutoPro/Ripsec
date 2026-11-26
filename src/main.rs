use ripsec::ike::Engine;
use ripsec::seal::Vault;
use ripsec::store::Store;
use ripsec::{config, secrets, server, web, xfrm};
use std::sync::{Arc, Mutex};

fn main() {
    if let Err(e) = run() {
        eprintln!("ripsec: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let path = match args.as_slice() {
        [] => "/etc/ripsec/ripsec.toml",
        [flag, path] if flag == "--config" => path,
        _ => return Err("usage: ripsec [--config FILE]".into()),
    };
    let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    let config = config::parse(&text).map_err(|e| format!("{path}: {e}"))?;

    std::fs::create_dir_all(&config.data_dir).map_err(|e| format!("data_dir: {e}"))?;
    let devices = config.data_dir.join("devices.json");
    let existing = Store::needs_existing_key(&devices).map_err(|e| format!("devices.json: {e}"))?;
    let vault = Vault::open_or_create(&config.master_key_file, !existing).map_err(|e| e.to_string())?;
    let vault = Arc::new(vault);
    let store = Store::load(devices, vault.clone(), config.cloud_cache.is_some())
        .map_err(|e| format!("devices.json: {e}"))?;
    let store = Arc::new(Mutex::new(store));
    let cache = match &config.cloud_cache {
        Some(settings) => {
            let handle = secrets::start(settings, &config.vpn.server_id, store.clone(), vault)?;
            eprintln!("device secrets are kept in Cloud Cache at {}", settings.address);
            Some(handle)
        }
        None => None,
    };
    let dataplane = xfrm::Xfrm::open().map_err(|e| format!("XFRM netlink: {e}"))?;
    let engine = Engine::new(config.vpn.clone(), dataplane, store.clone());

    // One thread is enough: packet encryption happens in the kernel.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(4)
        .build()
        .map_err(|e| e.to_string())?;
    runtime.block_on(async {
        let (sender, receiver) = tokio::sync::mpsc::channel(32);
        let app = web::router(&config, store, sender, cache);
        let listener =
            tokio::net::TcpListener::bind(config.web.listen).await.map_err(|e| format!("web.listen: {e}"))?;
        eprintln!("portal listening on {} ({})", config.web.listen, config.web.public_url);
        tokio::spawn(async move {
            if let Err(e) = axum::serve(listener, app).await {
                eprintln!("portal stopped: {e}");
            }
        });
        server::run(engine, config.vpn.local_ip, receiver).await.map_err(|e| format!("IKE: {e}"))
    })
}
