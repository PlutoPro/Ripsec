//! The Windows service that owns the tunnel and the stored profile.

#[cfg(windows)]
use ripsec_client::{controller, store};

#[cfg(windows)]
mod server;
#[cfg(windows)]
mod setup;

#[cfg(windows)]
fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let result = match args.as_slice() {
        // Started by the service manager.
        ["service"] => setup::run_service(),
        ["install"] => setup::install(),
        ["uninstall"] => setup::uninstall(),
        ["import", file, options @ ..] => {
            setup::installed_store().and_then(|s| s.import(file.as_ref(), options))
        }
        ["remove"] => setup::installed_store().and_then(|s| s.remove()),
        // For development: the same service in the foreground, with a profile of your choice.
        #[cfg(debug_assertions)]
        ["console", pipe, directory] => {
            let controller = controller::Controller::new(store::Store::at(directory.into()));
            server::serve(pipe, false, controller)
        }
        #[cfg(debug_assertions)]
        ["import-to", directory, file, options @ ..] => {
            store::Store::at(directory.into()).import(file.as_ref(), options)
        }
        #[cfg(debug_assertions)]
        ["ask", request] => serde_json::from_str(&format!("\"{request}\""))
            .map_err(|e| e.to_string())
            .and_then(ripsec_client::ipc::call)
            .and_then(|status| serde_json::to_string(&status).map_err(|e| e.to_string()))
            .map(|json| println!("{json}")),
        _ => Err("usage: ripsec-service install | uninstall | import <ripsec.conf> \
                  [--server HOST] [--port PORT] [--route CIDR]... | remove"
            .into()),
    };
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(not(windows))]
fn main() {
    eprintln!("ripsec-service is for Windows; on Linux use ripsec-client");
}
