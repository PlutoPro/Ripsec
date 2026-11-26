//! The Ripsec app. The screens are the same everywhere; what happens behind them differs:
//! on Windows a service does the work, on Android a VpnService inside the app.

#[cfg(desktop)]
mod desktop;
#[cfg(desktop)]
mod elevate;
#[cfg(mobile)]
mod mobile;

use ripsec_client::cidr::Cidr;
use ripsec_client::profile::Profile;
use serde::Serialize;

#[derive(Serialize)]
pub(crate) struct Preview {
    name: String,
    server: String,
    port: u16,
    routes: String,
}

/// What to show before a profile is added. The secret never reaches the page.
pub(crate) fn preview(name: String, text: &str) -> Result<Preview, String> {
    let profile = Profile::parse(text)?;
    Ok(Preview {
        name,
        server: profile.server,
        port: profile.port.unwrap_or(4500),
        routes: profile.routes.iter().map(ToString::to_string).collect::<Vec<_>>().join(", "),
    })
}

/// Builds the import options. Everything is checked here, so nothing unexpected can end up
/// on the elevated command line on Windows.
pub(crate) fn import_options(server: &str, port: u16, routes: &str) -> Result<Vec<String>, String> {
    let server = server.trim();
    let host = |c: char| c.is_ascii_alphanumeric() || c == '.' || c == '-';
    if server.is_empty() || server.starts_with('-') || !server.chars().all(host) {
        return Err("enter a server name or IPv4 address".into());
    }
    if port == 0 {
        return Err("enter a port from 1 to 65535".into());
    }
    let mut options = vec!["--server".into(), server.into(), "--port".into(), port.to_string()];
    for route in routes.split([',', ' ', '\n']).filter(|r| !r.is_empty()) {
        options.push("--route".into());
        options.push(route.parse::<Cidr>()?.to_string());
    }
    Ok(options)
}

#[tauri::command]
fn platform() -> &'static str {
    std::env::consts::OS
}

pub(crate) fn context() -> tauri::Context<tauri::Wry> {
    tauri::generate_context!()
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    #[cfg(desktop)]
    desktop::run();
    #[cfg(mobile)]
    mobile::run();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn import_options_are_checked() {
        let options = import_options(" vpn.example.com ", 14500, "10.0.0.1/32, 10.1.0.0/16").unwrap();
        assert_eq!(options.len(), 8);
        assert!(import_options("a\" --route 0.0.0.0/0", 1, "").is_err());
        assert!(import_options("-x", 1, "").is_err());
        assert!(import_options("ok", 0, "").is_err());
        assert!(import_options("ok", 1, "everything").is_err());
    }
}
