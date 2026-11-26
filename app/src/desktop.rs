//! Windows: a window and tray icon that talk to the service. They hold no secrets and need
//! no special rights; changing the profile runs the service program elevated.

use crate::{Preview, elevate, import_options, preview};
use ripsec_client::ipc::{self, Request, State, Status};
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;
use tauri::image::Image;
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Manager, WindowEvent};
use tauri_plugin_dialog::DialogExt;

/// The profile file the user picked. Kept here so the page never names a path.
#[derive(Default)]
struct Chosen(Mutex<Option<PathBuf>>);

fn call(request: Request) -> Result<Status, String> {
    ipc::call(request)
}

#[tauri::command(async)]
fn status() -> Result<Status, String> {
    call(Request::Status)
}

#[tauri::command(async)]
fn connect() -> Result<Status, String> {
    call(Request::Connect)
}

#[tauri::command(async)]
fn disconnect() -> Result<Status, String> {
    call(Request::Disconnect)
}

#[tauri::command(async)]
fn choose_profile(app: AppHandle) -> Result<Option<Preview>, String> {
    let Some(picked) = app.dialog().file().add_filter("Ripsec profile", &["conf"]).blocking_pick_file()
    else {
        return Ok(None);
    };
    let path = picked.into_path().map_err(|e| e.to_string())?;
    if std::fs::metadata(&path).map_err(|e| e.to_string())?.len() > 64 * 1024 {
        return Err("that file is too large to be a profile".into());
    }
    let text = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;
    let name = path.file_name().map_or_else(String::new, |n| n.to_string_lossy().into_owned());
    let preview = preview(name, &text)?;
    *app.state::<Chosen>().0.lock().map_err(|e| e.to_string())? = Some(path);
    Ok(Some(preview))
}

#[tauri::command(async)]
fn import_profile(app: AppHandle, server: String, port: u16, routes: String) -> Result<(), String> {
    let path = app.state::<Chosen>().0.lock().map_err(|e| e.to_string())?.clone();
    let path = path.ok_or("choose a profile first")?;
    let path = path.to_str().ok_or("the file name is not valid text")?;
    let mut arguments = vec!["import".to_string(), path.to_string()];
    arguments.extend(import_options(&server, port, &routes)?);
    // A new profile takes effect on a new connection.
    let _ = call(Request::Disconnect);
    elevate::service_program(&arguments)
}

#[tauri::command(async)]
fn remove_profile() -> Result<(), String> {
    call(Request::Disconnect)?;
    elevate::service_program(&["remove".to_string()])
}

/// A filled disc: green when protected, amber while working, grey otherwise.
fn tray_image(state: State) -> Image<'static> {
    const SIZE: u32 = 32;
    let colour = match state {
        State::Connected => [34, 160, 90],
        State::Connecting | State::Reconnecting => [220, 150, 30],
        State::Disconnected => [130, 135, 145],
    };
    let centre = (SIZE as f32 - 1.0) / 2.0;
    let mut pixels = Vec::with_capacity((SIZE * SIZE * 4) as usize);
    for y in 0..SIZE {
        for x in 0..SIZE {
            let distance = (x as f32 - centre).hypot(y as f32 - centre);
            let alpha = ((14.5 - distance).clamp(0.0, 1.0) * 255.0) as u8;
            pixels.extend_from_slice(&[colour[0], colour[1], colour[2], alpha]);
        }
    }
    Image::new_owned(pixels, SIZE, SIZE)
}

fn show(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}

fn tray(app: &mut tauri::App) -> tauri::Result<()> {
    let item = |id: &str, text: &str| MenuItem::with_id(app, id, text, true, None::<&str>);
    let menu = Menu::with_items(
        app,
        &[
            &item("open", "Open Ripsec")?,
            &item("connect", "Connect")?,
            &item("disconnect", "Disconnect")?,
            &PredefinedMenuItem::separator(app)?,
            // The connection belongs to the service and outlives this program.
            &item("quit", "Quit (the VPN stays as it is)")?,
        ],
    )?;
    let icon = TrayIconBuilder::new()
        .icon(tray_image(State::Disconnected))
        .tooltip("Ripsec")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match event.id().as_ref() {
            "open" => show(app),
            "connect" => drop(std::thread::spawn(|| call(Request::Connect))),
            "disconnect" => drop(std::thread::spawn(|| call(Request::Disconnect))),
            "quit" => app.exit(0),
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                show(tray.app_handle());
            }
        })
        .build(app)?;

    std::thread::spawn(move || {
        let mut shown = None;
        loop {
            let state = call(Request::Status).map(|s| s.state).unwrap_or_default();
            if shown != Some(state) {
                let _ = icon.set_icon(Some(tray_image(state)));
                let _ = icon.set_tooltip(Some(match state {
                    State::Connected => "Ripsec: connected",
                    State::Connecting => "Ripsec: connecting",
                    State::Reconnecting => "Ripsec: reconnecting",
                    State::Disconnected => "Ripsec: not connected",
                }));
                shown = Some(state);
            }
            std::thread::sleep(Duration::from_secs(2));
        }
    });
    Ok(())
}

pub fn run() {
    let result = tauri::Builder::default()
        // Must come first: a second launch just brings the window forward.
        .plugin(tauri_plugin_single_instance::init(|app, _, _| show(app)))
        .plugin(tauri_plugin_dialog::init())
        .manage(Chosen::default())
        .invoke_handler(tauri::generate_handler![
            crate::platform,
            status,
            connect,
            disconnect,
            choose_profile,
            import_profile,
            remove_profile
        ])
        .setup(|app| Ok(tray(app)?))
        // Closing the window leaves the tray icon.
        .on_window_event(|window, event| {
            if let WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .run(crate::context());
    if let Err(e) = result {
        eprintln!("cannot start: {e}");
        std::process::exit(1);
    }
}
