//! Registering the service with Windows, and running as it.

use crate::controller::Controller;
use crate::server;
use crate::store::Store;
use ripsec_client::ipc::PIPE;
use std::ffi::{OsString, c_void};
use std::path::PathBuf;
use std::process::Command;
use std::sync::mpsc;
use std::time::{Duration, Instant};
use windows_service::service::{
    ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode, ServiceInfo,
    ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_service::{define_windows_service, service_dispatcher};
use windows_sys::Win32::System::Com::CoTaskMemFree;
use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;
use windows_sys::Win32::UI::Shell::{FOLDERID_ProgramFiles, SHGetKnownFolderPath};

const NAME: &str = "RipsecVpn";

// Both folders come from Windows itself, not from environment variables, which the person
// who started an elevated process may have set.
fn program_files() -> Result<PathBuf, String> {
    let mut path: *mut u16 = std::ptr::null_mut();
    // SAFETY: valid out pointer; the returned string is null terminated and freed below.
    unsafe {
        let result = SHGetKnownFolderPath(&FOLDERID_ProgramFiles, 0, std::ptr::null_mut(), &mut path);
        if result < 0 {
            return Err("cannot find Program Files".into());
        }
        let mut length = 0;
        while *path.add(length) != 0 {
            length += 1;
        }
        let text = String::from_utf16_lossy(std::slice::from_raw_parts(path, length));
        CoTaskMemFree(path as *const c_void);
        Ok(text.into())
    }
}

fn system_directory() -> Result<PathBuf, String> {
    let mut buffer = [0u16; 260];
    // SAFETY: the buffer's length is passed with it.
    let length = unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) } as usize;
    if length == 0 || length >= buffer.len() {
        return Err("cannot find the system directory".into());
    }
    Ok(String::from_utf16_lossy(&buffer[..length]).into())
}

fn describe(error: windows_service::Error) -> String {
    match &error {
        windows_service::Error::Winapi(e) => format!("{e} (administrator rights are needed)"),
        _ => error.to_string(),
    }
}

/// Restricts the data directory to the system and administrators.
fn protect(store: &Store) -> Result<(), String> {
    let directory = store.directory();
    std::fs::create_dir_all(directory).map_err(|e| format!("{}: {e}", directory.display()))?;
    let icacls = system_directory()?.join("icacls.exe");
    let status = Command::new(icacls)
        .arg(directory)
        .args(["/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F"])
        .stdout(std::process::Stdio::null())
        .status()
        .map_err(|e| format!("icacls: {e}"))?;
    if status.success() { Ok(()) } else { Err("cannot protect the data directory".into()) }
}

pub fn install() -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    // The service runs as the system. Anyone able to replace its files would gain that power.
    if !exe.starts_with(program_files()?) {
        return Err("run the installer: the service must be installed under Program Files".into());
    }
    protect(&Store::installed()?)?;

    let access = ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE;
    let manager = ServiceManager::local_computer(None::<&str>, access).map_err(describe)?;
    let info = ServiceInfo {
        name: NAME.into(),
        display_name: "Ripsec VPN".into(),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: exe,
        launch_arguments: vec!["service".into()],
        dependencies: vec![],
        account_name: None,
        account_password: None,
    };
    let wanted = ServiceAccess::START | ServiceAccess::CHANGE_CONFIG;
    let service = match manager.open_service(NAME, wanted) {
        Ok(existing) => {
            existing.change_config(&info).map_err(describe)?;
            existing
        }
        Err(_) => manager.create_service(&info, wanted).map_err(describe)?,
    };
    service.set_description("Post-quantum VPN connection for the Ripsec app").map_err(describe)?;
    service.start::<OsString>(&[]).map_err(describe)
}

/// Stops and removes the service. The program files are the installer's to delete.
pub fn uninstall() -> Result<(), String> {
    let manager =
        ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT).map_err(describe)?;
    let wanted = ServiceAccess::STOP | ServiceAccess::DELETE | ServiceAccess::QUERY_STATUS;
    let Ok(service) = manager.open_service(NAME, wanted) else { return Ok(()) };
    let _ = service.stop();
    let deadline = Instant::now() + Duration::from_secs(20);
    while service.query_status().is_ok_and(|s| s.current_state != ServiceState::Stopped)
        && Instant::now() < deadline
    {
        std::thread::sleep(Duration::from_millis(200));
    }
    service.delete().map_err(describe)
}

pub fn run_service() -> Result<(), String> {
    service_dispatcher::start(NAME, entry).map_err(describe)
}

define_windows_service!(entry, service_main);

fn service_main(_arguments: Vec<OsString>) {
    if let Err(e) = serve() {
        eprintln!("{e}");
    }
}

fn serve() -> Result<(), String> {
    let (stop, stopped) = mpsc::channel();
    let failed = stop.clone();
    let handle = service_control_handler::register(NAME, move |control| match control {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            let _ = stop.send(());
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    })
    .map_err(describe)?;
    let report = |state: ServiceState, exit: u32| {
        let accept = if state == ServiceState::Running {
            ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN
        } else {
            ServiceControlAccept::empty()
        };
        let status = ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: accept,
            exit_code: ServiceExitCode::Win32(exit),
            checkpoint: 0,
            wait_hint: Duration::from_secs(20),
            process_id: None,
        };
        let _ = handle.set_service_status(status);
    };

    let controller = Controller::new(Store::installed()?);
    let serving = controller.clone();
    let listener = std::thread::spawn(move || {
        let result = server::serve(PIPE, true, serving);
        let _ = failed.send(());
        result
    });
    report(ServiceState::Running, 0);
    let _ = stopped.recv();
    report(ServiceState::StopPending, 0);
    // Removes the routes before the process goes away.
    controller.disconnect();
    let exit = u32::from(listener.is_finished());
    report(ServiceState::Stopped, exit);
    Ok(())
}
