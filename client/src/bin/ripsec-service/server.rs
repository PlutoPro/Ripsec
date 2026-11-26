//! The service's end of the named pipe.

use ripsec_client::controller::Controller;
use ripsec_client::ipc::{MAX_REQUEST, Request};
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::windows::io::{FromRawHandle, OwnedHandle};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use windows_sys::Win32::Foundation::{ERROR_PIPE_CONNECTED, GetLastError, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_FLAG_FIRST_PIPE_INSTANCE, FlushFileBuffers, PIPE_ACCESS_DUPLEX,
};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES,
};

/// Full control for the system and administrators; interactive users may only use it.
const ACCESS: &str = "D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x12019b;;;IU)";
const MAX_CLIENTS: usize = 16;

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain([0]).collect()
}

/// Creates one instance of the pipe. `restrict` applies the service's access list.
fn instance(name: &[u16], first: bool, restrict: bool) -> Result<OwnedHandle, String> {
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    if restrict {
        // SAFETY: a valid null terminated string and out pointer. The descriptor is kept for
        // the life of the process, which creates only a handful.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide(ACCESS).as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err("cannot build the pipe's access list".into());
        }
    }
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor,
        bInheritHandle: 0,
    };
    // Refusing to join an existing pipe means nobody else can have set it up for us.
    let mode = PIPE_ACCESS_DUPLEX | if first { FILE_FLAG_FIRST_PIPE_INSTANCE } else { 0 };
    // SAFETY: valid name and attributes.
    let handle = unsafe {
        CreateNamedPipeW(
            name.as_ptr(),
            mode,
            PIPE_TYPE_BYTE | PIPE_REJECT_REMOTE_CLIENTS,
            PIPE_UNLIMITED_INSTANCES,
            4096,
            4096,
            0,
            if restrict { &attributes } else { std::ptr::null() },
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        // SAFETY: reads this thread's last error.
        return Err(format!("cannot create the pipe (error {})", unsafe { GetLastError() }));
    }
    // SAFETY: a new handle that we own.
    Ok(unsafe { OwnedHandle::from_raw_handle(handle) })
}

fn answer(mut pipe: File, controller: &Controller) -> Option<()> {
    let mut line = String::new();
    BufReader::new((&pipe).take(MAX_REQUEST)).read_line(&mut line).ok()?;
    let request: Request = serde_json::from_str(line.trim()).ok()?;
    let mut reply = serde_json::to_vec(&controller.handle(request)).ok()?;
    reply.push(b'\n');
    pipe.write_all(&reply).ok()?;
    // SAFETY: a valid handle. Waits until the client has read the answer.
    unsafe { FlushFileBuffers(std::os::windows::io::AsRawHandle::as_raw_handle(&pipe)) };
    Some(())
}

/// Serves the pipe until the process ends.
pub fn serve(name: &str, restrict: bool, controller: Arc<Controller>) -> Result<(), String> {
    let name = wide(name);
    let mut pipe = instance(&name, true, restrict)?;
    let clients = Arc::new(AtomicUsize::new(0));
    loop {
        // SAFETY: a valid pipe handle, used synchronously.
        let connected = unsafe {
            ConnectNamedPipe(std::os::windows::io::AsRawHandle::as_raw_handle(&pipe), std::ptr::null_mut())
                != 0
                || GetLastError() == ERROR_PIPE_CONNECTED
        };
        // The next instance exists before this one is served, so the name never lapses.
        let current = std::mem::replace(&mut pipe, instance(&name, false, restrict)?);
        if !connected || clients.load(Ordering::Relaxed) >= MAX_CLIENTS {
            continue;
        }
        let (controller, clients) = (controller.clone(), clients.clone());
        clients.fetch_add(1, Ordering::Relaxed);
        std::thread::spawn(move || {
            let _ = answer(File::from(current), &controller);
            clients.fetch_sub(1, Ordering::Relaxed);
        });
    }
}
