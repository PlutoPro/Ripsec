//! How the app talks to the Windows service: one JSON line each way over a named pipe.
//!
//! The pipe carries no secrets. It can only ask for the state, connect and disconnect;
//! changing the stored profile is done by an elevated process instead.

use serde::{Deserialize, Serialize};

pub const PIPE: &str = r"\\.\pipe\ripsec-vpn";
/// Longer requests are not something a client of ours would send.
pub const MAX_REQUEST: u64 = 1024;

/// What an interactive user may open the pipe with: read and write, but not the right
/// to create further instances of it, which would let them impersonate the service.
pub const CLIENT_ACCESS: u32 = 0x0012_019b;

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Request {
    Status,
    Connect,
    Disconnect,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Default)]
#[serde(rename_all = "lowercase")]
pub enum State {
    #[default]
    Disconnected,
    Connecting,
    Connected,
    Reconnecting,
}

/// The stored profile, without its secret.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ProfileSummary {
    pub id: String,
    pub server: String,
    pub port: u16,
    pub routes: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct Status {
    pub state: State,
    pub profile: Option<ProfileSummary>,
    pub address: Option<String>,
    /// What actually goes through the tunnel while connected.
    pub routes: Vec<String>,
    pub connected_seconds: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    /// Why the last connection failed or ended.
    pub error: Option<String>,
}

#[cfg(windows)]
pub use pipe::call;

#[cfg(windows)]
mod pipe {
    use super::{CLIENT_ACCESS, PIPE, Request, Status};
    use std::fs::{File, OpenOptions};
    use std::io::{BufRead, BufReader, Read, Write};
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    use std::time::Duration;
    use windows_sys::Win32::Foundation::{ERROR_PIPE_BUSY, LocalFree};
    use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_KERNEL_OBJECT};
    use windows_sys::Win32::Security::{
        IsWellKnownSid, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, WinBuiltinAdministratorsSid,
        WinLocalSystemSid,
    };

    /// Stops the pipe server from acting with our identity.
    const SECURITY_IDENTIFICATION: u32 = 0x0001_0000;

    /// Another program could create the pipe first and pose as the service, for example to
    /// claim the VPN is up. Only the system or an administrator is accepted as its owner.
    fn owned_by_service(file: &File) -> bool {
        let mut owner: PSID = std::ptr::null_mut();
        let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        // SAFETY: a valid handle and out pointers; the descriptor is freed below, and the
        // owner points into it, so it is only used before that.
        unsafe {
            let status = GetSecurityInfo(
                file.as_raw_handle(),
                SE_KERNEL_OBJECT,
                OWNER_SECURITY_INFORMATION,
                &mut owner,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut descriptor,
            );
            if status != 0 {
                return false;
            }
            let trusted = IsWellKnownSid(owner, WinLocalSystemSid) != 0
                || IsWellKnownSid(owner, WinBuiltinAdministratorsSid) != 0;
            LocalFree(descriptor);
            trusted
        }
    }

    fn open(name: &str) -> Result<File, String> {
        let mut tries = 0;
        loop {
            match OpenOptions::new()
                .access_mode(CLIENT_ACCESS)
                .security_qos_flags(SECURITY_IDENTIFICATION)
                .open(name)
            {
                Ok(file) => return Ok(file),
                Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY as i32) && tries < 20 => {
                    tries += 1;
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(_) => return Err("the Ripsec service is not running".into()),
            }
        }
    }

    /// Sends one request and returns the state that results.
    pub fn call(request: Request) -> Result<Status, String> {
        // Development builds can talk to a service run by hand, which owns its own pipe.
        let development = cfg!(debug_assertions).then(|| std::env::var("RIPSEC_PIPE").ok()).flatten();
        let mut file = open(development.as_deref().unwrap_or(PIPE))?;
        if development.is_none() && !owned_by_service(&file) {
            return Err("something other than the Ripsec service is answering".into());
        }
        let mut line = serde_json::to_vec(&request).map_err(|e| e.to_string())?;
        line.push(b'\n');
        file.write_all(&line).map_err(|e| e.to_string())?;
        let mut answer = String::new();
        BufReader::new(file.take(64 * 1024)).read_line(&mut answer).map_err(|e| e.to_string())?;
        serde_json::from_str(&answer).map_err(|_| "unreadable answer from the service".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_three_requests_exist() {
        assert_eq!(serde_json::from_str::<Request>("\"connect\"").unwrap(), Request::Connect);
        assert!(serde_json::from_str::<Request>("\"import\"").is_err());
        assert!(serde_json::from_str::<Request>("{\"connect\":1}").is_err());
    }
}
