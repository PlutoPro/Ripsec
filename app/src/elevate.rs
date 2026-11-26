//! Runs the installed service program with administrator rights, which shows the usual
//! Windows prompt. Used only to change the stored profile.

/// Callers pass arguments that contain no quotation marks.
fn command_line(arguments: &[String]) -> Result<String, String> {
    if arguments.iter().any(|a| a.contains('"') || a.ends_with('\\')) {
        return Err("invalid argument".into());
    }
    Ok(arguments.iter().map(|a| format!("\"{a}\"")).collect::<Vec<_>>().join(" "))
}

#[cfg(windows)]
pub fn service_program(arguments: &[String]) -> Result<(), String> {
    use windows_sys::Win32::Foundation::{CloseHandle, ERROR_CANCELLED, GetLastError, WAIT_OBJECT_0};
    use windows_sys::Win32::System::Threading::{GetExitCodeProcess, WaitForSingleObject};
    use windows_sys::Win32::UI::Shell::{SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW};
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_HIDE;

    let wide = |text: &str| text.encode_utf16().chain([0]).collect::<Vec<u16>>();
    let program = std::env::current_exe().map_err(|e| e.to_string())?.with_file_name("ripsec-service.exe");
    if !program.is_file() {
        return Err("ripsec-service.exe is missing; reinstall Ripsec".into());
    }
    let program = wide(program.to_str().ok_or("invalid install path")?);
    let verb = wide("runas");
    let parameters = wide(&command_line(arguments)?);

    // SAFETY: the structure is zeroed, then given null terminated strings that outlive the
    // call. The process handle is closed once its exit code has been read.
    unsafe {
        let mut info: SHELLEXECUTEINFOW = std::mem::zeroed();
        info.cbSize = size_of::<SHELLEXECUTEINFOW>() as u32;
        info.fMask = SEE_MASK_NOCLOSEPROCESS;
        info.lpVerb = verb.as_ptr();
        info.lpFile = program.as_ptr();
        info.lpParameters = parameters.as_ptr();
        info.nShow = SW_HIDE;
        if ShellExecuteExW(&mut info) == 0 {
            return Err(if GetLastError() == ERROR_CANCELLED {
                "administrator approval was declined".into()
            } else {
                "could not ask for administrator approval".into()
            });
        }
        let finished = WaitForSingleObject(info.hProcess, 60_000) == WAIT_OBJECT_0;
        let mut code = 1;
        let read = GetExitCodeProcess(info.hProcess, &mut code) != 0;
        CloseHandle(info.hProcess);
        if finished && read && code == 0 {
            Ok(())
        } else {
            Err("the change could not be saved; is Ripsec installed correctly?".into())
        }
    }
}

#[cfg(not(windows))]
pub fn service_program(arguments: &[String]) -> Result<(), String> {
    command_line(arguments)?;
    Err("only supported on Windows".into())
}
