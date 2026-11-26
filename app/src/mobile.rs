//! Android: the connection lives in this process, inside a VpnService written in Kotlin that
//! creates the interface. The Rust side is the same code the other platforms use.

use crate::{Preview, import_options, preview};
use ripsec_client::controller::Controller;
use ripsec_client::ipc::Status;
use ripsec_client::store::Store;
use std::net::{IpAddr, ToSocketAddrs};
use std::sync::{Arc, Mutex, OnceLock};
use tauri::{AppHandle, Manager, State};
use tauri_plugin_ripsec_vpn::Vpn;

static CONTROLLER: OnceLock<Arc<Controller>> = OnceLock::new();
static DIRECTORY: OnceLock<String> = OnceLock::new();

/// One per process. The service may be what creates it, if Android starts it first.
fn controller(directory: &str) -> Arc<Controller> {
    CONTROLLER.get_or_init(|| Controller::new(Store::at(directory.into()))).clone()
}

/// The profile text the user picked, waiting to be confirmed.
#[derive(Default)]
struct Chosen(Mutex<Option<String>>);

fn directory(app: &AppHandle) -> Result<&'static str, String> {
    if let Some(known) = DIRECTORY.get() {
        return Ok(known);
    }
    let found = app.state::<Vpn<tauri::Wry>>().directory()?;
    Ok(DIRECTORY.get_or_init(|| found))
}

#[tauri::command(async)]
fn status(app: AppHandle) -> Result<Status, String> {
    Ok(controller(directory(&app)?).status())
}

#[tauri::command(async)]
fn connect(app: AppHandle) -> Result<Status, String> {
    let directory = directory(&app)?;
    let controller = controller(directory);
    let profile = controller.status().profile.ok_or("add a profile first")?;
    app.state::<Vpn<tauri::Wry>>().start(directory, is_local(&profile.server, profile.port))?;
    Ok(controller.status())
}

/// Whether reaching this server needs Android's local network permission.
fn is_local(server: &str, port: u16) -> bool {
    (server, port).to_socket_addrs().is_ok_and(|mut addresses| {
        addresses.any(|a| match a.ip() {
            IpAddr::V4(ip) => ip.is_private() || ip.is_link_local(),
            IpAddr::V6(_) => false,
        })
    })
}

#[tauri::command(async)]
fn disconnect(app: AppHandle) -> Result<Status, String> {
    let controller = controller(directory(&app)?);
    controller.disconnect();
    Ok(controller.status())
}

#[tauri::command(async)]
fn choose_profile(app: AppHandle, chosen: State<'_, Chosen>) -> Result<Option<Preview>, String> {
    let picked = app.state::<Vpn<tauri::Wry>>().pick_profile()?;
    let Some(text) = picked.text else { return Ok(None) };
    let preview = preview(picked.name.unwrap_or_default(), &text)?;
    *chosen.0.lock().map_err(|e| e.to_string())? = Some(text);
    Ok(Some(preview))
}

#[tauri::command(async)]
fn import_profile(
    app: AppHandle,
    chosen: State<'_, Chosen>,
    server: String,
    port: u16,
    routes: String,
) -> Result<(), String> {
    let text = chosen.0.lock().map_err(|e| e.to_string())?.clone().ok_or("choose a profile first")?;
    let options = import_options(&server, port, &routes)?;
    let controller = controller(directory(&app)?);
    controller.disconnect();
    controller.store().import_text(text, &options.iter().map(String::as_str).collect::<Vec<_>>())?;
    *chosen.0.lock().map_err(|e| e.to_string())? = None;
    Ok(())
}

#[tauri::command(async)]
fn remove_profile(app: AppHandle) -> Result<(), String> {
    let controller = controller(directory(&app)?);
    controller.disconnect();
    controller.store().remove()
}

pub fn run() {
    let result = tauri::Builder::default()
        .plugin(tauri_plugin_ripsec_vpn::init())
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
        .run(crate::context());
    if let Err(e) = result {
        eprintln!("cannot start: {e}");
    }
}

/// The functions the Kotlin class `Native` calls, and what Rust calls back on the service.
mod native {
    use super::controller;
    use jni::objects::{GlobalRef, JClass, JObject, JString, JValue};
    use jni::{JNIEnv, JavaVM};
    use ripsec_client::tun::{MTU, Network, Settings, Tun};
    use std::net::UdpSocket;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::sync::Arc;

    struct Service {
        vm: JavaVM,
        object: GlobalRef,
    }

    /// Runs a call on the service, turning a Java exception into an error.
    fn with<T>(
        service: &Service,
        call: impl FnOnce(&mut JNIEnv) -> jni::errors::Result<T>,
    ) -> Result<T, String> {
        let mut env = service.vm.attach_current_thread().map_err(|e| e.to_string())?;
        let result = call(&mut env);
        if env.exception_check().unwrap_or(false) {
            let _ = env.exception_describe();
            let _ = env.exception_clear();
        }
        result.map_err(|e| format!("Android VPN service: {e}"))
    }

    fn strings<'a>(env: &mut JNIEnv<'a>, values: &[String]) -> jni::errors::Result<JObject<'a>> {
        let array = env.new_object_array(values.len() as i32, "java/lang/String", JObject::null())?;
        for (i, value) in values.iter().enumerate() {
            let value = env.new_string(value)?;
            env.set_object_array_element(&array, i as i32, value)?;
        }
        Ok(array.into())
    }

    impl Network for Service {
        fn protect(&self, socket: &UdpSocket) -> Result<(), String> {
            let fd = socket.as_raw_fd();
            let protected =
                with(self, |env| env.call_method(&self.object, "protect", "(I)Z", &[JValue::Int(fd)])?.z())?;
            if protected {
                Ok(())
            } else {
                Err("Android refused to keep the connection outside the VPN".into())
            }
        }

        fn open(&self, settings: &Settings) -> Result<Tun, String> {
            let routes: Vec<String> = settings.routes.iter().map(ToString::to_string).collect();
            let dns: Vec<String> = settings.dns.iter().map(ToString::to_string).collect();
            let address = settings.address.to_string();
            let fd = with(self, |env| {
                let address = env.new_string(&address)?;
                let routes = strings(env, &routes)?;
                let dns = strings(env, &dns)?;
                env.call_method(
                    &self.object,
                    "establish",
                    "(Ljava/lang/String;[Ljava/lang/String;[Ljava/lang/String;I)I",
                    &[
                        JValue::Object(&address),
                        JValue::Object(&routes),
                        JValue::Object(&dns),
                        JValue::Int(MTU as i32),
                    ],
                )?
                .i()
            })?;
            if fd < 0 {
                return Err("Android would not create the VPN interface".into());
            }
            // SAFETY: the service detached this descriptor and handed us its ownership.
            Ok(Tun::from_fd(unsafe { OwnedFd::from_raw_fd(fd) }))
        }

        fn finished(&self) {
            if let Err(e) = with(self, |env| env.call_method(&self.object, "finished", "()V", &[])?.v()) {
                eprintln!("{e}");
            }
        }
    }

    #[unsafe(no_mangle)]
    pub extern "system" fn Java_io_github_plutopro_ripsec_vpn_Native_start(
        mut env: JNIEnv,
        _class: JClass,
        service: JObject,
        directory: JString,
    ) {
        let Ok(directory) = env.get_string(&directory).map(String::from) else { return };
        let (Ok(vm), Ok(object)) = (env.get_java_vm(), env.new_global_ref(service)) else { return };
        controller(&directory).connect_with(Arc::new(Service { vm, object }));
    }

    #[unsafe(no_mangle)]
    pub extern "system" fn Java_io_github_plutopro_ripsec_vpn_Native_stop(_env: JNIEnv, _class: JClass) {
        if let Some(controller) = super::CONTROLLER.get() {
            controller.disconnect();
        }
    }
}
