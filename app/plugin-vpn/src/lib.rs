//! Calls into the Kotlin plugin. Only built for Android; elsewhere this crate is empty.

#[cfg(target_os = "android")]
pub use android::{Vpn, init};

#[cfg(target_os = "android")]
mod android {
    use serde::{Deserialize, Serialize};
    use tauri::plugin::{Builder, PluginHandle, TauriPlugin};
    use tauri::{Manager, Runtime};

    pub struct Vpn<R: Runtime>(PluginHandle<R>);

    #[derive(Serialize)]
    struct Start<'a> {
        directory: &'a str,
        local: bool,
    }

    #[derive(Deserialize)]
    struct Directory {
        directory: String,
    }

    /// What the user picked, or nothing if they backed out.
    #[derive(Deserialize)]
    pub struct Picked {
        pub name: Option<String>,
        pub text: Option<String>,
    }

    #[derive(Deserialize)]
    struct Done {}

    impl<R: Runtime> Vpn<R> {
        /// Private storage that Android never copies into backups.
        pub fn directory(&self) -> Result<String, String> {
            let answer: Directory = self.0.run_mobile_plugin("directory", ()).map_err(|e| e.to_string())?;
            Ok(answer.directory)
        }

        /// Asks for the VPN permission if needed, then starts the service.
        pub fn start(&self, directory: &str, local: bool) -> Result<(), String> {
            self.0
                .run_mobile_plugin::<Done>("start", Start { directory, local })
                .map(|_| ())
                .map_err(|e| e.to_string())
        }

        pub fn pick_profile(&self) -> Result<Picked, String> {
            self.0.run_mobile_plugin("pickProfile", ()).map_err(|e| e.to_string())
        }
    }

    pub fn init<R: Runtime>() -> TauriPlugin<R> {
        Builder::new("ripsec-vpn")
            .setup(|app, api| {
                let handle = api.register_android_plugin("io.github.plutopro.ripsec.vpn", "VpnPlugin")?;
                app.manage(Vpn(handle));
                Ok(())
            })
            .build()
    }
}
