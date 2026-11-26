fn main() {
    // No commands are exposed to the page: only the application's Rust code calls the plugin.
    tauri_plugin::Builder::new(&[]).android_path("android").build();
}
