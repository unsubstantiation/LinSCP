#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    linscp_tauri::run_native_app(tauri::generate_context!());
}
