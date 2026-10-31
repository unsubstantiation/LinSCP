fn main() {
    #[cfg(feature = "native-shell")]
    tauri_build::build();
}
