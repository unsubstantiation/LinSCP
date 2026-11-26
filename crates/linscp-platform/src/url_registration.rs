//! Explicit per-user Windows URL registration. This only advertises LinSCP in
//! Default Apps; it never changes the user's chosen defaults or HKLM.

use std::path::Path;

pub const SCHEMES: &[&str] = &["sftp", "ssh", "scp", "ftp", "ftps", "ftpes", "dav", "davs", "webdav", "webdavs", "s3"];

/// Registers LinSCP as an available URL handler for the current Windows user.
pub fn install(launcher: &Path) -> Result<String, String> {
    #[cfg(windows)] { windows::install(&windows::Keys::production(), launcher) }
    #[cfg(not(windows))] { let _ = launcher; Err("URL handler registration is available on Windows only.".into()) }
}

/// Removes only LinSCP-owned registration. Windows controls default choices.
pub fn uninstall() -> Result<String, String> {
    #[cfg(windows)] { windows::uninstall(&windows::Keys::production()) }
    #[cfg(not(windows))] { Err("URL handler registration is available on Windows only.".into()) }
}

#[cfg(windows)]
mod windows {
    use super::*;
    use std::os::windows::process::CommandExt;
    use std::process::{Command, Output};

    const PROG_ID: &str = "LinSCP.Url";
    const MARKER: &str = "LinSCP-Managed";

    pub(super) struct Keys { class: String, capabilities: String, registered: String }
    impl Keys {
        pub(super) fn production() -> Self {
            Self { class: r"HKCU\Software\Classes\LinSCP.Url".into(),
                   capabilities: r"HKCU\Software\LinSCP\UrlHandlers\Capabilities".into(),
                   registered: r"HKCU\Software\RegisteredApplications".into() }
        }
        fn relative_capabilities(&self) -> &str { self.capabilities.strip_prefix("HKCU\\").unwrap_or(&self.capabilities) }
    }

    fn reg(args: &[&str]) -> Result<Output, String> {
        let system_root = std::env::var_os("SystemRoot").ok_or("SystemRoot is not set")?;
        let executable = std::path::PathBuf::from(system_root).join("System32").join("reg.exe");
        Command::new(executable).args(args).creation_flags(0x08000000).output()
            .map_err(|e| format!("Cannot run Windows registry tool: {e}"))
    }
    fn query(key: &str, value: Option<&str>) -> Result<Option<String>, String> {
        let mut args = vec!["query", key];
        if let Some(value) = value { args.extend(["/v", value]); }
        let output = reg(&args)?;
        if output.status.success() { Ok(Some(String::from_utf8_lossy(&output.stdout).into_owned())) }
        else { Ok(None) }
    }
    fn add(key: &str, value: Option<&str>, data: &str) -> Result<(), String> {
        let mut args = vec!["add", key];
        match value { Some(value) => args.extend(["/v", value]), None => args.push("/ve") }
        args.extend(["/t", "REG_SZ", "/d", data, "/f"]);
        if reg(&args)?.status.success() { Ok(()) } else { Err(format!("Could not write registry key {key}.")) }
    }
    fn delete(key: &str, value: Option<&str>) -> Result<(), String> {
        let mut args = vec!["delete", key];
        if let Some(value) = value { args.extend(["/v", value]); }
        args.push("/f");
        if reg(&args)?.status.success() { Ok(()) } else { Err(format!("Could not remove registry key {key}.")) }
    }
    fn marker(key: &str) -> String { format!(r"{key}\{MARKER}") }
    fn assert_owned_or_absent(key: &str) -> Result<(), String> {
        if query(key, None)?.is_some() && query(&marker(key), None)?.is_none() {
            return Err(format!("Refusing to replace an existing registry key not owned by LinSCP: {key}"));
        }
        Ok(())
    }
    fn registered_is_ours(keys: &Keys) -> Result<bool, String> {
        match query(&keys.registered, Some("LinSCP"))? {
            None => Ok(false),
            Some(output) if output.lines().any(|line| line.split_whitespace().last() == Some(keys.relative_capabilities())) => Ok(true),
            Some(_) => Err("Refusing to replace another application's LinSCP registration.".into()),
        }
    }
    fn launcher_command(launcher: &Path) -> Result<String, String> {
        let text = launcher.to_str().ok_or("The launcher path is not Unicode.")?;
        if !launcher.is_absolute() || text.chars().any(|c| c.is_control() || c == '"' || c == '%') {
            return Err("The launcher path cannot safely be registered as a URL handler.".into());
        }
        Ok(format!("\"{text}\" \"%1\""))
    }
    pub(super) fn install(keys: &Keys, launcher: &Path) -> Result<String, String> {
        let command = launcher_command(launcher)?;
        assert_owned_or_absent(&keys.class)?;
        assert_owned_or_absent(&keys.capabilities)?;
        let _ = registered_is_ours(keys)?;
        // Marker first makes a partially written registration removable on retry.
        add(&marker(&keys.class), None, "LinSCP URL handler")?;
        add(&marker(&keys.capabilities), None, "LinSCP URL handler")?;
        add(&keys.class, None, "URL:LinSCP session")?;
        add(&keys.class, Some("URL Protocol"), "")?;
        add(&format!(r"{}\shell\open\command", keys.class), None, &command)?;
        add(&keys.capabilities, Some("ApplicationName"), "LinSCP")?;
        add(&keys.capabilities, Some("ApplicationDescription"), "LinSCP file transfer session URLs")?;
        let associations = format!(r"{}\URLAssociations", keys.capabilities);
        for scheme in SCHEMES { add(&associations, Some(scheme), PROG_ID)?; }
        add(&keys.registered, Some("LinSCP"), keys.relative_capabilities())?;
        Ok("LinSCP is registered for this user. Choose defaults in Windows Settings; no defaults were changed.".into())
    }
    pub(super) fn uninstall(keys: &Keys) -> Result<String, String> {
        assert_owned_or_absent(&keys.class)?;
        assert_owned_or_absent(&keys.capabilities)?;
        let registered = registered_is_ours(keys)?;
        if registered { delete(&keys.registered, Some("LinSCP"))?; }
        for key in [&keys.class, &keys.capabilities] {
            if query(&marker(key), None)?.is_some() { delete(key, None)?; }
        }
        Ok("LinSCP URL registration removed for this user; Windows controls existing defaults.".into())
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn windows_url_registration_is_scoped_and_refuses_foreign_keys() {
            let base = format!(r"HKCU\Software\LinSCP-UrlTest-{}-{}", std::process::id(), rand::random::<u64>());
            let keys = Keys { class: format!(r"{base}\Classes\{PROG_ID}"), capabilities: format!(r"{base}\Capabilities"), registered: format!(r"{base}\RegisteredApplications") };
            let launcher = std::env::current_exe().unwrap();
            assert!(launcher_command(Path::new(r"C:\unsafe%path\app.exe")).is_err());
            add(&keys.class, None, "other application").unwrap();
            assert!(install(&keys, &launcher).is_err());
            assert!(uninstall(&keys).is_err());
            assert!(query(&keys.class, None).unwrap().is_some());
            delete(&keys.class, None).unwrap();
            install(&keys, &launcher).unwrap();
            assert!(registered_is_ours(&keys).unwrap());
            for scheme in SCHEMES { assert!(query(&format!(r"{}\URLAssociations", keys.capabilities), Some(scheme)).unwrap().is_some()); }
            assert!(query(&format!(r"{}\shell\open\command", keys.class), None).unwrap().unwrap().contains("%1"));
            uninstall(&keys).unwrap();
            assert!(query(&keys.class, None).unwrap().is_none());
            assert!(!registered_is_ours(&keys).unwrap());
            delete(&base, None).unwrap();
        }
    }
}
