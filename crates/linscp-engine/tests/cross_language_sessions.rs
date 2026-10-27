//! Cross-language integration tests proving `sessions.ini` + `sessions.key`
//! written by C++ `SessionStore.cpp` / Python `linscp_crypto.py` open and
//! round-trip cleanly in Rust on Linux and Windows.

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use linscp_engine::SessionStore;
use linscp_platform::{NativeSecretVault, SecretVault};
use linscp_types::ProtocolScheme;

const SHARED_SESSIONS_INI: &str = "\
# LinSCP saved sessions

[prod/app]
protocol=sftp
host=10.20.30.40
port=2222
username=deploy
password=lscp1$EBESExQVFhcYGRobHB0eH2D5KCrxRD3Ywhe8N9EQRMkWYEZi8Wgx82dw8JbNY1cG9ZqC/cQj0XOuABAB5uMk
hostkey=SHA256:prodHostPin123
remote_directory=/srv\\twith\\ttabs
local_directory=/tmp/local
tunnel=1
tunnel_host=bastion.example.com
tunnel_port=22
tunnel_username=jump
tunnel_password=lscp1$ICEiIyQlJicoKSorLC0uLwJf89rOmL8XWlWmcAv2HI4iqKCX/qjrJr45w/svIsylOzcYmuTY0gzoPSwfOQ==
tunnel_hostkey=SHA256:bastionPin456

[staging/s3]
protocol=s3
host=s3.eu-west-1.amazonaws.com
port=443
username=AKIAEXAMPLE
s3_storage_class=STANDARD_IA
";

#[test]
fn python_and_cpp_sessions_ini_opens_and_round_trips_in_rust() {
    let dir = std::env::temp_dir().join(format!(
        "linscp-xlang-test-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    // Base64-encoded 0x00..=0x1f master key (`sessions.key`), matching C++ & Python
    let raw_key: [u8; 32] = core::array::from_fn(|i| i as u8);
    std::fs::write(dir.join("sessions.key"), format!("{}\n", BASE64.encode(raw_key))).unwrap();
    std::fs::write(dir.join("sessions.ini"), SHARED_SESSIONS_INI).unwrap();

    let vault = NativeSecretVault::new();
    let loaded_key = vault.load_master_key(&dir).unwrap().unwrap();
    assert_eq!(*loaded_key, raw_key);

    let store = SessionStore::load_from_dir(&dir, &vault).expect("load shared sessions.ini");
    assert_eq!(store.folders(), vec!["prod", "staging"]);

    let prod = store.find("prod/app").expect("prod/app site");
    assert_eq!(prod.protocol, ProtocolScheme::Sftp);
    assert_eq!(prod.port, 2222);
    assert_eq!(prod.password.as_deref(), Some("Pr0d$Pass\t2026!"));
    assert_eq!(prod.remote_directory, "/srv\twith\ttabs");
    assert!(prod.tunnel.enabled);
    assert_eq!(prod.tunnel.password.as_deref(), Some("Bastion#Key99"));
    assert_eq!(prod.tunnel.hostkey, "SHA256:bastionPin456");

    let s3 = store.find("staging/s3").expect("staging/s3 site");
    assert_eq!(s3.protocol, ProtocolScheme::S3);
    assert_eq!(
        s3.extra_fields.get("s3_storage_class").map(String::as_str),
        Some("STANDARD_IA")
    );

    // Save from Rust and reload to prove full round-trip parity
    store.save_to_dir(&dir, &vault).expect("save sessions.ini from Rust");
    let reloaded = SessionStore::load_from_dir(&dir, &vault).expect("reload sessions.ini");
    let prod2 = reloaded.find("prod/app").unwrap();
    assert_eq!(prod2.password.as_deref(), Some("Pr0d$Pass\t2026!"));
    assert_eq!(prod2.tunnel.password.as_deref(), Some("Bastion#Key99"));
    assert_eq!(prod2.remote_directory, "/srv\twith\ttabs");

    let _ = std::fs::remove_dir_all(&dir);
}
