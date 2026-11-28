//! Explicit, isolated Linux MIT KDC/OpenSSH fixture; see tools/live_kerberos_ci.sh.
#![cfg(target_os = "linux")]
use linscp_engine::url_and_raw::{connect_ssh_for_shell, parse_site_url};
use std::path::Path;

#[tokio::test]
#[ignore = "requires isolated KDC and OpenSSH fixture"]
async fn live_kerberos_authentication_and_delegation() {
    let port = std::env::var("LINSCP_KRB_PORT").expect("fixture port");
    let user = std::env::var("LINSCP_KRB_USER").expect("fixture user");
    let fingerprint = std::env::var("LINSCP_KRB_HOSTKEY").expect("host key fingerprint");
    let cache = std::env::var("LINSCP_KRB_CACHE").expect("credential cache");
    let missing = format!("{cache}.missing");
    let mut spec = parse_site_url(&format!("ssh://{user}@127.0.0.1:{port}")).unwrap();
    spec.session.hostkey = fingerprint;
    spec.raw_fields.insert("auth_gssapi".into(), "1".into());
    spec.raw_fields.insert("logical_host".into(), "localhost".into());
    std::env::remove_var("SSH_AUTH_SOCK");
    std::env::set_var("KRB5CCNAME", &missing);
    assert!(connect_ssh_for_shell(&spec, Path::new("."), false, false, "en", 0, None).await.is_err(), "missing credentials must not authenticate");
    std::env::set_var("KRB5CCNAME", &cache);
    let mut wrong = spec.clone();
    wrong.raw_fields.insert("logical_host".into(), "wrong.invalid".into());
    assert!(connect_ssh_for_shell(&wrong, Path::new("."), false, false, "en", 0, None).await.is_err(), "wrong service principal must not authenticate");
    for (delegate, expected) in [(false, "no"), (true, "yes")] {
        spec.raw_fields.insert("gssapi_fwd_tgt".into(), if delegate { "1" } else { "0" }.into());
        let (conn, _) = connect_ssh_for_shell(&spec, Path::new("."), false, false, "en", 0, None)
            .await.unwrap_or_else(|error| panic!("Kerberos connect (delegation={delegate}): {error}"));
        let result = conn.exec_command("if [ -n \"$KRB5CCNAME\" ] && klist -s; then echo yes; else echo no; fi").await.unwrap();
        assert_eq!(String::from_utf8_lossy(&result.stdout).trim(), expected, "delegation={delegate}, stderr={}", String::from_utf8_lossy(&result.stderr));
        conn.disconnect().await.unwrap();
    }
}
