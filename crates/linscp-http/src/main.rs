//! `linscp-web`: LinSCP in a browser.
//!
//! The native window (`linscp-gui`, from `linscp-tauri`) and this binary are the
//! two ways to run the same application: both serve `ui/dist`, both dispatch the
//! same requests to the same `CommanderService`. This binary is what a headless
//! host, a remote machine or a phone's browser uses, so a feature the page
//! offers is not one that only the native window can reach.
//!
//! The security model is the one `linscp-http` documents: a loopback bind by
//! default, a `Host`/`Origin` allowlist (DNS-rebinding defence) and a bearer
//! token printed once at startup.

use std::net::{IpAddr, SocketAddr};

use linscp_http::BrowserServer;

const USAGE: &str = "\
LinSCP browser server

Usage: linscp-web [options]

  --port=<port>          Port to listen on (8765 by default); 0 lets the system
                         pick one
  --allow-host=<host>    Accept this Host/Origin too (repeatable)
  --bind=<addr>          Address to bind; 127.0.0.1 by default
  --allow-remote         Bind 0.0.0.0 and print the token, for a container or a
                         headless host. The token is then the only thing between
                         the network and your sessions.
  --print-token          Print the access token for a script (the page is served
                         with it already, so opening the URL needs no typing)
  -h, --help             This text
";

fn fail(message: &str) -> ! {
    eprintln!("linscp-web: {message}");
    eprintln!();
    eprint!("{USAGE}");
    std::process::exit(2);
}

#[tokio::main]
async fn main() {
    let mut port: u16 = 8765;
    let mut print_token = false;
    let mut allowed_hosts: Vec<String> = Vec::new();
    let mut bind: Option<IpAddr> = None;
    let mut allow_remote = false;

    for arg in std::env::args().skip(1) {
        let (key, value) = match arg.split_once('=') {
            Some((key, value)) => (key, Some(value)),
            None => (arg.as_str(), None),
        };
        match key {
            "-h" | "--help" => {
                print!("{USAGE}");
                return;
            }
            "--port" => match value.and_then(|v| v.parse::<u16>().ok()) {
                Some(value) => port = value,
                None => fail("--port needs a number between 0 and 65535"),
            },
            "--print-token" => print_token = true,
            "--allow-host" => match value {
                Some(value) if !value.trim().is_empty() => {
                    allowed_hosts.push(value.trim().to_string())
                }
                _ => fail("--allow-host needs a host name"),
            },
            "--bind" => match value.and_then(|v| v.parse::<IpAddr>().ok()) {
                Some(ip) => bind = Some(ip),
                None => fail("--bind needs an IP address, for example 127.0.0.1"),
            },
            "--allow-remote" => allow_remote = true,
            other => fail(&format!("unknown option '{other}'")),
        }
    }

    let bind_addr = bind.or_else(|| allow_remote.then(|| IpAddr::from([0, 0, 0, 0])));
    let server = match BrowserServer::bind(
        port,
        &allowed_hosts,
        bind_addr.map(|ip| SocketAddr::new(ip, port)),
    ) {
        Ok(server) => server,
        Err(error) => fail(&format!("cannot listen on port {port}: {error}")),
    };

    // The page cannot be used without the token, and a token nobody can read is
    // no better; a loopback bind prints it only when asked, a remote bind
    // always does. Printing it is the one line a test or a user waits for.
    println!("Listening on {}", server.url());
    if print_token || allow_remote {
        println!("Token: {}", server.token);
    } else {
        println!("Start with --print-token to print the access token.");
    }
    if allow_remote {
        eprintln!(
            "linscp-web is reachable from the network; anyone with the token can \
             drive your sessions. Keep it on a trusted network or behind a proxy."
        );
    }
    if let Err(error) = server.serve().await {
        fail(&format!("the server stopped: {error}"));
    }
}
