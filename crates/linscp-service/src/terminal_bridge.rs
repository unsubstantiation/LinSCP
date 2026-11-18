//! Embedded SSH shell bridge multiplexed over a tab's pooled `SshConnection`.
//!
//! Two consumers read the same shell. The ring buffer keeps the raw bytes for
//! window to ask for them after an offset, which is how the page and the
//! desktop window both used to get their output. The [`TerminalScreen`] is the
//! parsed state of the same bytes: the VT stream is fed to it as it arrives,
//! so a window can be handed cells and a cursor instead of a byte history and
//! a second emulator. Emulating once, here, is what lets two windows show the
//! same terminal and what stops the page from needing `xterm.js` at all.
//!
//! The ring stays because it is the only thing that can answer "what did I miss
//! while no window was open", and because a screen that has scrolled away its
//! history cannot be replayed from the grid.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use base64::engine::general_purpose::STANDARD as BASE64_STD;
use base64::Engine as _;
use linscp_proto::ssh::{PtyShellEvent, PtyShellHandle, SshConnection};
use linscp_terminal::{Size, TerminalScreen};
use serde_json::{json, Value};
use tokio::sync::broadcast;
use zeroize::Zeroizing;

pub const DEFAULT_TERMINAL_BUFFER_LIMIT: usize = 256 * 1024;

// Terminal output is untrusted. This is deliberately opt-in: even this exact
// sudo prompt can be forged by any program running on the remote host.
struct SudoPasswordResponder {
    password: Zeroizing<String>,
    prompt: Vec<u8>,
    output_tail: Vec<u8>,
    armed: bool,
}

impl SudoPasswordResponder {
    fn new(username: &str, password: String) -> Option<Self> {
        let password = Zeroizing::new(password);
        if username.is_empty() || username.chars().any(char::is_control)
            || password.is_empty() || password.chars().any(char::is_control) {
            return None;
        }
        Some(Self {
            password,
            prompt: format!("[sudo] password for {username}:").into_bytes(),
            output_tail: Vec::new(),
            armed: false,
        })
    }

    // Arm only on a user-submitted line. Never retry on a rejected password
    // until the user submits another line; startup output is never answered.
    fn input(&mut self, data: &[u8]) {
        if data.iter().any(|b| *b == b'\r' || *b == b'\n') {
            self.armed = true;
            self.output_tail.clear();
        }
        if data.contains(&3) { self.armed = false; self.output_tail.clear(); }
    }

    fn output(&mut self, data: &[u8]) -> Option<Vec<u8>> {
        if !self.armed { return None; }
        self.output_tail.extend_from_slice(data);
        if self.output_tail.len() > self.prompt.len() + 8 {
            let excess = self.output_tail.len() - (self.prompt.len() + 8);
            self.output_tail.drain(..excess);
        }
        let tail = self.output_tail.strip_suffix(b" ").unwrap_or(&self.output_tail);
        if tail.ends_with(&self.prompt) {
            self.armed = false;
            self.output_tail.clear();
            let mut response = self.password.as_bytes().to_vec();
            response.push(b'\n');
            return Some(response);
        }
        None
    }
}

struct TerminalRingState {
    buffer: Vec<u8>,
    dropped: u64,
    alive: bool,
    exit_code: Option<i32>,
    /// Why the session is no longer alive, when the server said why. A
    /// refused shell and a shell that exited are both "not alive"; only one
    /// of them is something the person at the keyboard can act on.
    failure: Option<String>,
    cols: u32,
    rows: u32,
}

#[derive(Clone)]
pub struct EmbeddedTerminal {
    pub id: String,
    pub tab_id: u64,
    buffer_limit: usize,
    handle: PtyShellHandle,
    sudo: Option<Arc<Mutex<SudoPasswordResponder>>>,
    ring: Arc<Mutex<TerminalRingState>>,
    /// The parsed screen, shared so a window can paint without owning the
    /// shell. `None` only if the terminal was built with a size no screen can
    /// have, which `open_over_ssh` refuses up front.
    screen: Arc<Mutex<Option<TerminalScreen>>>,
}

impl EmbeddedTerminal {
    pub async fn open_over_ssh(
        id: String,
        tab_id: u64,
        ssh: &Arc<SshConnection>,
        cols: u32,
        rows: u32,
        initial_dir: Option<&str>,
        sudo_credentials: Option<(String, String)>,
        event_tx: broadcast::Sender<Value>,
    ) -> Result<Self, String> {
        let init_cols = if (1..=1000).contains(&cols) { cols } else { 100 };
        let init_rows = if (1..=1000).contains(&rows) { rows } else { 30 };
        let (handle, mut rx) = ssh
            .open_pty_shell_session("xterm-256color", init_cols, init_rows)
            .await
            .map_err(|e| e.to_string())?;

        if let Some(dir) = initial_dir.map(str::trim).filter(|s| !s.is_empty() && *s != "~") {
            let escaped = dir.replace('\'', "'\\''");
            let cd_cmd = format!("cd -- '{escaped}' 2>/dev/null\n");
            let _ = handle.write_bytes(cd_cmd.into_bytes());
        }

        let screen = Arc::new(Mutex::new(TerminalScreen::new(Size::new(
            init_cols as usize,
            init_rows as usize,
        )).ok()));

        let ring = Arc::new(Mutex::new(TerminalRingState {
            buffer: Vec::new(),
            dropped: 0,
            alive: true,
            exit_code: None,
            failure: None,
            cols: init_cols,
            rows: init_rows,
        }));

        let sudo = sudo_credentials.and_then(|(user, password)| SudoPasswordResponder::new(&user, password))
            .map(|responder| Arc::new(Mutex::new(responder)));
        let sudo_bg = sudo.clone();
        let ring_bg = Arc::clone(&ring);
        let screen_bg = Arc::clone(&screen);
        // The replies a screen owes its program go back down the same channel
        // the output came up, so the reader task needs the handle too - and
        // the terminal keeps its own for input from a window.
        let handle_bg = handle.clone();
        let id_bg = id.clone();
        let buffer_limit = DEFAULT_TERMINAL_BUFFER_LIMIT;
        tokio::spawn(async move {
            while let Some(evt) = rx.recv().await {
                match evt {
                    PtyShellEvent::Data(bytes) => {
                        if bytes.is_empty() {
                            continue;
                        }
                        if let Some(responder) = &sudo_bg {
                            if let Ok(mut responder) = responder.lock() {
                                if let Some(response) = responder.output(&bytes) {
                                    let _ = handle_bg.write_bytes(response);
                                }
                            }
                        }
                        // Parse before storing: the screen is the authority on
                        // what the terminal shows, and a program waiting for a
                        // reply to a cursor-position query is waiting on this
                        // call. Its answer goes back down the same channel the
                        // output came up.
                        if let Ok(mut slot) = screen_bg.lock() {
                            if let Some(screen) = slot.as_mut() {
                                screen.advance(&bytes);
                                let replies = screen.take_replies();
                                if !replies.is_empty() {
                                    let _ = handle_bg.write_bytes(replies);
                                }
                            }
                        }
                        let offset = {
                            let mut g = ring_bg.lock().expect("terminal ring mutex");
                            g.buffer.extend_from_slice(&bytes);
                            if g.buffer.len() > buffer_limit {
                                let excess = g.buffer.len() - buffer_limit;
                                g.buffer.drain(0..excess);
                                g.dropped += excess as u64;
                            }
                            g.dropped + g.buffer.len() as u64
                        };
                        let _ = event_tx.send(json!({
                            "type": "terminal_output",
                            "terminal": id_bg,
                            "data": BASE64_STD.encode(&bytes),
                            "offset": offset,
                        }));
                    }
                    PtyShellEvent::ExitStatus(code) => {
                        let mut g = ring_bg.lock().expect("terminal ring mutex");
                        g.exit_code = Some(code as i32);
                    }
                    PtyShellEvent::Failed(reason) => {
                        let exit_code = {
                            let mut g = ring_bg.lock().expect("terminal ring mutex");
                            g.alive = false;
                            g.failure = Some(reason);
                            if g.exit_code.is_none() {
                                g.exit_code = Some(1);
                            }
                            g.exit_code
                        };
                        let _ = event_tx.send(json!({
                            "type": "terminal_closed",
                            "terminal": id_bg,
                            "exit_code": exit_code,
                        }));
                        break;
                    }
                    PtyShellEvent::Closed => {
                        let exit_code = {
                            let mut g = ring_bg.lock().expect("terminal ring mutex");
                            g.alive = false;
                            if g.exit_code.is_none() {
                                g.exit_code = Some(0);
                            }
                            g.exit_code
                        };
                        let _ = event_tx.send(json!({
                            "type": "terminal_closed",
                            "terminal": id_bg,
                            "exit_code": exit_code,
                        }));
                        break;
                    }
                }
            }
        });

        Ok(Self {
            id,
            tab_id,
            buffer_limit,
            handle,
            sudo,
            ring,
            screen,
        })
    }

    pub fn poll(&self, after: u64) -> (Vec<u8>, u64, bool, Option<i32>) {
        let g = self.ring.lock().expect("terminal ring mutex");
        let total = g.dropped + g.buffer.len() as u64;
        let data = if after >= total {
            Vec::new()
        } else if after <= g.dropped {
            g.buffer.clone()
        } else {
            let start = (after - g.dropped) as usize;
            g.buffer[start..].to_vec()
        };
        (data, total, g.alive, g.exit_code)
    }

    pub fn resize(&self, cols: u32, rows: u32) -> bool {
        if !(1..=1000).contains(&cols) || !(1..=1000).contains(&rows) {
            return false;
        }
        if let Ok(mut g) = self.ring.lock() {
            g.cols = cols;
            g.rows = rows;
        }
        // The parsed grid has to follow the PTY, or a program that redraws for
        // the new width is parsed into the old one and the screen and the
        // shell disagree about where the cursor is. The guard is a named
        // binding: a temporary dropped at the end of the `if let` would end the
        // borrow while the screen is still in use.
        if let Ok(mut slot) = self.screen.lock() {
            if let Some(screen) = slot.as_mut() {
                screen.resize(Size::new(cols as usize, rows as usize));
            }
        }
        self.handle.resize(cols, rows).is_ok()
    }

    pub fn write(&self, data: &[u8]) -> bool {
        if data.is_empty() {
            return self.is_alive();
        }
        if let Some(responder) = &self.sudo {
            if let Ok(mut responder) = responder.lock() { responder.input(data); }
        }
        self.handle.write_bytes(data.to_vec()).is_ok()
    }

    pub fn is_alive(&self) -> bool {
        self.ring
            .lock()
            .map(|g| g.alive)
            .unwrap_or(false)
    }

    pub fn dimensions(&self) -> (u32, u32) {
        self.ring
            .lock()
            .map(|g| (g.cols, g.rows))
            .unwrap_or((100, 30))
    }

    /// Why the session ended, when the server refused it. `None` for a shell
    /// that ran and finished, which needs no explanation.
    pub fn failure(&self) -> Option<String> {
        self.ring
            .lock()
            .map(|g| g.failure.clone())
            .unwrap_or(None)
    }

    pub fn buffer_limit(&self) -> usize {
        self.buffer_limit
    }

    /// The parsed screen, locked for the caller.
    ///
    /// A window paints from this rather than from the byte ring: the bytes are
    /// the history, the screen is what is on it. The guard is short-lived on
    /// both sides - the reader task holds it only for the length of one parse -
    /// so a paint never waits behind a transfer.
    pub fn with_screen<T>(&self, read: impl FnOnce(&mut TerminalScreen) -> T) -> Option<T> {
        let mut slot = self.screen.lock().ok()?;
        slot.as_mut().map(read)
    }

    pub fn close(&self) {
        self.handle.close();
        if let Ok(mut g) = self.ring.lock() {
            g.alive = false;
        }
    }
}

#[derive(Default)]
pub struct TerminalRegistry {
    next_id: u64,
    terminals: BTreeMap<String, EmbeddedTerminal>,
}

impl TerminalRegistry {
    pub fn allocate_id(&mut self) -> String {
        self.next_id += 1;
        format!("term-{}", self.next_id)
    }

    pub fn insert(&mut self, term: EmbeddedTerminal) {
        self.terminals.insert(term.id.clone(), term);
    }

    pub fn get(&self, id: &str) -> Option<EmbeddedTerminal> {
        self.terminals.get(id).cloned()
    }

    pub fn close(&mut self, id: &str) -> bool {
        if let Some(term) = self.terminals.remove(id) {
            term.close();
            true
        } else {
            false
        }
    }

    /// One summary per open terminal, in the order they were opened.
    pub fn summaries(&self) -> Vec<Value> {
        self.terminals
            .values()
            .map(|term| {
                let (cols, rows) = term.dimensions();
                let title = term
                    .with_screen(|screen| screen.title())
                    .flatten()
                    .filter(|title| !title.is_empty());
                json!({
                    "terminal": term.id,
                    "tab": term.tab_id,
                    "cols": cols,
                    "rows": rows,
                    "alive": term.is_alive(),
                    "title": title,
                })
            })
            .collect()
    }

    pub fn close_for_tab(&mut self, tab_id: u64) {
        let ids: Vec<String> = self
            .terminals
            .iter()
            .filter_map(|(k, v)| (v.tab_id == tab_id).then(|| k.clone()))
            .collect();
        for id in ids {
            self.close(&id);
        }
    }
}

#[cfg(test)]
mod sudo_password_tests {
    use super::SudoPasswordResponder;

    #[test]
    fn recognizes_split_prompt_only_after_input_and_once_per_submission() {
        let mut r = SudoPasswordResponder::new("alice", "secret".into()).unwrap();
        assert!(r.output(b"[sudo] password for alice: ").is_none());
        r.input(b"sudo apt update\r");
        assert!(r.output(b"[sudo] pass").is_none());
        assert_eq!(r.output(b"word for alice: "), Some(b"secret\n".to_vec()));
        assert!(r.output(b"[sudo] password for alice: ").is_none());
        r.input(b"sudo whoami\r");
        assert!(r.output(b"[sudo] password for bob: ").is_none());
        assert_eq!(r.output(b"[sudo] password for alice:"), Some(b"secret\n".to_vec()));
    }

    #[test]
    fn recognizes_prompt_split_at_every_byte_boundary() {
        let prompt = b"[sudo] password for alice: ";
        for split in 0..prompt.len() {
            let mut r = SudoPasswordResponder::new("alice", "secret".into()).unwrap();
            r.input(b"sudo true\r");
            let first = r.output(&prompt[..split]);
            let second = r.output(&prompt[split..]);
            assert_eq!(first.or(second), Some(b"secret\n".to_vec()), "split {split}");
        }
    }

    #[test]
    fn refuses_control_characters_and_cancels_on_control_c() {
        assert!(SudoPasswordResponder::new("alice", "bad\npassword".into()).is_none());
        assert!(SudoPasswordResponder::new("a\rb", "password".into()).is_none());
        let mut r = SudoPasswordResponder::new("alice", "password".into()).unwrap();
        r.input(b"sudo cmd\r");
        r.input(&[3]);
        assert!(r.output(b"[sudo] password for alice: ").is_none());
    }
}
