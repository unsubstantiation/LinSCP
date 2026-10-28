//! Embedded `xterm.js` SSH channel bridge (`TerminalBridge`) multiplexed over
//! a tab's pooled `SshConnection`, with a bounded 256 KiB ring buffer and
//! monotonic byte offsets compatible with HTTP polling and WebSocket/Tauri events.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use base64::engine::general_purpose::STANDARD as BASE64_STD;
use base64::Engine as _;
use linscp_proto::ssh::{PtyShellEvent, PtyShellHandle, SshConnection};
use serde_json::{json, Value};
use tokio::sync::broadcast;

pub const DEFAULT_TERMINAL_BUFFER_LIMIT: usize = 256 * 1024;

struct TerminalRingState {
    buffer: Vec<u8>,
    dropped: u64,
    alive: bool,
    exit_code: Option<i32>,
    cols: u32,
    rows: u32,
}

#[derive(Clone)]
pub struct EmbeddedTerminal {
    pub id: String,
    pub tab_id: u64,
    buffer_limit: usize,
    handle: PtyShellHandle,
    ring: Arc<Mutex<TerminalRingState>>,
}

impl EmbeddedTerminal {
    pub async fn open_over_ssh(
        id: String,
        tab_id: u64,
        ssh: &Arc<SshConnection>,
        cols: u32,
        rows: u32,
        initial_dir: Option<&str>,
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

        let ring = Arc::new(Mutex::new(TerminalRingState {
            buffer: Vec::new(),
            dropped: 0,
            alive: true,
            exit_code: None,
            cols: init_cols,
            rows: init_rows,
        }));

        let ring_bg = Arc::clone(&ring);
        let id_bg = id.clone();
        let buffer_limit = DEFAULT_TERMINAL_BUFFER_LIMIT;
        tokio::spawn(async move {
            while let Some(evt) = rx.recv().await {
                match evt {
                    PtyShellEvent::Data(bytes) => {
                        if bytes.is_empty() {
                            continue;
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
            ring,
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
        self.handle.resize(cols, rows).is_ok()
    }

    pub fn write(&self, data: &[u8]) -> bool {
        if data.is_empty() {
            return self.is_alive();
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

    pub fn buffer_limit(&self) -> usize {
        self.buffer_limit
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
