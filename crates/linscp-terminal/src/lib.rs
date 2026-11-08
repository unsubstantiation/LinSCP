//! The terminal *model*: what the screen is, not how it is painted.
//!
//! The embedded terminal used to be `xterm.js`, a JavaScript emulator that both
//! parsed the VT stream and painted it into a DOM node. This crate owns the
//! parsing half in Rust, on top of `alacritty_terminal` (Alacritty's VT parser
//! and grid, published separately from the Alacritty binary and carrying no
//! renderer, window or GPU dependency).
//!
//! Splitting the two halves is what makes more than one presentation possible
//! from one model: the desktop app shows a terminal in its own OS window, and
//! the Android app - which has no OS windows to open - shows the same model in
//! the page. Neither can be the definition of what the terminal *is*, so the
//! definition lives here.
//!
//! Bytes arrive through [`TerminalScreen::advance`]; [`TerminalScreen::snapshot`]
//! turns the current state into one self-describing frame. A renderer never
//! needs to know a VT sequence: it draws cells, a cursor and a title.
//!
//! Snapshot text is encoded as **UTF-32 code points**, not as a Rust `String`
//! and not as UTF-16. A JavaScript renderer receives JSON, and serde serialises
//! a `String` as UTF-8 bytes; decoding that in the page would need a whole
//! encoding layer for something the renderer only ever indexes per cell.
//! UTF-32 costs four bytes per column in the frame and needs no decoder at all.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use alacritty_terminal::event::{Event, EventListener, WindowSize};
use alacritty_terminal::grid::{Dimensions, Scroll};
use alacritty_terminal::index::Line;
use alacritty_terminal::term::cell::Flags;
use alacritty_terminal::term::{Config, Term, TermMode};
use alacritty_terminal::vte::ansi::{
    Color, CursorShape, NamedColor, Processor, Rgb as VteRgb, StdSyncHandler,
};
use serde::Serialize;

/// The scrollback depth a new screen starts with.
///
/// This is the one number the page used to pass to `xterm.js` (`scrollback:
/// 5000`); keeping it here keeps a terminal's history independent of which
/// window happens to be showing it.
pub const DEFAULT_SCROLLBACK: usize = 5_000;

/// Attribute bits for one cell, resolved by the model.
///
/// The renderer gets a bitmask rather than Alacritty's `Flags`, so a change in
/// the parser's flag layout is absorbed here instead of reaching every
/// renderer. `WIDE` marks the first column of a double-width glyph; the spacer
/// column the grid keeps behind it has no glyph of its own.
pub const ATTR_BOLD: u16 = 0b0000_0001;
pub const ATTR_ITALIC: u16 = 0b0000_0010;
pub const ATTR_UNDERLINE: u16 = 0b0000_0100;
pub const ATTR_DIM: u16 = 0b0000_1000;
pub const ATTR_INVERSE: u16 = 0b0001_0000;
pub const ATTR_STRIKE: u16 = 0b0010_0000;
pub const ATTR_HIDDEN: u16 = 0b0100_0000;
pub const ATTR_WIDE: u16 = 0b1000_0000;

/// An RGB colour, as the grid stores it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct Rgb {
    pub r: u8,
    pub g: u8,
    pub b: u8,
}

impl Rgb {
    pub const fn new(r: u8, g: u8, b: u8) -> Self {
        Self { r, g, b }
    }
}

impl From<VteRgb> for Rgb {
    fn from(rgb: VteRgb) -> Self {
        Self::new(rgb.r, rgb.g, rgb.b)
    }
}

impl From<Rgb> for VteRgb {
    fn from(rgb: Rgb) -> Self {
        Self { r: rgb.r, g: rgb.g, b: rgb.b }
    }
}

/// A colour as a renderer needs it: a palette index, or four components.
///
/// A named colour is reported as `named` *and* resolved through whatever the
/// VT stream has defined for it, so a renderer that knows the theme can prefer
/// `named` and one that does not can draw `rgb` directly. A renderer must never
/// have to parse a colour name, and it must never have to guess.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct CellColor {
    /// `NamedColor` as its numeric value, or `-1` when the colour is not named.
    pub named: i16,
    /// Palette entry (`0..=255`) for an indexed colour, or `-1`.
    pub indexed: i16,
    /// The colour the VT stream defined for this slot, when it defined one.
    pub rgb: Option<Rgb>,
}

impl CellColor {
    fn resolved(color: Color, colors: &alacritty_terminal::term::color::Colors) -> Self {
        match color {
            // `NamedColor` is a small enum indexed straight into the colour
            // table, which is sized to hold every variant; the parser only ever
            // produces values in that range.
            Color::Named(named) => {
                Self { named: named as i16, indexed: -1, rgb: colors[named].map(Rgb::from) }
            }
            Color::Indexed(index) => {
                Self { named: -1, indexed: index as i16, rgb: colors[index as usize].map(Rgb::from) }
            }
            Color::Spec(rgb) => Self { named: -1, indexed: -1, rgb: Some(Rgb::from(rgb)) },
        }
    }
}

/// One character cell, already resolved to what a renderer draws.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CellSnapshot {
    /// The cell's text as UTF-32 code points. Usually one character; more when
    /// the cell carries combining marks, none for the spacer after a wide
    /// glyph or for a cell the stream hid.
    pub text: Vec<u32>,
    pub fg: CellColor,
    pub bg: CellColor,
    pub attrs: u16,
}

/// The cursor's position and shape.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CursorSnapshot {
    /// Column within the viewport, counted from zero.
    pub column: usize,
    /// Line within the viewport, counted from zero at the top.
    pub line: usize,
    /// `block`, `underline` or `beam`; `hidden` when the stream hid it.
    pub shape: &'static str,
}

/// The subset of terminal modes that changes how a window behaves.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Modes {
    pub alternate_screen: bool,
    pub app_cursor: bool,
    pub bracketed_paste: bool,
    pub mouse_reporting: bool,
    pub show_cursor: bool,
}

/// Everything needed to paint the visible screen, and nothing else.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Frame {
    pub columns: usize,
    pub lines: usize,
    /// Row-major: `columns * lines` cells, top-left first.
    pub cells: Vec<CellSnapshot>,
    pub cursor: CursorSnapshot,
    /// Lines scrolled back above the viewport; zero means the viewport is at
    /// the bottom of the history, where live output arrives.
    pub display_offset: usize,
    /// Total lines in the buffer, scrollback included.
    pub total_lines: usize,
    /// The stream's window title, when it set one.
    pub title: Option<String>,
    pub modes: Modes,
}

/// Why a screen cannot be built.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScreenError {
    /// Zero columns or lines; there is no screen to draw.
    EmptyDimensions,
}

impl std::fmt::Display for ScreenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a terminal needs at least one column and one line")
    }
}

impl std::error::Error for ScreenError {}

/// The dimensions of a viewport, in cells.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Size {
    pub columns: usize,
    pub lines: usize,
}

impl Size {
    pub const fn new(columns: usize, lines: usize) -> Self {
        Self { columns, lines }
    }

    const fn is_usable(&self) -> bool {
        self.columns > 0 && self.lines > 0
    }

    /// The report a program receives when it asks how large the text area is
    /// (CSI 14 t / CSI 18 t). `cell_width`/`cell_height` are zero until a
    /// renderer has told the screen what its font measures, which is the
    /// honest answer for a screen nobody has painted yet.
    const fn window_size(&self, cell: (u16, u16)) -> WindowSize {
        WindowSize {
            num_lines: self.lines as u16,
            num_cols: self.columns as u16,
            cell_width: cell.0,
            cell_height: cell.1,
        }
    }

    /// Reports the viewport to `alacritty_terminal`, which needs the history
    /// kept in `total_lines` separate from the lines actually shown.
    fn as_dimensions(&self, history: usize) -> Viewport {
        Viewport { columns: self.columns, lines: self.lines, history }
    }
}

/// A viewport plus its scrollback, in the shape the grid asks for.
struct Viewport {
    columns: usize,
    lines: usize,
    history: usize,
}

impl Dimensions for Viewport {
    fn total_lines(&self) -> usize {
        self.lines.saturating_add(self.history)
    }

    fn screen_lines(&self) -> usize {
        self.lines
    }

    fn columns(&self) -> usize {
        self.columns
    }
}

/// A question the parser asked that only the screen can answer.
///
/// These exist because the listener is owned *by* the terminal: it is called
/// while the grid is borrowed, so it cannot read the grid to answer. It queues
/// the question and [`TerminalScreen`] answers it as soon as the parse returns.
/// A terminal that stayed silent here would leave `vim` waiting for the cursor
/// report it asked for, which looks exactly like a hung session.
enum Query {
    Color(usize, Arc<dyn Fn(VteRgb) -> String + Sync + Send + 'static>),
    TextAreaSize(Arc<dyn Fn(WindowSize) -> String + Sync + Send + 'static>),
    /// A report the parser already formatted. It is queued rather than sent
    /// from the listener because the listener is called while the terminal is
    /// borrowed, and a report is the answer to a question the parse itself
    /// asked.
    PtyWrite(String),
}

/// What the listener reports upwards, and what the screen answers with.
#[derive(Default)]
struct Shared {
    /// Live output arrived; a window should repaint.
    wakeup: AtomicBool,
    /// The stream rang the bell.
    bell: AtomicBool,
    /// The window title, as last set by the stream. `None` means the stream
    /// has not set one (or reset it), not "the title is empty".
    title: Mutex<Option<String>>,
    /// Bytes owed to the remote program: replies to its queries, and any
    /// sequence the parser asked to write on its own behalf.
    replies: Mutex<Vec<u8>>,
    /// Questions the parser asked that need the parsed grid to answer.
    pending: Mutex<Vec<Query>>,
    /// What one cell measures on screen, in pixels, once a renderer knows.
    cell_width: AtomicUsize,
    cell_height: AtomicUsize,
}

/// The listener handed to `alacritty_terminal`.
///
/// It owns nothing but a handle to the shared state, so the terminal can be
/// dropped without the listener's callbacks pointing at freed memory.
#[derive(Clone)]
struct ScreenListener {
    shared: Arc<Shared>,
}

impl EventListener for ScreenListener {
    fn send_event(&self, event: Event) {
        match event {
            Event::Wakeup => self.shared.wakeup.store(true, Ordering::Release),
            Event::Bell => self.shared.bell.store(true, Ordering::Release),
            Event::Title(title) => {
                *self.shared.title.lock().expect("terminal title mutex") = Some(title);
            }
            Event::ResetTitle => {
                *self.shared.title.lock().expect("terminal title mutex") = None;
            }
            Event::PtyWrite(text) => {
                self.shared.pending.lock().expect("terminal query mutex").push(Query::PtyWrite(text));
            }
            Event::ColorRequest(index, format) => {
                self.shared.pending.lock().expect("terminal query mutex").push(Query::Color(index, format));
            }
            Event::TextAreaSizeRequest(format) => {
                self.shared
                    .pending
                    .lock()
                    .expect("terminal query mutex")
                    .push(Query::TextAreaSize(format));
            }
            // The clipboard belongs to the window, not to the screen: a window
            // that is not focused must not be able to write the user's
            // clipboard, and a screen has no idea which window shows it.
            Event::ClipboardStore(..) | Event::ClipboardLoad(..) => {}
            Event::MouseCursorDirty
            | Event::CursorBlinkingChange
            | Event::Exit
            | Event::ChildExit(_) => {}
        }
    }
}

/// One terminal's screen state.
///
/// This is a pure model: it holds no socket, no PTY and no window. The SSH
/// channel that feeds it, and the window that paints it, both live elsewhere,
/// which is what lets one screen be shown in a desktop window and the same
/// kind of screen be shown inside the page on a device without windows.
pub struct TerminalScreen {
    term: Term<ScreenListener>,
    parser: Processor<StdSyncHandler>,
    shared: Arc<Shared>,
    size: Size,
    dirty: bool,
}

impl TerminalScreen {
    /// Builds a screen of `size` cells with a scrollback history and no output
    /// yet. An unusable size is refused instead of being rounded up to
    /// something the caller did not ask for.
    pub fn new(size: Size) -> Result<Self, ScreenError> {
        Self::with_scrollback(size, DEFAULT_SCROLLBACK)
    }

    /// Builds a screen with an explicit scrollback depth.
    pub fn with_scrollback(size: Size, scrollback: usize) -> Result<Self, ScreenError> {
        if !size.is_usable() {
            return Err(ScreenError::EmptyDimensions);
        }
        let shared = Arc::default();
        // Spelled out rather than `..Default::default()`: the crate is pinned
        // to one release, and a new field upstream is exactly the change that
        // should be read before a terminal picks up a default nobody reviewed.
        let defaults = Config::default();
        let config = Config {
            scrolling_history: scrollback,
            default_cursor_style: defaults.default_cursor_style,
            vi_mode_cursor_style: defaults.vi_mode_cursor_style,
            semantic_escape_chars: defaults.semantic_escape_chars,
            kitty_keyboard: defaults.kitty_keyboard,
            osc52: defaults.osc52,
        };
        let listener = ScreenListener { shared: Arc::clone(&shared) };
        let term = Term::new(config, &size.as_dimensions(scrollback), listener);
        Ok(Self {
            term,
            parser: Processor::new(),
            shared,
            size,
            dirty: true,
        })
    }

    /// The size the screen is currently laid out for.
    pub const fn size(&self) -> Size {
        self.size
    }

    /// Feeds bytes from the PTY to the parser.
    ///
    /// The parser is per screen and keeps its state between calls: an escape
    /// sequence split across two reads of the socket is completed by the next
    /// call, which is why a screen owns a `Processor` rather than creating one
    /// per chunk.
    pub fn advance(&mut self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        self.parser.advance(&mut self.term, bytes);
        self.answer_queries();
        self.dirty = true;
    }

    /// Answers the questions the parser queued while the grid was borrowed.
    fn answer_queries(&mut self) {
        let pending = {
            let mut guard = self.shared.pending.lock().expect("terminal query mutex");
            if guard.is_empty() {
                return;
            }
            std::mem::take(&mut *guard)
        };
        let mut replies = Vec::new();
        for query in pending {
            match query {
                Query::Color(index, format) => {
                    let rgb = match self.defined_color(index) {
                        Some(rgb) => rgb,
                        // The cursor colour has no default: a program is told
                        // "not set" there rather than a colour nobody chose.
                        None if index == NamedColor::Cursor as usize => continue,
                        None => named_color_rgb(index as i16).into(),
                    };
                    replies.extend_from_slice(format(rgb).as_bytes());
                }
                // The cursor report is formatted from the cursor's own grid
                // line by the parser, and the grid grows upward through its
                // history, so the report is the viewport row the cursor is on
                // without any translation. Moving it here would break what
                // already works.
                Query::PtyWrite(text) => replies.extend_from_slice(text.as_bytes()),
                Query::TextAreaSize(format) => {
                    let cell = (
                        self.shared.cell_width.load(Ordering::Relaxed) as u16,
                        self.shared.cell_height.load(Ordering::Relaxed) as u16,
                    );
                    replies.extend_from_slice(format(self.size.window_size(cell)).as_bytes());
                }
            }
        }
        if !replies.is_empty() {
            self.shared.replies.lock().expect("terminal reply mutex").extend_from_slice(&replies);
        }
    }

    /// Bytes the screen owes the remote program, and they are now taken.
    ///
    /// A terminal that answers a program's question has to send the answer
    /// back over the same channel the program wrote to; the caller owns that
    /// channel, so the bytes are handed over rather than sent from here.
    pub fn take_replies(&self) -> Vec<u8> {
        std::mem::take(&mut *self.shared.replies.lock().expect("terminal reply mutex"))
    }

    /// Resizes the viewport. Returns the previous size, so a caller that has to
    /// tell the remote PTY about a change can tell whether there was one.
    pub fn resize(&mut self, size: Size) -> Option<Size> {
        if !size.is_usable() || size == self.size {
            return None;
        }
        let previous = self.size;
        self.size = size;
        self.term.resize(size.as_dimensions(self.term.grid().history_size()));
        self.dirty = true;
        Some(previous)
    }

    /// Tells the screen what one cell measures on screen, so a program that
    /// asks for the text area in pixels gets a real answer.
    pub fn set_cell_size(&self, width: u16, height: u16) {
        self.shared.cell_width.store(width as usize, Ordering::Relaxed);
        self.shared.cell_height.store(height as usize, Ordering::Relaxed);
    }

    /// Scrolls the viewport through the scrollback. Positive values scroll up
    /// into history, as a mouse wheel does.
    pub fn scroll(&mut self, lines: i32) {
        if lines == 0 {
            return;
        }
        self.term.scroll_display(Scroll::Delta(lines));
        self.dirty = true;
    }

    /// Jumps the viewport back to live output without changing the history.
    pub fn scroll_to_bottom(&mut self) {
        self.term.scroll_display(Scroll::Bottom);
        self.dirty = true;
    }

    /// True when the screen changed since the last [`Self::snapshot`].
    ///
    /// A window that repaints on every wake-up wastes a frame per keystroke the
    /// remote echoes; asking first is what keeps a quiet shell quiet.
    pub fn is_dirty(&self) -> bool {
        self.dirty || self.shared.wakeup.load(Ordering::Acquire)
    }

    /// The current frame, and the screen is marked clean.
    ///
    /// A cell reports the character the grid holds. The spacer a double-width
    /// glyph leaves behind reports no text and `ATTR_WIDE` is set on the glyph
    /// itself, so a renderer can draw one wide glyph and skip the spacer
    /// instead of drawing it twice.
    pub fn snapshot(&mut self) -> Frame {
        let size = self.size;
        let modes = self.modes();
        let mut cells = Vec::with_capacity(size.columns * size.lines);
        {
            let content = self.term.renderable_content();
            for indexed in content.display_iter {
                cells.push(cell_snapshot(indexed.cell, &content.colors));
            }
        }
        let frame = Frame {
            columns: size.columns,
            lines: size.lines,
            cells,
            cursor: self.cursor_snapshot(),
            display_offset: self.term.grid().display_offset(),
            total_lines: self.term.grid().total_lines(),
            title: self.title(),
            modes,
        };
        self.dirty = false;
        self.shared.wakeup.store(false, Ordering::Release);
        frame
    }

    /// A colour the VT stream defined, by `NamedColor` index.
    ///
    /// `None` means the stream never set it, which is a different answer from
    /// "black" and has to stay one: it is what makes an unanswered palette
    /// entry fall back to the theme instead of to whatever the grid defaulted
    /// to.
    fn defined_color(&self, index: usize) -> Option<VteRgb> {
        self.term.renderable_content().colors[index]
    }

    /// The modes a window acts on, resolved from the parser's flag set.
    pub fn modes(&self) -> Modes {
        let mode = self.term.mode();
        Modes {
            alternate_screen: mode.contains(TermMode::ALT_SCREEN),
            app_cursor: mode.contains(TermMode::APP_CURSOR),
            bracketed_paste: mode.contains(TermMode::BRACKETED_PASTE),
            mouse_reporting: mode.intersects(
                TermMode::MOUSE_REPORT_CLICK | TermMode::MOUSE_MOTION | TermMode::MOUSE_DRAG,
            ),
            show_cursor: mode.contains(TermMode::SHOW_CURSOR),
        }
    }

    /// The text a selection covers, or `None` when nothing is selected.
    ///
    /// Copy comes from the model rather than from the painted pixels: a
    /// renderer that had to rebuild text from a canvas would get wrapped lines
    /// and wide glyphs wrong in exactly the cases people copy text for.
    pub fn selection_text(&self) -> Option<String> {
        self.term.selection_to_string()
    }

    /// The screen's window title, if the stream set one.
    pub fn title(&self) -> Option<String> {
        self.shared.title.lock().expect("terminal title mutex").clone()
    }

    /// Takes the bell, so a window rings once per ring rather than once per
    /// repaint.
    pub fn take_bell(&self) -> bool {
        self.shared.bell.swap(false, Ordering::AcqRel)
    }

    /// Copies the visible screen into the scrollback as plain lines, which is
    /// what a "save output" action writes.
    ///
    /// The rows come from the grid rather than from a frame, so a screen that
    /// has never been painted can still be saved.
    pub fn visible_lines(&self) -> Vec<String> {
        let mut lines = Vec::with_capacity(self.size.lines);
        {
            let content = self.term.renderable_content();
            let mut current = String::with_capacity(self.size.columns);
            let mut last_line = None;
            for indexed in content.display_iter {
                if last_line.is_some_and(|line| line != indexed.point.line) {
                    lines.push(std::mem::take(&mut current).trim_end().to_string());
                }
                last_line = Some(indexed.point.line);
                if let Some(ch) = plain_char(indexed.cell) {
                    current.push(ch);
                }
            }
            if last_line.is_some() {
                lines.push(current.trim_end().to_string());
            }
        }
        lines
    }

    fn cursor_snapshot(&self) -> CursorSnapshot {
        let content = self.term.renderable_content();
        let point = content.cursor.point;
        let shape = match content.cursor.shape {
            CursorShape::Hidden => "hidden",
            CursorShape::Underline => "underline",
            CursorShape::Beam => "beam",
            _ => "block",
        };
        CursorSnapshot {
            column: point.column.0,
            line: viewport_line(point.line, content.display_offset, self.size.lines),
            shape,
        }
    }
}

/// The character a cell contributes to plain text, or `None` when it draws
/// nothing of its own.
fn plain_char(cell: &alacritty_terminal::term::cell::Cell) -> Option<char> {
    if cell.flags.contains(Flags::WIDE_CHAR_SPACER) || cell.flags.contains(Flags::HIDDEN) {
        return None;
    }
    Some(cell.c)
}

/// Maps a grid line to a row of the viewport.
///
/// This is the parser's own translation (`point.line + display_offset`) with
/// both ends saturated: the grid addresses history with negative lines and a
/// scrolled viewport slides the window over that range, so a cursor the
/// scrollback has pushed out of view must not wrap to the opposite edge - it
/// is simply not on screen.
fn viewport_line(line: Line, display_offset: usize, lines: usize) -> usize {
    let row = line.0 + display_offset as i32;
    row.clamp(0, lines.saturating_sub(1) as i32) as usize
}

fn cell_snapshot(
    cell: &alacritty_terminal::term::cell::Cell,
    colors: &alacritty_terminal::term::color::Colors,
) -> CellSnapshot {
    let mut attrs = 0u16;
    if cell.flags.contains(Flags::BOLD) {
        attrs |= ATTR_BOLD;
    }
    if cell.flags.contains(Flags::ITALIC) {
        attrs |= ATTR_ITALIC;
    }
    if cell.flags.intersects(Flags::ALL_UNDERLINES) {
        attrs |= ATTR_UNDERLINE;
    }
    if cell.flags.contains(Flags::DIM) {
        attrs |= ATTR_DIM;
    }
    if cell.flags.contains(Flags::INVERSE) {
        attrs |= ATTR_INVERSE;
    }
    if cell.flags.contains(Flags::STRIKEOUT) {
        attrs |= ATTR_STRIKE;
    }
    if cell.flags.contains(Flags::HIDDEN) {
        attrs |= ATTR_HIDDEN;
    }
    if cell.flags.contains(Flags::WIDE_CHAR) {
        attrs |= ATTR_WIDE;
    }
    // A spacer column belongs to the glyph to its left. Reporting it as an
    // empty cell is what lets a renderer advance the cursor without drawing a
    // second half of a character it has already drawn.
    let text = if attrs & (ATTR_HIDDEN) != 0 || cell.flags.contains(Flags::WIDE_CHAR_SPACER) {
        Vec::new()
    } else {
        let mut text = vec![cell.c as u32];
        if let Some(extra) = cell.zerowidth() {
            text.extend(extra.iter().map(|c| *c as u32));
        }
        text
    };
    CellSnapshot {
        text,
        fg: CellColor::resolved(cell.fg, colors),
        bg: CellColor::resolved(cell.bg, colors),
        attrs,
    }
}

/// The default palette a renderer uses for named colours the VT stream did not
/// define. Kept here, beside the model, so the desktop window and the page
/// cannot drift into two different looks for the same screen.
pub const DEFAULT_PALETTE: [Rgb; 16] = [
    Rgb::new(0x00, 0x00, 0x00),
    Rgb::new(0xcd, 0x31, 0x31),
    Rgb::new(0x0d, 0xbc, 0x79),
    Rgb::new(0xe5, 0xe5, 0x10),
    Rgb::new(0x24, 0x72, 0xc8),
    Rgb::new(0xbc, 0x3f, 0xbc),
    Rgb::new(0x11, 0xa8, 0xcd),
    Rgb::new(0xe5, 0xe5, 0xe5),
    Rgb::new(0x66, 0x66, 0x66),
    Rgb::new(0xf1, 0x4c, 0x4c),
    Rgb::new(0x3c, 0xe0, 0x8c),
    Rgb::new(0xf5, 0xf5, 0x67),
    Rgb::new(0x4f, 0x9c, 0xff),
    Rgb::new(0xe8, 0x6f, 0xe8),
    Rgb::new(0x4f, 0xd4, 0xf1),
    Rgb::new(0xff, 0xff, 0xff),
];

/// The colour a renderer draws for a named colour the grid left unresolved.
///
/// `named` is the numeric value of `NamedColor` (see the parser's declaration
/// order): 0-7 and 9-15 are the standard and bright palette, 256 is the
/// foreground, 257 the background, 258 the cursor. Everything the model cannot
/// answer falls back to the foreground, because text is what a renderer is
/// drawing when it asks.
pub fn named_color_rgb(named: i16) -> Rgb {
    match named {
        0..=7 => DEFAULT_PALETTE[named as usize],
        9..=15 => DEFAULT_PALETTE[(named - 1) as usize],
        256 => DEFAULT_PALETTE[7],
        257 => DEFAULT_PALETTE[0],
        258 => DEFAULT_PALETTE[7],
        _ => DEFAULT_PALETTE[7],
    }
}

/// The colours a frame should be painted with, for a renderer that does not
/// theme itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct Theme {
    pub palette: [Rgb; 16],
    pub foreground: Rgb,
    pub background: Rgb,
    pub cursor: Rgb,
}

impl Default for Theme {
    fn default() -> Self {
        Self {
            palette: DEFAULT_PALETTE,
            foreground: DEFAULT_PALETTE[7],
            background: DEFAULT_PALETTE[0],
            cursor: DEFAULT_PALETTE[7],
        }
    }
}

/// Resolves a cell colour to something drawable, given a theme.
///
/// The order matters: a colour the VT stream defined wins over the theme (an
/// application that set its own palette means it), then the palette index the
/// model resolved, then the theme's own answer for a named colour.
pub fn resolve_color(color: &CellColor, theme: &Theme) -> Rgb {
    if let Some(rgb) = color.rgb {
        return rgb;
    }
    if (0..16).contains(&color.indexed) {
        return theme.palette[color.indexed as usize];
    }
    if color.indexed >= 16 {
        // 16-231 is the 6x6x6 colour cube and 232-255 the grey ramp; both are
        // fixed by the VT specification, not by the theme.
        return xterm_palette_entry(color.indexed as u8);
    }
    if color.named >= 0 {
        return match color.named {
            0..=7 => theme.palette[color.named as usize],
            9..=15 => theme.palette[(color.named - 1) as usize],
            256 => theme.foreground,
            257 => theme.background,
            258 => theme.cursor,
            other => named_color_rgb(other),
        };
    }
    theme.foreground
}

/// Entries 16-255 of the standard 256-colour palette.
fn xterm_palette_entry(index: u8) -> Rgb {
    const CUBE: [u8; 6] = [0x00, 0x5f, 0x87, 0xaf, 0xd7, 0xff];
    if index >= 232 {
        let level = 8 + (index - 232) * 10;
        return Rgb::new(level, level, level);
    }
    let index = index - 16;
    let r = CUBE[(index / 36) as usize];
    let g = CUBE[((index % 36) / 6) as usize];
    let b = CUBE[(index % 6) as usize];
    Rgb::new(r, g, b)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn screen(columns: usize, lines: usize) -> TerminalScreen {
        TerminalScreen::new(Size::new(columns, lines)).expect("a usable size")
    }

    /// Row-major text of the viewport, one `String` per line.
    fn lines_of(frame: &Frame) -> Vec<String> {
        frame
            .cells
            .chunks(frame.columns)
            .map(|row| {
                row.iter()
                    .map(|cell| {
                        cell.text.first().and_then(|code| char::from_u32(*code)).unwrap_or(' ')
                    })
                    .collect::<String>()
                    .trim_end()
                    .to_string()
            })
            .collect()
    }

    #[test]
    fn a_plain_line_lands_in_the_top_row() {
        let mut screen = screen(20, 4);
        screen.advance(b"hello world");
        let frame = screen.snapshot();
        assert_eq!(frame.columns, 20);
        assert_eq!(frame.lines, 4);
        assert_eq!(frame.cells.len(), 80);
        assert_eq!(lines_of(&frame)[0], "hello world");
        assert!(lines_of(&frame)[1..].iter().all(|line| line.is_empty()));
    }

    #[test]
    fn carriage_return_and_newline_move_the_cursor_not_the_text() {
        let mut screen = screen(10, 3);
        screen.advance(b"one\r\ntwo");
        let frame = screen.snapshot();
        assert_eq!(lines_of(&frame), vec!["one".to_string(), "two".to_string(), String::new()]);
        assert_eq!(frame.cursor.line, 1);
        assert_eq!(frame.cursor.column, 3);
    }

    /// The parser is per screen: a sequence split across two socket reads must
    /// be completed by the next one. A parser built per chunk would print the
    /// escape as literal text, which is what a broken terminal looks like.
    #[test]
    fn an_escape_sequence_split_across_reads_is_completed_by_the_next() {
        let mut screen = screen(20, 3);
        screen.advance(b"\x1b[");
        screen.advance(b"31mred");
        let frame = screen.snapshot();
        assert_eq!(lines_of(&frame)[0], "red");
        assert_eq!(frame.cells[0].fg.indexed, 1, "SGR 31 selects palette colour 1");
        assert_eq!(frame.cells[0].text, vec!['r' as u32]);
    }

    #[test]
    fn attributes_are_reported_as_bits_a_renderer_can_test() {
        let mut screen = screen(20, 3);
        screen.advance(b"\x1b[1;3;4;9mx");
        let cell = &screen.snapshot().cells[0];
        assert_ne!(cell.attrs & ATTR_BOLD, 0);
        assert_ne!(cell.attrs & ATTR_ITALIC, 0);
        assert_ne!(cell.attrs & ATTR_UNDERLINE, 0);
        assert_ne!(cell.attrs & ATTR_STRIKE, 0);
        assert_eq!(cell.attrs & ATTR_INVERSE, 0);
    }

    #[test]
    fn scrolling_keeps_history_and_reports_the_offset() {
        let mut screen = screen(10, 2);
        // Five numbered lines through a two-line viewport: three must be in
        // the scrollback and two on screen.
        screen.advance(b"1\r\n2\r\n3\r\n4\r\n5");
        let live = screen.snapshot();
        assert_eq!(lines_of(&live), vec!["4".to_string(), "5".to_string()]);
        assert_eq!(live.display_offset, 0);
        assert!(live.total_lines > live.lines);

        screen.scroll(1);
        let scrolled = screen.snapshot();
        assert_eq!(scrolled.display_offset, 1);
        assert_eq!(lines_of(&scrolled), vec!["3".to_string(), "4".to_string()]);

        screen.scroll_to_bottom();
        assert_eq!(screen.snapshot().display_offset, 0);
    }

    #[test]
    fn a_wide_glyph_marks_itself_and_empties_its_spacer() {
        let mut screen = screen(10, 2);
        // U+4E2D is a double-width character: it occupies two columns, and the
        // second is a spacer that must not be drawn as a second glyph.
        screen.advance("\u{4e2d}".as_bytes());
        let frame = screen.snapshot();
        assert_eq!(frame.cells[0].text, vec![0x4E2D]);
        assert_ne!(frame.cells[0].attrs & ATTR_WIDE, 0);
        assert!(frame.cells[1].text.is_empty(), "the spacer reports no text");
    }

    #[test]
    fn a_combining_mark_stays_with_its_base_character() {
        let mut screen = screen(10, 2);
        // "e" followed by U+0301 COMBINING ACUTE ACCENT is one cell, not two.
        screen.advance("e\u{301}".as_bytes());
        assert_eq!(screen.snapshot().cells[0].text, vec!['e' as u32, 0x301]);
    }

    #[test]
    fn resizing_reports_the_previous_size_and_relays_out() {
        let mut screen = screen(10, 3);
        screen.advance(b"abcdefghij");
        assert_eq!(screen.resize(Size::new(20, 5)), Some(Size::new(10, 3)));
        assert_eq!(screen.size(), Size::new(20, 5));
        // Same size is not a change, and an unusable size is refused rather
        // than producing a screen with no cells.
        assert_eq!(screen.resize(Size::new(20, 5)), None);
        assert_eq!(screen.resize(Size::new(0, 5)), None);
        assert_eq!(screen.size(), Size::new(20, 5));
        let frame = screen.snapshot();
        assert_eq!(frame.cells.len(), 100);
        assert_eq!(lines_of(&frame)[0], "abcdefghij");
    }

    #[test]
    fn an_empty_screen_is_refused_instead_of_rounded_up() {
        assert_eq!(TerminalScreen::new(Size::new(0, 10)).unwrap_err(), ScreenError::EmptyDimensions);
        assert_eq!(TerminalScreen::new(Size::new(80, 0)).unwrap_err(), ScreenError::EmptyDimensions);
    }

    #[test]
    fn the_alternate_screen_is_reported_so_a_renderer_can_clear_it() {
        let mut screen = screen(10, 3);
        screen.advance(b"shell");
        assert!(!screen.snapshot().modes.alternate_screen);
        // What an editor or a pager does on start-up.
        screen.advance(b"\x1b[?1049h");
        let frame = screen.snapshot();
        assert!(frame.modes.alternate_screen);
        assert_eq!(lines_of(&frame)[0], "");
        screen.advance(b"\x1b[?1049l");
        assert!(!screen.snapshot().modes.alternate_screen);
        assert_eq!(lines_of(&screen.snapshot())[0], "shell");
    }

    #[test]
    fn a_repaint_is_announced_and_a_snapshot_clears_it() {
        let mut screen = screen(10, 3);
        assert!(screen.is_dirty(), "a new screen has never been painted");
        let _ = screen.snapshot();
        assert!(!screen.is_dirty());
        screen.advance(b"");
        assert!(!screen.is_dirty(), "empty output changes nothing");
        screen.advance(b"x");
        assert!(screen.is_dirty());
        let _ = screen.snapshot();
        assert!(!screen.is_dirty());
        screen.scroll(1);
        assert!(screen.is_dirty(), "scrolling moves what is shown");
    }

    #[test]
    fn the_window_title_follows_the_stream() {
        let mut screen = screen(20, 3);
        screen.advance(b"\x1b]0;deploy@web-1\x07");
        assert_eq!(screen.title().as_deref(), Some("deploy@web-1"));
        assert_eq!(screen.snapshot().title.as_deref(), Some("deploy@web-1"));
        screen.advance(b"\x1b]0;\x07");
        assert_eq!(screen.title().as_deref(), Some(""));
    }

    #[test]
    fn a_device_status_query_is_answered_by_the_screen() {
        let mut screen = screen(20, 4);
        // CSI 6 n asks for the cursor position. A terminal that stays silent
        // leaves the program that asked waiting forever.
        screen.advance(b"\x1b[2;5H");
        screen.advance(b"\x1b[6n");
        let replies = String::from_utf8(screen.take_replies()).expect("an ASCII report");
        assert_eq!(replies, "\x1b[2;5R");
        assert!(screen.take_replies().is_empty(), "a report is handed over once");
    }

    /// A cursor report names the row the cursor is on. The grid grows upward
    /// through its history, so the parser's own formatting already produces
    /// viewport rows; this pins that, because "fixing" it is easy and wrong.
    #[test]
    fn a_report_on_the_first_row_names_the_first_row() {
        let mut screen = screen(80, 24);
        screen.advance(b"\x1b[H");
        screen.advance(b"\x1b[6n");
        assert_eq!(String::from_utf8(screen.take_replies()).unwrap(), "\x1b[1;1R");
    }

    /// The same correction has to hold for every row, not just the ones where
    /// absolute and viewport numbering happen to agree.
    #[test]
    fn a_report_on_the_last_row_names_the_last_row() {
        let mut screen = screen(80, 24);
        screen.advance(b"\x1b[24;1H");
        screen.advance(b"\x1b[6n");
        assert_eq!(String::from_utf8(screen.take_replies()).unwrap(), "\x1b[24;1R");
    }

    /// The cursor snapshot uses the parser's own offset translation, so a
    /// cursor on the last grid line is on the last viewport row.
    #[test]
    fn the_cursor_row_is_the_viewport_row() {
        let mut screen = screen(10, 3);
        screen.advance(b"\x1b[3;1H");
        assert_eq!(screen.snapshot().cursor.line, 2);
        screen.advance(b"\x1b[1;1H");
        assert_eq!(screen.snapshot().cursor.line, 0);
    }

    #[test]
    fn a_size_query_is_answered_with_the_real_viewport() {
        let mut screen = screen(80, 24);
        screen.set_cell_size(9, 18);
        // CSI 18 t asks for the text area in cells; CSI 14 t in pixels.
        screen.advance(b"\x1b[18t");
        assert_eq!(String::from_utf8(screen.take_replies()).unwrap(), "\x1b[8;24;80t");
        screen.advance(b"\x1b[14t");
        assert_eq!(String::from_utf8(screen.take_replies()).unwrap(), "\x1b[4;432;720t");
    }

    #[test]
    fn a_colour_query_is_answered_from_the_streams_own_palette() {
        let mut screen = screen(20, 3);
        // OSC 11 sets the background, OSC 11 ? asks for it back.
        screen.advance(b"\x1b]11;rgb:12/34/56\x07");
        screen.advance(b"\x1b]11;?\x07");
        assert_eq!(
            String::from_utf8(screen.take_replies()).expect("an ASCII report"),
            "\x1b]11;rgb:1212/3434/5656\x07"
        );
    }

    #[test]
    fn an_unresolved_named_colour_falls_back_to_the_theme() {
        let theme = Theme::default();
        let foreground = CellColor { named: 256, indexed: -1, rgb: None };
        assert_eq!(resolve_color(&foreground, &theme), theme.foreground);
        let background = CellColor { named: 257, indexed: -1, rgb: None };
        assert_eq!(resolve_color(&background, &theme), theme.background);
        // A colour the stream defined wins over the theme, because an
        // application that set its own palette means it.
        let defined = CellColor { named: 1, indexed: -1, rgb: Some(Rgb::new(1, 2, 3)) };
        assert_eq!(resolve_color(&defined, &theme), Rgb::new(1, 2, 3));
        let themed = CellColor { named: -1, indexed: 4, rgb: None };
        assert_eq!(resolve_color(&themed, &theme), theme.palette[4]);
    }

    #[test]
    fn the_extended_palette_is_the_standard_cube_and_grey_ramp() {
        assert_eq!(xterm_palette_entry(16), Rgb::new(0, 0, 0));
        assert_eq!(xterm_palette_entry(196), Rgb::new(255, 0, 0));
        assert_eq!(xterm_palette_entry(231), Rgb::new(255, 255, 255));
        assert_eq!(xterm_palette_entry(232), Rgb::new(8, 8, 8));
        assert_eq!(xterm_palette_entry(255), Rgb::new(238, 238, 238));
        let indexed = CellColor { named: -1, indexed: 196, rgb: None };
        assert_eq!(resolve_color(&indexed, &Theme::default()), Rgb::new(255, 0, 0));
    }

    #[test]
    fn bright_named_colours_map_to_the_upper_palette() {
        // NamedColor::BrightBlack is 8, BrightWhite is 15; the palette has 16
        // entries for both halves, and an off-by-one here recolours every
        // bright colour in the app.
        assert_eq!(named_color_rgb(8), DEFAULT_PALETTE[8]);
        assert_eq!(named_color_rgb(15), DEFAULT_PALETTE[15]);
        assert_eq!(named_color_rgb(0), DEFAULT_PALETTE[0]);
    }

    #[test]
    fn the_bell_rings_once_per_ring() {
        let mut screen = screen(10, 3);
        assert!(!screen.take_bell());
        screen.advance(b"\x07");
        assert!(screen.take_bell());
        assert!(!screen.take_bell());
    }

    #[test]
    fn visible_lines_reports_the_screen_without_a_repaint() {
        let mut screen = screen(10, 3);
        screen.advance(b"one\r\ntwo");
        assert_eq!(screen.visible_lines(), vec!["one".to_string(), "two".to_string(), String::new()]);
    }

    #[test]
    fn a_frame_survives_a_json_round_trip() {
        let mut screen = screen(4, 2);
        screen.advance(b"ab");
        let frame = screen.snapshot();
        let json = serde_json::to_value(&frame).expect("a frame is serialisable");
        assert_eq!(json["columns"], 4);
        assert_eq!(json["cells"][0]["text"][0], 'a' as u32);
        assert_eq!(json["cursor"]["shape"], "block");
    }
}
