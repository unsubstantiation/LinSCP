/**
 * One terminal window: the model's frames in, the shell's bytes out.
 *
 * A desktop terminal opens in its own OS window (see
 * `linscp_open_terminal_window`), which is what makes it alt-tabbable and lets
 * it sit beside the file panes. Android has no OS windows to open, so the same
 * session runs inside the page there. The window is therefore not part of the
 * terminal: it is one of two places this session can be mounted.
 *
 * The session is also where input is encoded. Every key has to become the byte
 * sequence a terminal on the other end of an SSH channel expects, and that
 * depends on modes the *model* tracks (`app_cursor`, `bracketed_paste`). Asking
 * the model for them - rather than assuming a mode - is what keeps arrows
 * working in `vi` and paste working in `less`.
 */

import type { TransportClient } from '../transport/client.js';
import type { TerminalFrame, TerminalModes } from './terminal.js';
import { TerminalRenderer } from './terminal.js';

/** The keyboard state a key press needs to become bytes. */
export interface KeyEventLike {
  key: string;
  ctrlKey?: boolean;
  altKey?: boolean;
  shiftKey?: boolean;
  metaKey?: boolean;
  preventDefault?: () => void;
}

/**
 * Encodes one key press as the bytes a terminal sends.
 *
 * Returns `null` for a key the terminal does not send anything for (a bare
 * modifier, a browser shortcut the page is allowed to keep). Printable text is
 * sent as UTF-8 by the caller, so this only decides the non-printable keys and
 * the control characters.
 *
 * `applicationCursor` switches the arrow and Home/End sequences, which is the
 * difference between working and broken arrow keys inside `vi`, `less` and
 * any other full-screen program.
 */
export function encodeKey(event: KeyEventLike, applicationCursor: boolean): string | null {
  const { key } = event;
  const ctrl = event.ctrlKey === true;
  const alt = event.altKey === true;
  const shift = event.shiftKey === true;

  // Ctrl+letter is the ASCII control code; Ctrl+Space and Ctrl+@ are NUL.
  if (ctrl && key.length === 1) {
    const code = key.toUpperCase().charCodeAt(0);
    if (key === ' ' || key === '@') {
      return alt ? '\x1b\x00' : '\x00';
    }
    if (code >= 0x40 && code <= 0x5f) {
      const control = String.fromCharCode(code - 0x40);
      return alt ? `\x1b${control}` : control;
    }
  }

  const cursor = applicationCursor;
  switch (key) {
    case 'Enter':
      return alt ? '\x1b\r' : '\r';
    case 'Tab':
      return shift ? '\x1b[Z' : '\t';
    case 'Backspace':
      return alt ? '\x1b\x7f' : '\x7f';
    case 'Escape':
      return '\x1b';
    case 'ArrowUp':
      return cursor ? '\x1bOA' : '\x1b[A';
    case 'ArrowDown':
      return cursor ? '\x1bOB' : '\x1b[B';
    case 'ArrowRight':
      return cursor ? '\x1bOC' : '\x1b[C';
    case 'ArrowLeft':
      return cursor ? '\x1bOD' : '\x1b[D';
    case 'Home':
      return cursor ? '\x1bOH' : '\x1b[H';
    case 'End':
      return cursor ? '\x1bOF' : '\x1b[F';
    case 'Insert':
      return '\x1b[2~';
    case 'Delete':
      return '\x1b[3~';
    case 'PageUp':
      return '\x1b[5~';
    case 'PageDown':
      return '\x1b[6~';
    case 'F1':
      return cursor ? '\x1bOP' : '\x1b[11~';
    case 'F2':
      return cursor ? '\x1bOQ' : '\x1b[12~';
    case 'F3':
      return cursor ? '\x1bOR' : '\x1b[13~';
    case 'F4':
      return cursor ? '\x1bOS' : '\x1b[14~';
    case 'F5':
      return '\x1b[15~';
    case 'F6':
      return '\x1b[17~';
    case 'F7':
      return '\x1b[18~';
    case 'F8':
      return '\x1b[19~';
    case 'F9':
      return '\x1b[20~';
    case 'F10':
      return '\x1b[21~';
    case 'F11':
      return '\x1b[23~';
    case 'F12':
      return '\x1b[24~';
    default:
      break;
  }
  // A single printable character is the caller's to send, so the shift and
  // dead-key handling of the platform's own input method is not bypassed here.
  if ([...key].length === 1) {
    return alt ? `\x1b${key}` : key;
  }
  return null;
}

/** The bytes a paste sends, honouring the model's bracketed-paste mode. */
export function encodePaste(text: string, bracketedPaste: boolean): string {
  // A pasted newline is a line feed to the shell, not a carriage return; a
  // paste full of CRs runs every line as if Enter was pressed, which is exactly
  // the "pasted a script and it executed" surprise bracketed paste exists to
  // avoid.
  const normalized = text.replace(/\r\n?/g, '\n');
  return bracketedPaste ? `\x1b[200~${normalized}\x1b[201~` : normalized;
}

/** UTF-8 bytes of a string, base64 encoded for the transport. */
export function encodeInput(text: string): string {
  const bytes = new TextEncoder().encode(text);
  let binary = '';
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}

export interface TerminalSessionOptions {
  transport: TransportClient;
  terminal: string;
  /** Where the canvas goes. Its size decides the grid. */
  container: HTMLElement;
  /** Poll interval in milliseconds; the old page used 120. */
  pollInterval?: number;
  /** Called when the session ends, with the reason if the backend gave one. */
  onEnded?: (reason: string | null) => void;
  /** Called on the first frame and whenever the window title changes. */
  onTitle?: (title: string | null) => void;
  /** Called when a repaint actually happened, so a test can count frames. */
  onFrame?: (frame: TerminalFrame) => void;
}

interface FrameReply {
  success?: boolean;
  dirty?: boolean;
  alive?: boolean;
  error?: string | null;
  frame?: TerminalFrame;
}

/**
 * Drives one terminal: polls the model's frames, paints them, and sends input.
 *
 * Frames are polled rather than pushed because the terminal already had a
 * polled byte path and a poll is what a slow (SSH) sink can absorb: a window
 * that fell behind asks for the *current* screen, not a queue of every
 * intermediate one. Every painted frame therefore costs one request and no
 * backlog.
 */
export class TerminalSession {
  private readonly transport: TransportClient;
  private readonly pollInterval: number;
  private readonly onEnded?: TerminalSessionOptions['onEnded'];
  private readonly onTitle?: TerminalSessionOptions['onTitle'];
  private readonly onFrame?: TerminalSessionOptions['onFrame'];
  public readonly terminal: string;
  private readonly renderer: TerminalRenderer;
  private timer: ReturnType<typeof setTimeout> | null = null;
  private stopped = false;
  /** Serialises input so rapid key presses reach the PTY in order. */
  private inputQueue: Promise<unknown> = Promise.resolve();
  private backendClosed = false;
  private lastTitle: string | null = null;
  private pollFailures = 0;
  private grid: { columns: number; lines: number };
  /**
   * The modes of the last painted frame.
   *
   * Input encoding depends on them - arrows are two different sequences in
   * normal and application cursor mode, and a paste is wrapped only when the
   * program asked for it - so a key press has to be encoded against the modes
   * the screen is actually in, not against a guess.
   */
  private modes: TerminalModes = {
    alternate_screen: false,
    app_cursor: false,
    bracketed_paste: false,
    mouse_reporting: false,
    show_cursor: true,
  };

  constructor(options: TerminalSessionOptions) {
    this.transport = options.transport;
    this.terminal = options.terminal;
    this.pollInterval = options.pollInterval ?? 120;
    this.onEnded = options.onEnded;
    this.onTitle = options.onTitle;
    this.onFrame = options.onFrame;
    this.renderer = new TerminalRenderer({
      container: options.container,
      onCellSize: (size) => {
        // The model answers a program that asks how large the text area is in
        // pixels, and only the renderer knows what a cell measures.
        if (this.grid) {
          void this.resize({ width: size.width, height: size.height });
        }
      },
    });
    this.grid = this.renderer.size();
  }

  /** The grid the window can show, in cells. */
  public size(): { columns: number; lines: number } {
    return this.renderer.size();
  }

  /** Starts painting and polling. */
  public start(): void {
    this.poll();
  }

  /** Stops polling and removes the canvas. The shell is told only by `close`. */
  public stop(): void {
    this.stopped = true;
    if (this.timer !== null) {
      clearTimeout(this.timer);
      this.timer = null;
    }
    this.renderer.destroy();
  }

  /** Tells the backend to close the shell and stops painting. */
  public async close(): Promise<void> {
    this.stopped = true;
    if (this.timer !== null) {
      clearTimeout(this.timer);
      this.timer = null;
    }
    if (!this.backendClosed) {
      this.backendClosed = true;
      try {
        await this.transport.post('/api/terminal/close', { terminal: this.terminal });
      } catch {
        // A shell that is already gone is the same outcome as closing it.
      }
    }
    this.renderer.destroy();
  }

  /** Reports a new grid size to the model and the remote PTY. */
  public async resize(next: { columns?: number; lines?: number; width?: number; height?: number }): Promise<void> {
    if (this.stopped) {
      return;
    }
    const columns = next.columns ?? this.grid.columns;
    const lines = next.lines ?? this.grid.lines;
    this.grid = { columns, lines };
    // An empty payload carries the size, exactly as the page's xterm handler
    // did: the endpoint already interprets "no data" as "resize only".
    try {
      await this.transport.post('/api/terminal/input', {
        terminal: this.terminal,
        data: '',
        cols: columns,
        rows: lines,
        ...(next.width !== undefined ? { cell_width: next.width, cell_height: next.height } : {}),
      });
    } catch {
      // A size the backend refused is not fatal; the next frame is unchanged
      // and the next resize will try again.
    }
  }

  /** Sends bytes to the shell, in order, after any input already queued. */
  public write(text: string): void {
    if (!text || this.stopped) {
      return;
    }
    const data = encodeInput(text);
    this.inputQueue = this.inputQueue
      .then(() => {
        if (this.stopped) {
          return;
        }
        return this.transport.post('/api/terminal/input', {
          terminal: this.terminal,
          data,
          cols: this.grid.columns,
          rows: this.grid.lines,
        });
      })
      .catch(() => {
        // A write the backend refused ends the session on the next poll, which
        // reports why; failing here as well would say it twice.
      });
  }

  /** The modes of the last painted frame. */
  public currentModes(): TerminalModes {
    return this.modes;
  }

  /** Handles one key press and reports whether it was sent. */
  public handleKey(event: KeyEventLike, modes?: { app_cursor: boolean; bracketed_paste: boolean }): boolean {
    const active = modes ?? this.modes;
    const encoded = encodeKey(event, active.app_cursor);
    if (encoded === null) {
      return false;
    }
    event.preventDefault?.();
    this.write(encoded);
    return true;
  }

  /** Handles a paste, honouring the model's bracketed-paste mode. */
  public paste(text: string, bracketedPaste?: boolean): void {
    this.write(encodePaste(text, bracketedPaste ?? this.modes.bracketed_paste));
  }

  /** Scrolls the model's viewport; positive is up into history. */
  public async scroll(lines: number): Promise<void> {
    if (lines === 0) {
      return;
    }
    // Scrolling is a view operation, not a shell input: it must not enter the
    // input queue, or a wheel spin would arrive as keystrokes behind a paste.
    try {
      await this.transport.post('/api/terminal/scroll', { terminal: this.terminal, lines });
    } catch {
      // A screen that cannot scroll stays where it is; nothing is lost.
    }
  }

  private poll(): void {
    if (this.stopped) {
      return;
    }
    this.timer = setTimeout(() => {
      this.timer = null;
      // A session can end between the timer being set and it firing - the
      // window closing is the common case - and polling from there would ask
      // for a frame of a terminal the caller has already been told about.
      if (this.stopped) {
        return;
      }
      void this.refresh();
    }, this.pollInterval);
  }

  private async refresh(): Promise<void> {
    if (this.stopped) {
      return;
    }
    let reply: FrameReply | null = null;
    try {
      reply = await this.transport.get<FrameReply>(
        `/api/terminal/frame?terminal=${encodeURIComponent(this.terminal)}`,
      );
    } catch {
      reply = null;
    }
    if (this.stopped) {
      return;
    }
    if (reply && reply.success && reply.frame) {
      this.pollFailures = 0;
      const frame = reply.frame;
      this.modes = frame.modes;
      this.renderer.render(frame);
      if (frame.title !== this.lastTitle) {
        this.lastTitle = frame.title;
        this.onTitle?.(frame.title);
      }
      this.onFrame?.(frame);
      // A resize the window noticed is sent only after a frame has painted:
      // the model's answer is what the new grid's programs redraw against.
      const resized = this.renderer.takeResize(this.grid);
      if (resized) {
        this.grid = resized;
      }
      if (!reply.alive) {
        this.finish(reply.error ?? null);
        return;
      }
    } else if (++this.pollFailures >= 5) {
      // Five empty answers in a row is a terminal that is not coming back.
      // Saying so is the difference between a slow shell and a dead one.
      this.finish(reply && reply.error ? reply.error : null);
      return;
    }
    // A refresh that ended the session has already told the caller; scheduling
    // another poll here would ask for a frame of a terminal that is gone.
    if (this.stopped) {
      return;
    }
    this.poll();
  }

  private finish(reason: string | null): void {
    if (this.stopped) {
      return;
    }
    this.stopped = true;
    this.backendClosed = true;
    if (this.timer !== null) {
      clearTimeout(this.timer);
      this.timer = null;
    }
    this.onEnded?.(reason);
  }
}
