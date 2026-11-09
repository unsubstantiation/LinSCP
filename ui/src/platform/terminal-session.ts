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
import { TerminalInput } from './terminal-input.js';

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
  /**
   * Attach a keyboard to the canvas.
   *
   * A canvas cannot raise a soft keyboard, so on a touch host this is the
   * difference between a terminal that can be typed into and a picture of one.
   * It is off by default only so a host that already has a keyboard - a test, a
   * window that only mirrors a shell - does not get a stray hidden textarea.
   */
  keyboard?: boolean;
  /** Called whenever the grid the window can show changes. */
  onResize?: (grid: { columns: number; lines: number }) => void;
  /** Called when the cursor mode changes, for the extra-keys row's arrows. */
  onModes?: (modes: TerminalModes) => void;
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
  private readonly onResize?: TerminalSessionOptions['onResize'];
  private readonly onModes?: TerminalSessionOptions['onModes'];
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
  /** The keyboard attachment, when the host asked for one. */
  private keyboard: TerminalInput | null = null;
  /** The canvas, kept only so the tap listener can be removed again. */
  private canvas: HTMLCanvasElement | null = null;
  /** Where a one-finger drag started, and how far it has travelled. */
  private drag: { y: number; lines: number } | null = null;
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
    this.onResize = options.onResize;
    this.onModes = options.onModes;
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
    if (options.keyboard) {
      this.keyboard = new TerminalInput({
        container: options.container,
        // Typed text goes to the shell exactly as typed: the input method has
        // already applied the person's language, so nothing is transformed
        // here. Latched Ctrl/Alt from the extra-keys row come through `write`.
        onData: (data) => this.write(data),
        onKey: (event) => this.handleTypedKey(event),
        onPaste: (text) => this.paste(text),
      });
      // A tap on the terminal is a tap into it: the canvas is not focusable, so
      // without this the soft keyboard never appears and there is nothing to
      // type into. Tapping again dismisses it, which is what every phone
      // terminal does.
      const canvas = this.renderer.element;
      // `click`, not `pointerdown`: a scroll drag cancels its own click when it
      // calls `preventDefault` on the move, so dragging through history cannot
      // also dismiss the keyboard the person is using.
      canvas.addEventListener('click', this.handleTap);
      canvas.addEventListener('touchstart', this.handleTouchStart, { passive: true });
      canvas.addEventListener('touchmove', this.handleTouchMove, { passive: false });
      canvas.addEventListener('touchend', this.handleTouchEnd);
      canvas.addEventListener('wheel', this.handleWheel, { passive: false });
      this.canvas = canvas;
    }
  }

  /** The keyboard attachment, when this session has one. */
  public get input(): TerminalInput | null {
    return this.keyboard;
  }

  /**
   * The painted surface.
   *
   * Exposed so a host can attach its own gestures to it - the touch shell does,
   * and a test that could not reach it could not check that a swipe scrolls
   * anything.
   */
  public get element(): HTMLCanvasElement {
    return this.renderer.element;
  }

  /** The grid the window can show, in cells. */
  public size(): { columns: number; lines: number } {
    return this.renderer.size();
  }

  /** Starts painting and polling. */
  public start(): void {
    this.watchViewport();
    this.poll();
  }

  /**
   * Re-measures the canvas when the part of the screen it occupies changes.
   *
   * On a phone the soft keyboard does not resize the layout viewport, it
   * shrinks the *visual* one, so a grid sized from `clientHeight` either hides
   * its bottom rows behind the keyboard or, worse, keeps claiming a size the
   * shell cannot show and the prompt ends up underneath the keys. Watching the
   * visual viewport is what makes the prompt stay above the keyboard.
   */
  private watchViewport(): void {
    if (this.stopped) {
      return;
    }
    const doc = this.renderer.element.ownerDocument;
    const view = doc?.defaultView as (Window & typeof globalThis) | null | undefined;
    this.viewport = view?.visualViewport ?? null;
    if (this.viewport) {
      this.viewport.addEventListener('resize', this.handleViewportChange);
    }
    view?.addEventListener('resize', this.handleViewportChange);
  }

  private readonly handleViewportChange = (): void => {
    if (this.stopped) {
      return;
    }
    this.renderer.resizeBackingStore();
    const next = this.renderer.size();
    if (next.columns !== this.grid.columns || next.lines !== this.grid.lines) {
      this.grid = next;
      this.onResize?.(next);
      // The frame's own `takeResize` would also notice this, but only on the
      // next poll; sending it here is what makes the prompt stay visible while
      // the keyboard is still animating open.
      void this.resize({ columns: next.columns, lines: next.lines });
    }
    this.renderer.repaint();
  };

  private viewport: VisualViewport | null = null;

  /** Stops polling and removes the canvas. The shell is told only by `close`. */
  public stop(): void {
    this.stopped = true;
    if (this.timer !== null) {
      clearTimeout(this.timer);
      this.timer = null;
    }
    this.viewport?.removeEventListener('resize', this.handleViewportChange);
    this.viewport = null;
    this.detachKeyboard();
    this.renderer.destroy();
  }

  /**
   * Tears down the keyboard attachment.
   *
   * Removing the textarea while it has focus is what tells the phone to put the
   * soft keyboard away; leaving it behind would leave a focused invisible
   * element holding the keyboard open over whatever the person opened next.
   */
  private detachKeyboard(): void {
    if (this.canvas) {
      this.canvas.removeEventListener('click', this.handleTap);
      this.canvas.removeEventListener('touchstart', this.handleTouchStart);
      this.canvas.removeEventListener('touchmove', this.handleTouchMove);
      this.canvas.removeEventListener('touchend', this.handleTouchEnd);
      this.canvas.removeEventListener('wheel', this.handleWheel);
      this.canvas = null;
    }
    this.keyboard?.destroy();
    this.keyboard = null;
  }

  /** Tells the backend to close the shell and stops painting. */
  public async close(): Promise<void> {
    // `stop` is the whole teardown - timers, the keyboard, the canvas, the
    // viewport listener - and it used to be copied here. Two copies meant the
    // listeners added since the copy was made were left attached: a closed
    // terminal went on hearing taps.
    this.stop();
    if (!this.backendClosed) {
      this.backendClosed = true;
      try {
        await this.transport.post('/api/terminal/close', { terminal: this.terminal });
      } catch {
        // A shell that is already gone is the same outcome as closing it.
      }
    }
  }

  /** Reports a new grid size to the model and the remote PTY. */
  public async resize(next: { columns?: number; lines?: number; width?: number; height?: number }): Promise<void> {
    if (this.stopped) {
      return;
    }
    const columns = next.columns ?? this.grid.columns;
    const lines = next.lines ?? this.grid.lines;
    this.grid = { columns, lines };
    // An empty payload carries the size, exactly as the page's old handler
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

  /**
   * Handles one key press and reports whether it was sent.
   *
   * `handleTypedKey` is the soft keyboard's path: an ordinary character must
   * come through the textarea's `input` event, not from here, or every letter
   * typed on a phone would be sent twice - once for the key press and once for
   * the text it produced.
   */
  public handleTypedKey(event: KeyEventLike): boolean {
    // A single printable character (and no modifier) is the input event's job.
    if ([...event.key].length === 1 && !event.ctrlKey && !event.altKey && !event.metaKey) {
      return false;
    }
    return this.handleKey(event);
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

  /**
   * Encodes a key the extra-keys row pressed.
   *
   * The row has key names, not key events, and its arrows have to become the
   * same bytes a physical arrow does - including the application-cursor
   * variant, or the arrows in `vi` and `less` would move nothing. Returns null
   * for the row's text keys (`/`, `-`, `|`, `~`), which go through `write`.
   */
  public encodeNamedKey(name: string): string | null {
    const arrow = this.modes.app_cursor;
    switch (name) {
      case 'esc': return '\x1b';
      case 'tab': return '\t';
      case 'up': return arrow ? '\x1bOA' : '\x1b[A';
      case 'down': return arrow ? '\x1bOB' : '\x1b[B';
      case 'left': return arrow ? '\x1bOD' : '\x1b[D';
      case 'right': return arrow ? '\x1bOC' : '\x1b[C';
      default: return null;
    }
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

  /**
   * A tap on the terminal is a tap into it.
   *
   * The canvas cannot take focus, so this is what raises the soft keyboard on a
   * phone; tapping an already-focused terminal dismisses it, so the person can
   * see the bottom of the screen without hunting for a back button.
   */
  private readonly handleTap = (): void => {
    if (this.stopped || !this.keyboard) {
      return;
    }
    this.keyboard.toggle();
  };

  /**
   * Drags through scrollback.
   *
   * The model's viewport moves, not the page: scrolling a canvas terminal by
   * scrolling the document would move the keyboard and the extra-keys row with
   * it and leave the prompt behind. A drag is accumulated in whole cells so a
   * slow drag is not a request per pixel.
   */
  private readonly handleTouchStart = (event: TouchEvent): void => {
    if (this.stopped) {
      return;
    }
    const touch = event.touches[0];
    if (!touch) {
      return;
    }
    this.drag = { y: touch.clientY, lines: 0 };
  };

  private readonly handleTouchMove = (event: TouchEvent): void => {
    if (this.stopped || !this.drag) {
      return;
    }
    const touch = event.touches[0];
    if (!touch) {
      return;
    }
    const cell = this.renderer.cellSize().height || 18;
    // Dragging down reveals what is above, which is the history; the model
    // counts positive lines as going up, so the sign is inverted from the
    // finger's.
    const delta = this.drag.y - touch.clientY;
    const lines = Math.trunc(delta / cell);
    if (lines === this.drag.lines) {
      return;
    }
    // Cancelling the move is what stops the browser turning this drag into a
    // click at the end of it, and a click would toggle the keyboard shut over
    // the scrollback the person just opened.
    event.preventDefault?.();
    const step = lines - this.drag.lines;
    this.drag.lines = lines;
    void this.scroll(step);
  };

  private readonly handleTouchEnd = (): void => {
    this.drag = null;
  };

  /** A wheel spin is a short drag: the same three-line step every terminal uses. */
  private readonly handleWheel = (event: WheelEvent): void => {
    if (this.stopped || event.deltaY === 0) {
      return;
    }
    event.preventDefault?.();
    const lines = Math.sign(event.deltaY) * 3;
    void this.scroll(-lines);
  };

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
      if (frame.modes.app_cursor !== this.modes.app_cursor) {
        // The on-screen row holds its own copy of this; nothing else changes it.
        this.onModes?.(frame.modes);
      }
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
      // The keyboard follows the cursor, not the element's last position: on a
      // phone this is what keeps the input method's candidate window at the
      // prompt instead of in the corner it was first put in.
      const rect = this.renderer.cursorRect();
      if (rect) {
        this.keyboard?.moveTo(rect);
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
