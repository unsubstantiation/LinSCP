/**
 * The page a terminal window shows: one terminal, filling the window.
 *
 * A desktop terminal opens in its own OS window, so this page is the whole of
 * that window: no file panes, no queue, no navigation. The Android app has no
 * OS windows, so the same page is what its terminal pane shows inside the app.
 * One page for both is what keeps the two from drifting apart - and it is the
 * reason the windows exist at all: the terminal is no longer a modal fighting
 * the file panes for one window.
 */

import type { TransportClient } from '../transport/client.js';
import { TerminalSession } from './terminal-session.js';

export interface TerminalWindowOptions {
  /** The element the terminal fills. */
  container: HTMLElement;
  /** The terminal to show, or a tab to open one on. */
  terminal?: string | null;
  tab?: number | null;
  /** The transport; defaults to the one the page built. */
  transport?: TransportClient | null;
  /** Called when the shell ends, with the reason when the backend gave one. */
  onEnded?: (reason: string | null) => void;
  /** Called with the terminal's title, for the window title bar. */
  onTitle?: (title: string | null) => void;
  /** The element for the Esc/Tab/Ctrl row on a narrow window, if there is one. */
  extraKeysElement?: HTMLElement | null;
  /**
   * Attach a keyboard to the canvas.
   *
   * A desktop window has a physical keyboard and a document-level listener
   * hears it, so a soft keyboard is only needed where there is one: the Android
   * app's terminal pane. The page sets this there and leaves it off in a
   * desktop window.
   */
  keyboard?: boolean;
  /** Called when the grid the window can show changes. */
  onResize?: (grid: { columns: number; lines: number }) => void;
  /** Called with the cursor mode each time it changes (the extra-keys row). */
  onModes?: (modes: { app_cursor: boolean }) => void;
  /** Called when a long-press selection opens or closes, for the copy bar. */
  onSelection?: (open: boolean) => void;
}

interface OpenReply {
  success?: boolean;
  terminal?: string;
  error?: string;
}

/**
 * Opens (or attaches to) one terminal and keeps it painted until it ends.
 *
 * The container is filled with a canvas, and the window title follows the
 * shell's own title: a window called "Terminal" four times is four windows
 * nobody can tell apart in an alt-tab list, and the title the shell set is the
 * one that says which is which.
 */
export class TerminalWindow {
  private readonly options: TerminalWindowOptions;
  private session: TerminalSession | null = null;
  private disposed = false;

  constructor(options: TerminalWindowOptions) {
    this.options = options;
  }

  /** The terminal this window is showing, once it has one. */
  public get terminal(): string | null {
    return this.session?.terminal ?? null;
  }

  /**
   * Attaches to an existing terminal, or opens one on `tab`.
   *
   * A terminal window is always opened *for* a terminal, so the id is usually
   * given. A window given only a tab opens its own shell, which is what the
   * page's Terminal pane does on Android.
   */
  public async start(): Promise<boolean> {
    const transport = this.options.transport;
    if (!transport) {
      this.fail('There is no connection to the application backend.');
      return false;
    }
    let terminal = this.options.terminal ?? null;
    if (!terminal) {
      const tab = this.options.tab;
      if (tab === null || tab === undefined) {
        this.fail('This window was not given a terminal to show.');
        return false;
      }
      try {
        const reply = await transport.post<OpenReply>('/api/session/terminal', {
          tab,
          cols: 80,
          rows: 24,
        });
        if (!reply || !reply.success || !reply.terminal) {
          this.fail(reply && reply.error ? reply.error : 'Cannot open a terminal.');
          return false;
        }
        terminal = reply.terminal;
      } catch (error) {
        this.fail(error instanceof Error ? error.message : 'Cannot open a terminal.');
        return false;
      }
    }
    if (this.disposed) {
      return false;
    }
    const session = new TerminalSession({
      transport,
      terminal,
      container: this.options.container,
      onEnded: (reason) => {
        this.options.onEnded?.(reason);
      },
      onTitle: (title) => {
        this.options.onTitle?.(title);
      },
      onResize: (grid) => {
        this.options.onResize?.(grid);
      },
      onModes: (modes) => {
        this.options.onModes?.(modes);
      },
      onSelection: (open) => {
        this.options.onSelection?.(open);
      },
      keyboard: this.options.keyboard === true,
    });
    this.session = session;
    session.start();
    return true;
  }

  /**
   * Sends one press from the extra-keys row.
   *
   * The row speaks key names (`up`, `esc`, `/`), not bytes, so the named ones
   * are encoded here against the screen's own modes - the arrows have to become
   * the application-cursor variant inside `vi`. The rest are text and are sent
   * as typed.
   */
  public pressExtraKey(keyId: string): void {
    const session = this.session;
    if (!session) {
      return;
    }
    const encoded = session.encodeNamedKey(keyId);
    if (encoded !== null) {
      session.write(encoded);
      return;
    }
    if (keyId.length === 1) {
      session.write(keyId);
    }
  }

  /** Sends typed text; `Enter` and the other named keys go through `key`. */
  public write(text: string): void {
    this.session?.write(text);
  }

  /** Handles one key press, encoded against the modes the screen is in. */
  public handleKey(event: Parameters<TerminalSession['handleKey']>[0]): boolean {
    return this.session?.handleKey(event) ?? false;
  }

  /** The open selection, if one is being dragged. */
  public get selection(): TerminalSession['selection'] {
    return this.session?.selection ?? null;
  }

  /** Copies the selection, which also closes it; null when nothing was selected. */
  public async copySelection(): Promise<string | null> {
    return (await this.session?.copySelection()) ?? null;
  }

  /** Clears a selection without copying it. */
  public async clearSelection(): Promise<void> {
    await this.session?.endSelection();
  }

  /** Scrolls the viewport through history; positive is back into it. */
  public async scroll(lines: number): Promise<void> {
    await this.session?.scroll(lines);
  }

  /** The keyboard attachment, so the page can raise or dismiss it. */
  public get input(): TerminalSession['input'] {
    return this.session?.input ?? null;
  }

  /** Handles a paste, wrapped when the program asked for bracketed paste. */
  public paste(text: string): void {
    this.session?.paste(text);
  }

  /** Closes the shell and stops painting. */
  public async close(): Promise<void> {
    this.disposed = true;
    const session = this.session;
    this.session = null;
    if (session) {
      await session.close();
    }
  }

  /** Stops painting without closing the shell; the window is going away. */
  public stop(): void {
    this.disposed = true;
    this.session?.stop();
    this.session = null;
  }

  private fail(message: string): void {
    this.options.onEnded?.(message);
  }
}
