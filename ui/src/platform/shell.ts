/**
 * The one application shell every host draws.
 *
 * `MobileShellController` owns the behaviour of a single-pane touch layout -
 * bottom navigation, swipe, long-press selection and the terminal extra-key
 * row. Until this module existed, that controller was compiled into the shared
 * bundle but nothing mounted it: the page shipped the CSS, the catalogs and the
 * tests, while the Android app and a narrow desktop window still showed the
 * two-pane desktop layout with no bottom navigation, no touch selection and no
 * Esc/Ctrl row above the soft keyboard. That is a parity bug, not a platform
 * difference, because the same `ui/dist` bundle is embedded in every host.
 *
 * `AppShell` therefore connects the controller to the DOM the page owns, in the
 * same way `LocalRootSwitcher` connects the root selector: the page supplies
 * the elements and the callbacks, the bundle supplies the behaviour. The
 * desktop window and the Android app mount the identical object.
 *
 * Everything here is defensive about its host. A missing element, a WebView
 * without `matchMedia`, a page that never resizes: none of them may throw,
 * because a shell that throws leaves the app with no navigation at all.
 */

import { EXTRA_KEYS, MobileShellController, type MobilePaneId } from './mobile.js';

/** The panels a touch layout shows one at a time, in swipe order. */
export type ShellPane = Extract<MobilePaneId, 'local' | 'remote'>;

/** An action offered by the floating bar while a selection is active. */
export type ShellAction = 'copy' | 'delete' | 'selectAll' | 'clear' | 'cancel';

/** The reviewed order of the floating action bar. */
export const SHELL_ACTIONS: readonly ShellAction[] = [
  'copy',
  'delete',
  'selectAll',
  'clear',
  'cancel',
] as const;

export interface ShellSelection {
  pane: ShellPane;
  names: string[];
}

export interface AppShellOptions {
  /** The element that receives `data-mobile-pane`/`data-selection-mode`. */
  rootElement?: HTMLElement;
  /** `<nav>` filled with one button per pane. */
  bottomNavElement?: HTMLElement | null;
  /** The scrolling pane container that becomes swipeable. */
  swipeContainer?: HTMLElement | null;
  /** `<div>` filled with the Esc/Tab/Ctrl/Alt/cursor keys. */
  extraKeysElement?: HTMLElement | null;
  /** The floating action bar shown while a touch selection exists. */
  actionBarElement?: HTMLElement | null;
  /** Translates a pane name for the bottom navigation and its ARIA label. */
  paneLabel?: (pane: MobilePaneId) => string;
  /** Translates a key cap ("Esc", "Ctrl", …); often the same in every locale. */
  extraKeyLabel?: (label: string) => string;
  /** Translates a floating-bar action. */
  actionLabel?: (action: ShellAction) => string;
  /** The user chose another pane by tapping, swiping or a keyboard shortcut. */
  onPaneChange?: (pane: MobilePaneId) => void;
  /** Bytes for the open terminal, already encoded by the latched modifiers. */
  onTerminalInput?: (data: string) => void;
  /** The touch selection of one pane changed. */
  onSelectionChange?: (selection: ShellSelection) => void;
  /** One of `SHELL_ACTIONS` was pressed. */
  onAction?: (action: ShellAction) => void;
}

/** The maximum a narrow window may be for the touch layout to apply. */
export const TOUCH_LAYOUT_MAX_WIDTH = 720;

/**
 * True when this host shows the single-pane touch layout: a coarse pointer or
 * a narrow window. It is the same question the theme's media queries ask, so
 * the DOM the shell builds matches the CSS that lays it out.
 */
export function isTouchLayout(host: unknown = globalThis): boolean {
  const candidate = host as {
    matchMedia?: (query: string) => { matches?: boolean };
    innerWidth?: number;
  } | null;
  if (!candidate) {
    return false;
  }
  try {
    const coarse = candidate.matchMedia?.('(pointer: coarse)');
    if (coarse && coarse.matches === true) {
      return true;
    }
  } catch {
    // A WebView that refuses the query is treated as a fine pointer; the
    // width fallback below still applies.
  }
  return typeof candidate.innerWidth === 'number' && candidate.innerWidth <= TOUCH_LAYOUT_MAX_WIDTH;
}

/**
 * Wires the shared touch shell to the page.
 *
 * A caller that has no bottom-navigation element gets no navigation, but every
 * other part keeps working: the shell never assumes the page offers all of it.
 */
export class AppShell {
  private readonly root: HTMLElement;
  private readonly doc: Document;
  private readonly options: AppShellOptions;
  private readonly controller: MobileShellController;
  /** The window this shell draws in, not whatever `globalThis` happens to be. */
  private readonly hostWindow: Window & typeof globalThis;
  private readonly selections: Record<ShellPane, Set<string>> = {
    local: new Set(),
    remote: new Set(),
  };
  private readonly rowCleanup = new Map<ShellPane, Array<() => void>>();
  private readonly actionButtons: HTMLButtonElement[] = [];
  private touch = false;
  private listening = false;
  private quiet = false;
  private readonly onResize = (): void => {
    this.updateLayout();
  };

  public constructor(options: AppShellOptions = {}) {
    this.options = options;
    this.root = options.rootElement ??
      ((globalThis as { document?: Document }).document?.body as HTMLElement);
    this.doc = this.root.ownerDocument;
    this.hostWindow = (this.doc.defaultView ?? globalThis) as Window & typeof globalThis;
    this.controller = new MobileShellController({
      rootElement: this.root,
      bottomNavElement: options.bottomNavElement ?? undefined,
      swipeContainer: options.swipeContainer ?? undefined,
      paneLabel: options.paneLabel,
      onTerminalInput: (data) => this.emitTerminalInput(data),
      // The controller reports a pane the user chose; `syncPane` below marks
      // the changes the page made so the page is never told its own news.
      onPaneChange: (pane) => {
        if (!this.quiet) {
          this.options.onPaneChange?.(pane);
        }
      },
    });
    this.renderExtraKeys();
    this.renderActionBar();
    this.updateLayout();
    if (typeof this.hostWindow.addEventListener === 'function') {
      this.hostWindow.addEventListener('resize', this.onResize);
      this.listening = true;
    }
  }

  /** The pane the touch layout currently shows. */
  public get pane(): MobilePaneId {
    return this.controller.pane;
  }

  /** True when the single-pane touch layout is active for this host. */
  public get touchLayout(): boolean {
    return this.touch;
  }

  /** Names selected in one pane, in insertion order. */
  public selection(pane: ShellPane): string[] {
    return [...this.selections[pane]];
  }

  /** Every name selected in either pane. */
  public get selectionsByName(): ShellSelection[] {
    return (['local', 'remote'] as ShellPane[]).map((pane) => ({
      pane,
      names: this.selection(pane),
    }));
  }

  /**
   * Chooses the visible pane. This is the user's act, so the page is told
   * through `onPaneChange` and can move its own focus with it.
   */
  public setPane(pane: MobilePaneId): void {
    // `setActivePane` reports the change through `onPaneChange` by itself.
    this.controller.setActivePane(pane);
    this.syncFloatingBar();
  }

  /**
   * Follows a change the page made itself (a click in a pane, F5 to the other
   * panel, a tab switch). It never calls `onPaneChange`, so the page and the
   * shell cannot drive each other in a loop.
   */
  public syncPane(pane: MobilePaneId): void {
    if (this.controller.pane === pane) {
      return;
    }
    this.quiet = true;
    try {
      this.controller.setActivePane(pane);
    } finally {
      this.quiet = false;
    }
    this.syncFloatingBar();
  }

  /** Replaces the selection of one pane and repaints the touch affordances. */
  public setSelection(pane: ShellPane, names: Iterable<string>): void {
    this.selections[pane] = new Set(names);
    this.syncFloatingBar();
    this.paintSelectedRows(pane);
  }

  /** Adds or removes one name, and reports the new selection to the page. */
  public toggleSelection(pane: ShellPane, name: string): string[] {
    const set = this.selections[pane];
    if (set.has(name)) {
      set.delete(name);
    } else {
      set.add(name);
    }
    this.syncFloatingBar();
    this.paintSelectedRows(pane);
    const names = [...set];
    this.options.onSelectionChange?.({ pane, names });
    return names;
  }

  /**
   * Re-binds the rows of a pane after the page re-rendered it.
   *
   * The page calls this with the same `<tbody>` it just filled; the previous
   * listeners are removed first so a repaint cannot stack long-press timers.
   */
  public refreshRows(pane: ShellPane, body: HTMLElement | null): void {
    for (const cleanup of this.rowCleanup.get(pane) ?? []) {
      try {
        cleanup();
      } catch {
        // A row the page replaced is already gone; there is nothing to undo.
      }
    }
    const cleanups: Array<() => void> = [];
    this.rowCleanup.set(pane, cleanups);
    if (!body || !this.touch) {
      this.paintSelectedRows(pane);
      return;
    }
    for (const row of Array.from(body.querySelectorAll<HTMLElement>('tr[data-name]'))) {
      const name = row.dataset['name'];
      if (!name) {
        continue;
      }
      cleanups.push(
        this.controller.attachLongPress(
          row,
          () => {
            this.selectRow(pane, name);
          },
          () => {
            // A plain tap inside a touch selection toggles instead of opening,
            // which is what a file manager does while a selection is active.
            if (this.selections[pane].size > 0) {
              this.selectRow(pane, name);
            }
          },
        ),
      );
    }
    this.paintSelectedRows(pane);
  }

  /** Shows the Esc/Tab/Ctrl row while the terminal has the keyboard focus. */
  public setTerminalFocused(focused: boolean): void {
    this.controller.setTerminalFocused(focused);
  }

  /** Tells the key row which cursor mode the screen is in, so its arrows work. */
  public setApplicationCursor(applicationCursor: boolean): void {
    this.controller.setApplicationCursor(applicationCursor);
  }

  /** Sends a hardware key press through the same encoding as the key row. */
  public pressExtraKey(keyId: string): string | null {
    return this.controller.pressExtraKey(keyId);
  }

  /** Encodes typed text with any latched Ctrl/Alt, as `applyCtrlModifier` does. */
  public transformTextInput(raw: string): string {
    return this.controller.transformTextInput(raw);
  }

  /** Removes every listener this shell installed. */
  public destroy(): void {
    for (const cleanups of this.rowCleanup.values()) {
      for (const cleanup of cleanups) {
        try {
          cleanup();
        } catch {
          // Best effort, as above.
        }
      }
    }
    this.rowCleanup.clear();
    this.controller.destroy();
    if (this.listening) {
      try {
        this.hostWindow.removeEventListener('resize', this.onResize);
      } catch {
        // A host without removeEventListener had no listener either.
      }
      this.listening = false;
    }
  }

  // Rendering ---------------------------------------------------------------

  /**
   * Re-evaluates whether the touch layout applies and binds or unbinds the
   * rows accordingly. Called on every resize by a desktop window that grows
   * past the breakpoint, which is why the bindings are tracked per pane.
   */
  public updateLayout(): void {
    const touch = isTouchLayout(this.hostWindow);
    if (touch === this.touch) {
      return;
    }
    this.touch = touch;
    if (!touch) {
      // Leaving the touch layout must not leave a selection behind that the
      // desktop interaction model does not know how to clear.
      for (const pane of ['local', 'remote'] as ShellPane[]) {
        if (this.selections[pane].size > 0) {
          this.selections[pane].clear();
          this.options.onSelectionChange?.({ pane, names: [] });
        }
      }
    }
    for (const pane of ['local', 'remote'] as ShellPane[]) {
      this.refreshRows(pane, this.doc.getElementById(`${pane}FileList`));
    }
    this.syncFloatingBar();
  }

  private emitTerminalInput(data: string): void {
    if (!data) {
      return;
    }
    this.options.onTerminalInput?.(data);
  }

  private renderExtraKeys(): void {
    const host = this.options.extraKeysElement;
    if (!host) {
      return;
    }
    const translate = this.options.extraKeyLabel ?? ((label: string) => label);
    host.classList.add('terminal-extra-keys');
    host.setAttribute('role', 'toolbar');
    host.setAttribute('aria-label', translate('Extra keys'));
    host.innerHTML = '';
    for (const key of EXTRA_KEYS) {
      const button = this.doc.createElement('button');
      button.type = 'button';
      button.className = 'extra-key';
      button.dataset['extraKey'] = key.id;
      const label = translate(key.label) || key.label;
      button.textContent = label;
      button.setAttribute('aria-label', label);
      if (key.modifier) {
        button.setAttribute('aria-pressed', 'false');
      }
      button.addEventListener('click', (event) => {
        event.preventDefault();
        // A key press must not steal the caret from the terminal.
        event.stopPropagation();
        this.controller.pressExtraKey(key.id);
        if (key.modifier) {
          const latched = key.modifier === 'ctrl'
            ? this.controller.isCtrlLatched
            : this.controller.isAltLatched;
          button.setAttribute('aria-pressed', latched ? 'true' : 'false');
        }
      });
      host.appendChild(button);
    }
  }

  private renderActionBar(): void {
    const host = this.options.actionBarElement;
    if (!host) {
      return;
    }
    const translate = this.options.actionLabel ?? ((action: ShellAction) => action);
    host.classList.add('floating-action-bar');
    host.setAttribute('role', 'toolbar');
    host.innerHTML = '';
    const count = this.doc.createElement('span');
    count.className = 'fab-count';
    count.setAttribute('aria-live', 'polite');
    count.textContent = '0';
    host.appendChild(count);
    for (const action of SHELL_ACTIONS) {
      const button = this.doc.createElement('button');
      button.type = 'button';
      button.className = 'btn fab-btn';
      button.dataset['shellAction'] = action;
      const label = translate(action);
      button.textContent = label;
      button.setAttribute('aria-label', label);
      button.addEventListener('click', (event) => {
        event.preventDefault();
        this.options.onAction?.(action);
      });
      this.actionButtons.push(button);
      host.appendChild(button);
    }
  }

  /** Keeps the floating bar's count and visibility in step with the state. */
  private syncFloatingBar(): void {
    const pane = this.controller.pane;
    const active: ShellPane | null = pane === 'local' || pane === 'remote' ? pane : null;
    const names: string[] = active ? [...this.selections[active]] : [];
    this.controller.setSelection(names);
    const host = this.options.actionBarElement;
    if (!host) {
      return;
    }
    const count = host.querySelector('.fab-count');
    if (count) {
      count.textContent = String(names.length);
    }
    host.classList.toggle('visible', names.length > 0);
    host.dataset['pane'] = active ?? '';
  }

  private selectRow(pane: ShellPane, name: string): void {
    // Selecting in the other panel would be two selections at once; the
    // active pane wins, as it does for every other Commander action.
    this.syncPane(pane);
    this.toggleSelection(pane, name);
  }

  private paintSelectedRows(pane: ShellPane): void {
    const body = this.doc.getElementById(`${pane}FileList`);
    if (!body) {
      return;
    }
    const selected = this.selections[pane];
    for (const row of Array.from(body.querySelectorAll<HTMLElement>('tr[data-name]'))) {
      const name = row.dataset['name'];
      const isSelected = Boolean(name) && selected.has(name as string);
      row.classList.toggle('selected-touch', isSelected && this.touch);
      row.classList.toggle('selecting', isSelected && this.touch);
    }
  }
}

/**
 * Mounts the shared shell on the page that owns the elements.
 *
 * The page calls this once at boot. A host that has none of the optional
 * elements still gets a working shell object, so the page never has to branch
 * on which app it is running in.
 */
export function mountAppShell(options: AppShellOptions = {}): AppShell {
  return new AppShell(options);
}
