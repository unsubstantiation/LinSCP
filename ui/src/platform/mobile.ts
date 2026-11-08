export type MobilePaneId = 'local' | 'remote' | 'queue' | 'terminal';

export interface ExtraKeySpec {
  id: string;
  label: string;
  sequence?: string;
  /** The sequence in application-cursor mode, where it differs (the arrows). */
  applicationSequence?: string;
  modifier?: 'ctrl' | 'alt';
}

/**
 * Touch-friendly terminal extra-key row for Android soft keyboards that omit
 * hardware Esc, Tab, Ctrl, Alt, and cursor keys. The same row is rendered by
 * the desktop window behind the terminal when the keyboard lacks these keys,
 * so both apps expose identical terminal input.
 */
export const EXTRA_KEYS: readonly ExtraKeySpec[] = [
  { id: 'esc', label: 'Esc', sequence: '\x1b' },
  { id: 'tab', label: 'Tab', sequence: '\t' },
  { id: 'ctrl', label: 'Ctrl', modifier: 'ctrl' },
  { id: 'alt', label: 'Alt', modifier: 'alt' },
  // The arrows are the one pair of sequences a full-screen program changes:
  // `vi` and `less` ask for application-cursor mode and expect `ESC O A`. A row
  // that always sent `ESC [ A` moved the cursor nowhere in either of them.
  { id: 'up', label: '↑', sequence: '\x1b[A', applicationSequence: '\x1bOA' },
  { id: 'down', label: '↓', sequence: '\x1b[B', applicationSequence: '\x1bOB' },
  { id: 'left', label: '←', sequence: '\x1b[D', applicationSequence: '\x1bOD' },
  { id: 'right', label: '→', sequence: '\x1b[C', applicationSequence: '\x1bOC' },
  { id: 'slash', label: '/', sequence: '/' },
  { id: 'dash', label: '-', sequence: '-' },
  { id: 'pipe', label: '|', sequence: '|' },
  { id: 'tilde', label: '~', sequence: '~' },
];

/**
 * Localizes the extra-key labels. A translator is optional so the controller
 * keeps working in tests and in pages without a catalog; "Esc" and "Ctrl"
 * often translate to themselves.
 */
export function extraKeyLabels(
  translate?: (label: string) => string,
): Array<{ id: string; label: string }> {
  return EXTRA_KEYS.map((key) => ({
    id: key.id,
    label: translate ? translate(key.label) || key.label : key.label,
  }));
}

/**
 * Converts a printable character into its ASCII control code when the touch
 * `Ctrl` latch is active (`c` -> `\x03` SIGINT, `d` -> `\x04` EOF, `l` -> `\x0c`).
 */
export function applyCtrlModifier(input: string): string {
  if (input.length !== 1) {
    return input;
  }
  const code = input.toUpperCase().charCodeAt(0);
  if (code >= 64 && code <= 95) {
    return String.fromCharCode(code - 64);
  }
  return input;
}

export interface MobileShellOptions {
  rootElement: HTMLElement;
  onTerminalInput?: (data: string) => void;
  /** Optional bottom nav element to drive. If supplied, controller wires it. */
  bottomNavElement?: HTMLElement;
  /** Optional swipe container (usually `.commander-main`). */
  swipeContainer?: HTMLElement;
  /** Localizes a pane name for the bottom navigation. */
  paneLabel?: (pane: MobilePaneId) => string;
  /**
   * The visible pane changed because the user tapped, swiped or used a
   * shortcut. The host uses it to move its own focus; a change the host makes
   * itself (`syncPane`) does not call it.
   */
  onPaneChange?: (pane: MobilePaneId) => void;
}

export const MOBILE_PANE_ORDER: readonly MobilePaneId[] = ['local', 'remote', 'queue', 'terminal'] as const;

export function nextPane(current: MobilePaneId): MobilePaneId {
  const idx = MOBILE_PANE_ORDER.indexOf(current);
  return MOBILE_PANE_ORDER[(idx + 1) % MOBILE_PANE_ORDER.length] as MobilePaneId;
}

export function prevPane(current: MobilePaneId): MobilePaneId {
  const idx = MOBILE_PANE_ORDER.indexOf(current);
  return MOBILE_PANE_ORDER[(idx - 1 + MOBILE_PANE_ORDER.length) % MOBILE_PANE_ORDER.length] as MobilePaneId;
}

const PANE_ICONS: Record<MobilePaneId, string> = {
  local: '💻',
  remote: '☁️',
  queue: '⬇',
  terminal: '>_',
};

/**
 * Single-pane touch shell shared by the Android app and any narrow desktop or
 * browser window: swipe between the panes, drive the bottom navigation, keep a
 * multi-select set for long-press selection, and feed the terminal extra keys.
 *
 * Every listener the controller adds is tracked so `destroy()` leaves the page
 * exactly as it found it; the desktop window destroys it when it grows past the
 * touch layout instead of leaving duplicate handlers behind.
 */
export class MobileShellController {
  private readonly root: HTMLElement;
  private readonly onTerminalInput?: (data: string) => void;
  private readonly paneLabel?: (pane: MobilePaneId) => string;
  private readonly onPaneChange?: (pane: MobilePaneId) => void;
  private activePane: MobilePaneId = 'local';
  private ctrlLatched = false;
  /** Whether the screen asked for application-cursor arrows. */
  private applicationCursor = false;
  private altLatched = false;
  private bottomNav: HTMLElement | null = null;
  private swipeContainer: HTMLElement | null = null;
  private swipeStartX = 0;
  private swipeStartY = 0;
  private swipeTracking = false;
  private selectionMode = false;
  private shouldSwipe: ((event: TouchEvent) => boolean) | null = null;
  private readonly cleanupFns: Array<() => void> = [];
  // Tracked for floating bar count display; read via getter for tests.
  private _selectedCount = 0;
  private selection = new Set<string>();

  public constructor(options: MobileShellOptions) {
    this.root = options.rootElement;
    this.onTerminalInput = options.onTerminalInput;
    this.paneLabel = options.paneLabel;
    this.onPaneChange = options.onPaneChange;
    this.root.dataset['mobilePane'] = this.activePane;
    if (options.bottomNavElement) {
      this.attachBottomNav(options.bottomNavElement);
    }
    if (options.swipeContainer) {
      this.attachSwipe(options.swipeContainer);
    }
  }

  public get pane(): MobilePaneId {
    return this.activePane;
  }

  public get isCtrlLatched(): boolean {
    return this.ctrlLatched;
  }

  public get isAltLatched(): boolean {
    return this.altLatched;
  }

  public get isSelectionMode(): boolean {
    return this.selectionMode;
  }

  /** Names currently in the touch multi-select set. */
  public get selectedNames(): string[] {
    return [...this.selection];
  }

  public setActivePane(pane: MobilePaneId): void {
    const changed = this.activePane !== pane;
    this.activePane = pane;
    this.root.dataset['mobilePane'] = pane;
    this.syncBottomNav();
    this.syncSwipeScroll();
    if (changed) {
      this.onPaneChange?.(pane);
    }
  }

  /**
   * Removes every listener this controller installed. Called when the window
   * leaves the touch layout so a later resize does not stack handlers.
   */
  public destroy(): void {
    for (const cleanup of this.cleanupFns.splice(0)) {
      try {
        cleanup();
      } catch {
        // The host page may have replaced the container; cleanup is best effort.
      }
    }
    this.bottomNav = null;
    this.swipeContainer = null;
    this.selection.clear();
  }

  // Bottom navigation -------------------------------------------------------

  public attachBottomNav(navEl: HTMLElement): void {
    this.bottomNav = navEl;
    this.renderBottomNav();
    const listener = (event: Event): void => {
      const target = (event.target as HTMLElement | null)?.closest?.('[data-pane]') as HTMLElement | null;
      if (!target) return;
      const pane = target.getAttribute('data-pane') as MobilePaneId | null;
      if (pane && (MOBILE_PANE_ORDER as readonly string[]).includes(pane)) {
        this.setActivePane(pane);
      }
    };
    navEl.addEventListener('click', listener);
    this.cleanupFns.push(() => navEl.removeEventListener('click', listener));
    this.syncBottomNav();
  }

  private renderBottomNav(): void {
    if (!this.bottomNav) return;
    const doc = this.bottomNav.ownerDocument;
    this.bottomNav.innerHTML = '';
    this.bottomNav.classList.add('mobile-bottom-nav');
    this.bottomNav.setAttribute('role', 'tablist');
    for (const pane of MOBILE_PANE_ORDER) {
      const btn = doc.createElement('button');
      btn.type = 'button';
      btn.setAttribute('data-pane', pane);
      btn.setAttribute('role', 'tab');
      const label = this.paneLabel ? this.paneLabel(pane) : pane;
      btn.setAttribute('aria-label', label);
      const icon = doc.createElement('span');
      icon.className = 'nav-icon';
      icon.setAttribute('aria-hidden', 'true');
      icon.textContent = PANE_ICONS[pane];
      const text = doc.createElement('span');
      text.textContent = label;
      btn.appendChild(icon);
      btn.appendChild(text);
      this.bottomNav.appendChild(btn);
    }
  }

  private syncBottomNav(): void {
    if (!this.bottomNav) return;
    for (const btn of Array.from(this.bottomNav.querySelectorAll('[data-pane]'))) {
      const pane = btn.getAttribute('data-pane');
      const active = pane === this.activePane;
      btn.classList.toggle('active', active);
      btn.setAttribute('aria-selected', active ? 'true' : 'false');
    }
  }

  // Horizontal swipe ---------------------------------------------------------

  public attachSwipe(container: HTMLElement): void {
    this.swipeContainer = container;
    container.addEventListener('touchstart', this.onTouchStart, { passive: true });
    container.addEventListener('touchmove', this.onTouchMove, { passive: true });
    container.addEventListener('touchend', this.onTouchEnd, { passive: true });
    // Desktop drag swipe fallback for testing with mouse
    container.addEventListener('mousedown', this.onMouseDown);
    this.cleanupFns.push(() => this.detachSwipe());
  }

  public detachSwipe(): void {
    if (!this.swipeContainer) return;
    this.swipeContainer.removeEventListener('touchstart', this.onTouchStart);
    this.swipeContainer.removeEventListener('touchmove', this.onTouchMove);
    this.swipeContainer.removeEventListener('touchend', this.onTouchEnd);
    this.swipeContainer.removeEventListener('mousedown', this.onMouseDown);
    this.swipeContainer = null;
  }

  /**
   * Declines a swipe that began on a row, a scrollbar, an input or any element
   * the page marks `[data-no-swipe]`. Without this a horizontal drag to select
   * rows flipped the whole pane on Android.
   */
  public setSwipeFilter(filter: ((event: TouchEvent) => boolean) | null): void {
    this.shouldSwipe = filter;
  }

  private onTouchStart = (event: TouchEvent): void => {
    if (event.touches.length !== 1) return;
    const touch = event.touches[0];
    if (!touch) return;
    if (this.shouldSwipe && !this.shouldSwipe(event)) {
      this.swipeTracking = false;
      return;
    }
    this.swipeStartX = touch.clientX;
    this.swipeStartY = touch.clientY;
    this.swipeTracking = true;
  };

  private onTouchMove = (_event: TouchEvent): void => {
    // No-op: we wait for touchend to decide; prevents interfering with vertical scroll.
  };

  private onTouchEnd = (event: TouchEvent): void => {
    if (!this.swipeTracking) return;
    this.swipeTracking = false;
    const touch = event.changedTouches[0];
    if (!touch) return;
    const dx = touch.clientX - this.swipeStartX;
    const dy = touch.clientY - this.swipeStartY;
    // Require horizontal dominance and minimum distance (40px)
    if (Math.abs(dx) < 40 || Math.abs(dx) < Math.abs(dy) * 1.2) return;
    if (dx < 0) {
      this.setActivePane(nextPane(this.activePane));
    } else {
      this.setActivePane(prevPane(this.activePane));
    }
  };

  private onMouseDown = (event: MouseEvent): void => {
    // Simple mouse drag swipe for desktop testing: track 40px drag.
    const view = (this.swipeContainer?.ownerDocument?.defaultView ?? globalThis) as
      Window & typeof globalThis;
    const startX = event.clientX;
    const startY = event.clientY;
    const onUp = (up: MouseEvent): void => {
      view.removeEventListener('mouseup', onUp);
      const dx = up.clientX - startX;
      const dy = up.clientY - startY;
      if (Math.abs(dx) < 60 || Math.abs(dx) < Math.abs(dy) * 1.2) return;
      if (dx < 0) this.setActivePane(nextPane(this.activePane));
      else this.setActivePane(prevPane(this.activePane));
    };
    view.addEventListener('mouseup', onUp, { once: true });
  };

  private syncSwipeScroll(): void {
    if (!this.swipeContainer) return;
    // When in single-pane swipe mode (flex row with scroll-snap), scroll to active pane.
    // Fallback: rely on CSS [data-mobile-pane] selector; scroll is progressive enhancement.
    const idx = MOBILE_PANE_ORDER.indexOf(this.activePane);
    if (idx < 0) return;
    try {
      const paneWidth = this.swipeContainer.clientWidth || 1;
      this.swipeContainer.scrollTo({ left: idx * paneWidth, behavior: 'smooth' });
    } catch {
      // JSDOM or older browsers may not support scrollTo – ignore.
    }
  }

  // Touch selection / long-press -------------------------------------------

  /**
   * Enters or exits multi-select mode. When entering, the floating action bar
   * (`.floating-action-bar`) becomes visible and file rows show checkboxes.
   */
  public setSelectionMode(enabled: boolean, selectedCount = 0): void {
    this.selectionMode = enabled;
    this._selectedCount = selectedCount;
    this.root.dataset['selectionMode'] = enabled ? 'on' : 'off';
    if (!enabled) {
      this.selection.clear();
    }
    this.syncFloatingBar();
  }

  public get selectedCount(): number {
    return this._selectedCount;
  }

  /** Adds or removes one name from the touch selection, entering the mode. */
  public toggleSelection(name: string): boolean {
    const selected = this.selection.has(name);
    if (selected) {
      this.selection.delete(name);
    } else {
      this.selection.add(name);
    }
    this.selectionMode = true;
    this._selectedCount = this.selection.size;
    this.root.dataset['selectionMode'] = 'on';
    this.syncFloatingBar();
    return !selected;
  }

  /** Replaces the touch selection (used by "select all" and after a delete). */
  public setSelection(names: Iterable<string>): void {
    this.selection = new Set(names);
    this._selectedCount = this.selection.size;
    this.selectionMode = this.selection.size > 0;
    this.root.dataset['selectionMode'] = this.selectionMode ? 'on' : 'off';
    this.syncFloatingBar();
  }

  public clearSelection(): void {
    this.setSelection([]);
  }

  private syncFloatingBar(): void {
    const bar = this.root.ownerDocument.querySelector('.floating-action-bar') as HTMLElement | null;
    if (!bar) return;
    const visible = this.selectionMode && this._selectedCount > 0;
    bar.classList.toggle('visible', visible);
    const countEl = bar.querySelector('.fab-count') as HTMLElement | null;
    if (countEl) countEl.textContent = String(this._selectedCount);
  }

  /**
   * Creates a long-press detector for a file row element. After `delayMs`
   * (default 500ms) without significant movement, `onLongPress` is invoked
   * and the row enters selection mode. Single tap still enters directory.
   */
  public attachLongPress(
    row: HTMLElement,
    onLongPress: () => void,
    onSingleTap: () => void,
    delayMs = 500,
  ): () => void {
    // The row's own window, so the timer and its clearing come from the same
    // realm: a timer created by the page and cleared by the bundle would leak
    // a pending long press into the next render.
    const view = (row.ownerDocument?.defaultView ?? globalThis) as Window & typeof globalThis;
    let timer: number | null = null;
    let moved = false;
    let longPressed = false;
    let startX = 0;
    let startY = 0;

    const start = (event: TouchEvent | MouseEvent): void => {
      moved = false;
      longPressed = false;
      const point = (event as TouchEvent).touches?.[0] ?? (event as MouseEvent);
      startX = (point as { clientX: number }).clientX ?? 0;
      startY = (point as { clientY: number }).clientY ?? 0;
      timer = view.setTimeout(() => {
        longPressed = true;
        this.setSelectionMode(true, 1);
        onLongPress();
      }, delayMs) as unknown as number;
    };
    const move = (event: TouchEvent | MouseEvent): void => {
      const point = (event as TouchEvent).touches?.[0] ?? (event as MouseEvent);
      const x = (point as { clientX: number }).clientX ?? startX;
      const y = (point as { clientY: number }).clientY ?? startY;
      if (Math.abs(x - startX) > 10 || Math.abs(y - startY) > 10) {
        moved = true;
        if (timer !== null) {
          view.clearTimeout(timer as unknown as number);
          timer = null;
        }
      }
    };
    const end = (): void => {
      if (timer !== null) {
        view.clearTimeout(timer as unknown as number);
        timer = null;
      }
      if (!moved && !longPressed) {
        onSingleTap();
      }
    };
    const cancel = (): void => {
      if (timer !== null) {
        view.clearTimeout(timer as unknown as number);
        timer = null;
      }
    };

    row.addEventListener('touchstart', start as EventListener, { passive: true });
    row.addEventListener('touchmove', move as EventListener, { passive: true });
    row.addEventListener('touchend', end as EventListener);
    row.addEventListener('touchcancel', cancel as EventListener);
    // Mouse fallback for desktop testing
    row.addEventListener('mousedown', start as EventListener);
    row.addEventListener('mousemove', move as EventListener);
    row.addEventListener('mouseup', end as EventListener);

    const cleanup = (): void => {
      row.removeEventListener('touchstart', start as EventListener);
      row.removeEventListener('touchmove', move as EventListener);
      row.removeEventListener('touchend', end as EventListener);
      row.removeEventListener('touchcancel', cancel as EventListener);
      row.removeEventListener('mousedown', start as EventListener);
      row.removeEventListener('mousemove', move as EventListener);
      row.removeEventListener('mouseup', end as EventListener);
      if (timer !== null) view.clearTimeout(timer as unknown as number);
    };
    this.cleanupFns.push(cleanup);
    return cleanup;
  }

  // Extra keys ---------------------------------------------------------------

  /**
   * Tells the row which cursor mode the screen is in.
   *
   * The terminal reports it with every frame; the row cannot know it on its
   * own, and guessing normal mode is what made the arrows dead in `vi`.
   */
  public setApplicationCursor(applicationCursor: boolean): void {
    this.applicationCursor = applicationCursor;
  }

  public pressExtraKey(keyId: string): string | null {
    const spec = EXTRA_KEYS.find((key) => key.id === keyId);
    if (!spec) {
      return null;
    }
    if (spec.modifier === 'ctrl') {
      this.ctrlLatched = !this.ctrlLatched;
      this.syncLatchedKeys();
      return null;
    }
    if (spec.modifier === 'alt') {
      this.altLatched = !this.altLatched;
      this.syncLatchedKeys();
      return null;
    }
    const base = this.applicationCursor && spec.applicationSequence
      ? spec.applicationSequence
      : spec.sequence ?? '';
    const seq = this.transformTextInput(base);
    this.syncLatchedKeys();
    this.onTerminalInput?.(seq);
    return seq;
  }

  /** Marks the latched Ctrl/Alt buttons so the bar shows the pending modifier. */
  private syncLatchedKeys(): void {
    const doc = this.root.ownerDocument;
    const ctrl = doc.querySelector('[data-extra-key="ctrl"]');
    const alt = doc.querySelector('[data-extra-key="alt"]');
    if (ctrl) ctrl.classList.toggle('latched', this.ctrlLatched);
    if (alt) alt.classList.toggle('latched', this.altLatched);
  }

  public transformTextInput(raw: string): string {
    let out = raw;
    if (this.ctrlLatched) {
      out = applyCtrlModifier(out);
      this.ctrlLatched = false;
    }
    if (this.altLatched) {
      out = `\x1b${out}`;
      this.altLatched = false;
    }
    return out;
  }

  /** Clears both latches, for when the terminal loses focus mid-keypress. */
  public resetLatches(): void {
    this.ctrlLatched = false;
    this.altLatched = false;
    this.syncLatchedKeys();
  }

  /** Updates the extra-keys accessory bar visibility tied to terminal focus. */
  public setTerminalFocused(focused: boolean): void {
    const bar = this.root.ownerDocument.querySelector('.terminal-extra-keys') as HTMLElement | null;
    if (bar) bar.classList.toggle('visible', focused);
    if (!focused) this.resetLatches();
  }
}
