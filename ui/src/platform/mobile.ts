export type MobilePaneId = 'local' | 'remote' | 'queue' | 'terminal';

export interface ExtraKeySpec {
  id: string;
  label: string;
  sequence?: string;
  modifier?: 'ctrl' | 'alt';
}

/**
 * Touch-friendly terminal extra-key row for Android soft keyboards that omit
 * hardware Esc, Tab, Ctrl, Alt, and cursor keys.
 */
export const EXTRA_KEYS: readonly ExtraKeySpec[] = [
  { id: 'esc', label: 'Esc', sequence: '\x1b' },
  { id: 'tab', label: 'Tab', sequence: '\t' },
  { id: 'ctrl', label: 'Ctrl', modifier: 'ctrl' },
  { id: 'alt', label: 'Alt', modifier: 'alt' },
  { id: 'up', label: '↑', sequence: '\x1b[A' },
  { id: 'down', label: '↓', sequence: '\x1b[B' },
  { id: 'left', label: '←', sequence: '\x1b[D' },
  { id: 'right', label: '→', sequence: '\x1b[C' },
  { id: 'slash', label: '/', sequence: '/' },
  { id: 'dash', label: '-', sequence: '-' },
  { id: 'pipe', label: '|', sequence: '|' },
  { id: 'tilde', label: '~', sequence: '~' },
];

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

export class MobileShellController {
  private readonly root: HTMLElement;
  private readonly onTerminalInput?: (data: string) => void;
  private activePane: MobilePaneId = 'local';
  private ctrlLatched = false;
  private altLatched = false;
  private bottomNav: HTMLElement | null = null;
  private swipeContainer: HTMLElement | null = null;
  private swipeStartX = 0;
  private swipeStartY = 0;
  private swipeTracking = false;
  private selectionMode = false;
  // Tracked for floating bar count display; read via getter for tests.
  private _selectedCount = 0;

  public constructor(options: MobileShellOptions) {
    this.root = options.rootElement;
    this.onTerminalInput = options.onTerminalInput;
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

  public setActivePane(pane: MobilePaneId): void {
    this.activePane = pane;
    this.root.dataset['mobilePane'] = pane;
    this.syncBottomNav();
    this.syncSwipeScroll();
  }

  // Bottom navigation -------------------------------------------------------

  public attachBottomNav(navEl: HTMLElement): void {
    this.bottomNav = navEl;
    this.renderBottomNav();
    navEl.addEventListener('click', (e) => {
      const target = (e.target as HTMLElement).closest('[data-pane]') as HTMLElement | null;
      if (!target) return;
      const pane = target.getAttribute('data-pane') as MobilePaneId | null;
      if (pane && (MOBILE_PANE_ORDER as readonly string[]).includes(pane)) {
        this.setActivePane(pane);
      }
    });
    this.syncBottomNav();
  }

  private renderBottomNav(): void {
    if (!this.bottomNav) return;
    const doc = this.bottomNav.ownerDocument;
    this.bottomNav.innerHTML = '';
    this.bottomNav.classList.add('mobile-bottom-nav');
    const icons: Record<MobilePaneId, string> = {
      local: '💻',
      remote: '☁️',
      queue: '⬇',
      terminal: '>_',
    };
    for (const pane of MOBILE_PANE_ORDER) {
      const btn = doc.createElement('button');
      btn.setAttribute('data-pane', pane);
      btn.setAttribute('aria-label', pane);
      const icon = doc.createElement('span');
      icon.className = 'nav-icon';
      icon.textContent = icons[pane];
      const label = doc.createElement('span');
      label.textContent = pane;
      btn.appendChild(icon);
      btn.appendChild(label);
      this.bottomNav.appendChild(btn);
    }
  }

  private syncBottomNav(): void {
    if (!this.bottomNav) return;
    for (const btn of Array.from(this.bottomNav.querySelectorAll('[data-pane]'))) {
      const pane = btn.getAttribute('data-pane');
      btn.classList.toggle('active', pane === this.activePane);
    }
  }

  // Horizontal swipe ---------------------------------------------------------

  public attachSwipe(container: HTMLElement): void {
    this.swipeContainer = container;
    container.addEventListener('touchstart', this.onTouchStart, { passive: true });
    container.addEventListener('touchmove', this.onTouchMove, { passive: true });
    container.addEventListener('touchend', this.onTouchEnd, { passive: true });
    // Desktop drag swipe fallback for testing with mouse
    container.addEventListener('mousedown', this.onMouseDown as EventListener);
  }

  public detachSwipe(): void {
    if (!this.swipeContainer) return;
    this.swipeContainer.removeEventListener('touchstart', this.onTouchStart);
    this.swipeContainer.removeEventListener('touchmove', this.onTouchMove);
    this.swipeContainer.removeEventListener('touchend', this.onTouchEnd);
    this.swipeContainer.removeEventListener('mousedown', this.onMouseDown as EventListener);
    this.swipeContainer = null;
  }

  private onTouchStart = (e: TouchEvent): void => {
    if (e.touches.length !== 1) return;
    const t = e.touches[0];
    if (!t) return;
    this.swipeStartX = t.clientX;
    this.swipeStartY = t.clientY;
    this.swipeTracking = true;
  };

  private onTouchMove = (_e: TouchEvent): void => {
    // No-op: we wait for touchend to decide; prevents interfering with vertical scroll.
  };

  private onTouchEnd = (e: TouchEvent): void => {
    if (!this.swipeTracking) return;
    this.swipeTracking = false;
    const t = e.changedTouches[0];
    if (!t) return;
    const dx = t.clientX - this.swipeStartX;
    const dy = t.clientY - this.swipeStartY;
    // Require horizontal dominance and minimum distance (40px)
    if (Math.abs(dx) < 40 || Math.abs(dx) < Math.abs(dy) * 1.2) return;
    if (dx < 0) {
      this.setActivePane(nextPane(this.activePane));
    } else {
      this.setActivePane(prevPane(this.activePane));
    }
  };

  private onMouseDown = (e: MouseEvent): void => {
    // Simple mouse drag swipe for desktop testing: track 40px drag.
    const startX = e.clientX;
    const startY = e.clientY;
    const onUp = (up: MouseEvent): void => {
      window.removeEventListener('mouseup', onUp);
      const dx = up.clientX - startX;
      const dy = up.clientY - startY;
      if (Math.abs(dx) < 60 || Math.abs(dx) < Math.abs(dy) * 1.2) return;
      if (dx < 0) this.setActivePane(nextPane(this.activePane));
      else this.setActivePane(prevPane(this.activePane));
    };
    window.addEventListener('mouseup', onUp, { once: true });
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
    // Sync floating bar if present in DOM
    const bar = this.root.ownerDocument.querySelector('.floating-action-bar') as HTMLElement | null;
    if (bar) {
      bar.classList.toggle('visible', enabled && selectedCount > 0);
      const countEl = bar.querySelector('.fab-count') as HTMLElement | null;
      if (countEl) countEl.textContent = String(selectedCount);
    }
  }

  public get selectedCount(): number {
    return this._selectedCount;
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
    let timer: number | null = null;
    let moved = false;
    let longPressed = false;
    let startX = 0;
    let startY = 0;

    const start = (e: TouchEvent | MouseEvent): void => {
      moved = false;
      longPressed = false;
      const point = (e as TouchEvent).touches?.[0] ?? (e as MouseEvent);
      startX = (point as { clientX: number }).clientX ?? 0;
      startY = (point as { clientY: number }).clientY ?? 0;
      timer = window.setTimeout(() => {
        longPressed = true;
        this.setSelectionMode(true, 1);
        onLongPress();
      }, delayMs) as unknown as number;
    };
    const move = (e: TouchEvent | MouseEvent): void => {
      const point = (e as TouchEvent).touches?.[0] ?? (e as MouseEvent);
      const x = (point as { clientX: number }).clientX ?? startX;
      const y = (point as { clientY: number }).clientY ?? startY;
      if (Math.abs(x - startX) > 10 || Math.abs(y - startY) > 10) {
        moved = true;
        if (timer !== null) {
          clearTimeout(timer as unknown as number);
          timer = null;
        }
      }
    };
    const end = (): void => {
      if (timer !== null) {
        clearTimeout(timer as unknown as number);
        timer = null;
      }
      if (!moved && !longPressed) {
        onSingleTap();
      }
    };
    const cancel = (): void => {
      if (timer !== null) {
        clearTimeout(timer as unknown as number);
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

    return () => {
      row.removeEventListener('touchstart', start as EventListener);
      row.removeEventListener('touchmove', move as EventListener);
      row.removeEventListener('touchend', end as EventListener);
      row.removeEventListener('touchcancel', cancel as EventListener);
      row.removeEventListener('mousedown', start as EventListener);
      row.removeEventListener('mousemove', move as EventListener);
      row.removeEventListener('mouseup', end as EventListener);
      if (timer !== null) clearTimeout(timer as unknown as number);
    };
  }

  // Extra keys ---------------------------------------------------------------

  public pressExtraKey(keyId: string): string | null {
    const spec = EXTRA_KEYS.find((k) => k.id === keyId);
    if (!spec) {
      return null;
    }
    if (spec.modifier === 'ctrl') {
      this.ctrlLatched = !this.ctrlLatched;
      return null;
    }
    if (spec.modifier === 'alt') {
      this.altLatched = !this.altLatched;
      return null;
    }
    const seq = this.transformTextInput(spec.sequence ?? '');
    this.onTerminalInput?.(seq);
    return seq;
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

  /** Updates the extra-keys accessory bar visibility tied to terminal focus. */
  public setTerminalFocused(focused: boolean): void {
    const bar = this.root.ownerDocument.querySelector('.terminal-extra-keys') as HTMLElement | null;
    if (bar) bar.classList.toggle('visible', focused);
  }
}
