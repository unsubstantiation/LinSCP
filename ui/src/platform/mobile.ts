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
}

export class MobileShellController {
  private readonly root: HTMLElement;
  private readonly onTerminalInput?: (data: string) => void;
  private activePane: MobilePaneId = 'local';
  private ctrlLatched = false;
  private altLatched = false;

  public constructor(options: MobileShellOptions) {
    this.root = options.rootElement;
    this.onTerminalInput = options.onTerminalInput;
    this.root.dataset['mobilePane'] = this.activePane;
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

  public setActivePane(pane: MobilePaneId): void {
    this.activePane = pane;
    this.root.dataset['mobilePane'] = pane;
  }

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
}
