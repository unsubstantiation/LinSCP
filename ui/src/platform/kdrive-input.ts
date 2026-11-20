import type { DesktopInputEvent } from './desktop-input.js';
import { kdriveButtonEvent, kdriveKeyEvent, kdriveMotionEvent } from './kdrive-events.js';

/** A barrier is a required server round trip, not a write or a timer. The
 * transport must complete it before sending any following action. */
export type KDriveInputAction = { type: 'packet'; bytes: Uint8Array } | { type: 'barrier' };

// XKB evdev physical keycodes (Linux evdev + 8); the server's selected XKB
// layout determines characters. Unknown browser codes are not guessed.
const KEYS: Readonly<Record<string, number>> = {
  Escape: 9, Digit1: 10, Digit2: 11, Digit3: 12, Digit4: 13, Digit5: 14,
  Digit6: 15, Digit7: 16, Digit8: 17, Digit9: 18, Digit0: 19, Minus: 20, Equal: 21,
  Backspace: 22, Tab: 23, KeyQ: 24, KeyW: 25, KeyE: 26, KeyR: 27, KeyT: 28,
  KeyY: 29, KeyU: 30, KeyI: 31, KeyO: 32, KeyP: 33, BracketLeft: 34,
  BracketRight: 35, Enter: 36, KeyA: 38, KeyS: 39, KeyD: 40, KeyF: 41,
  KeyG: 42, KeyH: 43, KeyJ: 44, KeyK: 45, KeyL: 46, Semicolon: 47,
  Quote: 48, Backquote: 49, Backslash: 51, KeyZ: 52, KeyX: 53, KeyC: 54,
  KeyV: 55, KeyB: 56, KeyN: 57, KeyM: 58, Comma: 59, Period: 60,
  Slash: 61, NumpadMultiply: 63, Space: 65, F1: 67, F2: 68, F3: 69,
  F4: 70, F5: 71, F6: 72, F7: 73, F8: 74, F9: 75, F10: 76,
  Numpad7: 79, Numpad8: 80, Numpad9: 81, NumpadSubtract: 82,
  Numpad4: 83, Numpad5: 84, Numpad6: 85, NumpadAdd: 86,
  Numpad1: 87, Numpad2: 88, Numpad3: 89, Numpad0: 90, NumpadDecimal: 91,
  IntlBackslash: 94, F11: 95, F12: 96, NumpadEnter: 104, NumpadDivide: 106,
  PrintScreen: 107, Home: 110, ArrowUp: 111, PageUp: 112, ArrowLeft: 113,
  ArrowRight: 114, End: 115, ArrowDown: 116, PageDown: 117, Insert: 118,
  Delete: 119, Pause: 127, ContextMenu: 135,
};
type Modifier = { bit: number; keycode: number };
const MODIFIERS: Readonly<Record<string, Modifier>> = {
  ShiftLeft: { bit: 1, keycode: 50 }, ShiftRight: { bit: 1, keycode: 62 },
  ControlLeft: { bit: 4, keycode: 37 }, ControlRight: { bit: 4, keycode: 105 },
  AltLeft: { bit: 8, keycode: 64 }, AltRight: { bit: 8, keycode: 108 },
  MetaLeft: { bit: 64, keycode: 133 }, MetaRight: { bit: 64, keycode: 134 },
};
const SERVER_MODIFIER_KEY: Readonly<Record<number, number>> = { 1: 50, 4: 37, 8: 64, 64: 133, 128: 92 };
const LOCKS: Readonly<Record<string, { bit: number; keycode: number }>> = {
  CapsLock: { bit: 2, keycode: 66 }, NumLock: { bit: 16, keycode: 77 },
};
const BUTTONS: readonly number[] = [1, 2, 3, 8, 9];

/** Translates DesktopInput's ordered physical events for an evdev XKB server.
 * A new instance is required for each connection. The caller supplies the
 * initial remote lock states; they cannot be inferred from a DOM key event.
 * Unsupported keys, composition and horizontal scrolling are not synthesized.
 * The connection must serialize actions and implement barrier round trips. */
export class KDriveInputTranslator {
  private readonly heldModifiers = new Map<string, Modifier>();
  private readonly heldKeys = new Set<string>();
  private readonly heldButtons = new Set<number>();
  private locks: number;
  private sentMask: number;
  private pendingTap: string | null = null;
  private position: { x: number; y: number } | null = null;
  private readonly altGr: boolean;

  constructor(options: { capsLock: boolean; numLock: boolean; rightAltIsAltGr: boolean }) {
    this.locks = (options.capsLock ? 2 : 0) | (options.numLock ? 16 : 0);
    this.sentMask = this.locks;
    this.altGr = options.rightAltIsAltGr;
  }

  private mask(): number {
    let mask = this.locks;
    for (const mod of this.heldModifiers.values()) mask |= mod.bit;
    return mask;
  }
  private key(out: KDriveInputAction[], down: boolean, code: number): void {
    const mask = this.mask();
    out.push({ type: 'packet', bytes: kdriveKeyEvent(down, mask, code) });
    this.sentMask = mask;
  }
  private button(out: KDriveInputAction[], down: boolean, button: number): void {
    const mask = this.mask();
    out.push({ type: 'packet', bytes: kdriveButtonEvent(down, mask, button) });
    this.sentMask = mask;
  }
  private move(out: KDriveInputAction[], x: number, y: number): void {
    if (!this.position || this.position.x !== x || this.position.y !== y) {
      out.push({ type: 'packet', bytes: kdriveMotionEvent(x, y) });
      this.position = { x, y };
    }
  }

  public translate(input: DesktopInputEvent): KDriveInputAction[] {
    const out: KDriveInputAction[] = [];
    if (input.type === 'key') {
      const mod = Object.hasOwn(MODIFIERS, input.code) ? MODIFIERS[input.code] : undefined;
      if (mod) {
        const actual = input.code === 'AltRight' && this.altGr ? { bit: 128, keycode: mod.keycode } : mod;
        if (input.down) {
          if (!this.heldModifiers.has(input.code)) { this.heldModifiers.set(input.code, actual); this.pendingTap = input.code; }
        } else {
          const held = this.heldModifiers.get(input.code);
          if (!held) return out;
          this.heldModifiers.delete(input.code);
          const mask = this.mask();
          if (this.pendingTap === input.code && !(mask & held.bit) && !(this.sentMask & held.bit)) {
            this.key(out, true, held.keycode);
          } else if (!(mask & held.bit) && (this.sentMask & held.bit)) {
            out.push({ type: 'packet', bytes: kdriveKeyEvent(false, this.sentMask, SERVER_MODIFIER_KEY[held.bit]!) });
            this.sentMask &= ~held.bit;
            // The server compares modifiers against a batch's initial state.
            // Wait for the release to be processed before a later press.
            out.push({ type: 'barrier' });
          }
          this.pendingTap = null;
        }
        return out;
      }
      const lock = Object.hasOwn(LOCKS, input.code) ? LOCKS[input.code] : undefined;
      if (lock) {
        if (!input.down) { this.heldKeys.delete(input.code); return out; }
        if (this.heldKeys.has(input.code)) return out;
        this.heldKeys.add(input.code); this.pendingTap = null;
        this.key(out, true, lock.keycode);
        out.push({ type: 'barrier' });
        this.locks ^= lock.bit;
        this.sentMask = (this.sentMask & ~lock.bit) | (this.locks & lock.bit);
        return out;
      }
      const code = Object.hasOwn(KEYS, input.code) ? KEYS[input.code] : undefined;
      if (!code) return out;
      if (!input.down && !this.heldKeys.has(input.code)) return out;
      if (input.down) this.heldKeys.add(input.code); else this.heldKeys.delete(input.code);
      this.pendingTap = null;
      this.key(out, input.down, code);
      return out;
    }
    // Validate coordinates before mutating any state.
    kdriveMotionEvent(input.x, input.y);
    if (input.type === 'pointer') { this.move(out, input.x, input.y); return out; }
    if (input.type === 'button') {
      const button = BUTTONS[input.button];
      if (!Number.isInteger(input.button) || button === undefined || this.heldButtons.has(button) === input.down) return out;
      this.move(out, input.x, input.y); this.pendingTap = null;
      if (input.down) this.heldButtons.add(button); else this.heldButtons.delete(button);
      this.button(out, input.down, button);
      return out;
    }
    if (!Number.isFinite(input.deltaY) || !Number.isFinite(input.deltaX) || ![0, 1, 2].includes(input.deltaMode)) return out;
    this.move(out, input.x, input.y);
    if (input.deltaY) {
      this.pendingTap = null;
      // Bound remote work; tiny touchpad deltas still produce one notch.
      const scale = input.deltaMode === 0 ? 100 : input.deltaMode === 1 ? 3 : 1;
      const count = Math.min(10, Math.max(1, Math.round(Math.abs(input.deltaY) / scale)));
      const button = input.deltaY < 0 ? 4 : 5;
      for (let n = 0; n < count; n++) { this.button(out, true, button); this.button(out, false, button); }
    }
    return out;
  }
}
