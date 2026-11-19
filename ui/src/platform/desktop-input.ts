import type { DesktopFrameRenderer } from './desktop-frame-renderer.js';

/** Input events for a future decoded-desktop backend, not KDrive wire messages. */
export type DesktopInputEvent =
  | { type: 'key'; down: boolean; code: string; key: string; location: number; repeat: boolean }
  | { type: 'pointer'; x: number; y: number }
  | { type: 'button'; down: boolean; button: number; x: number; y: number }
  | { type: 'scroll'; x: number; y: number; deltaX: number; deltaY: number; deltaMode: number };

type KeyDown = Extract<DesktopInputEvent, { type: 'key' }>;
type Point = { x: number; y: number };

/**
 * Captures input only while the decoded desktop canvas is focused and enabled.
 *
 * The sink must accept events synchronously in order; a transport needs its own
 * ordered queue and must reset remote key/button state if it disconnects. This
 * class does not translate DOM key codes to X keysyms or send NX messages.
 * IME/composition and clipboard input need a separate backend contract.
 */
export class DesktopInput {
  private readonly renderer: DesktopFrameRenderer;
  private readonly canvas: HTMLCanvasElement;
  private readonly doc: Document;
  private readonly view: Window | null;
  private readonly send: (event: DesktopInputEvent) => void;
  private readonly keys = new Map<string, KeyDown>();
  private readonly buttons = new Set<number>();
  private lastPoint: Point | null = null;
  private enabled = false;
  private destroyed = false;

  constructor(renderer: DesktopFrameRenderer, send: (event: DesktopInputEvent) => void) {
    this.renderer = renderer;
    this.canvas = renderer.element;
    this.doc = this.canvas.ownerDocument;
    this.view = this.doc.defaultView;
    this.send = send;
    this.canvas.tabIndex = 0;
    this.canvas.addEventListener('keydown', this.keyDown);
    this.canvas.addEventListener('keyup', this.keyUp);
    this.canvas.addEventListener('blur', this.releaseAll);
    this.canvas.addEventListener('mousedown', this.mouseDown);
    this.canvas.addEventListener('wheel', this.wheel, { passive: false });
    this.canvas.addEventListener('contextmenu', this.contextMenu);
    this.doc.addEventListener('mousemove', this.mouseMove);
    this.doc.addEventListener('mouseup', this.mouseUp);
    this.view?.addEventListener('blur', this.releaseAll);
  }

  /** Enable only after the real backend is ready. Disabling releases held input. */
  public setEnabled(enabled: boolean): void {
    if (this.destroyed || this.enabled === enabled) return;
    if (!enabled) this.releaseAll();
    this.enabled = enabled;
  }

  public destroy(): void {
    if (this.destroyed) return;
    this.releaseAll();
    this.enabled = false;
    this.destroyed = true;
    this.canvas.removeEventListener('keydown', this.keyDown);
    this.canvas.removeEventListener('keyup', this.keyUp);
    this.canvas.removeEventListener('blur', this.releaseAll);
    this.canvas.removeEventListener('mousedown', this.mouseDown);
    this.canvas.removeEventListener('wheel', this.wheel);
    this.canvas.removeEventListener('contextmenu', this.contextMenu);
    this.doc.removeEventListener('mousemove', this.mouseMove);
    this.doc.removeEventListener('mouseup', this.mouseUp);
    this.view?.removeEventListener('blur', this.releaseAll);
  }

  private get active(): boolean {
    return this.enabled && !this.destroyed && this.doc.activeElement === this.canvas;
  }

  private readonly keyDown = (event: KeyboardEvent): void => {
    if (!this.active || event.isComposing || !event.code || event.key === 'Dead' || event.key === 'Process') return;
    const id = `${event.code}:${event.location}`;
    const prior = this.keys.get(id);
    const input: KeyDown = { type: 'key', down: true, code: event.code, key: event.key,
      location: event.location, repeat: event.repeat || !!prior };
    if (!prior) this.keys.set(id, input);
    this.send(input);
    event.preventDefault();
  };

  private readonly keyUp = (event: KeyboardEvent): void => {
    if (!this.active) return;
    const id = `${event.code}:${event.location}`;
    const prior = this.keys.get(id);
    if (!prior) return;
    this.keys.delete(id);
    this.send({ ...prior, down: false, repeat: false });
    event.preventDefault();
  };

  private readonly mouseDown = (event: MouseEvent): void => {
    if (!this.enabled || this.destroyed || event.button < 0 || event.button > 4 || this.buttons.has(event.button)) return;
    const point = this.renderer.remotePoint(event.clientX, event.clientY);
    if (!point) return;
    this.canvas.focus();
    if (!this.active) return;
    this.lastPoint = point;
    this.buttons.add(event.button);
    this.send({ type: 'button', down: true, button: event.button, ...point });
    event.preventDefault();
  };

  private readonly mouseMove = (event: MouseEvent): void => {
    if (!this.active) return;
    // While a button is held, track drags outside the surface to its edge.
    // Hover motion elsewhere in the document must not reach the remote desktop.
    if (!this.buttons.size && event.target !== this.canvas) return;
    const point = this.renderer.remotePoint(event.clientX, event.clientY, this.buttons.size > 0);
    if (!point) return;
    if (this.lastPoint && this.lastPoint.x === point.x && this.lastPoint.y === point.y) return;
    this.lastPoint = point;
    this.send({ type: 'pointer', ...point });
    event.preventDefault();
  };

  private readonly mouseUp = (event: MouseEvent): void => {
    if (!this.active || !this.buttons.has(event.button)) return;
    const point = this.renderer.remotePoint(event.clientX, event.clientY, true) ?? this.lastPoint;
    this.buttons.delete(event.button);
    if (point) {
      this.lastPoint = point;
      this.send({ type: 'button', down: false, button: event.button, ...point });
    }
    event.preventDefault();
  };

  private readonly wheel = (event: WheelEvent): void => {
    if (!this.active || !Number.isFinite(event.deltaX) || !Number.isFinite(event.deltaY)) return;
    const point = this.renderer.remotePoint(event.clientX, event.clientY);
    if (!point) return;
    this.lastPoint = point;
    this.send({ type: 'scroll', ...point, deltaX: event.deltaX, deltaY: event.deltaY, deltaMode: event.deltaMode });
    event.preventDefault();
  };

  private readonly contextMenu = (event: MouseEvent): void => {
    if (this.active && this.renderer.remotePoint(event.clientX, event.clientY)) event.preventDefault();
  };

  /** Release in reverse press order, so modifiers outlive the keys they modified. */
  private readonly releaseAll = (): void => {
    if (!this.enabled) return;
    const keys = [...this.keys.values()].reverse();
    const buttons = [...this.buttons].reverse();
    this.keys.clear();
    this.buttons.clear();
    for (const key of keys) this.send({ ...key, down: false, repeat: false });
    if (this.lastPoint) for (const button of buttons) this.send({ type: 'button', down: false, button, ...this.lastPoint });
    this.lastPoint = null;
  };
}
