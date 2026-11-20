import { kdriveUpdateEvent } from './kdrive-events.js';
import type { KDriveInputAction } from './kdrive-input.js';

interface Batch {
  actions: KDriveInputAction[];
  resolve: () => void;
  reject: (error: Error) => void;
}

/** Ordered, bounded writer for translated KDrive input. A barrier sends a
 * one-pixel update request and waits for the session to acknowledge its
 * response. The session owns reading/decoding and must not call acknowledge
 * for a different message. A write error, timeout or close permanently stops
 * this queue; the owning session must then close its channel and reset input.
 * This class does not itself connect to SSH or infer a barrier response. */
export class KDriveInputQueue {
  private readonly pending: Batch[] = [];
  private outstanding = 0;
  private active = false;
  private stopped: Error | null = null;
  private waiting: { resolve: () => void; reject: (error: Error) => void } | null = null;
  private cancelCurrent: ((error: Error) => void) | null = null;

  constructor(private readonly write: (packet: Uint8Array) => Promise<void>,
              private readonly timeoutMs = 5000, private readonly maxActions = 1024) {
    if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 120000 ||
        !Number.isInteger(maxActions) || maxActions < 1 || maxActions > 16384) {
      throw new Error('Invalid KDrive input queue limits.');
    }
  }

  /** Atomically queues a batch, taking an immutable copy of every packet. */
  public enqueue(actions: readonly KDriveInputAction[]): Promise<void> {
    if (this.stopped) return Promise.reject(this.stopped);
    if (!Array.isArray(actions) || actions.length > this.maxActions || this.outstanding + actions.length > this.maxActions) {
      const error = new Error('KDrive input queue limit exceeded.');
      this.stop(error);
      return Promise.reject(error);
    }
    const snapshot: KDriveInputAction[] = [];
    for (const action of actions) {
      if (action?.type === 'barrier') snapshot.push({ type: 'barrier' });
      else if (action?.type === 'packet' && action.bytes instanceof Uint8Array && action.bytes.length === 41) {
        snapshot.push({ type: 'packet', bytes: action.bytes.slice() });
      } else {
        const error = new Error('Invalid KDrive input action.');
        this.stop(error);
        return Promise.reject(error);
      }
    }
    if (!snapshot.length) return Promise.resolve();
    this.outstanding += snapshot.length;
    return new Promise<void>((resolve, reject) => {
      this.pending.push({ actions: snapshot, resolve, reject });
      void this.pump();
    });
  }

  /** Called only when the reader identifies the response to the current
   * one-pixel update. Returns false if no barrier is awaiting a response. */
  public acknowledgeBarrier(): boolean {
    const waiting = this.waiting;
    if (!waiting || this.stopped) return false;
    this.waiting = null;
    waiting.resolve();
    return true;
  }

  /** Rejects pending and in-flight batches. The owner must close the stream:
   * a writer already in progress cannot be cancelled by this queue. */
  public close(): void { this.stop(new Error('KDrive input queue closed.')); }

  private stop(error: Error): void {
    if (this.stopped) return;
    this.stopped = error;
    if (this.waiting) { const waiting = this.waiting; this.waiting = null; waiting.reject(error); }
    this.cancelCurrent?.(error);
    for (const batch of this.pending.splice(0)) { this.outstanding -= batch.actions.length; batch.reject(error); }
  }

  private async timed<T>(work: Promise<T>): Promise<T> {
    let timer: ReturnType<typeof setTimeout> | undefined;
    let cancel: ((error: Error) => void) | undefined;
    const interrupted = new Promise<never>((_resolve, reject) => {
      cancel = reject;
      timer = setTimeout(() => reject(new Error('KDrive input timed out.')), this.timeoutMs);
    });
    this.cancelCurrent = cancel ?? null;
    try { return await Promise.race([work, interrupted]); }
    finally { if (timer !== undefined) clearTimeout(timer); this.cancelCurrent = null; }
  }

  private async send(packet: Uint8Array): Promise<void> {
    if (this.stopped) throw this.stopped;
    await this.timed(Promise.resolve().then(() => {
      if (this.stopped) throw this.stopped;
      return this.write(packet);
    }));
    if (this.stopped) throw this.stopped;
  }

  private async barrier(): Promise<void> {
    // Install the waiter before writing: a fast response can arrive while the
    // write promise is still resolving. The write and acknowledgement share a
    // deadline; neither may allow subsequent actions to pass on its own.
    const reply = new Promise<void>((resolve, reject) => { this.waiting = { resolve, reject }; });
    const write = Promise.resolve().then(() => {
      if (this.stopped) throw this.stopped;
      return this.write(kdriveUpdateEvent(0, 0, 1, 1));
    });
    try { await this.timed(Promise.all([write, reply])); }
    finally { this.waiting = null; }
    if (this.stopped) throw this.stopped;
  }

  private async pump(): Promise<void> {
    if (this.active || this.stopped) return;
    this.active = true;
    try {
      while (!this.stopped && this.pending.length) {
        const batch = this.pending.shift()!;
        try {
          for (const action of batch.actions) {
            if (this.stopped) throw this.stopped;
            if (action.type === 'barrier') await this.barrier();
            else await this.send(action.bytes);
          }
          batch.resolve();
        } catch (error) {
          const reason = error instanceof Error ? error : new Error('KDrive input write failed.');
          batch.reject(reason);
          this.stop(reason);
        } finally { this.outstanding -= batch.actions.length; }
      }
    } finally { this.active = false; }
  }
}
