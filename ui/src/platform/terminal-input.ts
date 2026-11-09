/**
 * The keyboard attachment for a canvas terminal.
 *
 * A terminal is a canvas, and a canvas cannot summon a soft keyboard: it is not
 * focusable, it takes no text, and Android's input method has nothing to
 * compose against. On a desktop that is invisible - the keyboard is physical and
 * a document-level `keydown` listener hears every press - but on a phone the
 * terminal was a picture nobody could type into.
 *
 * So the canvas gets a companion: an off-screen `<textarea>` parked under the
 * cursor cell. It is the thing that is actually focused, the thing the input
 * method composes in, and the thing that receives the text the keyboard
 * produces. It is kept empty at all times - every character it receives is sent
 * to the shell and deleted again - because the terminal's own grid is the only
 * place text is allowed to accumulate. Left to fill up, the textarea would
 * become a second, invisible buffer that auto-correct could rewrite, and the
 * shell would receive text the person never saw at the cursor.
 *
 * Being a textarea rather than a contenteditable is deliberate: a textarea is
 * what Android's and iOS's input methods are built around, so composition,
 * autocorrect, the emoji picker and swipe typing all behave the way a person
 * expects. `inputmode` is left alone for the same reason - the terminal might
 * run `vi` just as easily as `npm`, so no keyboard type is right for it.
 *
 * The Enter key is the one thing that must not come through as text: a
 * textarea turns Enter into `\n`, and a shell wants `\r`. Backspace either
 * deletes a character the textarea holds (sent as `\x7f`) or, when it is empty,
 * is a key press the shell should hear. Both cases are handled below, and the
 * extra-keys row still provides Tab, Ctrl and the arrows, which a soft keyboard
 * has none of.
 */

/** One key press, as much of it as the terminal needs to encode it. */
export interface TerminalKeyEvent {
  key: string;
  ctrlKey?: boolean;
  altKey?: boolean;
  shiftKey?: boolean;
  metaKey?: boolean;
  preventDefault?: () => void;
}

export interface TerminalInputOptions {
  /** The element the canvas is in; the textarea is parked inside it. */
  container: HTMLElement;
  /** Sends bytes to the shell. */
  onData: (data: string) => void;
  /** Encodes a non-text key (Enter, Backspace, the arrows). */
  onKey?: (event: TerminalKeyEvent) => boolean;
  /** Builds the textarea; defaults to `document.createElement`. */
  createElement?: () => HTMLTextAreaElement;
  /** Asked before sending, so a paste can honour bracketed-paste mode. */
  onPaste?: (text: string) => void;
}

/**
 * Attaches a keyboard to a canvas terminal.
 *
 * `moveTo` is called with the cursor cell's pixel position and the cell size on
 * every frame: the textarea sits at the cursor so the input method's candidate
 * window appears where the person is typing rather than wherever the element
 * happened to be left.
 */
export class TerminalInput {
  private readonly container: HTMLElement;
  private readonly element: HTMLTextAreaElement;
  private readonly onData: TerminalInputOptions['onData'];
  private readonly onKey: TerminalInputOptions['onKey'];
  private readonly onPaste?: TerminalInputOptions['onPaste'];
  private destroyed = false;
  /** True while a composition is in progress, so interim text is not sent. */
  private composing = false;

  constructor(options: TerminalInputOptions) {
    this.container = options.container;
    this.onData = options.onData;
    this.onKey = options.onKey;
    this.onPaste = options.onPaste;
    // The container's own document, not the global one: a terminal mounted in
    // a window or a test frame has to build its keyboard in that document.
    this.element = options.createElement
      ? options.createElement()
      : options.container.ownerDocument.createElement('textarea');

    const element = this.element;
    element.setAttribute('aria-label', 'Terminal input');
    // Not `display: none` or `visibility: hidden`: an input method ignores, and
    // often cannot focus, an element that is not laid out. It is made
    // effectively invisible instead - a one-pixel, transparent box with no
    // caret - which keeps it focusable and composable everywhere.
    element.setAttribute('autocapitalize', 'off');
    element.setAttribute('autocomplete', 'off');
    element.setAttribute('autocorrect', 'off');
    element.setAttribute('spellcheck', 'false');
    element.setAttribute('inputmode', 'text');
    const style = element.style;
    style.position = 'absolute';
    style.width = '1px';
    style.height = '1px';
    style.padding = '0';
    style.border = '0';
    style.margin = '0';
    style.resize = 'none';
    style.outline = 'none';
    style.overflow = 'hidden';
    style.opacity = '0';
    style.background = 'transparent';
    style.color = 'transparent';
    style.caretColor = 'transparent';
    style.zIndex = '-1';
    style.left = '0px';
    style.top = '0px';

    this.listen();
    this.container.appendChild(element);
  }

  /** True while the person is typing into the terminal. */
  public get focused(): boolean {
    return this.destroyed ? false : this.hasFocus();
  }

  /**
   * Focuses the attachment, which is what raises the soft keyboard.
   *
   * Browsers only honour this inside a user gesture, so it is called from the
   * terminal's own tap and focus handlers rather than on load.
   */
  public focus(): void {
    if (this.destroyed) {
      return;
    }
    this.element.focus();
    this.syncCaret();
  }

  /** Dismisses the soft keyboard. */
  public blur(): void {
    if (this.destroyed) {
      return;
    }
    this.element.blur();
  }

  /** Toggles the keyboard, for a tap on a terminal that already has focus. */
  public toggle(): void {
    if (this.focused) {
      this.blur();
    } else {
      this.focus();
    }
  }

  /**
   * Parks the attachment under the cursor cell.
   *
   * Called on every frame, because the cursor moves with the shell's output and
   * the candidate window has to follow it. Coordinates are CSS pixels within
   * the container, which is where the canvas is drawn too.
   */
  public moveTo(cursor: { left: number; top: number; width: number; height: number }): void {
    if (this.destroyed) {
      return;
    }
    // The element is a pixel wide and tall; it is positioned at the cursor's
    // top-left so the input method's popup opens there.
    this.element.style.left = `${Math.round(cursor.left)}px`;
    this.element.style.top = `${Math.round(cursor.top)}px`;
    this.syncCaret();
  }

  /** Sends text as if it had been typed, and empties the attachment. */
  public send(text: string): void {
    if (!text) {
      return;
    }
    this.onData(text);
  }

  /** Removes the attachment and every listener. */
  public destroy(): void {
    if (this.destroyed) {
      return;
    }
    this.destroyed = true;
    this.unlisten();
    try {
      this.element.remove();
    } catch {
      // An element that is already detached is already gone.
    }
  }

  // Listeners -----------------------------------------------------------------

  private readonly handleInput = (event: Event): void => {
    // While an input method is composing, the textarea holds interim text that
    // the person has not committed: sending it would print half-typed romaji
    // into the shell on the way to the character they meant.
    if ((event as InputEvent).isComposing || this.composing) {
      return;
    }
    this.flush();
  };

  private readonly handleCompositionStart = (): void => {
    this.composing = true;
  };

  private readonly handleCompositionEnd = (): void => {
    this.composing = false;
    this.flush();
  };

  private readonly handleKeyDown = (event: KeyboardEvent): void => {
    const key = event;
    if (key.isComposing || this.composing) {
      return;
    }
    // Enter is sent as a carriage return rather than the `\n` a textarea would
    // produce, and it is never allowed to stay in the element: a textarea with
    // a newline in it grows and starts treating the next press as a new line.
    if (key.key === 'Enter') {
      key.preventDefault?.();
      this.onKey?.({ key: 'Enter', ctrlKey: key.ctrlKey, altKey: key.altKey, shiftKey: key.shiftKey }) ||
        this.onData('\r');
      return;
    }
    if (key.key === 'Backspace') {
      // A textarea with text deletes that text; sending `\x7f` as well would
      // delete two characters on the far side for one press.
      if (this.element.value.length === 0) {
        key.preventDefault?.();
        this.onKey?.({ key: 'Backspace', ctrlKey: key.ctrlKey, altKey: key.altKey }) ||
          this.onData('\x7f');
      }
      return;
    }
    // Everything else the terminal encodes - the arrows, Tab, Ctrl+letter, the
    // function keys - is offered to the encoder, which returns false for text
    // it does not want and lets the ordinary input event carry it.
    if (this.onKey?.(key)) {
      key.preventDefault?.();
    }
  };

  private readonly handlePaste = (event: ClipboardEvent): void => {
    const text = event.clipboardData ? event.clipboardData.getData('text') : '';
    if (!text) {
      return;
    }
    event.preventDefault();
    if (this.onPaste) {
      this.onPaste(text);
    } else {
      this.onData(text);
    }
  };

  private listen(): void {
    const element = this.element;
    element.addEventListener('input', this.handleInput);
    element.addEventListener('compositionstart', this.handleCompositionStart);
    element.addEventListener('compositionend', this.handleCompositionEnd);
    element.addEventListener('keydown', this.handleKeyDown);
    element.addEventListener('paste', this.handlePaste);
  }

  private unlisten(): void {
    const element = this.element;
    element.removeEventListener('input', this.handleInput);
    element.removeEventListener('compositionstart', this.handleCompositionStart);
    element.removeEventListener('compositionend', this.handleCompositionEnd);
    element.removeEventListener('keydown', this.handleKeyDown);
    element.removeEventListener('paste', this.handlePaste);
  }

  /** Sends whatever the textarea holds and empties it again. */
  private flush(): void {
    const text = this.element.value;
    if (!text) {
      this.syncCaret();
      return;
    }
    this.element.value = '';
    this.onData(text);
    this.syncCaret();
  }

  /** Keeps the caret in the element, which is what anchors the IME popup. */
  private syncCaret(): void {
    try {
      this.element.setSelectionRange(0, 0);
    } catch {
      // A detached or read-only element cannot hold a caret; the position of
      // the element is still the anchor, so nothing else is needed.
    }
  }

  private hasFocus(): boolean {
    return this.container.ownerDocument?.activeElement === this.element;
  }
}

/** The element-relative pixels of a cursor cell, for `TerminalInput.moveTo`. */
export function cursorCellRect(
  cursor: { column: number; line: number },
  cell: { width: number; height: number },
): { left: number; top: number; width: number; height: number } {
  return {
    left: cursor.column * cell.width,
    top: cursor.line * cell.height,
    width: cell.width,
    height: cell.height,
  };
}
