/**
 * A terminal *renderer*, not a terminal emulator.
 *
 * The emulation - VT parsing, the grid, scrollback, colour resolution - belongs
 * to the Rust model (`crates/linscp-terminal`, built on `alacritty_terminal`).
 * This module receives that model's frames and paints them. It deliberately
 * knows nothing about escape sequences: if it ever needs to know one, the
 * emulation has leaked out of the model and into a window.
 *
 * Why a canvas rather than DOM nodes: a 200x50 screen is 10,000 cells, and
 * 10,000 `<span>` elements per frame is a layout engine doing terminal work.
 * One canvas repaint per changed frame is the same amount of work xterm.js did
 * and needs no dependency to be correct.
 *
 * This is also the seam for a faster renderer later: everything outside this
 * file speaks in `TerminalFrame`, so a WebGL or native implementation can
 * replace the painting without touching the window, the model, or the tests
 * that drive both through this interface.
 */

/** A colour as the model reports it. */
export interface CellColor {
  /** `NamedColor` numeric value, or -1 when the colour is not named. */
  named: number;
  /** Palette entry for an indexed colour, or -1. */
  indexed: number;
  /** A colour the VT stream defined, when it defined one. */
  rgb: { r: number; g: number; b: number } | null;
}

/** One character cell, as pre-resolved by the model. */
export interface CellSnapshot {
  /** UTF-32 code points: one character, or a base plus combining marks. */
  text: number[];
  fg: CellColor;
  bg: CellColor;
  /** Attribute bitmask; the flags match `linscp_terminal::ATTR_*`. */
  attrs: number;
}

export interface CursorSnapshot {
  column: number;
  line: number;
  shape: string;
}

export interface TerminalModes {
  alternate_screen: boolean;
  app_cursor: boolean;
  bracketed_paste: boolean;
  mouse_reporting: boolean;
  show_cursor: boolean;
}

/** Everything needed to paint the visible screen. */
export interface TerminalFrame {
  columns: number;
  lines: number;
  cells: CellSnapshot[];
  cursor: CursorSnapshot;
  display_offset: number;
  total_lines: number;
  title: string | null;
  modes: TerminalModes;
  /** The selected block as `[row, column, row, column]`, when one is drawn. */
  selection?: [number, number, number, number] | null;
}

/** The little of the platform a renderer needs, so a test can supply its own. */
export interface RenderContext {
  createElement(tag: 'canvas'): HTMLCanvasElement;
  devicePixelRatio?: number;
}

export interface RendererTheme {
  palette: readonly string[];
  foreground: string;
  background: string;
  cursor: string;
  selection?: string;
}

/** The default colours, matching `linscp_terminal::DEFAULT_PALETTE`. */
export const DEFAULT_RENDERER_THEME: RendererTheme = {
  palette: [
    '#000000', '#cd3131', '#0dbc79', '#e5e510',
    '#2472c8', '#bc3fbc', '#11a8cd', '#e5e5e5',
    '#666666', '#f14c4c', '#3ce08c', '#f5f567',
    '#4f9cff', '#e86fe8', '#4fd4f1', '#ffffff',
  ],
  foreground: '#e5e5e5',
  background: '#000000',
  cursor: '#e5e5e5',
};

/** Attribute bits, as `linscp_terminal` defines them. */
const ATTR = {
  bold: 1 << 0,
  italic: 1 << 1,
  underline: 1 << 2,
  dim: 1 << 3,
  inverse: 1 << 4,
  strike: 1 << 5,
  hidden: 1 << 6,
  wide: 1 << 7,
} as const;

export interface RendererOptions {
  /** The element the canvas is appended to; it owns the size. */
  container: HTMLElement;
  context?: RenderContext;
  theme?: RendererTheme;
  /** Font stack, in CSS order. */
  fontFamily?: string;
  /** Cell height in CSS pixels; the width is measured from this font. */
  fontSize?: number;
  /** Called when the measured cell size changes, for the pixel-size report. */
  onCellSize?: (size: { width: number; height: number }) => void;
}

/**
 * Paints frames into a canvas and reports the grid it can show.
 *
 * The renderer owns no terminal state beyond what it needs to paint: it holds
 * the last frame so it can repaint after a resize, and its own measured cell
 * metrics. Everything else is the model's.
 */
export class TerminalRenderer {
  private readonly container: HTMLElement;
  private readonly theme: RendererTheme;
  private readonly fontFamily: string;
  private readonly fontSize: number;
  private readonly onCellSize?: RendererOptions['onCellSize'];
  private readonly canvas: HTMLCanvasElement;
  private readonly ctx: CanvasRenderingContext2D | null;
  private readonly measureContext: CanvasRenderingContext2D | null;
  private frame: TerminalFrame | null = null;
  private cellWidth = 9;
  private cellHeight = 18;
  private destroyed = false;
  /** False until the constructor has returned, so measuring cannot call back
   * into an owner whose own fields are not assigned yet. */
  private constructed = false;

  constructor(options: RendererOptions) {
    this.container = options.container;
    this.theme = options.theme ?? DEFAULT_RENDERER_THEME;
    this.fontFamily = options.fontFamily
      ?? 'ui-monospace, SFMono-Regular, Menlo, Consolas, "DejaVu Sans Mono", monospace';
    this.fontSize = options.fontSize ?? 14;
    this.onCellSize = options.onCellSize;
    const createElement = options.context?.createElement
      ?? ((tag: 'canvas') => document.createElement(tag));
    this.canvas = createElement('canvas');
    this.canvas.className = 'terminal-canvas';
    this.canvas.setAttribute('role', 'img');
    this.canvas.setAttribute('aria-label', 'Terminal');
    this.canvas.style.display = 'block';
    this.canvas.style.width = '100%';
    this.canvas.style.height = '100%';
    this.container.appendChild(this.canvas);
    this.ctx = typeof this.canvas.getContext === 'function'
      ? this.canvas.getContext('2d')
      : null;
    // A second, off-screen context measures one character without touching the
    // visible canvas; measuring on the painted canvas would clear a frame.
    this.measureContext = this.ctx;
    this.measureCell();
    this.constructed = true;
  }

  /** The grid this renderer can show right now, in cells. */
  public size(): { columns: number; lines: number } {
    const width = Math.max(1, this.container.clientWidth || 0);
    const height = Math.max(1, this.container.clientHeight || 0);
    return {
      columns: Math.max(1, Math.floor(width / this.cellWidth)),
      lines: Math.max(1, Math.floor(height / this.cellHeight)),
    };
  }

  /** What one cell measures, in CSS pixels, for the model's size report. */
  public cellSize(): { width: number; height: number } {
    return { width: Math.round(this.cellWidth), height: Math.round(this.cellHeight) };
  }

  /** Measures one character of the configured font and sizes the backing store. */
  public measureCell(): void {
    const ctx = this.measureContext;
    if (!ctx) {
      return;
    }
    const font = `${this.fontSize}px ${this.fontFamily}`;
    ctx.font = font;
    // A monospace advance is the same for every character in the font, so one
    // sample is enough; `M` is wide enough that a proportional fallback font
    // would measure differently and be caught by the rounding below.
    const metrics = ctx.measureText('MMMMMMMMMM');
    const advance = (metrics.width || this.fontSize * 10) / 10;
    // Whole pixels keep the grid from drifting against the canvas' device
    // pixel grid, which shows up as a seam of background between columns.
    this.cellWidth = Math.max(1, Math.round(advance));
    this.cellHeight = Math.max(1, Math.round(this.fontSize * 1.32));
    if (this.constructed) {
      this.onCellSize?.({ width: this.cellWidth, height: this.cellHeight });
    }
    this.resizeBackingStore();
    this.repaint();
  }

  /** Resizes the canvas for the container and the device pixel ratio. */
  public resizeBackingStore(devicePixelRatio?: number): void {
    const ratio = devicePixelRatio
      ?? (typeof globalThis !== 'undefined' ? globalThis.devicePixelRatio : 1)
      ?? 1;
    const width = Math.max(1, this.container.clientWidth || 0);
    const height = Math.max(1, this.container.clientHeight || 0);
    this.canvas.width = Math.max(1, Math.floor(width * ratio));
    this.canvas.height = Math.max(1, Math.floor(height * ratio));
    this.canvas.style.width = `${width}px`;
    this.canvas.style.height = `${height}px`;
    if (this.ctx) {
      // Paint in CSS pixels; the ratio is already in the backing store.
      this.ctx.setTransform(ratio, 0, 0, ratio, 0, 0);
      this.ctx.textBaseline = 'top';
    }
  }

  /**
   * The cell grid, when it differs from `previous`.
   *
   * A window resize has to reach the remote PTY, but only when it actually
   * changed the number of columns: sending the same size again makes a
   * full-screen program redraw for nothing.
   */
  public takeResize(previous: { columns: number; lines: number }): { columns: number; lines: number } | null {
    const size = this.size();
    if (size.columns === previous.columns && size.lines === previous.lines) {
      return null;
    }
    return size;
  }

  /** Paints one frame. A frame of a different size resizes the canvas first. */
  public render(frame: TerminalFrame): void {
    if (this.destroyed) {
      return;
    }
    this.frame = frame;
    this.repaint();
  }

  /** Repaints the last frame, after a resize or a re-measure. */
  public repaint(): void {
    const ctx = this.ctx;
    const frame = this.frame;
    if (!ctx || !frame || this.destroyed) {
      return;
    }
    const cw = this.cellWidth;
    const ch = this.cellHeight;
    ctx.fillStyle = this.theme.background;
    ctx.fillRect(0, 0, frame.columns * cw, frame.lines * ch);
    ctx.font = `${this.fontSize}px ${this.fontFamily}`;
    ctx.textBaseline = 'top';

    for (let line = 0; line < frame.lines; line++) {
      const rowStart = line * frame.columns;
      let column = 0;
      while (column < frame.columns) {
        const cell = frame.cells[rowStart + column];
        if (!cell) {
          column += 1;
          continue;
        }
        const isWide = (cell.attrs & ATTR.wide) !== 0;
        const width = isWide ? 2 : 1;
        // The background is painted first and per cell, because a run of the
        // same colour is what a line of text usually is and repainting the
        // whole row would erase an inverted block in the middle of it.
        const bg = this.backgroundOf(cell);
        if (bg !== this.theme.background) {
          ctx.fillStyle = bg;
          ctx.fillRect(column * cw, line * ch, width * cw, ch);
        }
        const text = cell.text;
        if (text.length > 0 && (cell.attrs & ATTR.hidden) === 0) {
          ctx.fillStyle = this.foregroundOf(cell);
          const glyph = String.fromCodePoint(...text);
          ctx.fillText(glyph, column * cw, line * ch);
          if ((cell.attrs & ATTR.underline) !== 0) {
            ctx.fillRect(column * cw, line * ch + ch - 2, width * cw, 1);
          }
          if ((cell.attrs & ATTR.strike) !== 0) {
            ctx.fillRect(column * cw, line * ch + Math.floor(ch / 2), width * cw, 1);
          }
        }
        column += width;
      }
    }

    this.paintSelection(frame, cw, ch);
    this.paintScrollPosition(frame);
    this.paintCursor(frame.cursor, cw, ch);
  }

  /**
   * A mark in the margin while the viewport is scrolled back.
   *
   * Without it, a screen scrolled into history looks exactly like a live one
   * that has stopped producing output - and the person keeps typing commands
   * into a prompt they cannot see. The mark is drawn over the canvas rather
   * than in an element so it moves and disappears with the frame that brought
   * it, and nothing has to be kept in step.
   */
  private paintScrollPosition(frame: TerminalFrame): void {
    const ctx = this.ctx;
    const scrollable = frame.total_lines - frame.lines;
    if (!ctx || frame.display_offset <= 0 || scrollable <= 0) {
      return;
    }
    const width = frame.columns * this.cellWidth;
    const height = frame.lines * this.cellHeight;
    const track = 4;
    const visible = Math.max(8, Math.round((frame.lines / frame.total_lines) * height));
    // Offset counts back from the bottom, so the thumb travels up the margin as
    // the viewport does.
    const travelled = Math.round((frame.display_offset / scrollable) * (height - visible));
    ctx.fillStyle = 'rgba(255, 255, 255, 0.25)';
    ctx.fillRect(width - track - 2, height - visible - travelled, track, visible);
  }

  /**
   * Tints the cells the selection covers.
   *
   * Assertions about which cells are selected belong to the model; this only
   * has to cover the rectangle it was given, whichever way round its corners
   * arrive.
   */
  private paintSelection(frame: TerminalFrame, cw: number, ch: number): void {
    const ctx = this.ctx;
    const selection = frame.selection;
    if (!ctx || !selection) {
      return;
    }
    const [startRow, startColumn, endRow, endColumn] = selection;
    // The model reports its ends in grid order, but a rectangle that is drawn
    // from a backwards pair would silently cover nothing, which reads as a
    // selection that failed rather than one that was mis-described.
    const top = Math.min(startRow, endRow);
    const bottom = Math.max(startRow, endRow);
    const firstColumn = startRow === top ? startColumn : endColumn;
    const lastColumn = startRow === top ? endColumn : startColumn;
    ctx.fillStyle = this.theme.selection ?? 'rgba(80, 140, 255, 0.35)';
    for (let row = top; row <= bottom; row += 1) {
      // The first and last rows of a selection usually stop mid-line; the rows
      // between them are covered from edge to edge.
      const from = row === top ? firstColumn : 0;
      const to = row === bottom ? lastColumn : frame.columns - 1;
      if (to < from) {
        continue;
      }
      ctx.fillRect(from * cw, row * ch, (to - from + 1) * cw, ch);
    }
  }

  /** Draws the cursor in whichever shape the stream last selected. */
  private paintCursor(cursor: CursorSnapshot, cw: number, ch: number): void {
    const ctx = this.ctx;
    if (!ctx || cursor.shape === 'hidden') {
      return;
    }
    ctx.fillStyle = this.theme.cursor;
    const x = cursor.column * cw;
    const y = cursor.line * ch;
    if (cursor.shape === 'underline') {
      ctx.fillRect(x, y + ch - 2, cw, 2);
    } else if (cursor.shape === 'beam') {
      ctx.fillRect(x, y, 1, ch);
    } else {
      // A block cursor inverts the cell underneath it, which is what makes it
      // visible on a cell that already has a background colour.
      ctx.fillRect(x, y, cw, ch);
      const frame = this.frame;
      if (frame) {
        const cell = frame.cells[cursor.line * frame.columns + cursor.column];
        if (cell && cell.text.length > 0) {
          ctx.fillStyle = this.theme.background;
          ctx.font = `${this.fontSize}px ${this.fontFamily}`;
          ctx.fillText(String.fromCodePoint(...cell.text), x, y);
        }
      }
    }
  }

  private foregroundOf(cell: CellSnapshot): string {
    const color = this.resolve(cell.fg);
    if ((cell.attrs & ATTR.dim) !== 0) {
      return this.mix(color, this.theme.background, 0.5);
    }
    return color;
  }

  private backgroundOf(cell: CellSnapshot): string {
    return this.resolve(cell.bg);
  }

  /** Resolves a model colour to a CSS colour. */
  private resolve(color: CellColor): string {
    if (color.rgb) {
      return rgbCss(color.rgb);
    }
    if (color.indexed >= 0 && color.indexed < 16) {
      return this.theme.palette[color.indexed] ?? this.theme.foreground;
    }
    if (color.indexed >= 16) {
      // 16-231 is the fixed 6x6x6 cube and 232-255 the grey ramp; both are
      // specified by the VT standard, not by the theme.
      const index = color.indexed - 16;
      if (color.indexed >= 232) {
        const level = 8 + (color.indexed - 232) * 10;
        return rgbCss({ r: level, g: level, b: level });
      }
      const cube: readonly number[] = [0x00, 0x5f, 0x87, 0xaf, 0xd7, 0xff];
      return rgbCss({
        r: cube[Math.floor(index / 36) % 6] ?? 0,
        g: cube[Math.floor(index / 6) % 6] ?? 0,
        b: cube[index % 6] ?? 0,
      });
    }
    if (color.named >= 0) {
      if (color.named < 8) {
        return this.theme.palette[color.named] ?? this.theme.foreground;
      }
      if (color.named < 16) {
        // `NamedColor` numbers its bright half straight on from its normal
        // half - BrightBlack is 8, BrightRed 9 - so the value is the palette
        // index. Subtracting one here painted every bright colour with the
        // grey before it, which is exactly what `ls --color` and every prompt
        // use.
        return this.theme.palette[color.named] ?? this.theme.foreground;
      }
      // 256 is the foreground, 257 the background, 258 the cursor.
      if (color.named === 257) {
        return this.theme.background;
      }
      if (color.named === 258) {
        return this.theme.cursor;
      }
    }
    return this.theme.foreground;
  }

  private mix(from: string, to: string, ratio: number): string {
    const a = parseCss(from);
    const b = parseCss(to);
    if (!a || !b) {
      return from;
    }
    return rgbCss({
      r: Math.round(a.r + (b.r - a.r) * ratio),
      g: Math.round(a.g + (b.g - a.g) * ratio),
      b: Math.round(a.b + (b.b - a.b) * ratio),
    });
  }

  /**
   * The canvas element, for the owner that has to attach listeners to it.
   *
   * The renderer paints; it does not decide what a tap means. Handing the
   * element out keeps that decision with the terminal, where the session and
   * its input live.
   */
  public get element(): HTMLCanvasElement {
    return this.canvas;
  }

  /**
   * The cursor cell's rectangle in CSS pixels, or `null` before a frame.
   *
   * A soft keyboard's candidate window is anchored to the element being typed
   * into, and this is what tells the terminal where that is: the cursor, which
   * moves with every byte the shell writes. A terminal whose keyboard popped up
   * in the screen corner instead of at the prompt would be technically usable
   * and practically not.
   */
  public cursorRect(): { left: number; top: number; width: number; height: number } | null {
    const frame = this.frame;
    if (!frame) {
      return null;
    }
    return {
      left: frame.cursor.column * this.cellWidth,
      top: frame.cursor.line * this.cellHeight,
      width: this.cellWidth,
      height: this.cellHeight,
    };
  }

  /** Removes the canvas and every listener this renderer installed. */
  public destroy(): void {
    this.destroyed = true;
    this.frame = null;
    this.canvas.remove();
  }
}

/** A CSS `rgb(...)` string for a colour. */
function rgbCss(color: { r: number; g: number; b: number }): string {
  return `rgb(${color.r}, ${color.g}, ${color.b})`;
}

/** Parses the two colour notations this module produces. */
function parseCss(value: string): { r: number; g: number; b: number } | null {
  const hex = /^#([0-9a-f]{6})$/i.exec(value);
  if (hex) {
    const n = parseInt(hex[1] ?? '000000', 16);
    return { r: (n >> 16) & 0xff, g: (n >> 8) & 0xff, b: n & 0xff };
  }
  const rgb = /^rgb\((\d+),\s*(\d+),\s*(\d+)\)$/.exec(value);
  if (rgb) {
    return { r: Number(rgb[1] ?? 0), g: Number(rgb[2] ?? 0), b: Number(rgb[3] ?? 0) };
  }
  return null;
}
