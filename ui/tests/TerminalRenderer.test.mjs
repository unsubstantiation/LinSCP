import assert from 'node:assert/strict';
import test from 'node:test';
import { JSDOM } from 'jsdom';

import {
  DEFAULT_RENDERER_THEME,
  DEFAULT_TERMINAL_FONT_SIZE,
  TERMINAL_FONT_SIZE_STEP,
  TERMINAL_FONT_SIZE_STORAGE_KEY,
  TerminalRenderer,
  TerminalSession,
  TerminalWindow,
  encodeKey,
  encodePaste,
} from '../dist/linscp-core.mjs';

/**
 * A canvas that records what it was asked to draw.
 *
 * The renderer's contract is "cells in, pixels out", so the tests assert on the
 * calls it makes: a test that compared pixels would need a real rasteriser and
 * would still not say *which* cell was wrong.
 */
function fakeCanvas() {
  const calls = [];
  const context = {
    font: '',
    fillStyle: '',
    textBaseline: '',
    setTransform: (...args) => calls.push(['setTransform', ...args]),
    fillRect: (...args) => calls.push(['fillRect', ...args, context.fillStyle]),
    fillText: (text, x, y) => calls.push(['fillText', text, x, y, context.fillStyle]),
    measureText: (text) => ({ width: text.length * 8.8 }),
    getContext: () => context,
  };
  const listeners = new Map();
  const canvas = {
    className: '',
    width: 0,
    height: 0,
    style: {},
    attributes: {},
    setAttribute(name, value) {
      this.attributes[name] = value;
    },
    getContext: () => context,
    // A real canvas carries events, and the terminal attaches its gestures to
    // this element, so the fake has to be able to hold and fire them.
    addEventListener(type, listener) {
      if (!listeners.has(type)) {
        listeners.set(type, new Set());
      }
      listeners.get(type).add(listener);
    },
    removeEventListener(type, listener) {
      listeners.get(type)?.delete(listener);
    },
    dispatchEvent(event) {
      for (const listener of listeners.get(event.type) ?? []) {
        listener(event);
      }
      this.lastEvent = event;
      return true;
    },
    hasListener(type) {
      return (listeners.get(type)?.size ?? 0) > 0;
    },
    remove() {
      this.removed = true;
    },
  };
  return { canvas, context, calls };
}

/**
 * A container with a fixed size, as an element the renderer measures.
 *
 * `ownerDocument` is real: a session with a keyboard builds its textarea in the
 * container's own document, which is what a page has and a bare object does
 * not.
 */
function fakeContainer(width = 90, height = 36) {
  const document = globalThis.document;
  return {
    clientWidth: width,
    clientHeight: height,
    ownerDocument: document,
    appended: [],
    appendChild(node) {
      this.appended.push(node);
    },
  };
}

/** One frame of `columns` x `lines` blank cells, as the model sends it. */
function blankFrame(columns, lines, overrides = {}) {
  const blankColor = { named: 257, indexed: -1, rgb: null };
  const foreground = { named: 256, indexed: -1, rgb: null };
  return {
    columns,
    lines,
    cells: Array.from({ length: columns * lines }, () => ({
      text: [0x20],
      fg: foreground,
      bg: blankColor,
      attrs: 0,
    })),
    cursor: { column: 0, line: 0, shape: 'block' },
    display_offset: 0,
    total_lines: 30,
    title: null,
    modes: {
      alternate_screen: false,
      app_cursor: false,
      bracketed_paste: false,
      mouse_reporting: false,
      show_cursor: true,
    },
    ...overrides,
  };
}

function makeRenderer(columns = 10, lines = 2) {
  const { canvas, context, calls } = fakeCanvas();
  const container = fakeContainer();
  const renderer = new TerminalRenderer({
    container,
    context: { createElement: () => canvas },
  });
  renderer.resizeBackingStore(1);
  return { renderer, container, canvas, context, calls, columns, lines };
}

test('the renderer measures one cell and reports the grid it can show', () => {
  const { renderer, canvas } = makeRenderer();
  // 90 px wide with a ~9 px advance is ten columns; 36 px tall with an 18 px
  // line is two rows. Both are what the canvas was appended to.
  assert.deepEqual(renderer.size(), { columns: 10, lines: 2 });
  assert.equal(typeof renderer.cellSize().width, 'number');
  assert.equal(canvas.attributes.role, 'img');
});

test('a frame paints every cell and the cursor', () => {
  const { renderer, calls } = makeRenderer();
  const frame = blankFrame(10, 2);
  // "hi" on the first row: two glyphs, drawn at the first two columns.
  frame.cells[0] = { ...frame.cells[0], text: [0x68] };
  frame.cells[1] = { ...frame.cells[1], text: [0x69] };
  renderer.render(frame);
  const texts = calls.filter((call) => call[0] === 'fillText' && call[1] !== ' ');
  const glyphs = texts.map((call) => call[1]);
  assert.equal(glyphs.filter((glyph) => glyph === 'h').length, 2, 'drawn, then repainted by the cursor');
  assert.ok(glyphs.includes('i'));
  // The cursor is a block at 0,0, so it repaints the glyph underneath it in the
  // background colour; that second paint is what makes the cursor a block.
  const cursorPaints = texts.filter((call) => call[1] === 'h' && call[2] === 0);
  assert.ok(cursorPaints.some((call) => call[4] === DEFAULT_RENDERER_THEME.background));
});

test('a colour the stream defined wins over the theme, and an indexed one uses it', () => {
  const { renderer, calls } = makeRenderer();
  const frame = blankFrame(10, 2);
  frame.cells[0] = {
    ...frame.cells[0],
    text: [0x61],
    fg: { named: -1, indexed: -1, rgb: { r: 1, g: 2, b: 3 } },
  };
  frame.cells[1] = {
    ...frame.cells[1],
    text: [0x62],
    fg: { named: -1, indexed: 1, rgb: null },
  };
  renderer.render(frame);
  const texts = calls.filter((call) => call[0] === 'fillText' && call[1] !== ' ');
  assert.equal(texts[0][4], 'rgb(1, 2, 3)');
  assert.equal(texts[1][4], DEFAULT_RENDERER_THEME.palette[1]);
});

test('a bright named colour maps to its own palette entry, not the one before it', () => {
  // `NamedColor` numbers its bright half straight on from its normal half:
  // BrightBlack is 8 and BrightRed 9. Reading them as `named - 1` painted every
  // bright colour with the grey before it, which is what `ls --color`, git's
  // diff colouring and most shells' prompts use.
  const { renderer, calls } = makeRenderer();
  const frame = blankFrame(10, 2);
  frame.cells[0] = { ...frame.cells[0], text: [0x61], fg: { named: 1, indexed: -1, rgb: null } };
  frame.cells[1] = { ...frame.cells[1], text: [0x62], fg: { named: 9, indexed: -1, rgb: null } };
  renderer.render(frame);
  const texts = calls.filter((call) => call[0] === 'fillText' && call[1] !== ' ');
  assert.equal(texts[0][4], DEFAULT_RENDERER_THEME.palette[1], 'SGR 31 is red');
  assert.equal(texts[1][4], DEFAULT_RENDERER_THEME.palette[9], 'SGR 91 is bright red');
  assert.notEqual(texts[0][4], texts[1][4], 'normal and bright must not be the same colour');
});

test('the extended palette is the standard cube and grey ramp', () => {
  const { renderer, calls } = makeRenderer();
  const frame = blankFrame(10, 2);
  frame.cells[0] = { ...frame.cells[0], text: [0x61], fg: { named: -1, indexed: 196, rgb: null } };
  frame.cells[1] = { ...frame.cells[1], text: [0x62], fg: { named: -1, indexed: 232, rgb: null } };
  renderer.render(frame);
  const texts = calls.filter((call) => call[0] === 'fillText' && call[1] !== ' ');
  assert.equal(texts[0][4], 'rgb(255, 0, 0)');
  assert.equal(texts[1][4], 'rgb(8, 8, 8)');
});

test('a wide glyph is drawn once and its spacer is skipped', () => {
  const { renderer, calls } = makeRenderer();
  const frame = blankFrame(10, 2);
  // U+4E2D occupies two columns; the model marks the first and empties the
  // second. Drawing the spacer as well would paint a second glyph.
  frame.cells[0] = { ...frame.cells[0], text: [0x4e2d], attrs: 0b1000_0000 };
  frame.cells[1] = { ...frame.cells[1], text: [], attrs: 0 };
  renderer.render(frame);
  const texts = calls.filter((call) => call[0] === 'fillText' && call[1] !== ' ');
  // The wide glyph is drawn once, and once more by the block cursor that sits
  // on it; the spacer column between them is never drawn.
  assert.deepEqual(texts.map((call) => call[1]), ['中', '中']);
});

test('underlined and struck text are ruled, hidden text is not drawn', () => {
  const { renderer, calls } = makeRenderer();
  const frame = blankFrame(10, 2);
  frame.cells[0] = { ...frame.cells[0], text: [0x61], attrs: 0b0000_0100 };
  frame.cells[1] = { ...frame.cells[1], text: [0x62], attrs: 0b0010_0000 };
  frame.cells[2] = { ...frame.cells[2], text: [0x63], attrs: 0b0100_0000 };
  renderer.render(frame);
  const texts = calls.filter((call) => call[0] === 'fillText' && call[1] !== ' ');
  // 'a' is drawn and then repainted by the cursor on top of it; 'c' is hidden
  // and never drawn at all.
  assert.equal(texts.filter((call) => call[1] === 'a').length, 2);
  assert.ok(texts.some((call) => call[1] === 'b'));
  assert.ok(!texts.some((call) => call[1] === 'c'), 'hidden text is not drawn');
  // Two glyphs plus at least the rules for the underline and the strike.
  assert.ok(calls.filter((call) => call[0] === 'fillRect').length >= 2);
});

test('the cursor shape follows the frame', () => {
  for (const shape of ['underline', 'beam']) {
    const { renderer, calls } = makeRenderer();
    renderer.render(blankFrame(10, 2, { cursor: { column: 3, line: 1, shape } }));
    const bars = calls.filter((call) => call[0] === 'fillRect');
    assert.ok(bars.length > 0, shape);
  }
  const { renderer, calls } = makeRenderer();
  renderer.render(blankFrame(10, 2, { cursor: { column: 0, line: 0, shape: 'hidden' } }));
  // A hidden cursor draws nothing, so the only glyphs are the blank cells.
  assert.deepEqual(calls.filter((call) => call[0] === 'fillText' && call[1] !== ' '), []);
});

test('a resize is reported only when the grid really changed', () => {
  const { renderer, container } = makeRenderer();
  assert.equal(renderer.takeResize({ columns: 10, lines: 2 }), null);
  container.clientWidth = 180;
  container.clientHeight = 72;
  assert.deepEqual(renderer.takeResize({ columns: 10, lines: 2 }), { columns: 20, lines: 4 });
});

test('destroying the renderer removes the canvas and stops painting', () => {
  const { renderer, canvas, calls } = makeRenderer();
  renderer.render(blankFrame(10, 2));
  renderer.destroy();
  assert.equal(canvas.removed, true);
  const before = calls.length;
  renderer.render(blankFrame(10, 2));
  assert.equal(calls.length, before, 'a destroyed renderer paints nothing');
});

test('a key becomes the byte sequence the shell expects', () => {
  assert.equal(encodeKey({ key: 'ArrowUp' }, false), '\x1b[A');
  // Application cursor mode is what a full-screen program turns on; sending
  // the normal-mode sequence there leaves the arrow keys doing nothing.
  assert.equal(encodeKey({ key: 'ArrowUp' }, true), '\x1bOA');
  assert.equal(encodeKey({ key: 'Home' }, true), '\x1bOH');
  assert.equal(encodeKey({ key: 'Enter' }, false), '\r');
  assert.equal(encodeKey({ key: 'Tab' }, false), '\t');
  assert.equal(encodeKey({ key: 'Tab', shiftKey: true }, false), '\x1b[Z');
  assert.equal(encodeKey({ key: 'Backspace' }, false), '\x7f');
  assert.equal(encodeKey({ key: 'Escape' }, false), '\x1b');
  assert.equal(encodeKey({ key: 'Delete' }, false), '\x1b[3~');
  assert.equal(encodeKey({ key: 'PageUp' }, false), '\x1b[5~');
  assert.equal(encodeKey({ key: 'F5' }, false), '\x1b[15~');
});

test('Ctrl and Alt combine with the key they modify', () => {
  // Ctrl+C interrupts; Ctrl+A is the readline home; both are control codes.
  assert.equal(encodeKey({ key: 'c', ctrlKey: true }, false), '\x03');
  assert.equal(encodeKey({ key: 'a', ctrlKey: true }, false), '\x01');
  assert.equal(encodeKey({ key: ' ', ctrlKey: true }, false), '\x00');
  // Alt sends ESC before the character.
  assert.equal(encodeKey({ key: 'b', altKey: true }, false), '\x1bb');
  assert.equal(encodeKey({ key: 'Enter', altKey: true }, false), '\x1b\r');
});

test('a plain modifier is not sent to the shell', () => {
  assert.equal(encodeKey({ key: 'Shift' }, false), null);
  assert.equal(encodeKey({ key: 'Control' }, false), null);
  assert.equal(encodeKey({ key: 'F13' }, false), null);
});

test('a paste keeps its newlines and is wrapped only when asked', () => {
  // A pasted CR runs every line as if Enter was pressed, which is the
  // surprise bracketed paste exists to prevent.
  assert.equal(encodePaste('one\r\ntwo\rthree', false), 'one\ntwo\nthree');
  assert.equal(encodePaste('x', true), '\x1b[200~x\x1b[201~');
});

// --- the session -----------------------------------------------------------

/**
 * Installs a jsdom document as the global the renderer falls back to, and a
 * canvas whose 2D context records what it draws. The session builds its own
 * renderer, so it cannot be handed a fake one.
 */
function installDom() {
  const dom = new JSDOM('<!doctype html><div id="host"></div>', {
    pretendToBeVisual: true,
    url: 'https://tauri.localhost/',
  });
  const { canvas, context, calls } = fakeCanvas();
  dom.window.HTMLCanvasElement.prototype.getContext = () => context;
  globalThis.document = dom.window.document;
  globalThis.devicePixelRatio = 1;
  const originalCreate = dom.window.document.createElement.bind(dom.window.document);
  dom.window.document.createElement = (tag) => (tag === 'canvas' ? Object.assign(canvas, { style: {}, ownerDocument: dom.window.document, remove() {} }) : originalCreate(tag));
  return { dom, calls, cleanup: () => {
    delete globalThis.document;
    delete globalThis.devicePixelRatio;
  } };
}

/** A transport that answers from a table and records every call. */
function fakeTransport(answers = {}) {
  const calls = [];
  return {
    calls,
    mode: 'tauri',
    async get(path) {
      calls.push({ method: 'GET', path });
      const answer = answers[path.split('?')[0]];
      return typeof answer === 'function' ? answer(path) : answer ?? {};
    },
    async post(path, body) {
      calls.push({ method: 'POST', path, body });
      const answer = answers[path];
      return typeof answer === 'function' ? answer(body) : answer ?? { success: true };
    },
    request() {
      return Promise.resolve({});
    },
    subscribe() {
      return () => {};
    },
  };
}

test('the session reports its initial window grid and later window resizes in order', async () => {
  const dom = installDom();
  const container = fakeContainer(90, 36);
  const calls = [];
  let releaseFirst;
  const first = new Promise(resolve => { releaseFirst = resolve; });
  const transport = {
    mode: 'tauri',
    async get() { return { success: true, alive: true, frame: blankFrame(10, 2) }; },
    async post(path, body) {
      if (path === '/api/terminal/input') {
        calls.push({ ...body });
        if (calls.length === 1) await first;
      }
      return { success: true };
    },
    request: async () => ({}), subscribe: () => () => {},
  };
  const removedListeners = [];
  const originalRemove = dom.dom.window.removeEventListener.bind(dom.dom.window);
  dom.dom.window.removeEventListener = (type, listener, options) => {
    removedListeners.push(type);
    return originalRemove(type, listener, options);
  };
  const session = new TerminalSession({ transport, terminal: 'term-1', container, pollInterval: 1000 });
  session.start();
  await new Promise(resolve => setTimeout(resolve, 5));
  assert.equal(DEFAULT_TERMINAL_FONT_SIZE, 11);
  assert.equal(TERMINAL_FONT_SIZE_STEP, 1);
  assert.deepEqual([calls[0].cols, calls[0].rows, calls[0].cell_width, calls[0].cell_height], [10, 2, 9, 15]);
  container.clientWidth = 180; container.clientHeight = 72;
  dom.dom.window.dispatchEvent(new dom.dom.window.Event('resize'));
  session.write('x');
  container.clientWidth = 270; container.clientHeight = 90;
  dom.dom.window.dispatchEvent(new dom.dom.window.Event('resize'));
  await new Promise(resolve => setTimeout(resolve, 5));
  assert.equal(calls.length, 1, 'later resizes wait for the first resize');
  releaseFirst();
  await new Promise(resolve => setTimeout(resolve, 15));
  assert.deepEqual(calls.map(c => [c.cols, c.rows]), [[10, 2], [20, 4], [20, 4], [30, 6]]);
  assert.equal(Buffer.from(calls[2].data, 'base64').toString(), 'x');
  session.stop();
  assert.ok(removedListeners.includes('resize'), 'the window listener is detached on teardown');
  container.clientWidth = 360;
  dom.dom.window.dispatchEvent(new dom.dom.window.Event('resize'));
  await new Promise(resolve => setTimeout(resolve, 5));
  assert.equal(calls.length, 4, 'stopped sessions no longer react to window changes');
  dom.cleanup();
});

test('a container-only layout change updates the PTY on the next frame', async () => {
  const dom = installDom();
  const container = fakeContainer(90, 36);
  const transport = fakeTransport({
    '/api/terminal/frame': () => ({ success: true, alive: true, frame: blankFrame(10, 2) }),
  });
  const resized = [];
  const session = new TerminalSession({ transport, terminal: 'term-1', container, pollInterval: 10,
    onResize: grid => resized.push(grid) });
  session.start();
  await new Promise(resolve => setTimeout(resolve, 20));
  container.clientWidth = 180; container.clientHeight = 72;
  await new Promise(resolve => setTimeout(resolve, 35));
  const inputs = transport.calls.filter(call => call.path === '/api/terminal/input');
  assert.deepEqual(inputs.map(call => [call.body.cols, call.body.rows]), [[10, 2], [20, 4]]);
  assert.deepEqual(resized, [{ columns: 20, lines: 4 }]);
  assert.equal(session.element.width, 180);
  assert.equal(session.element.height, 72);
  session.stop();
  dom.cleanup();
});

test('ResizeObserver on the terminal container updates PTY columns immediately when display width expands', async () => {
  const dom = installDom();
  let observerCallback = null;
  let disconnected = false;
  dom.dom.window.ResizeObserver = class {
    constructor(cb) { observerCallback = cb; }
    observe() {}
    disconnect() { disconnected = true; }
  };
  const container = fakeContainer(320, 600);
  const transport = fakeTransport();
  const resized = [];
  const session = new TerminalSession({
    transport,
    terminal: 'term-ro',
    container,
    pollInterval: 5000,
    onResize: grid => resized.push(grid),
  });
  session.start();
  assert.ok(typeof observerCallback === 'function', 'ResizeObserver observes terminal container');
  container.clientWidth = 412;
  observerCallback();
  await new Promise(resolve => setTimeout(resolve, 10));
  const inputs = transport.calls.filter(call => call.path === '/api/terminal/input');
  assert.equal(inputs.at(-1).body.cols, Math.floor(412 / 9));
  assert.equal(resized.at(-1).columns, Math.floor(412 / 9));
  assert.equal(session.element.width, 412);
  session.stop();
  assert.equal(disconnected, true);
  dom.cleanup();
});

test('the session polls frames and paints them', async () => {
  const dom = installDom();
  const { canvas } = fakeCanvas();
  const container = fakeContainer(180, 72);
  const frames = [];
  const transport = fakeTransport({
    '/api/terminal/frame': () => ({
      success: true,
      dirty: true,
      alive: true,
      error: null,
      frame: blankFrame(10, 2),
    }),
  });
  const session = new TerminalSession({
    transport,
    terminal: 'term-1',
    container,
    pollInterval: 1,
    onFrame: (frame) => frames.push(frame),
  });
  // The renderer would append its own canvas; this test cares about the
  // transport, so the container's appends are ignored.
  session.start();
  await new Promise((resolve) => setTimeout(resolve, 30));
  await session.close();
  assert.ok(frames.length > 0, 'at least one frame was painted');
  assert.ok(
    transport.calls.some((call) => call.method === 'GET' && call.path.includes('terminal=term-1')),
  );
  assert.ok(
    transport.calls.some((call) => call.method === 'POST' && call.path === '/api/terminal/close'),
  );
  assert.equal(container.appended.length, 1, 'the session appended its canvas');
  assert.ok(canvas);
  dom.cleanup();
});

test('a swipe over the terminal scrolls the model instead of the page', async () => {
  // A canvas terminal has no scrollbar and its page must not scroll: dragging
  // has to move the model's viewport. On a phone that is the only way into
  // scrollback, so a drag that did nothing would hide everything above the
  // screen for good.
  const dom = installDom();
  const transport = fakeTransport({
    '/api/terminal/frame': () => ({ success: true, alive: true, frame: blankFrame(10, 2) }),
  });
  const session = new TerminalSession({
    transport,
    terminal: 'term-2',
    container: fakeContainer(90, 36),
    pollInterval: 1,
    keyboard: true,
  });
  session.start();
  await new Promise((resolve) => setTimeout(resolve, 20));

  const el = session.element;
  const touch = (y) => ({ clientY: y, clientX: 10 });
  const start = new dom.dom.window.Event('touchstart');
  start.touches = [touch(200)];
  el.dispatchEvent(start);
  const move = new dom.dom.window.Event('touchmove', { cancelable: true });
  move.touches = [touch(110)];
  el.dispatchEvent(move);
  el.dispatchEvent(new dom.dom.window.Event('touchend'));
  await new Promise((resolve) => setTimeout(resolve, 10));

  const scrolls = transport.calls.filter((call) => call.path === '/api/terminal/scroll');
  assert.equal(scrolls.length, 1, 'one drag, one scroll request');
  // Dragging up by 90px at a 15px cell (11px default font) is six lines back
  // into history, which the model counts as positive.
  assert.equal(scrolls[0].body.lines, 6);
  assert.equal(move.defaultPrevented, true, 'the page must not scroll with the finger');

  // A wheel does the same thing for a desktop mouse.
  const wheel = new dom.dom.window.Event('wheel', { cancelable: true });
  wheel.deltaY = 100;
  el.dispatchEvent(wheel);
  await new Promise((resolve) => setTimeout(resolve, 10));
  const after = transport.calls.filter((call) => call.path === '/api/terminal/scroll');
  assert.equal(after.length, 2);
  assert.equal(after[1].body.lines, -3, 'a wheel down walks forward again');

  await session.close();
  dom.cleanup();
});

test('a tap on the terminal raises the keyboard and a drag does not dismiss it', async () => {
  const dom = installDom();
  const transport = fakeTransport({
    '/api/terminal/frame': () => ({ success: true, alive: true, frame: blankFrame(10, 2) }),
  });
  const session = new TerminalSession({
    transport,
    terminal: 'term-3',
    container: fakeContainer(90, 36),
    pollInterval: 1,
    keyboard: true,
  });
  session.start();
  await new Promise((resolve) => setTimeout(resolve, 20));

  const el = session.element;
  // The harness canvas is not in a document, so focus cannot move; what is
  // asserted here is that the gesture is heard at all, and heard only for taps.
  assert.equal(el.hasListener('click'), true, 'a tap has to be listened for');
  assert.equal(el.hasListener('touchstart'), true);

  el.dispatchEvent(new dom.dom.window.Event('click'));
  // A drag cancels its own click, so the click never reaches this listener;
  // the gesture code is what guarantees that, checked in the swipe test above.
  assert.ok(session.input, 'the session owns a keyboard to raise');

  await session.close();
  assert.equal(el.hasListener('click'), false, 'closing removes every listener');
  dom.cleanup();
});

test('input is queued in order and carries the current grid', async () => {
  const dom = installDom();
  const calls = [];
  const transport = {
    mode: 'tauri',
    async get() {
      return { success: true, alive: true, frame: blankFrame(80, 24) };
    },
    async post(path, body) {
      calls.push({ path, body });
      return { success: true };
    },
    request() {
      return Promise.resolve({});
    },
    subscribe() {
      return () => {};
    },
  };
  const session = new TerminalSession({
    transport,
    terminal: 'term-2',
    container: fakeContainer(720, 432),
    pollInterval: 1000,
  });
  session.write('a');
  session.write('b');
  await new Promise((resolve) => setTimeout(resolve, 20));
  const inputs = calls.filter((call) => call.path === '/api/terminal/input');
  assert.equal(inputs.length, 2);
  // Base64 of "a" and "b": the queue kept the order the keys were pressed in.
  assert.equal(Buffer.from(inputs[0].body.data, 'base64').toString(), 'a');
  assert.equal(Buffer.from(inputs[1].body.data, 'base64').toString(), 'b');
  assert.equal(inputs[0].body.terminal, 'term-2');
  session.stop();
  dom.cleanup();
});

test('a shell that ends is reported once, with its reason', async () => {
  const dom = installDom();
  const ended = [];
  const transport = fakeTransport({
    '/api/terminal/frame': () => ({
      success: true,
      dirty: true,
      alive: false,
      error: 'the server refused the shell',
      frame: blankFrame(10, 2),
    }),
  });
  const session = new TerminalSession({
    transport,
    terminal: 'term-3',
    container: fakeContainer(),
    pollInterval: 1,
    onEnded: (reason) => ended.push(reason),
  });
  session.start();
  await new Promise((resolve) => setTimeout(resolve, 25));
  assert.deepEqual(ended, ['the server refused the shell']);
  assert.equal(
    transport.calls.filter((call) => call.path.startsWith('/api/terminal/frame')).length,
    1,
    'a session that ended asks for its frame once',
  );
  // The reason it must ask once is that the loop has stopped: nothing is
  // scheduled after the end was reported.
  await new Promise((resolve) => setTimeout(resolve, 25));
  assert.equal(
    transport.calls.filter((call) => call.path.startsWith('/api/terminal/frame')).length,
    1,
    'a session that ended stops polling',
  );
  dom.cleanup();
});

test('a window given a tab opens a shell on it', async () => {
  const dom = installDom();
  const transport = fakeTransport({
    '/api/session/terminal': { success: true, terminal: 'term-9' },
    '/api/terminal/frame': () => ({ success: true, alive: true, frame: blankFrame(10, 2) }),
  });
  const window = new TerminalWindow({
    transport,
    tab: 4,
    container: fakeContainer(),
    onTitle: () => {},
  });
  const started = await window.start();
  assert.equal(started, true);
  assert.equal(window.terminal, 'term-9');
  const opened = transport.calls.find((call) => call.path === '/api/session/terminal');
  assert.equal(opened.body.tab, 4);
  await window.close();
  dom.cleanup();
});

test('closing a terminal window closes the remote shell behind it', async () => {
  // The window is the only thing drawing the shell, so it is also the thing
  // that ends it. A window that merely stopped painting would leave a remote
  // PTY - and its SSH channel - open on the server for the life of the app.
  const dom = installDom();
  const transport = fakeTransport({
    '/api/session/terminal': { success: true, terminal: 'term-7' },
    '/api/terminal/frame': () => ({ success: true, alive: true, frame: blankFrame(10, 2) }),
  });
  const window = new TerminalWindow({
    transport,
    tab: 2,
    container: fakeContainer(),
  });
  assert.equal(await window.start(), true);
  await window.close();
  const closed = transport.calls.find((call) => call.path === '/api/terminal/close');
  assert.ok(closed, 'the shell is closed by id, not just abandoned');
  assert.equal(closed.body.terminal, 'term-7');
  dom.cleanup();
});

test('stopping a window paints nothing more and leaves the shell to its owner', async () => {
  // `stop` is the teardown for a window that is not the shell's owner - the
  // page shutting down - so it must not close a shell somebody else may still
  // be using.
  const dom = installDom();
  const transport = fakeTransport({
    '/api/session/terminal': { success: true, terminal: 'term-8' },
    '/api/terminal/frame': () => ({ success: true, alive: true, frame: blankFrame(10, 2) }),
  });
  const window = new TerminalWindow({ transport, tab: 3, container: fakeContainer() });
  assert.equal(await window.start(), true);
  window.stop();
  assert.equal(transport.calls.filter((call) => call.path === '/api/terminal/close').length, 0);
  dom.cleanup();
});

test('a window with neither a terminal nor a tab says so instead of hanging', async () => {
  const reasons = [];
  const window = new TerminalWindow({
    transport: fakeTransport(),
    container: fakeContainer(),
    onEnded: (reason) => reasons.push(reason),
  });
  assert.equal(await window.start(), false);
  assert.equal(reasons.length, 1);
  assert.match(reasons[0], /terminal/i);
});

test('a selected block is painted over the cells it covers', () => {
  const { renderer, calls } = makeRenderer();
  const frame = blankFrame(10, 3);
  frame.selection = [0, 2, 1, 5];
  renderer.render(frame);
  const bands = calls.filter((call) => call[0] === 'fillRect' && call[5] === 'rgba(80, 140, 255, 0.35)');
  // The first row runs from the start column to the edge, the last from the
  // edge to the end column, so a selection that wraps covers both fully.
  const { width: cw, height: ch } = renderer.cellSize();
  assert.equal(bands.length, 2);
  assert.deepEqual(bands[0].slice(1, 5), [2 * cw, 0, 8 * cw, ch]);
  assert.deepEqual(bands[1].slice(1, 5), [0, ch, 6 * cw, ch]);
  // Rows given the other way round still cover the same rectangle: the model
  // orders its ends, but a renderer that trusted that would draw nothing the
  // day it stopped being true.
  const reversed = blankFrame(10, 3);
  reversed.selection = [1, 2, 1, 5];
  renderer.render(reversed);
  const oneRow = calls.filter((call) => call[0] === 'fillRect' && call[5] === 'rgba(80, 140, 255, 0.35)');
  assert.deepEqual(oneRow.at(-1).slice(1, 5), [2 * cw, ch, 4 * cw, ch]);
});

test('scrolling back shows where the viewport is, and being live shows nothing', () => {
  const { renderer, calls } = makeRenderer();
  const live = blankFrame(10, 2);
  renderer.render(live);
  const liveBands = calls.filter((call) => call[0] === 'fillRect' && call[5] === 'rgba(255, 255, 255, 0.25)');
  assert.equal(liveBands.length, 0, 'a live screen has no scroll mark');

  const scrolled = blankFrame(10, 2, { display_offset: 10, total_lines: 50 });
  renderer.render(scrolled);
  const marks = calls.filter((call) => call[0] === 'fillRect' && call[5] === 'rgba(255, 255, 255, 0.25)');
  assert.equal(marks.length, 1, 'a scrolled screen shows one');
  // Sits in the right margin, and higher up as more history is scrolled past.
  assert.ok(marks[0][1] > 80, 'in the margin, not over the text');
  const further = blankFrame(10, 2, { display_offset: 30, total_lines: 50 });
  renderer.render(further);
  const deeper = calls.filter((call) => call[0] === 'fillRect' && call[5] === 'rgba(255, 255, 255, 0.25)').at(-1);
  assert.ok(deeper[2] < marks[0][2], 'the mark travels up as the viewport goes back');
});

test('a long press selects, a drag extends it, and copy reads the model', async () => {
  const dom = installDom();
  installClipboard(dom.dom);
  const transport = fakeTransport({
    '/api/terminal/frame': () => ({ success: true, alive: true, frame: blankFrame(10, 2) }),
    '/api/terminal/selection': { success: true, text: 'bravo' },
  });
  const opens = [];
  const session = new TerminalSession({
    transport,
    terminal: 'term-4',
    container: fakeContainer(90, 36),
    pollInterval: 1,
    keyboard: true,
    onSelection: (open) => opens.push(open),
  });
  session.start();
  await new Promise((resolve) => setTimeout(resolve, 20));

  const el = session.element;
  const touch = (x, y) => ({ clientX: x, clientY: y });
  const start = new dom.dom.window.Event('touchstart');
  start.touches = [touch(0, 0)];
  el.dispatchEvent(start);
  await new Promise((resolve) => setTimeout(resolve, TerminalSession.LONG_PRESS_MS + 60));

  assert.deepEqual(opens, [true], 'holding still opens a selection');
  assert.ok(session.selection, 'the session reports the open selection');
  const started = transport.calls.filter((call) => call.path === '/api/terminal/select');
  assert.equal(started[0].body.action, 'start');

  const move = new dom.dom.window.Event('touchmove', { cancelable: true });
  move.touches = [touch(27, 18)];
  el.dispatchEvent(move);
  await new Promise((resolve) => setTimeout(resolve, 10));
  const extended = transport.calls.filter((call) => call.path === '/api/terminal/select').at(-1);
  assert.equal(extended.body.action, 'extend');
  assert.equal(extended.body.column, 3, 'the column the finger is over');
  assert.equal(extended.body.row, 1);

  // Nothing scrolled: choosing text is not scrolling away from it.
  assert.equal(transport.calls.filter((call) => call.path === '/api/terminal/scroll').length, 0);

  el.dispatchEvent(new dom.dom.window.Event('touchend'));
  assert.equal(await session.copySelection(), 'bravo');
  assert.deepEqual(opens, [true, false], 'copying closes the selection');
  const cleared = transport.calls.filter((call) => call.path === '/api/terminal/select').at(-1);
  assert.equal(cleared.body.action, 'clear');

  await session.close();
  dom.cleanup();
});

test('a quick swipe scrolls instead of selecting', async () => {
  const dom = installDom();
  const transport = fakeTransport({
    '/api/terminal/frame': () => ({ success: true, alive: true, frame: blankFrame(10, 2) }),
  });
  const opens = [];
  const session = new TerminalSession({
    transport,
    terminal: 'term-5',
    container: fakeContainer(90, 36),
    pollInterval: 1,
    keyboard: true,
    onSelection: (open) => opens.push(open),
  });
  session.start();
  await new Promise((resolve) => setTimeout(resolve, 20));

  const el = session.element;
  const start = new dom.dom.window.Event('touchstart');
  start.touches = [{ clientX: 0, clientY: 200 }];
  el.dispatchEvent(start);
  const move = new dom.dom.window.Event('touchmove', { cancelable: true });
  move.touches = [{ clientX: 0, clientY: 110 }];
  el.dispatchEvent(move);
  el.dispatchEvent(new dom.dom.window.Event('touchend'));
  // The press ended before the long-press threshold, so no selection was ever
  // armed - and a pending timer would have opened one after the swipe.
  await new Promise((resolve) => setTimeout(resolve, TerminalSession.LONG_PRESS_MS + 60));
  assert.deepEqual(opens, [], 'scrolling never opens a selection');
  assert.equal(transport.calls.filter((call) => call.path === '/api/terminal/select').length, 0);
  assert.ok(transport.calls.some((call) => call.path === '/api/terminal/scroll'));

  await session.close();
  dom.cleanup();
});

// --- the mouse -------------------------------------------------------------

/**
 * A frame whose first row carries text, for the gestures that read words.
 *
 * The renderer paints cells; a word selection reads the same cells back, so a
 * test of one has to give the session a frame with something in it.
 */
function textFrame(text, columns = 10, lines = 2) {
  const frame = blankFrame(columns, lines);
  for (let i = 0; i < text.length && i < columns; i++) {
    frame.cells[i].text = [...text[i]].map((ch) => ch.codePointAt(0));
  }
  return frame;
}

/** Installs a clipboard the session's `navigator.clipboard` look-up will find. */
function installClipboard(dom) {
  const written = [];
  Object.defineProperty(dom.window.navigator, 'clipboard', {
    configurable: true,
    value: { writeText: async (text) => { written.push(text); } },
  });
  return written;
}

test('a mouse drag selects, and releasing it copies without losing the highlight', async () => {
  const dom = installDom();
  const written = installClipboard(dom.dom);
  const transport = fakeTransport({
    '/api/terminal/frame': () => ({ success: true, alive: true, frame: blankFrame(10, 2) }),
    '/api/terminal/selection': { success: true, text: 'bravo' },
  });
  const opens = [];
  // No keyboard: this is the desktop window's configuration, where a mouse is
  // the only pointer there is.
  const session = new TerminalSession({
    transport,
    terminal: 'term-m1',
    container: fakeContainer(90, 36),
    pollInterval: 1,
    onSelection: (open) => opens.push(open),
  });
  session.start();
  await new Promise((resolve) => setTimeout(resolve, 20));

  const el = session.element;
  assert.equal(el.hasListener('mousedown'), true, 'a desktop terminal hears the mouse');
  const down = new dom.dom.window.MouseEvent('mousedown', { button: 0, detail: 1, clientX: 0, clientY: 0, cancelable: true });
  el.dispatchEvent(down);
  assert.equal(down.defaultPrevented, true, 'the press must not become a native drag of the canvas');
  assert.equal(session.selection, null, 'a press that has not moved is not a selection yet');

  // The drag listeners live on the document, so a drag that leaves the canvas
  // is still a drag; the move lands one cell right and one row down.
  const doc = dom.dom.window.document;
  doc.dispatchEvent(new dom.dom.window.MouseEvent('mousemove', { button: 0, clientX: 27, clientY: 18, cancelable: true }));
  await new Promise((resolve) => setTimeout(resolve, 10));
  const selects = transport.calls.filter((call) => call.path === '/api/terminal/select');
  assert.equal(selects[0].body.action, 'start');
  const extended = selects.at(-1);
  assert.equal(extended.body.action, 'extend');
  assert.deepEqual([extended.body.row, extended.body.column], [1, 3], 'the cell the pointer is over');
  assert.deepEqual(opens, [true], 'the first move opened the selection');

  doc.dispatchEvent(new dom.dom.window.MouseEvent('mouseup', { button: 0, clientX: 27, clientY: 18 }));
  await new Promise((resolve) => setTimeout(resolve, 10));
  assert.deepEqual(written, ['bravo'], 'releasing copies what the model read');
  assert.ok(session.selection, 'the highlight stays, showing what was copied');
  assert.equal(
    transport.calls.filter((call) => call.path === '/api/terminal/select' && call.body.action === 'clear').length,
    0,
    'copying with the mouse does not drop the selection',
  );

  await session.close();
  assert.equal(el.hasListener('mousedown'), false, 'closing removes the mouse too');
  dom.cleanup();
});

test('a plain click clears the selection a drag left open', async () => {
  const dom = installDom();
  installClipboard(dom.dom);
  const transport = fakeTransport({
    '/api/terminal/frame': () => ({ success: true, alive: true, frame: blankFrame(10, 2) }),
    '/api/terminal/selection': { success: true, text: 'bravo' },
  });
  const opens = [];
  const session = new TerminalSession({
    transport,
    terminal: 'term-m2',
    container: fakeContainer(90, 36),
    pollInterval: 1,
    onSelection: (open) => opens.push(open),
  });
  session.start();
  await new Promise((resolve) => setTimeout(resolve, 20));
  const el = session.element;
  const doc = dom.dom.window.document;
  const mouse = (type, x, y) => new dom.dom.window.MouseEvent(type, { button: 0, detail: 1, clientX: x, clientY: y, cancelable: true });

  el.dispatchEvent(mouse('mousedown', 0, 0));
  doc.dispatchEvent(mouse('mousemove', 18, 0));
  doc.dispatchEvent(mouse('mouseup', 18, 0));
  await new Promise((resolve) => setTimeout(resolve, 10));
  assert.ok(session.selection, 'the drag selected');

  // A click that never moves is a click into the terminal, not a selection:
  // the highlight it lands on goes away.
  el.dispatchEvent(mouse('mousedown', 45, 9));
  await new Promise((resolve) => setTimeout(resolve, 10));
  doc.dispatchEvent(mouse('mouseup', 45, 9));
  assert.equal(session.selection, null, 'the click cleared it');
  assert.deepEqual(opens, [true, false]);
  const cleared = transport.calls.filter((call) => call.path === '/api/terminal/select').at(-1);
  assert.equal(cleared.body.action, 'clear');

  await session.close();
  dom.cleanup();
});

test('a double click selects the word under the pointer', async () => {
  const dom = installDom();
  const written = installClipboard(dom.dom);
  const transport = fakeTransport({
    '/api/terminal/frame': () => ({ success: true, alive: true, frame: textFrame('echo hello') }),
    '/api/terminal/selection': { success: true, text: 'hello' },
  });
  const session = new TerminalSession({
    transport,
    terminal: 'term-m3',
    container: fakeContainer(90, 36),
    pollInterval: 1,
  });
  session.start();
  await new Promise((resolve) => setTimeout(resolve, 20));
  const el = session.element;
  const doc = dom.dom.window.document;

  // Column 7 is the second `l` of `hello`; a cell is 9px wide.
  el.dispatchEvent(new dom.dom.window.MouseEvent('mousedown', { button: 0, detail: 2, clientX: 67, clientY: 4, cancelable: true }));
  await new Promise((resolve) => setTimeout(resolve, 10));
  const selects = transport.calls.filter((call) => call.path === '/api/terminal/select');
  assert.deepEqual(
    selects.map((call) => [call.body.action, call.body.row, call.body.column]),
    [['start', 0, 5], ['extend', 0, 9]],
    'the word, from the space before it to the line width that follows',
  );

  doc.dispatchEvent(new dom.dom.window.MouseEvent('mouseup', { button: 0, detail: 2, clientX: 67, clientY: 4 }));
  await new Promise((resolve) => setTimeout(resolve, 10));
  assert.deepEqual(written, ['hello'], 'the word is copied on release');

  await session.close();
  dom.cleanup();
});

test('the wheel scrolls a desktop window, which has no keyboard and no scrollbar', async () => {
  const dom = installDom();
  const transport = fakeTransport({
    '/api/terminal/frame': () => ({ success: true, alive: true, frame: blankFrame(10, 2) }),
  });
  const session = new TerminalSession({
    transport,
    terminal: 'term-m4',
    container: fakeContainer(90, 36),
    pollInterval: 1,
  });
  session.start();
  await new Promise((resolve) => setTimeout(resolve, 20));
  const wheel = new dom.dom.window.Event('wheel', { cancelable: true });
  wheel.deltaY = -100;
  session.element.dispatchEvent(wheel);
  await new Promise((resolve) => setTimeout(resolve, 10));
  const scrolls = transport.calls.filter((call) => call.path === '/api/terminal/scroll');
  assert.equal(scrolls.length, 1);
  assert.equal(scrolls[0].body.lines, 3, 'a wheel up walks back into history');
  await session.close();
  dom.cleanup();
});

test('the mouse events a touch fires on its way out are ignored', async () => {
  const dom = installDom();
  const transport = fakeTransport({
    '/api/terminal/frame': () => ({ success: true, alive: true, frame: blankFrame(10, 2) }),
  });
  const opens = [];
  const session = new TerminalSession({
    transport,
    terminal: 'term-m5',
    container: fakeContainer(90, 36),
    pollInterval: 1,
    keyboard: true,
    onSelection: (open) => opens.push(open),
  });
  session.start();
  await new Promise((resolve) => setTimeout(resolve, 20));
  const el = session.element;
  const doc = dom.dom.window.document;

  // A finger that scrolls leaves the selection alone; the browser replays the
  // gesture as mouse events afterwards, and those must not select either.
  const start = new dom.dom.window.Event('touchstart');
  start.touches = [{ clientX: 10, clientY: 200 }];
  el.dispatchEvent(start);
  const move = new dom.dom.window.Event('touchmove', { cancelable: true });
  move.touches = [{ clientX: 10, clientY: 110 }];
  el.dispatchEvent(move);
  el.dispatchEvent(new dom.dom.window.Event('touchend'));
  el.dispatchEvent(new dom.dom.window.MouseEvent('mousedown', { button: 0, detail: 1, clientX: 10, clientY: 110, cancelable: true }));
  doc.dispatchEvent(new dom.dom.window.MouseEvent('mousemove', { button: 0, clientX: 40, clientY: 110, cancelable: true }));
  doc.dispatchEvent(new dom.dom.window.MouseEvent('mouseup', { button: 0, clientX: 40, clientY: 110 }));
  await new Promise((resolve) => setTimeout(resolve, 10));
  assert.deepEqual(opens, [], 'the echo of a touch opens no selection');
  assert.equal(transport.calls.filter((call) => call.path === '/api/terminal/select').length, 0);
  assert.ok(transport.calls.some((call) => call.path === '/api/terminal/scroll'), 'the touch itself scrolled');

  await session.close();
  dom.cleanup();
});

test('copy all reads retained model text and reports clipboard failures', async () => {
  const dom = installDom();
  const written = installClipboard(dom.dom);
  const transport = fakeTransport({
    '/api/terminal/text': { success: true, text: 'history\nvisible' },
    '/api/terminal/frame': { success: true, alive: true, frame: blankFrame(10, 2) },
  });
  const session = new TerminalSession({ transport, terminal: 'term/copy', container: fakeContainer(90, 36) });
  assert.equal(await session.copyAllText(), 'history\nvisible');
  assert.deepEqual(written, ['history\nvisible']);
  assert.ok(transport.calls.some(call => call.path === '/api/terminal/text?terminal=term%2Fcopy'));
  Object.defineProperty(dom.dom.window.navigator, 'clipboard', { configurable: true,
    value: { writeText: async () => { throw new Error('denied'); } } });
  dom.dom.window.document.execCommand = () => false;
  await assert.rejects(session.copyAllText(), /clipboard/);
  session.stop(); dom.cleanup();
});

test('selection survives a failed clipboard write', async () => {
  const dom = installDom();
  Object.defineProperty(dom.dom.window.navigator, 'clipboard', { configurable: true,
    value: { writeText: async () => { throw new Error('denied'); } } });
  dom.dom.window.document.execCommand = () => false;
  const transport = fakeTransport({
    '/api/terminal/selection': { success: true, text: 'selected' },
    '/api/terminal/frame': { success: true, alive: true, frame: blankFrame(10, 2) },
  });
  const session = new TerminalSession({ transport, terminal: 'term-1', container: fakeContainer(90, 36) });
  session.start();
  const win = dom.dom.window, doc = win.document;
  session.element.dispatchEvent(new win.MouseEvent('mousedown', { button: 0, detail: 1, clientX: 0, clientY: 0 }));
  doc.dispatchEvent(new win.MouseEvent('mousemove', { button: 0, clientX: 18, clientY: 0 }));
  await new Promise(resolve => setTimeout(resolve, 10));
  await assert.rejects(session.copySelection(), /clipboard/);
  assert.ok(session.selection);
  assert.equal(transport.calls.filter(call => call.path === '/api/terminal/select' && call.body.action === 'clear').length, 0);
  session.stop(); dom.cleanup();
});

test('right-click and Ctrl+V paste clipboard text once with bracketed-paste mode', async () => {
  const dom = installDom();
  Object.defineProperty(dom.dom.window.navigator, 'clipboard', { configurable: true,
    value: { readText: async () => 'first\r\nsecond' } });
  const modes = { alternate_screen: false, app_cursor: false, bracketed_paste: true,
    mouse_reporting: false, show_cursor: true };
  const transport = fakeTransport({ '/api/terminal/frame': { success: true, alive: true, frame: blankFrame(10, 2, { modes }) } });
  const session = new TerminalSession({ transport, terminal: 'term-paste', container: fakeContainer(90, 36), pollInterval: 5 });
  session.start(); await new Promise(resolve => setTimeout(resolve, 15));
  const right = new dom.dom.window.MouseEvent('contextmenu', { button: 2, cancelable: true });
  session.element.dispatchEvent(right);
  assert.equal(right.defaultPrevented, true, 'the image context menu is suppressed');
  const key = new dom.dom.window.KeyboardEvent('keydown', { key: 'v', ctrlKey: true, cancelable: true });
  assert.equal(session.handleKey(key), true);
  assert.equal(key.defaultPrevented, true);
  await new Promise(resolve => setTimeout(resolve, 20));
  const bytes = transport.calls.filter(call => call.path === '/api/terminal/input' && call.body.data)
    .map(call => Buffer.from(call.body.data, 'base64').toString());
  assert.deepEqual(bytes, ['\x1b[200~first\nsecond\x1b[201~', '\x1b[200~first\nsecond\x1b[201~']);
  await session.close();
  assert.equal(session.element.hasListener('contextmenu'), false);
  dom.cleanup();
});

test('clipboard read failure reports an error and never pastes input', async () => {
  const dom = installDom(); let errors = 0;
  Object.defineProperty(dom.dom.window.navigator, 'clipboard', { configurable: true,
    value: { readText: async () => { throw new Error('denied'); } } });
  const transport = fakeTransport();
  const session = new TerminalSession({ transport, terminal: 'term-paste', container: fakeContainer(),
    onClipboardError: () => { errors++; } });
  session.handleKey(new dom.dom.window.KeyboardEvent('keydown', { key: 'v', ctrlKey: true, cancelable: true }));
  await new Promise(resolve => setTimeout(resolve, 10));
  assert.equal(errors, 1);
  assert.equal(transport.calls.filter(call => call.path === '/api/terminal/input').length, 0);
  session.stop(); dom.cleanup();
});

test('touch selection copies on release after queued selection updates', async () => {
  const dom = installDom(); const written = installClipboard(dom.dom); let release;
  const transport = fakeTransport({
    '/api/terminal/frame': { success: true, alive: true, frame: blankFrame(10, 2) },
    '/api/terminal/select': async body => {
      if (body.action === 'extend') await new Promise(resolve => { release = resolve; });
      return { success: true };
    },
    '/api/terminal/selection': { success: true, text: 'touch selection' },
  });
  const session = new TerminalSession({ transport, terminal: 'term-touch', container: fakeContainer(), keyboard: true });
  session.start();
  const touch = (x, y) => ({ clientX: x, clientY: y });
  const start = new dom.dom.window.Event('touchstart'); start.touches = [touch(0, 0)];
  session.element.dispatchEvent(start);
  await new Promise(resolve => setTimeout(resolve, TerminalSession.LONG_PRESS_MS + 30));
  const move = new dom.dom.window.Event('touchmove', { cancelable: true }); move.touches = [touch(18, 0)];
  session.element.dispatchEvent(move);
  session.element.dispatchEvent(new dom.dom.window.Event('touchend'));
  await new Promise(resolve => setTimeout(resolve, 10));
  assert.equal(written.length, 0, 'waits for selection extension');
  release(); await new Promise(resolve => setTimeout(resolve, 15));
  assert.deepEqual(written, ['touch selection']);
  assert.ok(session.selection, 'the highlight remains visible');
  session.stop(); dom.cleanup();
});

test('terminal text size defaults to 11px, steps by 1px, remeasures, and is remembered across TerminalWindow sessions', async () => {
  const dom = installDom();
  const transport = fakeTransport();
  const grids = [];
  const session = new TerminalSession({ transport, terminal: 'term-size', container: fakeContainer(180, 90),
    onResize: grid => grids.push(grid) });
  const ctx = session.element.getContext('2d');
  ctx.measureText = text => ({ width: text.length * parseFloat(ctx.font) * 0.625 });
  assert.equal(session.textSize, 11);
  session.start();
  assert.equal(session.changeTextSize(1), 12);
  await new Promise(resolve => setTimeout(resolve, 10));
  let last = transport.calls.filter(call => call.path === '/api/terminal/input').at(-1).body;
  assert.deepEqual([last.cols, last.rows, last.cell_width, last.cell_height], [22, 5, 8, 16]);
  assert.deepEqual(grids.at(-1), { columns: 22, lines: 5 });
  assert.equal(session.changeTextSize(-1), 11);
  await new Promise(resolve => setTimeout(resolve, 10));
  last = transport.calls.filter(call => call.path === '/api/terminal/input').at(-1).body;
  assert.deepEqual([last.cols, last.rows, last.cell_width, last.cell_height], [25, 6, 7, 15]);
  assert.equal(session.changeTextSize(-100), 8);
  assert.equal(session.changeTextSize(100), 32);
  assert.equal(session.changeTextSize(1), 32);
  assert.equal(session.changeTextSize(Number.NaN), 32);
  session.stop();

  dom.dom.window.localStorage.removeItem(TERMINAL_FONT_SIZE_STORAGE_KEY);
  const firstWindow = new TerminalWindow({
    transport,
    terminal: 'term-win-1',
    container: fakeContainer(180, 90),
  });
  await firstWindow.start();
  assert.equal(firstWindow.textSize, 11, 'default font size is 11px (3 steps smaller than 14px)');
  assert.equal(firstWindow.changeTextSize(-1), 10);
  assert.equal(firstWindow.changeTextSize(-1), 9);
  assert.equal(firstWindow.changeTextSize(1), 10);
  assert.equal(dom.dom.window.localStorage.getItem(TERMINAL_FONT_SIZE_STORAGE_KEY), '10');
  firstWindow.stop();

  const secondWindow = new TerminalWindow({
    transport,
    terminal: 'term-win-2',
    container: fakeContainer(180, 90),
  });
  await secondWindow.start();
  assert.equal(secondWindow.textSize, 10, 'reopening TerminalWindow restores remembered font size');
  secondWindow.stop();
  dom.cleanup();
});

test('Android touch selection adjusts both start and end handles, unsticks on tap/re-press, and tolerates jitter', async () => {
  const dom = installDom();
  const written = installClipboard(dom.dom);
  Object.defineProperty(dom.dom.window.navigator, 'clipboard', {
    configurable: true,
    value: {
      writeText: async (text) => { written.push(text); },
      readText: async () => 'UNWANTED_PASTE',
    },
  });
  const frameWithSelection = () => ({
    ...textFrame('alpha bravo charlie'),
    selection: [0, 6, 0, 10],
  });
  const transport = fakeTransport({
    '/api/terminal/frame': () => ({ success: true, alive: true, frame: frameWithSelection() }),
    '/api/terminal/selection': { success: true, text: 'adjusted' },
  });
  const opens = [];
  const session = new TerminalSession({
    transport,
    terminal: 'term-android-adjust',
    container: fakeContainer(180, 90),
    fontSize: 14,
    pollInterval: 5,
    keyboard: true,
    onSelection: (open) => opens.push(open),
  });
  session.start();
  await new Promise((resolve) => setTimeout(resolve, 20));
  const el = session.element;
  const touch = (x, y) => ({ clientX: x, clientY: y });

  // 1. Long-press at column 6 (x = 54px, y = 4px) with minor 4px thumb jitter (< TOUCH_SLOP_PX)
  //    and an Android touch contextmenu event firing mid-press: must still select and NOT paste!
  const startHold = new dom.dom.window.Event('touchstart');
  startHold.touches = [touch(54, 4)];
  el.dispatchEvent(startHold);
  const jitter = new dom.dom.window.Event('touchmove', { cancelable: true });
  jitter.touches = [touch(57, 6)];
  el.dispatchEvent(jitter);
  el.dispatchEvent(new dom.dom.window.MouseEvent('contextmenu', { button: 2, cancelable: true }));
  await new Promise((resolve) => setTimeout(resolve, TerminalSession.LONG_PRESS_MS + 40));

  assert.deepEqual(opens, [true], 'minor thumb jitter does not cancel long-press');
  assert.equal(
    transport.calls.filter((c) => c.path === '/api/terminal/input' && c.body.data !== '').length,
    0,
    'touch long-press contextmenu must not paste clipboard text into the shell',
  );

  // Drag initial selection to column 10 (x = 92px) and release.
  const initialExtend = new dom.dom.window.Event('touchmove', { cancelable: true });
  initialExtend.touches = [touch(92, 4)];
  el.dispatchEvent(initialExtend);
  el.dispatchEvent(new dom.dom.window.Event('touchend'));
  await new Promise((resolve) => setTimeout(resolve, 15));
  assert.deepEqual(session.selection, { start: { row: 0, column: 6 }, end: { row: 0, column: 10 } });

  // 2. Grab the START handle near column 6 (x = 54px) and drag LEFT to column 2 (x = 20px):
  //    must adjust selectionStart to column 2 while keeping selectionEnd anchored at column 10!
  const grabStart = new dom.dom.window.Event('touchstart');
  grabStart.touches = [touch(54, 4)];
  el.dispatchEvent(grabStart);
  const moveStart = new dom.dom.window.Event('touchmove', { cancelable: true });
  moveStart.touches = [touch(20, 4)];
  el.dispatchEvent(moveStart);
  el.dispatchEvent(new dom.dom.window.Event('touchend'));
  await new Promise((resolve) => setTimeout(resolve, 15));
  assert.deepEqual(
    session.selection,
    { start: { row: 0, column: 2 }, end: { row: 0, column: 10 } },
    'dragging the start handle adjusts the start boundary instead of getting stuck at column 6',
  );

  // 3. Grab the END handle near column 10's right edge (x = 99px) and drag RIGHT to column 14 (x = 128px):
  //    must adjust selectionEnd to column 14 while keeping selectionStart anchored at column 2!
  const grabEnd = new dom.dom.window.Event('touchstart');
  grabEnd.touches = [touch(99, 13)];
  el.dispatchEvent(grabEnd);
  const moveEnd = new dom.dom.window.Event('touchmove', { cancelable: true });
  moveEnd.touches = [touch(128, 13)];
  el.dispatchEvent(moveEnd);
  el.dispatchEvent(new dom.dom.window.Event('touchend'));
  await new Promise((resolve) => setTimeout(resolve, 15));
  assert.deepEqual(
    session.selection,
    { start: { row: 0, column: 2 }, end: { row: 0, column: 14 } },
    'dragging the end handle adjusts the end boundary cleanly',
  );

  // 4. Long-press far away (row 3, column 1 -> x = 12px, y = 60px) while selection is open:
  //    must re-anchor at the new spot instead of staying stuck to (0, 2)!
  const pressElsewhere = new dom.dom.window.Event('touchstart');
  pressElsewhere.touches = [touch(12, 60)];
  el.dispatchEvent(pressElsewhere);
  await new Promise((resolve) => setTimeout(resolve, TerminalSession.LONG_PRESS_MS + 40));
  const dragElsewhere = new dom.dom.window.Event('touchmove', { cancelable: true });
  dragElsewhere.touches = [touch(48, 60)];
  el.dispatchEvent(dragElsewhere);
  el.dispatchEvent(new dom.dom.window.Event('touchend'));
  await new Promise((resolve) => setTimeout(resolve, 15));
  assert.deepEqual(
    session.selection,
    { start: { row: 3, column: 1 }, end: { row: 3, column: 5 } },
    'long-pressing a new location starts a fresh selection at that location',
  );

  // 5. Plain tap away from handles (row 0, column 18 -> x = 165px, y = 4px) dismisses selection.
  const tapAway = new dom.dom.window.Event('touchstart');
  tapAway.touches = [touch(165, 4)];
  el.dispatchEvent(tapAway);
  el.dispatchEvent(new dom.dom.window.Event('touchend'));
  await new Promise((resolve) => setTimeout(resolve, 15));
  assert.equal(session.selection, null, 'tapping away from handles clears the selection');
  assert.equal(opens.at(-1), false);

  await session.close();
  dom.cleanup();
});

test('switching apps on mobile pauses frame polling while hidden and resumes without killing the shell', async () => {
  const dom = installDom();
  const doc = dom.dom.window.document;
  let visibility = 'visible';
  Object.defineProperty(doc, 'visibilityState', {
    configurable: true,
    get: () => visibility,
  });

  let frameText = 'initial!';
  const ended = [];
  const frames = [];
  const transport = {
    calls: [],
    async get(path) {
      this.calls.push({ method: 'GET', path });
      if (path.startsWith('/api/terminal/frame')) {
        if (visibility === 'hidden') {
          throw new Error('Failed to fetch while WebView paused');
        }
        return {
          success: true,
          dirty: true,
          alive: true,
          frame: textFrame(frameText),
        };
      }
      return { success: true };
    },
    async post(path, body) {
      this.calls.push({ method: 'POST', path, body });
      return { success: true };
    },
  };

  const session = new TerminalSession({
    transport,
    terminal: 'term-mobile-bg',
    container: fakeContainer(90, 36),
    pollInterval: 8,
    onEnded: (reason) => ended.push(reason),
    onFrame: (frame) => frames.push(frame),
  });
  session.start();
  await new Promise((resolve) => setTimeout(resolve, 25));
  assert.ok(frames.length >= 1, 'initial foreground frame rendered');

  // Simulate switching to another app on Android: document becomes hidden.
  visibility = 'hidden';
  doc.dispatchEvent(new dom.dom.window.Event('visibilitychange'));
  const callsAtHide = transport.calls.filter((c) => c.path.startsWith('/api/terminal/frame')).length;

  // Wait > 10x pollInterval (well past the old 5-strike threshold!).
  await new Promise((resolve) => setTimeout(resolve, 90));
  const callsWhileHidden = transport.calls.filter((c) => c.path.startsWith('/api/terminal/frame')).length;
  assert.equal(ended.length, 0, 'backgrounding must never end a live terminal');
  assert.ok(callsWhileHidden <= callsAtHide + 1, 'polling pauses while the app is hidden');

  // Simulate output arriving while backgrounded and switching back to LinSCP.
  frameText = 'resumed!';
  const framesBeforeReturn = frames.length;
  visibility = 'visible';
  doc.dispatchEvent(new dom.dom.window.Event('visibilitychange'));
  await new Promise((resolve) => setTimeout(resolve, 25));

  assert.equal(ended.length, 0, 'returning from another app keeps the terminal alive');
  assert.ok(frames.length > framesBeforeReturn, 'returning immediately refreshes the terminal screen');
  const latestCodepoints = frames.at(-1).cells.slice(0, 'resumed!'.length).map((c) => c.text[0]);
  assert.equal(String.fromCodePoint(...latestCodepoints), 'resumed!');

  await session.close();
  dom.cleanup();
});

test('transient IPC glitches on resume do not kill the terminal while HTTP 400 still reports closure', async () => {
  const dom = installDom();
  let transientCount = 0;
  const ended = [];
  const transport = {
    calls: [],
    async get(path) {
      this.calls.push({ method: 'GET', path });
      if (path.startsWith('/api/terminal/frame')) {
        transientCount += 1;
        // 8 consecutive transient WebView IPC rejections (more than 5!) before recovery.
        if (transientCount <= 8) {
          throw new TypeError('Failed to fetch');
        }
        return { success: true, dirty: true, alive: true, frame: textFrame('recovered') };
      }
      return { success: true };
    },
    async post(path, body) {
      this.calls.push({ method: 'POST', path, body });
      return { success: true };
    },
  };

  const session = new TerminalSession({
    transport,
    terminal: 'term-resume-glitch',
    container: fakeContainer(90, 36),
    pollInterval: 2,
    onEnded: (reason) => ended.push(reason),
  });
  // Speed up transient backoff via direct focus resumes to exercise >5 transient errors quickly.
  session.start();
  const transientDeadline = Date.now() + 1000;
  while (transientCount < 9 && Date.now() < transientDeadline) {
    dom.dom.window.dispatchEvent(new dom.dom.window.Event('focus'));
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  assert.equal(ended.length, 0, 'transient IPC errors without 400/404 status do not kill the terminal');
  assert.ok(transientCount >= 9, 'recovered after >5 transient errors');
  await session.close();

  // Authoritative 400 TransportError ("This terminal is no longer open.") still finishes promptly.
  const closedReasons = [];
  const closedTransport = {
    async get() {
      const err = new Error('This terminal is no longer open.');
      err.status = 400;
      throw err;
    },
    async post() {
      return { success: true };
    },
  };
  const deadSession = new TerminalSession({
    transport: closedTransport,
    terminal: 'term-gone',
    container: fakeContainer(90, 36),
    pollInterval: 2,
    onEnded: (reason) => closedReasons.push(reason),
  });
  deadSession.start();
  const closeDeadline = Date.now() + 1000;
  while (closedReasons.length === 0 && Date.now() < closeDeadline) {
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  assert.deepEqual(closedReasons, ['This terminal is no longer open.']);
  dom.cleanup();
});

test('selecting text with the mouse and then right-clicking pastes and clears the highlight', async () => {
  const dom = installDom();
  let clipboardBuffer = '';
  Object.defineProperty(dom.dom.window.navigator, 'clipboard', {
    configurable: true,
    value: {
      writeText: async (text) => { clipboardBuffer = text; },
      readText: async () => clipboardBuffer,
    },
  });
  const transport = fakeTransport({
    '/api/terminal/frame': () => ({ success: true, alive: true, frame: textFrame('echo hello') }),
    '/api/terminal/selection': { success: true, text: 'hello' },
  });
  const session = new TerminalSession({
    transport,
    terminal: 'term-select-then-paste',
    container: fakeContainer(90, 36),
    pollInterval: 5,
  });
  session.start();
  try {
    await new Promise((resolve) => setTimeout(resolve, 20));
    const win = dom.dom.window;
    const doc = win.document;

    // Double-click `hello` to select and auto-copy it; `session.selection` stays open.
    session.element.dispatchEvent(new win.MouseEvent('mousedown', { button: 0, detail: 2, clientX: 67, clientY: 4, cancelable: true }));
    doc.dispatchEvent(new win.MouseEvent('mouseup', { button: 0, detail: 2, clientX: 67, clientY: 4 }));
    await new Promise((resolve) => setTimeout(resolve, 15));
    assert.equal(clipboardBuffer, 'hello');
    assert.ok(session.selection, 'selection stays highlighted after auto-copy');

    // Right-click while selection is still highlighted MUST paste and clear the finished highlight.
    const rightClick = new win.MouseEvent('contextmenu', { button: 2, cancelable: true });
    session.element.dispatchEvent(rightClick);
    assert.equal(rightClick.defaultPrevented, true);
    await new Promise((resolve) => setTimeout(resolve, 20));

    const pasted = transport.calls
      .filter((call) => call.path === '/api/terminal/input' && call.body.data)
      .map((call) => Buffer.from(call.body.data, 'base64').toString());
    assert.deepEqual(pasted, ['hello'], 'right-click pastes even when a selection was active');
    assert.equal(session.selection, null, 'pasting clears the completed selection highlight');

    // Shift+Insert also pastes clipboard text.
    const shiftInsert = new win.KeyboardEvent('keydown', { key: 'Insert', shiftKey: true, cancelable: true });
    assert.equal(session.handleKey(shiftInsert, { app_cursor: false, bracketed_paste: true }), true);
    assert.equal(shiftInsert.defaultPrevented, true);
    await new Promise((resolve) => setTimeout(resolve, 20));
    const afterShiftInsert = transport.calls
      .filter((call) => call.path === '/api/terminal/input' && call.body.data)
      .map((call) => Buffer.from(call.body.data, 'base64').toString());
    assert.equal(afterShiftInsert.at(-1), '\x1b[200~hello\x1b[201~');
  } finally {
    await session.close();
    dom.cleanup();
  }
});

test('right-click paste and mouse copy use native Tauri clipboard when WebView clipboard is denied', async () => {
  const dom = installDom();
  let nativeClip = 'from-wayland-clipboard';
  let errors = 0;
  dom.dom.window.__TAURI_INTERNALS__ = {
    invoke: async (cmd, args) => {
      if (cmd === 'linscp_read_clipboard') {
        return { success: true, text: nativeClip };
      }
      if (cmd === 'linscp_write_clipboard') {
        nativeClip = args.text;
        return { success: true };
      }
      return { status: 200, payload: { success: true } };
    },
  };
  Object.defineProperty(dom.dom.window.navigator, 'clipboard', {
    configurable: true,
    value: {
      readText: async () => { throw new Error('NotAllowedError: WebKitGTK clipboard denied'); },
      writeText: async () => { throw new Error('NotAllowedError: user gesture expired'); },
    },
  });
  dom.dom.window.document.execCommand = () => false;

  const transport = fakeTransport({
    '/api/terminal/frame': () => ({ success: true, alive: true, frame: blankFrame(10, 2) }),
    '/api/terminal/selection': { success: true, text: 'copied-via-native' },
  });
  const session = new TerminalSession({
    transport,
    terminal: 'term-native-clip',
    container: fakeContainer(90, 36),
    pollInterval: 5,
    onClipboardError: () => { errors += 1; },
  });
  session.start();
  try {
    await new Promise((resolve) => setTimeout(resolve, 15));
    const win = dom.dom.window;
    const doc = win.document;

    // 1. Right-click pastes from native OS clipboard even though navigator.clipboard.readText throws.
    session.element.dispatchEvent(new win.MouseEvent('contextmenu', { button: 2, cancelable: true }));
    await new Promise((resolve) => setTimeout(resolve, 20));
    const firstPaste = transport.calls
      .filter((call) => call.path === '/api/terminal/input' && call.body.data)
      .map((call) => Buffer.from(call.body.data, 'base64').toString());
    assert.deepEqual(firstPaste, ['from-wayland-clipboard']);
    assert.equal(errors, 0);

    // 2. Mouse drag copies via native OS clipboard even though navigator.clipboard.writeText throws,
    //    and subsequent right-click pastes the newly copied selection.
    session.element.dispatchEvent(new win.MouseEvent('mousedown', { button: 0, detail: 1, clientX: 0, clientY: 0, cancelable: true }));
    doc.dispatchEvent(new win.MouseEvent('mousemove', { button: 0, clientX: 27, clientY: 0, cancelable: true }));
    doc.dispatchEvent(new win.MouseEvent('mouseup', { button: 0, clientX: 27, clientY: 0 }));
    await new Promise((resolve) => setTimeout(resolve, 20));
    assert.equal(nativeClip, 'copied-via-native');
    assert.equal(errors, 0);

    session.element.dispatchEvent(new win.MouseEvent('contextmenu', { button: 2, cancelable: true }));
    await new Promise((resolve) => setTimeout(resolve, 20));
    const allPastes = transport.calls
      .filter((call) => call.path === '/api/terminal/input' && call.body.data)
      .map((call) => Buffer.from(call.body.data, 'base64').toString());
    assert.deepEqual(allPastes, ['from-wayland-clipboard', 'copied-via-native']);
    assert.equal(errors, 0);
  } finally {
    await session.close();
    dom.cleanup();
  }
});

test('encodeKey covers printable symbols, xterm modifier sequences, control chords, and IME/Meta guards', () => {
  // Printable symbols including '-' and '+' (which Commander uses for mask selection) go straight through.
  assert.equal(encodeKey({ key: '-' }, false), '-');
  assert.equal(encodeKey({ key: '+' }, false), '+');
  assert.equal(encodeKey({ key: '/' }, false), '/');
  assert.equal(encodeKey({ key: '~' }, false), '~');
  assert.equal(encodeKey({ key: '-', altKey: true }, false), '\x1b-');

  // Standard xterm Ctrl chords for readline/bash undo, delete, and NUL.
  assert.equal(encodeKey({ key: '/', ctrlKey: true }, false), '\x1f');
  assert.equal(encodeKey({ key: '-', ctrlKey: true }, false), '\x1f');
  assert.equal(encodeKey({ key: '_', ctrlKey: true, shiftKey: true }, false), '\x1f');
  assert.equal(encodeKey({ key: '?', ctrlKey: true, shiftKey: true }, false), '\x7f');
  assert.equal(encodeKey({ key: 'Backspace', ctrlKey: true }, false), '\x08');
  assert.equal(encodeKey({ key: 'Backspace', altKey: true }, false), '\x1b\x7f');

  // Unmapped Ctrl+symbol or OS Meta shortcuts must not leak literal printable characters into the PTY.
  assert.equal(encodeKey({ key: '=', ctrlKey: true }, false), null);
  assert.equal(encodeKey({ key: '9', ctrlKey: true }, false), null);
  assert.equal(encodeKey({ key: 'k', metaKey: true }, false), null);
  assert.equal(encodeKey({ key: 'a', isComposing: true }, false), null);

  // Word navigation and modified function/editing keys use xterm CSI modifier parameters.
  assert.equal(encodeKey({ key: 'ArrowLeft', ctrlKey: true }, false), '\x1b[1;5D');
  assert.equal(encodeKey({ key: 'ArrowRight', ctrlKey: true }, true), '\x1b[1;5C');
  assert.equal(encodeKey({ key: 'ArrowLeft', altKey: true }, false), '\x1b[1;3D');
  assert.equal(encodeKey({ key: 'Delete', ctrlKey: true }, false), '\x1b[3;5~');
  assert.equal(encodeKey({ key: 'Home', shiftKey: true }, true), '\x1b[1;2H');
  assert.equal(encodeKey({ key: 'F2', shiftKey: true }, false), '\x1b[1;2Q');
  assert.equal(encodeKey({ key: 'F10' }, false), '\x1b[21~');

  // Every standard printable ASCII character (including '-', '+', '_', '=', '/', '~', '|', '\\') passes straight through.
  for (let cp = 0x20; cp <= 0x7e; cp++) {
    const ch = String.fromCharCode(cp);
    assert.equal(encodeKey({ key: ch }, false), ch, `printable ASCII ${JSON.stringify(ch)} encodes 1:1`);
  }

  // Numpad and legacy WebView key names normalize cleanly to standard terminal sequences.
  assert.equal(encodeKey({ key: 'Subtract' }, false), '-');
  assert.equal(encodeKey({ key: 'Add' }, false), '+');
  assert.equal(encodeKey({ key: 'Multiply' }, false), '*');
  assert.equal(encodeKey({ key: 'Divide' }, false), '/');
  assert.equal(encodeKey({ key: 'Decimal' }, false), '.');
  assert.equal(encodeKey({ key: 'Spacebar' }, false), ' ');
  assert.equal(encodeKey({ key: 'Esc' }, false), '\x1b');
  assert.equal(encodeKey({ key: 'Del' }, false), '\x1b[3~');
  assert.equal(encodeKey({ key: 'Ins' }, false), '\x1b[2~');
  assert.equal(encodeKey({ key: 'Up' }, false), '\x1b[A');
  assert.equal(encodeKey({ key: 'Down' }, true), '\x1bOB');
  assert.equal(encodeKey({ key: 'Left' }, false), '\x1b[D');
  assert.equal(encodeKey({ key: 'Right' }, true), '\x1bOC');

  // International AltGr third-level symbols pass through as UTF-8 text instead of Ctrl+Alt control codes or null.
  for (const sym of ['@', '|', '\\', '[', ']', '{', '}', '~', '€', 'µ', '²', '³']) {
    assert.equal(
      encodeKey({
        key: sym,
        ctrlKey: true,
        altKey: true,
        getModifierState: (mod) => mod === 'AltGraph',
      }, false),
      sym,
      `AltGraph ${sym} encodes as UTF-8 text`,
    );
  }
  for (const sym of ['@', '{', '|', '}', '~', '€', 'µ']) {
    assert.equal(
      encodeKey({ key: sym, ctrlKey: true, altKey: true, shiftKey: false }, false),
      sym,
      `Windows Ctrl+Alt AltGr fallback ${sym} encodes as UTF-8 text`,
    );
  }
});

test('Shift+PageUp/PageDown scrolls terminal history and canvas mousedown focuses the terminal surface', async () => {
  const realDom = new JSDOM('<!doctype html><div id="host"></div>', {
    pretendToBeVisual: true,
    url: 'https://tauri.localhost/',
  });
  realDom.window.HTMLCanvasElement.prototype.getContext = () => fakeCanvas().context;
  const prevDoc = globalThis.document;
  const prevDpr = globalThis.devicePixelRatio;
  globalThis.document = realDom.window.document;
  globalThis.devicePixelRatio = 1;
  const transport = fakeTransport({
    '/api/terminal/frame': () => ({ success: true, alive: true, frame: blankFrame(80, 24) }),
  });
  const container = realDom.window.document.getElementById('host');
  Object.defineProperty(container, 'clientWidth', { value: 720, configurable: true });
  Object.defineProperty(container, 'clientHeight', { value: 432, configurable: true });
  const toolbarButton = realDom.window.document.createElement('button');
  realDom.window.document.body.appendChild(toolbarButton);
  const session = new TerminalSession({
    transport,
    terminal: 'term-keys-focus',
    container,
    pollInterval: 1000,
  });
  assert.equal(session.element.tabIndex, -1, 'terminal canvas is programmatically focusable without stealing Tab');
  session.start();
  try {
    const win = realDom.window;
    assert.equal(win.document.activeElement, session.element, 'starting a desktop terminal focuses its canvas surface');
    const pgUp = new win.KeyboardEvent('keydown', { key: 'PageUp', shiftKey: true, cancelable: true });
    const pgDn = new win.KeyboardEvent('keydown', { key: 'PageDown', shiftKey: true, cancelable: true });
    assert.equal(session.handleKey(pgUp), true);
    assert.equal(session.handleKey(pgDn), true);
    assert.equal(pgUp.defaultPrevented, true);
    assert.equal(pgDn.defaultPrevented, true);
    await new Promise((resolve) => setTimeout(resolve, 15));
    const scrolls = transport.calls.filter((call) => call.path === '/api/terminal/scroll').map((call) => call.body.lines);
    assert.equal(scrolls.length, 2);
    assert.ok(scrolls[0] > 0 && scrolls[1] < 0);
    assert.equal(
      transport.calls.filter((call) => call.path === '/api/terminal/input' && call.body.data).length,
      0,
      'Shift+PageUp/PageDown scrolls history without sending bytes to the shell',
    );

    // AltGr printable characters on the soft-keyboard textarea path defer to `input` so they are never sent twice.
    assert.equal(
      session.handleTypedKey({
        key: '@',
        ctrlKey: true,
        altKey: true,
        getModifierState: (mod) => mod === 'AltGraph',
      }),
      false,
    );

    toolbarButton.focus();
    assert.equal(win.document.activeElement, toolbarButton);
    session.element.dispatchEvent(new win.MouseEvent('mousedown', { button: 0, detail: 1, clientX: 5, clientY: 5, cancelable: true }));
    assert.equal(win.document.activeElement, session.element, 'clicking terminal canvas moves focus directly onto the canvas');
    toolbarButton.focus();
    session.focus();
    assert.equal(win.document.activeElement, session.element, 'session.focus() restores focus onto the canvas');
  } finally {
    await session.close();
    realDom.window.close();
    if (prevDoc === undefined) delete globalThis.document;
    else globalThis.document = prevDoc;
    if (prevDpr === undefined) delete globalThis.devicePixelRatio;
    else globalThis.devicePixelRatio = prevDpr;
  }
});



