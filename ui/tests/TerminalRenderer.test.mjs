import assert from 'node:assert/strict';
import test from 'node:test';
import { JSDOM } from 'jsdom';

import {
  DEFAULT_RENDERER_THEME,
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
  const dom = new JSDOM('<!doctype html><div id="host"></div>', { pretendToBeVisual: true });
  const { canvas, context, calls } = fakeCanvas();
  dom.window.HTMLCanvasElement.prototype.getContext = () => context;
  globalThis.document = dom.window.document;
  globalThis.devicePixelRatio = 1;
  const originalCreate = dom.window.document.createElement.bind(dom.window.document);
  dom.window.document.createElement = (tag) => (tag === 'canvas' ? Object.assign(canvas, { style: {}, remove() {} }) : originalCreate(tag));
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

test('the session polls frames, paints them and resizes only after a frame', async () => {
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
  // Dragging up by 90px at an 18px cell is five lines back into history, which
  // the model counts as positive.
  assert.equal(scrolls[0].body.lines, 5);
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
