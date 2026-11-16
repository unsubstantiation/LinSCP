import { build } from 'esbuild';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const uiRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const repoRoot = path.resolve(uiRoot, '..');
const distDir = path.join(uiRoot, 'dist');
const legacyWebDir = path.join(repoRoot, 'source', 'gui', 'web');

// The in-app version is the build's Alaska Standard Time (UTC-9, fixed: AKST
// does not observe daylight saving) stamp: VYYYY-MM-DD-HH-MM, minutes
// precision, the minute the build ran. SOURCE_DATE_EPOCH, when set, pins the
// instant so reproducible builds stamp the same string.
function buildStamp() {
  const configured = process.env.SOURCE_DATE_EPOCH;
  const seconds = configured === undefined ? Math.floor(Date.now() / 1000) : Number(configured);
  if (!Number.isInteger(seconds) || seconds <= 0) {
    throw new Error(`SOURCE_DATE_EPOCH must be a positive whole number of seconds, got: ${configured}`);
  }
  // Shift, then read the UTC fields: those are the AKST wall-clock fields.
  const akst = new Date((seconds - 9 * 3600) * 1000).toISOString();
  return `V${akst.slice(0, 10)}-${akst.slice(11, 13)}-${akst.slice(14, 16)}`;
}
const BUILD_STAMP = buildStamp();

fs.rmSync(distDir, { recursive: true, force: true });
fs.mkdirSync(distDir, { recursive: true });

await build({
  entryPoints: [path.join(uiRoot, 'src', 'index.ts')],
  outfile: path.join(distDir, 'linscp-core.mjs'),
  bundle: true,
  format: 'esm',
  platform: 'browser',
  target: ['es2022'],
  sourcemap: false,
});

const iifeResult = await build({
  entryPoints: [path.join(uiRoot, 'src', 'index.ts')],
  bundle: true,
  write: false,
  format: 'iife',
  globalName: 'LinSCPCore',
  platform: 'browser',
  target: ['es2022'],
});
const iifeCode = iifeResult.outputFiles[0].text;
fs.writeFileSync(path.join(distDir, 'linscp-core.iife.js'), iifeCode, 'utf8');

fs.copyFileSync(
  path.join(legacyWebDir, 'theme.css'),
  path.join(distDir, 'theme.css'),
);
fs.copyFileSync(
  path.join(legacyWebDir, 'icon.svg'),
  path.join(distDir, 'icon.svg'),
);
const rawHtml = fs.readFileSync(path.join(legacyWebDir, 'index.html'), 'utf8').replace(/\r\n/g, '\n');

const anchor = '  async function api(url, options) {\n    options = options || {};';
if (!rawHtml.includes(anchor)) {
  throw new Error('Expected api(url, options) entrypoint in source/gui/web/index.html');
}

// The page's own `api()` is the native implementation; the bundle only has to
// hand it the transport, the shared components and the shell mount. The shim
// ends by re-emitting the anchor so the page's function body stays intact.
const nativeShim = `  window.LinSCPTransport = window.LinSCPCore
    ? window.LinSCPCore.createTransport({ host: window })
    : null;

  // The local root switcher is a real component with behaviour (SAF picker,
  // root matching, empty-list handling), so it is not re-implemented in the
  // page. The page only borrows an instance and owns the DOM element.
  window.LinSCPCore.localRootSwitcher = function (options) {
    return new window.LinSCPCore.LocalRootSwitcher(options);
  };
  window.LinSCPCore.requestAndroidFolder = function () {
    return window.LinSCPCore.requestSafTree();
  };

  // The touch shell (bottom navigation, swipe, long-press selection and the
  // terminal extra-key row) is one component with real behaviour, so it lives
  // in the shared bundle as well. The page owns the elements and the actions;
  // every host - the desktop window and the Android app - mounts this same
  // object, which is why the narrow layout behaves the same in both.
  window.LinSCPCore.mountAppShell = function (options) {
    return new window.LinSCPCore.AppShell(options);
  };

  // A terminal window ("terminal-term-1") and the Android app show one
  // terminal and nothing else. Which one is inside the window's own label,
  // because the window was opened for exactly one terminal and a window that
  // guessed would be able to attach to a shell nobody asked it to show.
  //
  // The label comes from the shell's own window metadata rather than from a
  // guess about the URL: the page is the same document in every window, so the
  // window is the only thing that says which terminal this one is for.
  window.LinSCPCore.terminalWindowLabel = function () {
    try {
      const internals = window.__TAURI_INTERNALS__;
      const label = internals && internals.metadata && internals.metadata.currentWindow
        ? internals.metadata.currentWindow.label
        : null;
      return typeof label === 'string' && label ? label : null;
    } catch (error) {
      return null;
    }
  };
  window.LinSCPCore.terminalWindow = function (options) {
    return new window.LinSCPCore.TerminalWindow(options);
  };

  async function api(url, options) {
    options = options || {};`;

// The same stamp every host that bundles this page shows: the desktop
// window, the Android app. Inserted before the bundle, so the page's own
// script sees it; a page served without the build (the bare source tree)
// reads the absence and prints no version line.
const buildVersionLine = `window.LinSCPBuildVersion = ${JSON.stringify(BUILD_STAMP)};`;

const distHtml = rawHtml
  .replace('<script>', `<script>\n${buildVersionLine}\n${iifeCode}\n</script>\n<script>`)
  .replace(anchor, nativeShim);

fs.writeFileSync(path.join(distDir, 'index.html'), distHtml, 'utf8');
console.log(`Built ui/dist (linscp-core.mjs, linscp-core.iife.js, index.html, theme.css). Version: ${BUILD_STAMP}`);
