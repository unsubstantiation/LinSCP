import { build } from 'esbuild';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const uiRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const repoRoot = path.resolve(uiRoot, '..');
const distDir = path.join(uiRoot, 'dist');
const legacyWebDir = path.join(repoRoot, 'source', 'gui', 'web');

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
fs.cpSync(
  path.join(legacyWebDir, 'vendor'),
  path.join(distDir, 'vendor'),
  { recursive: true },
);

const rawHtml = fs.readFileSync(path.join(legacyWebDir, 'index.html'), 'utf8').replace(/\r\n/g, '\n');

const anchor = '  async function api(url, options) {\n    options = options || {};';
if (!rawHtml.includes(anchor)) {
  throw new Error('Expected api(url, options) entrypoint in source/gui/web/index.html');
}

const dualModeShim = `  window.LinSCPTransport = window.LinSCPCore
    ? window.LinSCPCore.createTransport({ host: window, bearerToken: window.LSCP_TOKEN || '' })
    : null;

  async function api(url, options) {
    options = options || {};
    if (window.LinSCPTransport && window.LinSCPTransport.mode === 'tauri') {
      const method = (options.method || 'GET').toUpperCase();
      let parsedBody = {};
      if (typeof options.body === 'string' && options.body.length > 0) {
        try { parsedBody = JSON.parse(options.body); } catch (_) { parsedBody = {}; }
      }
      try {
        return await window.LinSCPTransport.request(method, url, parsedBody);
      } catch (error) {
        // API errors can carry actionable data such as a host-key challenge
        // or overwrite conflicts. Do not discard it as a transport failure.
        if (error && error.payload && typeof error.payload === 'object') {
          return Object.assign({}, error.payload, { success: false });
        }
        if (error && (error.status === 401 || error.status === 403)) {
          toast(errorMessage(error.message, t("The backend refused this request.")), true);
          return { success: false, error: error.message || 'refused' };
        }
        toast(t("Cannot reach the LinSCP backend: {error}", {error: String(error)}), true);
        return { success: false, error: String(error) };
      }
    }`;

const distHtml = rawHtml
  .replace('<script>', `<script>\n${iifeCode}\n</script>\n<script>`)
  .replace(anchor, dualModeShim);

fs.writeFileSync(path.join(distDir, 'index.html'), distHtml, 'utf8');
console.log('Built ui/dist (linscp-core.mjs, linscp-core.iife.js, index.html, theme.css, vendor/).');
