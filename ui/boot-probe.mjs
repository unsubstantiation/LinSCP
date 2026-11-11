import fs from 'node:fs';
import { JSDOM } from 'jsdom';
const html = fs.readFileSync('/home/user/preview/app/dark.html', 'utf8');
const errors = [];
const dom = new JSDOM(html, {
  url: 'http://localhost:8080/', runScripts: 'dangerously', pretendToBeVisual: true,
  beforeParse(window) {
    window.HTMLCanvasElement.prototype.getContext = () => ({
      font: '', fillStyle: '', textBaseline: '',
      setTransform() {}, fillRect() {}, fillText() {},
      measureText: t => ({ width: String(t).length * 8.8 }),
    });
    window.addEventListener('error', e => errors.push(String(e.error || e.message)));
  },
});
await new Promise(r => setTimeout(r, 2500));
const d = dom.window.document;
const row = d.querySelector('table.file-table tbody tr');
const cs = dom.window.getComputedStyle;
console.log('title           :', d.title);
console.log('file rows local :', d.querySelectorAll('#localPane table.file-table tbody tr').length);
console.log('file rows remote:', d.querySelectorAll('#remotePane tbody tr').length);
console.log('first row       :', row ? row.textContent.trim().replace(/\s+/g,' ').slice(0,60) : 'NONE');
console.log('queue rows      :', d.querySelectorAll('.queue-table tbody tr').length);
console.log('tabs            :', d.querySelectorAll('.session-tab, .tab').length);
console.log('toasts          :', d.querySelectorAll('.toast').length);
console.log('errors          :', errors.length ? errors.slice(0,3) : 'none');
