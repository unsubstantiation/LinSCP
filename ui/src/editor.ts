/**
 * The built-in file editor.
 *
 * The Commander's editor modal used to hold a plain textarea: right for
 * size and shape, wrong for an actual editing session — no line numbers,
 * no syntax highlighting, no search panel, no bracket matching. This file
 * is the one that turns that modal into a CodeMirror 6 editor. The page
 * (source/gui/web/index.html) owns the dialog, the save/conflict rules
 * and the localisation; this module owns only the editing surface, and it
 * is bundled into the page by ui/scripts/build.mjs along with the rest of
 * the toolchain, so the desktop window, the Android app and a browser all
 * run the same code.
 *
 * The global is `LinSCPEditor`, the same shape as `LinSCPCore`: one entry
 * point, `mount(host, options)`, returning a small handle. Nothing here
 * reads the DOM at import time, so jsdom can boot the page without a
 * layout engine; CodeMirror degrades to zero-sized measures there and the
 * test suite drives the handle directly.
 */

import { Compartment, EditorState, type Extension } from '@codemirror/state';
import {
  EditorView,
  crosshairCursor,
  drawSelection,
  dropCursor,
  highlightActiveLine,
  highlightActiveLineGutter,
  keymap,
  lineNumbers,
  rectangularSelection,
} from '@codemirror/view';
import {
  defaultKeymap,
  history,
  historyKeymap,
  indentWithTab,
  toggleComment,
} from '@codemirror/commands';
import {
  StreamLanguage,
  bracketMatching,
  foldGutter,
  foldKeymap,
  indentOnInput,
  syntaxHighlighting,
  HighlightStyle,
} from '@codemirror/language';
import {
  searchKeymap,
  highlightSelectionMatches,
  openSearchPanel,
} from '@codemirror/search';
import { closeBrackets, closeBracketsKeymap } from '@codemirror/autocomplete';
import { tags } from '@lezer/highlight';

import { javascript } from '@codemirror/lang-javascript';
import { json } from '@codemirror/lang-json';
import { css } from '@codemirror/lang-css';
import { sass } from '@codemirror/lang-sass';
import { html } from '@codemirror/lang-html';
import { xml } from '@codemirror/lang-xml';
import { markdown } from '@codemirror/lang-markdown';
import { python } from '@codemirror/lang-python';
import { php } from '@codemirror/lang-php';
import { sql } from '@codemirror/lang-sql';
import { yaml } from '@codemirror/lang-yaml';
import { rust } from '@codemirror/lang-rust';

import { shell } from '@codemirror/legacy-modes/mode/shell';
import { properties } from '@codemirror/legacy-modes/mode/properties';
import { dockerFile } from '@codemirror/legacy-modes/mode/dockerfile';
import { toml } from '@codemirror/legacy-modes/mode/toml';
import { nginx } from '@codemirror/legacy-modes/mode/nginx';
import { cmake } from '@codemirror/legacy-modes/mode/cmake';
import { diff } from '@codemirror/legacy-modes/mode/diff';
import { go } from '@codemirror/legacy-modes/mode/go';
import { groovy } from '@codemirror/legacy-modes/mode/groovy';
import { powerShell } from '@codemirror/legacy-modes/mode/powershell';

export interface MountOptions {
  /** The file's text. */
  value: string;
  /** View mode: the document cannot be edited, only read. */
  readOnly?: boolean;
  /** The file's name or path — the extension picks the language. */
  languagePath?: string;
  /** Called with the full text whenever the document changes. */
  onDocChange?: (value: string) => void;
}

export interface MountedEditor {
  /** The current document text. */
  getValue(): string;
  /** Replace the whole document (used to load a file or discard changes). */
  setValue(text: string): void;
  /** Select all text; used by a few tests and menu actions. */
  focus(): void;
  get readOnly(): boolean;
  /** Detach the editor from the DOM and release its listeners. */
  destroy(): void;
}

const shellLanguage = StreamLanguage.define(shell);
const propertiesLanguage = StreamLanguage.define(properties);
const dockerLanguage = StreamLanguage.define(dockerFile);
const tomlLanguage = StreamLanguage.define(toml);
const nginxLanguage = StreamLanguage.define(nginx);
const cmakeLanguage = StreamLanguage.define(cmake);
const diffLanguage = StreamLanguage.define(diff);
const goLanguage = StreamLanguage.define(go);
const groovyLanguage = StreamLanguage.define(groovy);
const powerShellLanguage = StreamLanguage.define(powerShell);

/** Language for a path, by extension or by well-known file name. */
function languageFor(path: string): Extension {
  const fileName = (path.split(/[\\/]/).pop() || '').toLowerCase();
  const dot = fileName.lastIndexOf('.');
  const ext = dot > 0 ? fileName.slice(dot + 1) : '';
  switch (ext) {
    case 'js': case 'mjs': case 'cjs': case 'jsx': return javascript({ jsx: true });
    case 'ts': case 'mts': case 'cts': case 'tsx': return javascript({ jsx: true, typescript: true });
    case 'json': case 'jsonc': case 'geojson': case 'webmanifest': return json();
    case 'css': case 'less': return css();
    case 'scss': case 'sass': return sass();
    case 'html': case 'htm': return html();
    case 'xml': case 'svg': case 'xhtml': case 'rss': case 'xsl': case 'plist': case 'svgz': return xml();
    case 'md': case 'markdown': case 'mdown': return markdown();
    case 'py': case 'pyw': return python();
    case 'php': case 'phtml': case 'phps': return php();
    case 'sql': return sql();
    case 'yaml': case 'yml': return yaml();
    case 'rs': return rust();
    case 'sh': case 'bash': case 'zsh': case 'ksh': return shellLanguage;
    case 'ini': case 'cfg': case 'conf': case 'properties': case 'props': return propertiesLanguage;
    case 'toml': return tomlLanguage;
    case 'cmake': return cmakeLanguage;
    case 'diff': case 'patch': return diffLanguage;
    case 'go': return goLanguage;
    case 'gradle': case 'groovy': return groovyLanguage;
    case 'ps1': case 'psm1': case 'psd1': return powerShellLanguage;
    default: break;
  }
  // Extensionless or ambiguous names, by exact file name.
  if (fileName === 'dockerfile' || fileName.startsWith('dockerfile.') || fileName === '.dockerignore') return dockerLanguage;
  if (fileName === 'cmakelists.txt') return cmakeLanguage;
  if (fileName === 'nginx.conf' || fileName === '.nginx.conf') return nginxLanguage;
  if (fileName === '.bashrc' || fileName === '.bash_profile' || fileName === '.zshrc' || fileName === '.profile' || fileName === '.zprofile') return shellLanguage;
  if (fileName === 'build.gradle' || fileName === 'settings.gradle') return groovyLanguage;
  if (fileName === '.gitconfig' || fileName === '.editorconfig') return propertiesLanguage;
  if (fileName.startsWith('setup.py')) return python();
  return [];
}

/** Per-language indentation: the two-space family, four-space Python/Go, and a tab for Go. */
function indentFor(path: string): number {
  const fileName = (path.split(/[\\/]/).pop() || '').toLowerCase();
  const dot = fileName.lastIndexOf('.');
  const ext = dot > 0 ? fileName.slice(dot + 1) : '';
  if (ext === 'py' || ext === 'pyw' || ext === 'go' || ext === 'rs') return 4;
  return 2;
}

/* Token colours live in the palette (theme.css defines --syn-* for both the
 * dark and the light theme) so a token can never drift outside the app's
 * own colour scheme. */
const highlightStyle = HighlightStyle.define([
  { tag: tags.keyword, color: 'var(--syn-keyword)' },
  { tag: [tags.string, tags.special(tags.string)], color: 'var(--syn-string)' },
  { tag: tags.comment, color: 'var(--syn-comment)', fontStyle: 'italic' },
  { tag: [tags.number, tags.bool, tags.atom, tags.null], color: 'var(--syn-atom)' },
  { tag: [tags.typeName, tags.className, tags.namespace, tags.definition(tags.typeName)], color: 'var(--syn-type)' },
  { tag: [tags.tagName, tags.angleBracket], color: 'var(--syn-keyword)' },
  { tag: [tags.attributeName, tags.propertyName], color: 'var(--syn-attr)' },
  { tag: tags.attributeValue, color: 'var(--syn-string)' },
  { tag: [tags.function(tags.variableName), tags.function(tags.propertyName)], color: 'var(--syn-type)' },
  { tag: tags.heading, color: 'var(--syn-keyword)', fontWeight: 'bold' },
  { tag: tags.strong, fontWeight: 'bold' },
  { tag: tags.emphasis, fontStyle: 'italic' },
  { tag: tags.link, color: 'var(--syn-keyword)', textDecoration: 'underline' },
  { tag: tags.url, color: 'var(--syn-keyword)' },
  { tag: [tags.meta, tags.processingInstruction], color: 'var(--syn-comment)' },
]);

const editorTheme = EditorView.theme({
  '&': {
    height: '100%',
    backgroundColor: 'transparent',
    color: 'var(--code-text)',
    fontSize: 'var(--fs-base)',
  },
  '&.cm-focused': { outline: 'none' },
  '.cm-scroller': {
    fontFamily: 'var(--font-mono)',
    lineHeight: '1.6',
  },
  '.cm-content': {
    caretColor: 'var(--accent)',
    padding: 'var(--space-3) 0',
    userSelect: 'text',
    WebkitUserSelect: 'text',
  },
  '.cm-cursor': { borderLeftColor: 'var(--accent)' },
  '.cm-gutters': {
    backgroundColor: 'transparent',
    color: 'var(--subtle)',
    borderRight: '1px solid var(--border)',
  },
  '.cm-activeLineGutter': {
    backgroundColor: 'color-mix(in srgb, var(--accent) 12%, transparent)',
    color: 'var(--text)',
  },
  '.cm-activeLine': {
    backgroundColor: 'color-mix(in srgb, var(--accent) 7%, transparent)',
  },
  '.cm-selectionBackground, &.cm-focused .cm-selectionBackground, ::selection': {
    backgroundColor: 'var(--selection)',
  },
  '.cm-selectionMatch': {
    backgroundColor: 'color-mix(in srgb, var(--accent) 22%, transparent)',
  },
  '.cm-matchingBracket': {
    backgroundColor: 'color-mix(in srgb, var(--accent) 25%, transparent)',
    outline: '1px solid var(--accent)',
  },
  '.cm-foldGutter span': { color: 'var(--subtle)' },
  '.cm-foldPlaceholder': {
    backgroundColor: 'var(--surface-hover)',
    color: 'var(--text)',
    border: '1px solid var(--border-strong)',
    borderRadius: 'var(--r-sm, 4px)',
  },
  '.cm-searchMatch': {
    backgroundColor: 'color-mix(in srgb, var(--warning) 35%, transparent)',
  },
  '.cm-searchMatch.cm-searchMatch-selected': {
    backgroundColor: 'color-mix(in srgb, var(--warning) 65%, transparent)',
  },
  '.cm-panels': {
    backgroundColor: 'var(--surface-raised)',
    color: 'var(--text)',
    borderBottom: '1px solid var(--border-strong)',
  },
  '.cm-panels.cm-panels-top': { borderTop: 'none' },
  '.cm-panels.cm-panels-bottom': { borderBottom: 'none', borderTop: '1px solid var(--border-strong)' },
  '.cm-textfield': {
    backgroundColor: 'var(--surface-input)',
    color: 'var(--text)',
    border: '1px solid var(--border-strong)',
    borderRadius: 'var(--r-sm, 4px)',
  },
  '.cm-button': {
    backgroundColor: 'var(--surface-hover)',
    color: 'var(--text)',
    border: '1px solid var(--border-strong)',
    borderRadius: 'var(--r-sm, 4px)',
  },
  '.cm-tooltip': {
    backgroundColor: 'var(--surface-raised)',
    border: '1px solid var(--border-strong)',
    color: 'var(--text)',
  },
}, { dark: true });

function usesNativeTouchSelection(host: HTMLElement): boolean {
  const win = host.ownerDocument?.defaultView;
  const ua = win?.navigator?.userAgent ?? '';
  if (/android/i.test(ua)) {
    return true;
  }
  if (typeof win?.matchMedia === 'function') {
    try {
      if (win.matchMedia('(pointer: coarse)').matches) {
        return true;
      }
    } catch {
      // Ignore environments with incomplete matchMedia stubs.
    }
  }
  return false;
}

export function mount(host: HTMLElement, options: MountOptions): MountedEditor {
  const readOnly = options.readOnly === true;
  const nativeTouchSelection = usesNativeTouchSelection(host);
  const path = options.languagePath || '';
  const editable = new Compartment();
  const language = new Compartment();

  const updateListener = EditorView.updateListener.of(update => {
    if (update.docChanged && options.onDocChange) {
      options.onDocChange(update.state.doc.toString());
    }
  });

  const pointerSelectionExtensions = nativeTouchSelection
    ? []
    : [drawSelection(), rectangularSelection(), crosshairCursor()];

  const view = new EditorView({
    parent: host,
    state: EditorState.create({
      doc: options.value,
      extensions: [
        lineNumbers(),
        foldGutter(),
        history(),
        ...pointerSelectionExtensions,
        dropCursor(),
        highlightActiveLine(),
        highlightActiveLineGutter(),
        highlightSelectionMatches(),
        indentOnInput(),
        bracketMatching(),
        closeBrackets(),
        EditorState.tabSize.of(indentFor(path)),
        editable.of(readOnly ? [EditorState.readOnly.of(true), EditorView.editable.of(false)] : []),
        language.of(languageFor(path)),
        editorTheme,
        syntaxHighlighting(highlightStyle, { fallback: true }),
        EditorView.lineWrapping,
        keymap.of([
          ...closeBracketsKeymap,
          ...defaultKeymap,
          ...historyKeymap,
          ...searchKeymap,
          ...foldKeymap,
          indentWithTab,
          { key: 'Mod-/', run: toggleComment },
          { key: 'Mod-f', run: openSearchPanel, preventDefault: true },
        ]),
        updateListener,
      ],
    }),
  });

  return {
    getValue: () => view.state.doc.toString(),
    setValue: (text: string) => {
      view.dispatch({
        changes: { from: 0, to: view.state.doc.length, insert: text },
      });
    },
    focus: () => { view.focus(); },
    get readOnly() { return view.state.readOnly; },
    destroy: () => { view.destroy(); },
  };
}
