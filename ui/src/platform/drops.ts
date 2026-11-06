/**
 * Operating-system file drops, in the one form every host can deliver.
 *
 * The page drops a `File` through its own drag-and-drop handlers, and that is
 * the only path a browser has. A native window is different: the operating
 * system answers the drop with *paths* - a string per item, no bytes - and the
 * shell has to read them itself. The Android app gets paths the same way from
 * the share sheet, which stages each URI and records the same manifest.
 *
 * Without this module the same gesture behaved differently in each app: the
 * browser queued an upload, the desktop window did nothing at all (its
 * `dragDropEnabled` window consumes the drop before the page sees it) and the
 * Android app only offered the files after a restart of the pending check.
 * Reading a path is a backend operation, so it is dispatched through the
 * ordinary `TransferClient` instead of a private IPC call: whatever answers
 * `/api/transfer/drop` handles the browser's bytes and the desktop's path
 * through one implementation, with one set of conflict and overwrite rules.
 */

import type { TransportClient } from '../transport/client.js';

/** One item the operating system dropped, in path form. */
export interface DroppedPath {
  /** Absolute path on the machine that runs the backend. */
  path: string;
  /** Directory, so the backend creates it before copying its children. */
  isDirectory: boolean;
}

/** The reply both drop endpoints answer with. */
export interface DropResult {
  success?: boolean;
  error?: string;
  /** Names the destination already has; the page asks before replacing them. */
  conflicts?: string[];
  /** Set when the destination already holds folders a transfer would merge. */
  directory_conflicts?: string[] | boolean;
  /** Risk acknowledgements the queue asks for, relayed by the caller. */
  directory_copy_risk?: boolean;
  ftp_rename_risk?: boolean;
  /** ETags of the conflicting destination files, for a conditional retry. */
  conflict_versions?: Record<string, string>;
  /** Names the drop wrote, and per-name refusals when it wrote only some. */
  saved?: string[];
  refused?: string[];
  [key: string]: unknown;
}

export interface NativeDropOptions {
  /** Where the dropped items go: the remote panel, or the local one. */
  target: 'remote' | 'local';
  /** Directory the items land in (`state.remote.path` or `state.local.path`). */
  directory: string;
  /** Tab the drop belongs to; required for a remote target. */
  tab?: number | null;
  /** Filenames the destination already has, when the page knows them. */
  existing?: Iterable<string>;
}

/** The leaf name of a path the OS produced, on either separator. */
export function droppedLeafName(path: string): string {
  const trimmed = path.replace(/[\\/]+$/, '');
  const index = Math.max(trimmed.lastIndexOf('/'), trimmed.lastIndexOf('\\'));
  return index >= 0 ? trimmed.slice(index + 1) : trimmed;
}

/** A drop request, before anything is sent. */
export interface DropRequest {
  endpoint: string;
  payload: Record<string, unknown>;
}

/**
 * Builds the request one whole drop makes.
 *
 * One request per drop, not per item: the backend reads every path itself, so
 * a folder of two hundred files is one queue entry and one conflict answer
 * instead of two hundred round trips the page cannot even make sense of. The
 * approvals the dialogs collect (`overwrite`, `merge_directories`, the two risk
 * acceptances) are merged in unchanged, so a retry is the same request plus one
 * decision and the backend reads both identically.
 */
export function dropRequest(
  items: Iterable<DroppedPath>,
  options: NativeDropOptions & { approvals?: Record<string, unknown> },
): DropRequest {
  const list = Array.from(items).filter(item => item && typeof item.path === 'string' && item.path);
  const endpoint = options.target === 'remote' ? '/api/transfer/drop' : '/api/local/drop';
  const paths = list.map(item => item.path);
  const first = paths[0] ?? '';
  const payload: Record<string, unknown> = {
    // The first item's leaf name is what a single-item drop calls itself; the
    // path list is the authority for everything else.
    name: first ? droppedLeafName(first) : '',
    relative_path: '',
    source_path: first,
    source_paths: paths,
    directories: list.filter(item => item.isDirectory).map(item => item.path),
    source_kind: list.length === 1 && list.every(item => item.isDirectory) ? 'directory' : 'file',
    ...(options.approvals ?? {}),
  };
  if (options.target === 'remote') {
    if (options.directory) {
      payload['remote_dir'] = options.directory;
    }
    if (options.tab !== undefined && options.tab !== null) {
      payload['tab'] = options.tab;
    }
  } else if (options.directory) {
    payload['local_dir'] = options.directory;
  }
  return { endpoint, payload };
}

/** What one drop produced. `payload` is what a retry with an approval repeats. */
export interface DropOutcome {
  /** Items the backend accepted. */
  queued: number;
  /** Items it refused, with the reason it gave. */
  failed: Array<{ path: string; error: string }>;
  /** The first answer, unchanged, so the page can ask about a refusal. */
  result: DropResult;
  /** The request that was sent; a retry sends it again with an approval. */
  payload: Record<string, unknown>;
  endpoint: string;
}

/**
 * Sends one drop and reports what happened.
 *
 * The answer keeps the backend's own refusals (`conflicts`,
 * `directory_conflicts`, the two risk flags) instead of translating them: the
 * page already owns the questions those refusals ask, and asking them here
 * would put a second copy of the overwrite rules in the front end.
 */
export async function dropPaths(
  transport: TransportClient,
  items: DroppedPath[],
  options: NativeDropOptions & { approvals?: Record<string, unknown> },
): Promise<DropOutcome> {
  const { endpoint, payload } = dropRequest(items, options);
  if (!items.length) {
    return { queued: 0, failed: [], result: { success: false }, payload, endpoint };
  }
  let result: DropResult;
  try {
    result = await transport.post<DropResult>(endpoint, payload);
  } catch (error) {
    const message = String((error as Error)?.message ?? error);
    return {
      queued: 0,
      failed: items.map(item => ({ path: item.path, error: message })),
      result: { success: false, error: message },
      payload,
      endpoint,
    };
  }
  if (result && result.success === false) {
    const message = String(result.error ?? 'refused');
    return {
      queued: 0,
      failed: items.map(item => ({ path: item.path, error: message })),
      result,
      payload,
      endpoint,
    };
  }
  // A drop can be partly accepted: the endpoint names what it wrote and what
  // it refused, and the page reports the same counts either way.
  const saved = Array.isArray(result?.saved) ? result.saved : null;
  const refused = Array.isArray(result?.refused) ? result.refused : [];
  if (saved || refused.length) {
    return {
      queued: saved ? saved.length : Math.max(0, items.length - refused.length),
      failed: refused.map(reason => ({ path: '', error: String(reason) })),
      result: result ?? { success: true },
      payload,
      endpoint,
    };
  }
  return { queued: items.length, failed: [], result: result ?? { success: true }, payload, endpoint };
}

/**
 * Turns whatever the shell handed over into a `DroppedPath` list.
 *
 * A Tauri event payload is `{ paths }` or `{ paths, isDirectory }`; an Android
 * share hand-off is a list of `content://` URIs whose directories the shell
 * already staged. Anything unusable is dropped rather than guessed at, because
 * a wrong path would be uploaded to the wrong place.
 */
export function normalizeDropPayload(payload: unknown): DroppedPath[] {
  if (!payload || typeof payload !== 'object') {
    return [];
  }
  const record = payload as { paths?: unknown; isDirectory?: unknown; directories?: unknown };
  const directories = new Set(
    Array.isArray(record.directories)
      ? record.directories.filter((value): value is string => typeof value === 'string')
      : [],
  );
  if (!Array.isArray(record.paths)) {
    return [];
  }
  const items: DroppedPath[] = [];
  for (const value of record.paths) {
    if (typeof value !== 'string' || value.length === 0) {
      continue;
    }
    // A path that does not name anything is not a drop; null and control
    // characters would be rejected by the backend anyway.
    if (value.includes('\0') || /[\x00-\x1f]/.test(value)) {
      continue;
    }
    items.push({
      path: value,
      isDirectory: record.isDirectory === true || directories.has(value),
    });
  }
  return items;
}
