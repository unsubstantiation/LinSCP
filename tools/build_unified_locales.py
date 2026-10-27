#!/usr/bin/env python3
"""Build and validate unified cross-platform localization catalogs in locales/.

Merges CLI messages (source/linux/locales/*.json) and GUI messages
(source/gui/locales/*.json) into a single domain-namespaced catalog per
language under locales/<lang>.json:

    {
      "cli": { ... },
      "gui": { ... }
    }

Keeping the "cli" and "gui" namespaces distinct preserves context-specific
grammatical forms (for example, CLI operation nouns vs. GUI action labels for
"upload" and "download") while allowing Rust (linscp-i18n) and TypeScript
(ui/) to consume one validated source of truth.

Usage:
    python3 tools/build_unified_locales.py          # write locales/*.json
    python3 tools/build_unified_locales.py --check  # verify locales/*.json are current
"""
import argparse
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import compile_translations

ROOT = pathlib.Path(__file__).resolve().parents[1]
CLI_DIR = ROOT / 'source' / 'linux' / 'locales'
GUI_DIR = ROOT / 'source' / 'gui' / 'locales'
UNIFIED_DIR = ROOT / 'locales'


def build_unified_catalogs(cli_dir=CLI_DIR, gui_dir=GUI_DIR):
    cli_catalogs = compile_translations.load_catalogs(cli_dir)
    gui_catalogs = compile_translations.load_catalogs(gui_dir)
    if set(cli_catalogs.keys()) != set(gui_catalogs.keys()):
        raise ValueError(
            f'Locale set mismatch between CLI ({sorted(cli_catalogs)}) '
            f'and GUI ({sorted(gui_catalogs)})'
        )
    unified = {}
    for locale in sorted(cli_catalogs.keys()):
        unified[locale] = {
            'cli': dict(sorted(cli_catalogs[locale].items())),
            'gui': dict(sorted(gui_catalogs[locale].items())),
        }
    return unified


def format_catalog(data):
    return json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + '\n'


def write_or_check(check_only=False, out_dir=UNIFIED_DIR):
    unified = build_unified_catalogs()
    if not check_only:
        out_dir.mkdir(parents=True, exist_ok=True)
    stale = []
    for locale, payload in unified.items():
        rendered = format_catalog(payload)
        target = out_dir / f'{locale}.json'
        if check_only:
            if not target.is_file() or target.read_text(encoding='utf-8') != rendered:
                stale.append(str(target.relative_to(ROOT)))
        else:
            target.write_text(rendered, encoding='utf-8')
    if check_only:
        existing = sorted(p.stem for p in out_dir.glob('*.json')) if out_dir.is_dir() else []
        if existing != sorted(unified.keys()):
            stale.append('locales/*.json (unexpected locale set)')
    return stale, unified


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true',
                        help='fail if locales/*.json are missing or out of date')
    args = parser.parse_args()
    stale, unified = write_or_check(check_only=args.check)
    if stale:
        for item in stale:
            print(f'Stale or missing unified catalog: {item}', file=sys.stderr)
        return 1
    locales_list = ', '.join(sorted(unified.keys()))
    sample = next(iter(unified.values()))
    print(f'Unified locales verified ({locales_list}): '
          f"{len(sample['cli'])} cli + {len(sample['gui'])} gui messages.")
    return 0


if __name__ == '__main__':
    sys.exit(main())
