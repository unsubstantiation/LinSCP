#!/usr/bin/env python3
"""Validate and regenerate all translation artifacts, or check them read-only.

    python3 tools/update_translations.py
    python3 tools/update_translations.py --check

The source catalogs are source/linux/locales and source/gui/locales. All
outputs are rendered and validated before any file is written.
"""
import argparse
import sys

import build_unified_locales as unified
import compile_translations as translations


def render_all():
    """Prepare both sets of outputs; reject orphan unified locales."""
    outputs = translations.render_outputs()
    catalogs = unified.build_unified_catalogs()
    expected = {unified.UNIFIED_DIR / f'{locale}.json' for locale in catalogs}
    existing = set(unified.UNIFIED_DIR.glob('*.json')) if unified.UNIFIED_DIR.is_dir() else set()
    unexpected = sorted(existing - expected)
    if unexpected:
        raise ValueError('Unexpected unified locale files (remove or add corresponding source catalogs): '
                         + ', '.join(str(path) for path in unexpected))
    outputs.update({unified.UNIFIED_DIR / f'{locale}.json': unified.format_catalog(payload)
                    for locale, payload in catalogs.items()})
    return outputs


def apply_outputs(outputs, check_only=False):
    """Return stale paths in check mode; write rendered outputs otherwise."""
    if check_only:
        return [path for path, text in outputs.items()
                if not path.is_file() or path.read_text(encoding='utf-8') != text]
    for path, text in outputs.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding='utf-8')
    return []


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true', help='verify generated files without writing')
    args = parser.parse_args(argv)
    try:
        stale = apply_outputs(render_all(), check_only=args.check)
    except (ValueError, OSError) as error:
        print(f'Translation validation failed: {error}', file=sys.stderr)
        return 1
    if stale:
        for path in stale:
            try:
                name = path.relative_to(translations.ROOT)
            except ValueError:
                name = path
            print(f'Stale or missing translation output: {name}', file=sys.stderr)
        print('Run python3 tools/update_translations.py', file=sys.stderr)
        return 1
    print('Translation artifacts ' + ('are current.' if args.check else 'regenerated.'))
    return 0


if __name__ == '__main__':
    sys.exit(main())
