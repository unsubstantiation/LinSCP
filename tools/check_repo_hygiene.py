#!/usr/bin/env python3
"""Check cross-platform repository hygiene and architectural boundaries.

During and after the Rust + Tauri v2 + TypeScript migration, LinSCP targets
Linux, Windows, and Android from one shared codebase while preserving strict
isolation of OS-specific code and a single UI transport boundary:

  1. Upstream product-name allowlist across the entire repository.
  2. Obsolete historical artefacts stay absent.
  3. OS-specific Rust cfg gates and platform crates (windows-sys, jni, nix,
     libc, #[cfg(windows)], #[cfg(target_os = ...)], etc.) are allowed ONLY
     in crates/linscp-platform/ and crates/linscp-tauri/.
  4. Direct IPC primitives (__TAURI_INTERNALS__) in ui/src/ are allowed ONLY
     inside ui/src/transport/, so every UI component reaches the backend
     through the one native bridge.

Usage:
    python3 tools/check_repo_hygiene.py
"""
import argparse
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import check_platform_conversion as legacy_check

ROOT = pathlib.Path(__file__).resolve().parents[1]

PLATFORM_ALLOWED_CRATES = {
    'linscp-platform',
    'linscp-tauri',
}

LINE_COMMENT = re.compile(r'//[^\n]*')
BLOCK_COMMENT = re.compile(r'/\*.*?\*/', re.S)
TOML_COMMENT = re.compile(r'(?m)#[^\n]*$')

RUST_OS_CFG = re.compile(
    r'#\s*!\s*\[\s*cfg|\#\s*\[\s*cfg(?:_attr)?\s*\([^]]*\b'
    r'(?:windows|unix|target_os|target_family)\b[^]]*\)\s*\]'
)
RUST_OS_USE = re.compile(
    r'\b(?:use|extern\s+crate)\s+(?:windows_sys|windows|jni|ndk|ndk_context|libc|nix)\b'
)
CARGO_OS_DEP = re.compile(
    r'(?m)^\s*(?:windows-sys|windows|jni|ndk|ndk-context|libc|nix)\s*='
    r'|^\s*\[target\.[^\]]+\.dependencies\]'
)

UI_RAW_TRANSPORT = re.compile(
    r'(?:\bwindow\s*\.\s*fetch\s*\(|\bglobalThis\s*\.\s*fetch\s*\('
    r'|(?<![.\w])fetch\s*\(|\b__TAURI_INTERNALS__\b)'
)


def _blank_lines(match):
    return '\n' * match.group(0).count('\n')


def strip_code_comments(text):
    text = BLOCK_COMMENT.sub(_blank_lines, text)
    return LINE_COMMENT.sub('', text)


def mask_rust_non_code(text):
    """Blank Rust comments and literals without changing offsets or line numbers.

    Counting braces in test modules must ignore format strings, URLs, raw
    strings, character literals, and nested block comments. A regex that strips
    `//` first can consume a closing brace inside a quoted URL.
    """
    out = list(text)
    length = len(text)
    i = 0
    raw_pattern = re.compile(r'(?:br|cr|r)(#{0,255})"')
    char_pattern = re.compile(r"'(?:\\(?:u\{[0-9a-fA-F_]+\}|x[0-9a-fA-F]{2}|.)|[^'\\\n])'")

    def blank(start, end):
        for k in range(start, end):
            if text[k] != '\n':
                out[k] = ' '

    while i < length:
        start = i
        if text.startswith('//', i):
            end = text.find('\n', i)
            i = length if end < 0 else end
        elif text.startswith('/*', i):
            i += 2
            depth = 1
            while i < length and depth:
                if text.startswith('/*', i):
                    depth += 1
                    i += 2
                elif text.startswith('*/', i):
                    depth -= 1
                    i += 2
                else:
                    i += 1
        else:
            raw = raw_pattern.match(text, i) if text[i] in 'bcr' else None
            if raw and (i == 0 or not (text[i - 1].isalnum() or text[i - 1] == '_')):
                terminator = '"' + raw.group(1)
                end = text.find(terminator, raw.end())
                i = length if end < 0 else end + len(terminator)
            elif text[i] == '"':
                i += 1
                while i < length:
                    if text[i] == '\\':
                        i = min(length, i + 2)
                    elif text[i] == '"':
                        i += 1
                        break
                    else:
                        i += 1
            elif text[i] == "'":
                # A lifetime such as 'a is not a character literal.
                char = char_pattern.match(text, i)
                if not char:
                    i += 1
                    continue
                i = char.end()
            else:
                i += 1
                continue
        blank(start, i)
    return ''.join(out)


def _test_module_line_ranges(text):
    """Return line ranges of `#[cfg(test)] mod ...` blocks, excluding literals."""
    stripped = mask_rust_non_code(text)
    ranges = []
    for match in re.finditer(r'#\s*\[\s*cfg\(\s*test\s*\)\s*\]', stripped):
        start = stripped.count('\n', 0, match.start()) + 1
        # Attributes may intervene, but never cross a different Rust item:
        # a cfg(test) function must not exempt the next production module.
        mod = re.compile(r'\s*(?:#\s*\[[^]]*\]\s*)*(?:pub(?:\([^)]*\))?\s+)?mod\s+\w+\s*\{').match(stripped, match.end())
        if not mod:
            continue
        depth = 0
        for index, char in enumerate(stripped[mod.end() - 1:], start=mod.end() - 1):
            if char == '{':
                depth += 1
            elif char == '}':
                depth -= 1
                if depth == 0:
                    end = stripped.count('\n', 0, index) + 1
                    ranges.append((start, end))
                    break
    return ranges


def check_crate_boundaries(root=ROOT):
    """Ensure OS-specific gates and crates live only in platform/host crates."""
    findings = []
    crates_dir = root / 'crates'
    if not crates_dir.is_dir():
        return findings

    for crate_dir in sorted(crates_dir.iterdir()):
        if not crate_dir.is_dir():
            continue
        crate_name = crate_dir.name
        if crate_name in PLATFORM_ALLOWED_CRATES:
            continue

        manifest = crate_dir / 'Cargo.toml'
        if manifest.is_file():
            raw = manifest.read_text(encoding='utf-8')
            cleaned = TOML_COMMENT.sub('', raw)
            for match in CARGO_OS_DEP.finditer(cleaned):
                line = cleaned.count('\n', 0, match.start()) + 1
                findings.append((
                    manifest,
                    line,
                    'crate-os-dependency',
                    f'OS-specific dependency in {crate_name}; move OS bindings to linscp-platform',
                    match.group(0).strip(),
                ))

        src_dir = crate_dir / 'src'
        if not src_dir.is_dir():
            continue
        for rs_path in sorted(src_dir.rglob('*.rs')):
            if any(part in legacy_check.SKIP_DIRECTORIES for part in rs_path.parts):
                continue
            original = rs_path.read_text(encoding='utf-8')
            cleaned = mask_rust_non_code(original)
            test_ranges = _test_module_line_ranges(original)
            for rule_name, regex, desc in (
                ('crate-os-cfg', RUST_OS_CFG,
                 f'OS-specific #[cfg] in {crate_name}; isolate OS branches in linscp-platform'),
                ('crate-os-import', RUST_OS_USE,
                 f'OS-specific crate import in {crate_name}; isolate OS bindings in linscp-platform'),
            ):
                for match in regex.finditer(cleaned):
                    line = cleaned.count('\n', 0, match.start()) + 1
                    if any(start <= line <= end for start, end in test_ranges):
                        continue
                    findings.append((
                        rs_path,
                        line,
                        rule_name,
                        desc,
                        ' '.join(match.group(0).split()),
                    ))
    return findings


def check_ui_transport_boundary(root=ROOT):
    """Ensure ui/src only touches fetch() or __TAURI_INTERNALS__ in transport/."""
    findings = []
    ui_src = root / 'ui' / 'src'
    if not ui_src.is_dir():
        return findings

    for ts_path in sorted(ui_src.rglob('*.ts')):
        rel_parts = ts_path.relative_to(ui_src).parts
        if rel_parts and rel_parts[0] == 'transport':
            continue
        cleaned = strip_code_comments(ts_path.read_text(encoding='utf-8'))
        for match in UI_RAW_TRANSPORT.finditer(cleaned):
            line = cleaned.count('\n', 0, match.start()) + 1
            findings.append((
                ts_path,
                line,
                'ui-raw-transport',
                'direct fetch() or __TAURI_INTERNALS__ outside ui/src/transport/; '
                'route requests through TransportClient',
                match.group(0).strip(),
            ))
    return findings


def collect(root=ROOT):
    findings = []
    findings.extend(legacy_check.check_brand_references(root))
    findings.extend(legacy_check.check_removed_artefacts(root))
    findings.extend(check_crate_boundaries(root))
    findings.extend(check_ui_transport_boundary(root))
    return findings


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    findings = collect()
    if not findings:
        print('Repository hygiene check passed: brand allowlist, crate '
              'platform boundaries, and UI transport boundaries are intact.')
        return 0
    for path, line, name, description, text in findings:
        where = f'{path.relative_to(ROOT)}:{line}' if line else str(path.relative_to(ROOT))
        print(f'{where}: {name}: {description} ({text})')
    print(f'{len(findings)} problem(s) found.')
    return 1


if __name__ == '__main__':
    sys.exit(main())
