#!/usr/bin/env python3
"""Check cross-platform repository hygiene and architectural boundaries.

During and after the Rust + Tauri v2 + TypeScript migration, LinSCP targets
Linux, Windows, and Android from one shared codebase while preserving strict
isolation of OS-specific code and dual-mode UI transport calls:

  1. Upstream product-name allowlist across the entire repository.
  2. Obsolete historical artefacts stay absent.
  3. OS-specific Rust cfg gates and platform crates (windows-sys, jni, nix,
     libc, #[cfg(windows)], #[cfg(target_os = ...)], etc.) are allowed ONLY
     in crates/linscp-platform/ and crates/linscp-tauri/.
  4. Direct network/IPC primitives (fetch(...) and __TAURI_INTERNALS__) in
     ui/src/ are allowed ONLY inside ui/src/transport/, keeping every UI
     component compatible with both Tauri native apps and browser HTTP mode.

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
            cleaned = strip_code_comments(rs_path.read_text(encoding='utf-8'))
            for rule_name, regex, desc in (
                ('crate-os-cfg', RUST_OS_CFG,
                 f'OS-specific #[cfg] in {crate_name}; isolate OS branches in linscp-platform'),
                ('crate-os-import', RUST_OS_USE,
                 f'OS-specific crate import in {crate_name}; isolate OS bindings in linscp-platform'),
            ):
                for match in regex.finditer(cleaned):
                    line = cleaned.count('\n', 0, match.start()) + 1
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
