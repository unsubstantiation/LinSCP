#!/usr/bin/env python3
"""Print a compiler log as chunked annotations (CI logs are unreadable)."""
import sys
from pathlib import Path

lines = Path(sys.argv[1]).read_text(errors='replace').splitlines()
start = 0
for index, line in enumerate(lines):
    if 'error[' in line or line.startswith('error'):
        start = max(0, index - 5)
        break
blob = '\n'.join(lines[start:])
for offset in range(0, min(len(blob), 60000), 2500):
    chunk = blob[offset:offset + 2500]
    chunk = chunk.replace('%', '%25').replace('\r', '%0D').replace('\n', '%0A')
    print('::error title=probe ({0})::{1}'.format(offset // 2500 + 1, chunk))
