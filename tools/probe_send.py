#!/usr/bin/env python3
"""Print the compiler's explanation for a trait-bound failure as annotations."""
import re
import sys
from pathlib import Path

text = Path(sys.argv[1]).read_text(errors='replace').splitlines()
wanted = []
for index, line in enumerate(text):
    if 'error[E0277]' in line or 'note:' in line or '= help' in line or '= note' in line:
        wanted.append(line)
blob = '\n'.join(wanted)
for start in range(0, min(len(blob), 30000), 2500):
    chunk = blob[start:start + 2500]
    chunk = chunk.replace('%', '%25').replace('\r', '%0D').replace('\n', '%0A')
    print('::error title=probe ({0})::{1}'.format(start // 2500 + 1, chunk))
