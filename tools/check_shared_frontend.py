#!/usr/bin/env python3
"""Every endpoint the shared page calls has to be served by the service.

The browser page, the native Tauri window and the Android app all run
`source/gui/web/index.html` against `linscp-service`. An endpoint the page
calls but the service does not answer is the one parity break a user sees
immediately: a button that fails on every host.

Usage:
    python3 tools/check_shared_frontend.py
"""
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
PAGE = ROOT / 'source/gui/web/index.html'
SERVICE = ROOT / 'crates/linscp-service/src/lib.rs'

PAGE_ENDPOINT = re.compile(r"""['"`](/api/[a-zA-Z0-9/_.-]+)""")
ROUTE = re.compile(r'\("(?:GET|POST)",\s*"(/api/[^"]+)"\)')


def page_endpoints(page_text):
    """The endpoints the page names, without query strings."""
    return sorted({match.group(1) for match in PAGE_ENDPOINT.finditer(page_text)})


def routed_endpoints(service_text):
    return {match.group(1) for match in ROUTE.finditer(service_text)}


def unrouted(page_text, service_text):
    """Endpoints the page calls that no route answers, in a stable order."""
    return sorted(set(page_endpoints(page_text)) - routed_endpoints(service_text))


def main():
    problems = unrouted(PAGE.read_text(encoding='utf-8'),
                        SERVICE.read_text(encoding='utf-8'))
    if problems:
        for path in problems:
            print(f'{PAGE.relative_to(ROOT)}: no route for {path}')
        print(f'{len(problems)} endpoint(s) the shared page calls are not served.')
        return 1
    print('Every endpoint the shared page calls is served by the service.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
