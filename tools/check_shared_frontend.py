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
ROUTE = re.compile(r'\("(GET|POST)",\s*"(/api/[^"]+)"\)')
PAGE_CALL = re.compile(r"""\bapi(Get|Post)\s*\(\s*['"`](/api/[a-zA-Z0-9/_.-]+)""")


def page_endpoints(page_text):
    """The endpoints the page names, without query strings."""
    return sorted({match.group(1) for match in PAGE_ENDPOINT.finditer(page_text)})


def routed_endpoints(service_text):
    return {match.group(2) for match in ROUTE.finditer(service_text)}


def unrouted(page_text, service_text):
    """Endpoints the page calls that no route answers, in a stable order."""
    return sorted(set(page_endpoints(page_text)) - routed_endpoints(service_text))


def unrouted_methods(page_text, service_text):
    """Check literal apiGet/apiPost calls against method/path pairs.

    Dynamic paths and non-helper calls still require integration tests.
    """
    calls = {(match.group(1).upper(), match.group(2)) for match in PAGE_CALL.finditer(page_text)}
    routes = {(match.group(1), match.group(2)) for match in ROUTE.finditer(service_text)}
    return sorted(calls - routes)


def main():
    page = PAGE.read_text(encoding='utf-8')
    service = SERVICE.read_text(encoding='utf-8')
    problems = unrouted(page, service)
    method_problems = unrouted_methods(page, service)
    if problems or method_problems:
        for method, path in method_problems:
            print(f'{PAGE.relative_to(ROOT)}: no route for {method} {path}')
        for path in problems:
            print(f'{PAGE.relative_to(ROOT)}: no route for {path}')
        print(f'{len(problems)} endpoint(s) and {len(method_problems)} method/path pair(s) are not served.')
        return 1
    print('All literal page endpoints and apiGet/apiPost method pairs have routes; dynamic calls and behavior require integration tests.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
