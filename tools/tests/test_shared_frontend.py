"""Regressions for the shared-page endpoint check."""
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import check_shared_frontend as check


class SharedFrontendTests(unittest.TestCase):
    def test_real_page_is_fully_served(self):
        self.assertEqual(check.main(), 0)

    def test_a_page_endpoint_without_a_route_is_reported(self):
        page = "const a = '/api/status'; const b = `/api/not/real`;"
        service = '("GET", "/api/status") => self.handle_status(),'
        self.assertEqual(check.unrouted(page, service), ['/api/not/real'])

    def test_a_route_with_a_query_string_still_matches(self):
        page = "apiGet('/api/terminal/output?terminal=' + id)"
        service = '("GET", "/api/terminal/output") => self.read(),'
        self.assertEqual(check.unrouted(page, service), [])

    def test_an_endpoint_built_from_a_prefix_is_not_reported(self):
        page = "const p = '/api/local/' + action;"
        service = '("POST", "/api/local/list") => self.list(),'
        self.assertEqual(check.unrouted(page, service), ['/api/local/'])


if __name__ == '__main__':
    unittest.main()
