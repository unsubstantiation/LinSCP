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

    def test_method_mismatch_is_reported_even_when_path_exists(self):
        page = "apiGet('/api/import?source=x'); apiPost('/api/import', {});"
        service = '("GET", "/api/import") => self.scan(),'
        self.assertEqual(check.unrouted(page, service), [])
        self.assertEqual(check.unrouted_methods(page, service), [('POST', '/api/import')])

    def test_an_endpoint_built_from_a_prefix_is_not_reported(self):
        page = "const p = '/api/local/' + action;"
        service = '("POST", "/api/local/list") => self.list(),'
        self.assertEqual(check.unrouted(page, service), ['/api/local/'])

    def test_commander_workflow_contracts(self):
        root = pathlib.Path(__file__).resolve().parents[2]
        lib_rs = (root / "crates/linscp-service/src/lib.rs").read_text(encoding="utf-8")
        queue_rs = (root / "crates/linscp-service/src/queue.rs").read_text(encoding="utf-8")
        tabs_rs = (root / "crates/linscp-service/src/tabs.rs").read_text(encoding="utf-8")
        hostkeys_rs = (root / "crates/linscp-engine/src/hostkeys.rs").read_text(encoding="utf-8")
        index_html = (root / "source/gui/web/index.html").read_text(encoding="utf-8")

        self.assertIn('("POST", "/api/local/properties") => self.handle_local_properties(req.body)', lib_rs)
        self.assertIn('("GET", "/api/hostkeys") => self.handle_hostkeys_get()', lib_rs)
        self.assertIn('("POST", "/api/hostkeys") => self.handle_hostkeys_post(req.body)', lib_rs)
        self.assertIn('("POST", "/api/session/url") => self.handle_session_url_post(req.body)', lib_rs)
        self.assertIn('("POST", "/api/remote/save") => self.handle_remote_save(req.body)', lib_rs)
        self.assertIn("fn scan_remote_dir_size(", lib_rs)
        self.assertIn("fn scan_local_dir_size(", lib_rs)
        self.assertIn("fn apply_local_chmod_in_dir(", lib_rs)
        self.assertIn("pub fn filter_excluded_sync_items(", queue_rs)
        self.assertIn("fn parse_sync_transfer_options(", lib_rs)
        self.assertIn("fn parse_s3_byte_size_field(", tabs_rs)
        self.assertIn("pub fn format_session_url_with_options(", tabs_rs)
        self.assertIn("pub fn parsed_spec_to_gui_json(", tabs_rs)
        self.assertIn('obj.insert("has_unreadable_credential".into(), json!(site.summary().has_unreadable_secret));', tabs_rs)
        self.assertNotIn('"has_unreadable_secret"', tabs_rs)
        self.assertIn("pub fn remove(&mut self, host_port: &str, key_type: &str) -> bool", hostkeys_rs)
        self.assertIn("pub fn clear(&mut self)", hostkeys_rs)
        self.assertIn("newFilePrompt('remote')", index_html)
        self.assertIn("openHostKeysManager", index_html)
        self.assertIn("openPasteSessionUrl", index_html)
        for elem_id in (
            "paneCtxCustomCmdBtn",
            "paneCtxNewFileBtn",
            "editorSaveAsBtn",
            "editorReloadBtn",
            "siteS3Protocol",
            "siteS3MultipartThreshold",
            "siteS3MinPartSize",
            "siteS3RequestPayer",
            "siteFtpPasvIp",
            "siteFtpMlsd",
            "siteFtpAccount",
            "siteTlsKey",
            "siteCaCertDir",
            "syncTransferMode",
            "syncSpeed",
            "syncPreserveTime",
            "kudTransferMode",
            "kudSpeed",
            "kudPreserveTime",
            "kudDelete",
            "kudContinueOnError",
            "customCmdDescription",
            "customCmdDirs",
            "hostKeysModal",
            "hostKeyAddHost",
            "hostKeyAddPort",
            "hostKeyAddType",
            "hostKeyAddFingerprint",
            "hostKeysList",
            "pasteSessionUrlInput",
            "loadUrlIntoSiteBtn",
            "connectPastedUrlBtn",
            "bookmarkScopeSelect",
            "prefResumeSupport",
            "prefResumeSize",
            "paneCtxDuplicateBtn",
            "siteRenameBtn",
            "workspaceCloseExisting",
            "syncPermissions",
            "syncPermissionsOctal",
        ):
            self.assertIn(f'id="{elem_id}"', index_html)
        for fn_name in (
            "promptDuplicate",
            "renameSite",
            "renameSiteFolder",
            "renameWorkspace",
            "appendMtimeEditor",
            "applyPropertiesMtime",
        ):
            self.assertIn(f"function {fn_name}(", index_html)

        for route in (
            '"/api/local/touch"',
            '"/api/remote/touch"',
            '"/api/local/copy"',
            '"/api/sessions/rename"',
            '"/api/workspaces/rename"',
        ):
            self.assertIn(route, lib_rs)

        ops_rs = (root / "crates/linscp-service/src/ops.rs").read_text(encoding="utf-8")
        for cleanup_id in ('"presets"', '"sync_state"', '"monitor"', '"auto_reconnect"'):
            self.assertIn(cleanup_id, ops_rs)

    def test_terminal_window_focus_and_key_isolation_contracts(self):
        root = pathlib.Path(__file__).resolve().parents[2]
        tauri_lib = (root / "crates/linscp-tauri/src/lib.rs").read_text(encoding="utf-8")
        term_input = (root / "ui/src/platform/terminal-input.ts").read_text(encoding="utf-8")
        term_session = (root / "ui/src/platform/terminal-session.ts").read_text(encoding="utf-8")
        term_canvas = (root / "ui/src/platform/terminal.ts").read_text(encoding="utf-8")
        index_html = (root / "source/gui/web/index.html").read_text(encoding="utf-8")

        open_fn = tauri_lib.split("pub async fn linscp_open_terminal_window", 1)[1].split("pub async fn ", 1)[0]
        self.assertIn(".focused(true)", open_fn)
        self.assertIn("builder.show()", open_fn)
        self.assertIn("builder.set_focus()", open_fn)
        self.assertIn("existing.show()", open_fn)
        self.assertIn("existing.set_focus()", open_fn)

        self.assertIn("element.className = 'terminal-input';", term_input)
        self.assertIn("this.canvas.tabIndex = -1;", term_canvas)
        self.assertIn("export function isAltGraphKey(", term_session)
        self.assertIn("export function normalizeKeyName(", term_session)
        self.assertIn("function isTerminalCapturingKeys()", index_html)
        self.assertIn("function focusCliInput()", index_html)


if __name__ == '__main__':
    unittest.main()
