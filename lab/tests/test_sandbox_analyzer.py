"""ASTER Sandbox Analyzer safety and report tests (never run an APK)."""
import importlib.util
import pathlib
import tempfile
import unittest
from unittest.mock import MagicMock

SRC = pathlib.Path(__file__).resolve().parents[1] / "sandbox_analyzer.py"
spec = importlib.util.spec_from_file_location("sandbox_analyzer", SRC)
sandbox = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sandbox)


class SnapshotTests(unittest.TestCase):
    def test_package_name_rejects_shell_metacharacters(self):
        for bad in ("x;rm -rf /", "a.b$(id)", "a.b\nwhoami", "../foo", "onlyone", ""):
            with self.assertRaises(ValueError):
                sandbox.safe_package(bad)
        self.assertEqual("com.example.app", sandbox.safe_package("com.example.app"))

    def test_file_metadata_bounded_and_validated(self):
        lines = [
            "/data/user/0/com.test/a.xml|42|1000",
            "/data/user_de/0/com.test/b.db|900|2500",
            "/etc/passwd|44|1000",
            "/data/user/0/com.test/notnumber|oops|1000",
            "/data/user/0/com.test/weird|44|-4",
        ]
        parsed = sandbox.file_metadata("\n".join(lines))
        self.assertEqual(2, len(parsed))
        self.assertEqual(42, parsed["/data/user/0/com.test/a.xml"]["size"])
        self.assertNotIn("/etc/passwd", parsed)

    def test_snapshot_is_scoped_to_selected_guest_app_and_fixed_keys(self):
        class FakeLab:
            def __init__(self):
                self.calls = []
                self.root_calls = 0
            def root_required(self):
                self.root_calls += 1
            def adb(self, *args, **kwargs):
                self.calls.append(args)
                if args[-4:] == ("pm", "list", "packages", "-3"):
                    return "package:com.example.test\npackage:com.example.other\n"
                if "stat -c" in " ".join(args):
                    return "/data/user/0/com.example.test/settings.xml|33|1700\n"
                if args[:4] == ("shell", "ps", "-A", "-o"):
                    return "PID NAME\n52 com.example.test\n99 system_server"
                if args[:3] == ("shell", "sh", "-c") and len(args) == 4:
                    return "com.example.test\ncom.example.other\n"
                return "0"
        fake = FakeLab()
        result = sandbox.snapshot(fake, "com.example.test")
        self.assertEqual(1, fake.root_calls)
        self.assertIn("com.example.test", result["third_party_packages"])
        self.assertEqual(["com.example.other", "com.example.test"],
                         result["app_data_root_names"])
        self.assertTrue(result["coverage"]["root_guest"])
        self.assertFalse(result["coverage"]["kernel_syscall_trace"])
        # Guest only, no arbitrary user-provided commands.
        assert any(call[-2:] == ("_", "com.example.test") for call in fake.calls)

    def test_diff_reports_add_update_remove_and_settings(self):
        pre = {
            "third_party_packages": ["com.old"],
            "app_data_root_names": ["com.old"],
            "target_files": {
                "/data/user/0/com.sample/keep": {"size":1, "mtime":1},
                "/data/user/0/com.sample/removed": {"size":1, "mtime":1},
            },
            "settings_sha256": {"global/airplane_mode_on": "a"},
            "network_table_sha256": {"tcp": "a"},
            "appops": "CAMERA allow",
            "package_permission_lines": ["CAMERA: granted=true"],
            "system": {"process_names": ["system_server"]},
        }
        post = {
            **pre,
            "third_party_packages": ["com.old", "com.sample"],
            "app_data_root_names": ["com.old", "com.sample"],
            "target_files": {
                "/data/user/0/com.sample/keep": {"size":99, "mtime":2},
                "/data/user/0/com.sample/new": {"size":8, "mtime":2},
            },
            "settings_sha256": {"global/airplane_mode_on": "b"},
            "network_table_sha256": {"tcp": "b"},
            "appops": "CAMERA ignore",
            "package_permission_lines": ["CAMERA: granted=false"],
            "system": {"process_names": ["system_server", "com.sample"]},
        }
        result = sandbox.diff(pre, post)
        self.assertEqual(["com.sample"], result["installed_packages"])
        self.assertEqual(["com.sample"], result["created_app_data_roots"])
        self.assertEqual(1, len(result["target_files_created"]))
        self.assertEqual(1, len(result["target_files_modified"]))
        self.assertEqual(1, len(result["target_files_removed"]))
        self.assertEqual(["tcp"], result["network_tables_changed"])
        self.assertTrue(result["appops_changed"])
        self.assertTrue(result["permission_state_changed"])

    def test_html_is_offline_and_escapes_untrusted_report_data(self):
        report = {
            "session_id": "test",
            "package": "<script>alert(1)</script>",
            "status": "completed",
            "timeline": [{"detail": "<img src='https://evil.com'>"}],
        }
        rendered = sandbox.report_html(report).decode("utf-8")
        self.assertIn("&lt;script&gt;", rendered)
        self.assertNotIn("<script>alert(1)</script>", rendered)
        self.assertIn("default-src 'none'", rendered)
        self.assertNotIn("<img src='https://evil.com'>", rendered)
        self.assertIn("ASTER Sandbox Analyzer", rendered)

    def test_summary_explicitly_states_incomplete_observation(self):
        report = {
            "session_id": "e1", "status": "completed",
            "comparison": {"target_files_created": ["a", "b"], "settings_changed": ["x"]},
            "timeline": [1, 2, 3], "restore": {"verified": False},
        }
        result = sandbox.summary(report)
        self.assertEqual(2, result["created_files"])
        self.assertFalse(result["restored"])
        self.assertIn("Not all actions", result["coverage_warning"])

    def test_network_endpoints_decode_guest_table_without_app_attribution(self):
        sample = (
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
            "   0: 0100007F:1F90 08080808:01BB 01 00000000:00000000 00:00000000 00000000  0 0 0\n"
            "   1: 0100007F:0000 00000000:0000 0A 00000000:00000000 00:00000000 00000000  0 0 0\n"
        )
        connections=sandbox.parse_remote_endpoints(sample,"tcp")
        self.assertEqual(["tcp://8.8.8.8:443"], connections)
        self.assertEqual([], sandbox.parse_remote_endpoints(sample,"not-a-table"))

    def test_duration_allowlist_and_bounds(self):
        self.assertEqual((15, 30, 60, 120), sandbox.ALLOWED_SECONDS)
        self.assertLessEqual(sandbox.MAX_FILES, 500)
        self.assertLessEqual(sandbox.MAX_EVENTS, 2500)


if __name__ == "__main__":
    unittest.main()
