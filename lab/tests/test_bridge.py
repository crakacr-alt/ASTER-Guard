"""Pure unit tests for controller guards. Do not launch ADB or execute any APK."""
import importlib.util
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

SRC=pathlib.Path(__file__).resolve().parents[1]/"aster_lab_bridge.py"
sys.path.insert(0,str(SRC.parent))
spec=importlib.util.spec_from_file_location("aster_lab_bridge",SRC)
bridge=importlib.util.module_from_spec(spec)
spec.loader.exec_module(bridge)

class BridgeValidation(unittest.TestCase):
    def test_package_sanitizer(self):
        for bad in ["com.example;id","com.example $(whoami)","../etc/passwd",
                    "foo.bar\nid","","singleword","com.example /"]:
            with self.assertRaises(ValueError):
                bridge.clean_package(bad)
        self.assertEqual("com.example.sample",bridge.clean_package("com.example.sample"))

    def test_java_class_sanitizer(self):
        for bad in ["com.Foo;system","com.Foo:12","../Foo","foo $(whoami)"]:
            with self.assertRaises(ValueError):
                bridge.clean_class(bad)
        self.assertEqual("com.example.Test",bridge.clean_class("com.example.Test"))

    def test_idle_pidof_error_is_handled(self):
        with tempfile.TemporaryDirectory() as tmp:
            lab=bridge.Lab("emulator-5554",pathlib.Path(tmp))
            with mock.patch.object(lab,"adb",side_effect=RuntimeError("no process")):
                self.assertIsNone(lab.pid("com.example.demo"))

    def test_root_check_requires_guest_uid_zero(self):
        with tempfile.TemporaryDirectory() as tmp:
            lab=bridge.Lab("emulator-5554",pathlib.Path(tmp))
            with mock.patch.object(lab,"adb",return_value="2000"):
                with self.assertRaises(PermissionError):
                    lab.root_required()

    def test_soft_network_never_claims_hard_isolation(self):
        with tempfile.TemporaryDirectory() as tmp:
            lab=bridge.Lab("emulator-5554",pathlib.Path(tmp))
            with mock.patch.object(lab,"root_required"), \
                 mock.patch.object(lab,"adb",return_value=""):
                result=lab.network(False)
                self.assertEqual("guest_radio_off_unverified",result["network_isolation"])
                self.assertIn("host",result["warning"].lower())

    def test_debugger_commands_are_allowlisted(self):
        with tempfile.TemporaryDirectory() as tmp:
            lab=bridge.Lab("emulator-5554",pathlib.Path(tmp))
            for bad in ["exec","rm -rf /","shell","quit;os.system()"]:
                with self.assertRaises(ValueError):
                    lab.debug_command(bad)

    def test_sensitive_heap_dumps_are_erased_on_expiry(self):
        with tempfile.TemporaryDirectory() as tmp:
            lab=bridge.Lab("emulator-5554",pathlib.Path(tmp))
            target=pathlib.Path(tmp)/"deadbeef.hprof"
            target.write_bytes(b"private memory")
            lab.artifacts["deadbeef"]={"path":str(target),"created":0}
            lab.cleanup_artifacts()
            self.assertFalse(target.exists())
            self.assertNotIn("deadbeef",lab.artifacts)

    def test_sandbox_staging_never_installs_or_executes_apk(self):
        with tempfile.TemporaryDirectory() as tmp:
            lab=bridge.Lab("emulator-5554",pathlib.Path(tmp))
            with mock.patch.object(lab,"adb") as adb:
                result=lab.sandbox_stage(b"PK\x03\x04" + b"dummy test APK")
                self.assertFalse(result["installed"])
                self.assertFalse(result["executed"])
                self.assertIn(result["artifact_id"],lab.artifacts)
                adb.assert_not_called()

    def test_sandbox_execution_blocked_without_verified_host_egress(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.dict(__import__("os").environ,
                                 {"ASTER_LAB_EGRESS_ISOLATED":""}):
                lab=bridge.Lab("emulator-5554",pathlib.Path(tmp))
            staged=lab.sandbox_stage(b"PK\x03\x04" + b"dummy APK")
            with mock.patch.object(lab,"adb") as adb:
                with self.assertRaisesRegex(PermissionError,"host"):
                    lab.sandbox_begin({
                        "artifact_id":staged["artifact_id"],
                        "duration_seconds":15,
                        "acknowledge_lab_risk":True,
                    })
                adb.assert_not_called()
            self.assertEqual("idle",lab.sandbox_status()["status"])

    def test_sandbox_rejects_unbounded_duration_and_wrong_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            lab=bridge.Lab("emulator-5554",pathlib.Path(tmp))
            staged=lab.sandbox_stage(b"PK\x03\x04" + b"test APK")
            for duration in (0,10,121,"30",True):
                with self.assertRaises(ValueError):
                    lab.sandbox_begin({
                        "artifact_id":staged["artifact_id"],
                        "duration_seconds":duration,
                        "acknowledge_lab_risk":True,
                    })
            with self.assertRaises(ValueError):
                lab.sandbox_begin({
                    "artifact_id":"../../danger",
                    "duration_seconds":30,
                    "acknowledge_lab_risk":True,
                })

    def test_guest_serial_cannot_select_physical_phone_or_remote_adb(self):
        with tempfile.TemporaryDirectory() as tmp:
            for bad in ["R58T000000","192.168.0.4:5555","emulator-5554;id"]:
                with self.assertRaises(ValueError):
                    bridge.Lab(bad,pathlib.Path(tmp))

if __name__=="__main__":
    unittest.main()
