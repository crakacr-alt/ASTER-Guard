"""Pure unit tests for controller guards. Do not launch ADB or execute any APK."""
import importlib.util
import pathlib
import tempfile
import unittest
from unittest import mock

SRC=pathlib.Path(__file__).resolve().parents[1]/"aster_lab_bridge.py"
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

    def test_guest_serial_cannot_select_physical_phone_or_remote_adb(self):
        with tempfile.TemporaryDirectory() as tmp:
            for bad in ["R58T000000","192.168.0.4:5555","emulator-5554;id"]:
                with self.assertRaises(ValueError):
                    bridge.Lab(bad,pathlib.Path(tmp))

if __name__=="__main__":
    unittest.main()
