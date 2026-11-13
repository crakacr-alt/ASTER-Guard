"""Integration-style in-memory sandbox orchestration tests — NO emulator or malware."""
import importlib.util
import json
import pathlib
import sys
import tempfile
import threading
import unittest
from unittest import mock

HERE=pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(HERE))
import sandbox_analyzer
from test_bridge import bridge


def fake_snapshot(phase):
    pkgs=[] if phase==0 else ["com.example.test"]
    files={} if phase==0 else {
        "/data/user/0/com.example.test/shared_prefs/config.xml": {"size":24 if phase==1 else 31,"mtime":100 if phase==1 else 101}
    }
    return {
        "third_party_packages":pkgs,
        "app_data_root_names":pkgs,
        "target_files":files,
        "settings_sha256":{"global/airplane_mode_on":"a" if phase<2 else "b"},
        "network_table_sha256":{"tcp":"same" if phase<2 else "changed"},
        "network_guest_endpoints":[],
        "appops":"CAMERA allow",
        "package_permission_lines":[],
        "system":{"process_names":["system_server"]},
        "coverage":{"warnings":[]}
    }


class SandboxOrchestrationTests(unittest.TestCase):
    def lab_setup(self, directory):
        lab=bridge.Lab("emulator-5554",pathlib.Path(directory))
        lab.host_egress_attested=True
        session="a"*32
        lab.sandbox={"session_id":session,"status":"running","timeline":[]}
        apk=pathlib.Path(directory)/"fake-test.apk"
        apk.write_bytes(b"PK\x03\x04mock")
        return lab,session,str(apk)

    def test_success_writes_reports_and_verifies_restore(self):
        with tempfile.TemporaryDirectory() as temp:
            lab,session,apk=self.lab_setup(temp)
            calls=[]
            package_calls=iter([["com.example.test"],[]])
            def adb(*args,**kwargs):
                calls.append(args)
                if args[:4]==("emu","avd","snapshot","list"):
                    return "aster_"+session[:18]
                if args[:1]==("install",):
                    return "Success"
                return "OK"
            with mock.patch.object(lab,"root_required"), \
                 mock.patch.object(lab,"adb",side_effect=adb), \
                 mock.patch.object(lab,"packages",side_effect=lambda:next(package_calls)), \
                 mock.patch.object(lab,"pid",return_value=123), \
                 mock.patch.object(sandbox_analyzer,"snapshot",
                    side_effect=[fake_snapshot(0),fake_snapshot(1),fake_snapshot(2)]):
                lab._sandbox_execute(session,apk,"f"*64,0,threading.Event(),
                    {"schema":"aster-static-v1","sha256":"f"*64,"dex_files":2,
                     "sdk_references":{"Firebase Analytics":2},
                     "warning":"Static code only; not runtime evidence"})
            result=lab.sandbox_status()
            self.assertEqual("completed",result["status"])
            self.assertTrue(result["summary"]["restored"])
            self.assertEqual(1,result["summary"]["changed_files"])
            self.assertTrue(result["report_html_artifact"])
            self.assertTrue(result["report_json_artifact"])
            for kind in ("report_html_artifact","report_json_artifact"):
                artifact=lab.artifacts[result[kind]]
                self.assertTrue(pathlib.Path(artifact["path"]).is_file())
            evidence=json.loads(pathlib.Path(
                lab.artifacts[result["report_json_artifact"]]["path"]).read_text())
            self.assertTrue(evidence["restore"]["verified"])
            self.assertEqual(2,evidence["static_analysis"]["dex_files"])
            self.assertEqual(2,evidence["static_analysis"]["sdk_references"]["Firebase Analytics"])
            self.assertEqual(["com.example.test"],
                             evidence["install_delta"]["installed_packages"])
            self.assertIn(("emu","avd","snapshot","load","aster_"+session[:18]),calls)
            self.assertLess(calls.index(("emu","avd","snapshot","save","aster_"+session[:18])),
                            calls.index(("install",apk)))

    def test_missing_clean_checkpoint_prevents_apk_install(self):
        with tempfile.TemporaryDirectory() as temp:
            lab,session,apk=self.lab_setup(temp)
            calls=[]
            def adb(*args,**kwargs):
                calls.append(args)
                if args[:4]==("emu","avd","snapshot","list"):
                    return "no snapshots saved"
                return "OK"
            with mock.patch.object(lab,"root_required"), \
                 mock.patch.object(lab,"adb",side_effect=adb):
                lab._sandbox_execute(session,apk,"a"*64,0,threading.Event())
            result=lab.sandbox_status()
            self.assertEqual("failed",result["status"])
            self.assertFalse(result["summary"]["restored"])
            self.assertFalse(any(call[0]=="install" for call in calls))

    def test_cancellation_still_restores_clean_snapshot(self):
        with tempfile.TemporaryDirectory() as temp:
            lab,session,apk=self.lab_setup(temp)
            calls=[]
            cancel=threading.Event();cancel.set()
            def adb(*args,**kwargs):
                calls.append(args)
                if args[:4]==("emu","avd","snapshot","list"):
                    return "aster_"+session[:18]
                return "OK"
            with mock.patch.object(lab,"root_required"), \
                 mock.patch.object(lab,"adb",side_effect=adb), \
                 mock.patch.object(lab,"packages",return_value=[]):
                lab._sandbox_execute(session,apk,"a"*64,0,cancel)
            result=lab.sandbox_status()
            self.assertEqual("cancelled",result["status"])
            self.assertTrue(result["summary"]["restored"])
            self.assertFalse(any(call[0]=="install" for call in calls))


if __name__=="__main__":
    unittest.main()
