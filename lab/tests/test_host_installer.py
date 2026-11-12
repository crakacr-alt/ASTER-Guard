"""Safe static checks: the host installer is not executed in CI."""
import pathlib
import re
import subprocess
import unittest

ROOT=pathlib.Path(__file__).resolve().parents[2]
SCRIPTS=[
    "lab/auto_setup_server.sh","lab/host_start_guest.sh",
    "lab/setup.sh","lab/start_guest.sh"
]

class HostInstallerTest(unittest.TestCase):
    def test_bash_syntax(self):
        for rel in SCRIPTS:
            with self.subTest(script=rel):
                result=subprocess.run(["bash","-n",str(ROOT/rel)],
                    capture_output=True,text=True)
                self.assertEqual(0,result.returncode,result.stderr)

    def test_help_without_root_or_installation(self):
        result=subprocess.run(
            ["bash",str(ROOT/"lab/auto_setup_server.sh"),"--help"],
            capture_output=True,text=True,timeout=5)
        self.assertEqual(0,result.returncode,result.stderr)
        self.assertIn("--bind",result.stdout)
        self.assertIn("--api",result.stdout)

    def test_pinned_sdk_not_unverified_download(self):
        raw=(ROOT/"lab/auto_setup_server.sh").read_text()
        self.assertIn("dl.google.com/android/repository/",raw)
        self.assertRegex(raw,r"[a-f0-9]{64}")
        self.assertIn("sha256sum -c --status",raw)

    def test_rootless_bridge_and_private_by_default(self):
        raw=(ROOT/"lab/auto_setup_server.sh").read_text()
        self.assertIn("BIND=127.0.0.1",raw)
        self.assertIn("User=asterlab",raw)
        self.assertIn("IPAddressDeny=any",raw)
        self.assertIn("IPAddressAllow=localhost",raw)

    def test_no_automatic_network_isolation_attestation(self):
        raw=(ROOT/"lab/auto_setup_server.sh").read_text()
        self.assertNotIn("Environment=ASTER_LAB_EGRESS_ISOLATED=",raw)
        self.assertNotIn("export ASTER_LAB_EGRESS_ISOLATED=",raw)
        self.assertIn("does NOT assert malware network isolation",raw)

if __name__=="__main__":unittest.main()
