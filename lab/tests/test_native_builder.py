"""Unit tests for constrained NDK source compilation, without invoking compilers."""
import base64
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

SRC=Path(__file__).resolve().parents[1]/"native_builder.py"
spec=importlib.util.spec_from_file_location("aster_native_builder", SRC)
builder=importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


def sample(abi="arm64-v8a"):
    return {
        "language":"cpp",
        "abis":[abi],
        "api":24,
        "library":"libexample.so",
        "source_b64":base64.b64encode(b'extern "C" int answer(){return 42;}\n').decode(),
    }


def mock_so(abi):
    arch=builder.ABI_TARGETS[abi]
    b=bytearray(128)
    b[:4]=b"\x7fELF"
    b[4]=arch[1]
    b[5]=1
    b[16:18]=(3).to_bytes(2,"little")
    b[18:20]=arch[2].to_bytes(2,"little")
    return bytes(b)


class NativeBuilderTests(unittest.TestCase):
    def test_utf8_source_abi_api_and_name_validation(self):
        code,language,abis,api,name=builder.check_request(sample())
        self.assertIn(b"answer",code)
        self.assertEqual("cpp",language)
        self.assertEqual(["arm64-v8a"],abis)
        self.assertEqual(24,api)
        self.assertEqual("libexample.so",name)

    def test_invalid_api_and_abi_rejected(self):
        for value in (23,36,"35",True,None):
            data=sample();data["api"]=value
            with self.assertRaises(ValueError):builder.check_request(data)
        for val in (["arm64-v8a","arm64-v8a"],["amd64"],[],["x86","../../foo"]):
            data=sample();data["abis"]=val
            with self.assertRaises(ValueError):builder.check_request(data)

    def test_no_shell_flags_or_path_traversal_in_library(self):
        for value in ("-shared", "../libbad.so","libfoo.so;id","libaaa space.so", "foo.so"):
            data=sample();data["library"]=value
            with self.assertRaises(ValueError):builder.check_request(data)

    def test_rejects_bad_payloads_and_source_limits(self):
        data=sample();data["source_b64"]="^^^"
        with self.assertRaises(ValueError):builder.check_request(data)
        data=sample();data["source_b64"]=base64.b64encode(b"x"*65537).decode()
        with self.assertRaises(ValueError):builder.check_request(data)
        data=sample();data["source_b64"]=base64.b64encode(b"abc\x00def").decode()
        with self.assertRaises(ValueError):builder.check_request(data)

    def test_elf_machine_bits_must_match_actual_target(self):
        for abi in builder.ABI_TARGETS:
            elf=builder.check_elf(mock_so(abi),abi)
            self.assertIn(elf["elf_bits"],(32,64))
        with self.assertRaises(ValueError):
            builder.check_elf(mock_so("armeabi-v7a"),"arm64-v8a")
        with self.assertRaises(ValueError):
            builder.check_elf(bytes(128),"x86_64")

    def test_fixed_command_has_offline_sandbox_and_no_shell(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            toolchain=root/"toolchains/llvm/prebuilt/linux-x86_64/bin"
            toolchain.mkdir(parents=True)
            for name in ("clang","clang++"):
                (toolchain/name).touch()
            with mock.patch.object(builder.shutil,"which",return_value="/usr/bin/bwrap"):
                argv=builder.sandbox_command(root,root,"arm64-v8a",24,
                                             "cpp","libtest.so")
            self.assertIn("--unshare-all",argv)
            self.assertIn("--ro-bind",argv)
            self.assertIn("--target=aarch64-linux-android24",argv)
            self.assertIn("-Wl,-z,max-page-size=16384",argv)
            self.assertNotIn("sh",argv)
            self.assertEqual("/usr/bin/bwrap",argv[0])

    def test_no_unsandboxed_build_fallback(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            for name in ("clang","clang++"):
                p=root/"toolchains/llvm/prebuilt/linux-x86_64/bin"/name
                p.parent.mkdir(parents=True,exist_ok=True);p.touch()
            with mock.patch.object(builder.shutil,"which",return_value=None):
                with self.assertRaisesRegex(RuntimeError,"bwrap"):
                    builder.sandbox_command(root,root,"x86",24,"c","libfoo.so")

    def test_compilation_reports_sha_machine_and_private_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            artifacts=root/"results"
            source=sample()
            source["abis"]=["armeabi-v7a","arm64-v8a"]
            built=[]
            def fake_cmd(ndk,work,abi,api,lang,name):
                (work/name).write_bytes(mock_so(abi))
                built.append(abi)
                return ["/usr/bin/bwrap","--","test"]
            with mock.patch.object(builder,"ndk_status",return_value={
                "ndk_configured":True,"bubblewrap_available":True,
                "prlimit_available":True}), \
                 mock.patch.object(builder.shutil,"which",return_value="/usr/bin/prlimit"), \
                 mock.patch.object(builder,"sandbox_command",side_effect=fake_cmd), \
                 mock.patch.object(builder.subprocess,"run",
                    side_effect=lambda command,**kwargs: subprocess.CompletedProcess(command,0)):
                result=builder.build_native(source,artifacts,str(root))
            self.assertEqual([],result["failures"])
            self.assertEqual(["armeabi-v7a","arm64-v8a"],built)
            self.assertEqual(2,len(result["outputs"]))
            for output in result["outputs"]:
                self.assertEqual(64,len(output["sha256"]))
                self.assertEqual(128,output["bytes"])
                self.assertTrue(Path(output["host_path"]).is_file())

    def test_host_compiler_is_never_used_without_sandbox(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(builder,"ndk_status",return_value={
                "ndk_configured":True,"bubblewrap_available":False}):
                with self.assertRaisesRegex(RuntimeError,"bubblewrap"):
                    builder.build_native(sample(),Path(tmp),tmp)


if __name__=="__main__":
    unittest.main()
