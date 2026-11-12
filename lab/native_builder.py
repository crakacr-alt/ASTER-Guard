"""ASTER NDK source-to-.so builder on an *external dedicated Linux lab host*.

Builds ONLY one bounded user-selected C/C++ translation unit per request with
Android NDK Clang and fixed flags. Requires bubblewrap user-namespace sandbox
with no network, separate mount namespace, private workdir, time/resource limits.
Never executes generated .so. No arbitrary Make/CMake/scripts/flags. Compiler
compromise risk remains; do not use a personal host for hostile C/C++ inputs.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import os
from pathlib import Path
import re
import resource
import shutil
import subprocess
import tempfile
import time
import uuid

MAX_SOURCE = 64 * 1024
MAX_OUTPUT = 24 * 1024 * 1024
MAX_LOG = 24000
MAX_REQUEST = 150000
ABI_TARGETS = {
    "armeabi-v7a": ("armv7a-linux-androideabi", 1, 40),
    "arm64-v8a": ("aarch64-linux-android", 2, 183),
    "x86": ("i686-linux-android", 1, 3),
    "x86_64": ("x86_64-linux-android", 2, 62),
}
LIB_NAME = re.compile(r"^lib[A-Za-z0-9_]{1,48}\.so$")


def check_request(data: dict) -> tuple[bytes, str, list[str], int, str]:
    if not isinstance(data, dict):
        raise ValueError("Expected JSON object")
    if data.get("language") not in ("c", "cpp"):
        raise ValueError("Choose c or cpp")
    lang = data["language"]
    abi = data.get("abis")
    if not isinstance(abi, list) or not (1 <= len(abi) <= 4):
        raise ValueError("Choose 1–4 target ABIs")
    if any(not isinstance(x, str) or x not in ABI_TARGETS for x in abi) or len(set(abi)) != len(abi):
        raise ValueError("Invalid or repeated ABI")
    api = data.get("api")
    if type(api) is not int or api < 24 or api > 35:
        raise ValueError("Choose Android API 24–35")
    library = data.get("library")
    if not isinstance(library, str) or not LIB_NAME.fullmatch(library):
        raise ValueError("Library name must look like libexample.so")
    encoded = data.get("source_b64")
    if not isinstance(encoded, str) or not encoded or len(encoded) > 88000:
        raise ValueError("C/C++ source missing or exceeds 64 KiB")
    try:
        source = base64.b64decode(encoded, validate=True)
        source.decode("utf-8")
    except (binascii.Error, UnicodeError) as exc:
        raise ValueError("Source must be UTF-8 base64") from exc
    if not source or len(source) > MAX_SOURCE or b"\x00" in source:
        raise ValueError("Source empty, contains NUL, or exceeds 64 KiB")
    return source, lang, abi, api, library


def check_elf(data: bytes, abi: str) -> dict:
    if len(data) < 64 or data[:4] != b"\x7fELF" or data[5] != 1:
        raise ValueError("Compiler output is not a valid little-endian ELF file")
    expected_class, machine = ABI_TARGETS[abi][1:]
    if data[4] != expected_class or int.from_bytes(data[18:20], "little") != machine:
        raise ValueError("ELF machine class does not match requested ABI")
    if int.from_bytes(data[16:18], "little") != 3:
        raise ValueError("ELF is not a shared library (ET_DYN)")
    return {"elf_bits": 32 if data[4] == 1 else 64, "elf_machine": machine}


def ndk_status(ndk_home: str) -> dict:
    root = Path(ndk_home).expanduser()
    toolchain = root / "toolchains/llvm/prebuilt/linux-x86_64/bin"
    return {
        "ndk_configured": (toolchain/"clang").is_file() and (toolchain/"clang++").is_file(),
        "bubblewrap_available": shutil.which("bwrap") is not None,
        "supported_abis": list(ABI_TARGETS),
        "api_min": 24, "api_max": 35,
        "note": "No compiler execution unless NDK and bwrap are configured. "
                "Build runs in a no-network bubblewrap namespace; no arbitrary build scripts.",
    }


def sandbox_command(ndk_root: Path, work: Path, abi: str,
                    api: int, lang: str, library: str) -> list[str]:
    """Generate fixed argv; never run shell or user-supplied build scripts."""
    target = ABI_TARGETS[abi][0] + str(api)
    compiler = "/ndk/toolchains/llvm/prebuilt/linux-x86_64/bin/" + (
        "clang++" if lang == "cpp" else "clang"
    )
    sysroot = "/ndk/toolchains/llvm/prebuilt/linux-x86_64/sysroot"
    bwrap = shutil.which("bwrap")
    if not bwrap:
        raise RuntimeError("bubblewrap (bwrap) required; no unsandboxed fallback")
    for item in ("clang", "clang++"):
        if not (ndk_root/"toolchains/llvm/prebuilt/linux-x86_64/bin"/item).is_file():
            raise RuntimeError("Android NDK clang/clang++ missing")
    argv = [
        bwrap, "--unshare-all", "--die-with-parent", "--new-session",
        "--ro-bind", "/usr", "/usr",
        "--ro-bind", "/lib", "/lib",
    ]
    if Path("/lib64").exists():
        argv.extend(["--ro-bind", "/lib64", "/lib64"])
    argv += [
        "--ro-bind", str(ndk_root.resolve()), "/ndk",
        "--bind", str(work.resolve()), "/work",
        "--proc", "/proc", "--dev", "/dev",
        "--tmpfs", "/tmp", "--chdir", "/work",
        "--clearenv",
        "--setenv", "PATH", "/ndk/toolchains/llvm/prebuilt/linux-x86_64/bin:/usr/bin",
        "--setenv", "HOME", "/work", "--setenv", "TMPDIR", "/tmp",
        "--", compiler,
        "--target=" + target,
        "--sysroot=" + sysroot,
        "-fPIC", "-shared", "-O2", "-fstack-protector-strong",
        "-Wl,-z,relro", "-Wl,-z,now", "-Wl,--no-undefined",
        "-Wl,-z,max-page-size=16384",
        "-Wl,-soname," + library,
        "-o", "/work/" + library,
        "/work/source." + ("cpp" if lang == "cpp" else "c"),
    ]
    return argv


def _limits():
    resource.setrlimit(resource.RLIMIT_CPU, (35, 36))
    resource.setrlimit(resource.RLIMIT_AS, (2 * 1024**3, 2 * 1024**3))
    resource.setrlimit(resource.RLIMIT_FSIZE, (24 * 1024**2, 24 * 1024**2))
    resource.setrlimit(resource.RLIMIT_NOFILE, (128, 128))


def build_native(data: dict, artifacts_dir: Path, ndk_home: str) -> dict:
    source, lang, abis, api, library = check_request(data)
    state = ndk_status(ndk_home)
    if not state["ndk_configured"]:
        raise RuntimeError("Android NDK not installed on lab host; set ANDROID_NDK_HOME")
    if not state["bubblewrap_available"]:
        raise RuntimeError("Install bubblewrap and enable user namespaces; no unsafe fallback")
    root = Path(ndk_home).expanduser().resolve()
    artifacts_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    results: list[dict] = []
    failures: list[dict] = []
    for abi in abis:
        with tempfile.TemporaryDirectory(prefix="aster-ndk-") as scratch:
            work = Path(scratch)
            work.chmod(0o700)
            (work/("source." + ("cpp" if lang == "cpp" else "c"))).write_bytes(source)
            command = sandbox_command(root, work, abi, api, lang, library)
            try:
                with tempfile.TemporaryFile(mode="w+b") as log:
                    proc = subprocess.run(
                        command, stdin=subprocess.DEVNULL, stdout=log,
                        stderr=subprocess.STDOUT, timeout=45, check=False,
                        preexec_fn=_limits,
                    )
                    log.seek(0)
                    diagnostics = log.read(MAX_LOG).decode("utf-8", "replace")
                    if log.read(1):
                        diagnostics += "\n[Build output truncated]"
                built = work / library
                if proc.returncode or not built.is_file():
                    failures.append({
                        "abi": abi, "reason": "clang_failed",
                        "return_code": proc.returncode,
                        "diagnostics": diagnostics[-MAX_LOG:],
                    })
                    continue
                size = built.stat().st_size
                if size < 64 or size > MAX_OUTPUT:
                    failures.append({"abi":abi, "reason":"invalid_output_size",
                                     "bytes":size})
                    continue
                blob = built.read_bytes()
                elf = check_elf(blob, abi)
                digest = hashlib.sha256(blob).hexdigest()
                artifact_id = uuid.uuid4().hex
                dest = artifacts_dir / (artifact_id + ".so")
                dest.write_bytes(blob)
                dest.chmod(0o600)
                results.append({
                    "abi":abi, "api":api, "language":lang,
                    "artifact_id":artifact_id, "name":library,
                    "bytes":len(blob), "sha256":digest,
                    **elf, "host_path":str(dest),
                    "diagnostics":diagnostics[-4000:],
                })
            except subprocess.TimeoutExpired:
                failures.append({"abi":abi, "reason":"compiler_timeout_45s"})
            except (RuntimeError, OSError, ValueError) as exc:
                failures.append({"abi":abi, "reason":type(exc).__name__,
                                 "diagnostics":str(exc)[:1000]})
    return {
        "outputs":results, "failures":failures, "api":api,
        "library":library, "source_sha256":hashlib.sha256(source).hexdigest(),
        "isolation":"bubblewrap: unshare-all, offline network, read-only toolchain",
        "warning":"No APK code is run. Compiler sandbox limits risk but cannot guarantee "
                  "protection against toolchain/kernel exploits. Production-grade build "
                  "isolation requires a disposable dedicated host.",
    }
