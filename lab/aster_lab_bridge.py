#!/usr/bin/env python3
"""ASTER Guard lab bridge for an *external* user-controlled rooted Android Emulator.

This is NOT an emulator inside the phone. Aster's Android UI is the controller.
Root privileges are constrained to the selected guest. Exposing this bridge to
the public Internet is unsafe; pair over a trusted tunnel / private network.

API intentionally has NO arbitrary adb shell, host shell, URL fetch or injection
endpoint. It never executes selected APKs on the host OS.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

PACKAGE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+$")
MAX_JSON = 8192
MAX_UPLOAD = 96 * 1024 * 1024
MAX_ARTIFACT = 128 * 1024 * 1024
EVENT_LIMIT = 400
LOG_LIMIT = 64000
LOCK = threading.RLock()


def clean_package(name: str) -> str:
    if not isinstance(name, str) or not PACKAGE.fullmatch(name) or len(name) > 180:
        raise ValueError("Invalid Android package identifier")
    return name


def clean_class(name: str) -> str:
    if not isinstance(name, str) or not re.fullmatch(
        r"[a-zA-Z_$][a-zA-Z0-9_$]*(?:\.[a-zA-Z_$][a-zA-Z0-9_$]*)+",
        name or "",
    ) or len(name) > 230:
        raise ValueError("Invalid Java class")
    return name


def run(argv: list[str], timeout: int = 12, limit: int = 64000) -> str:
    """No shell=True; bound output, timeout, sanitized fixed command arguments."""
    proc = subprocess.run(argv, capture_output=True, timeout=timeout, check=False)
    result = (proc.stdout + b"\n" + proc.stderr)[:limit].decode("utf-8", "replace")
    if proc.returncode:
        raise RuntimeError(f"Command failed ({proc.returncode}): {result[:2000]}")
    return result.strip()


class Lab:
    def __init__(self, serial: str, artifacts_dir: Path):
        if not re.fullmatch(r"emulator-\d{4,5}", serial):
            raise ValueError("Only explicit local emulator-PORT serials are accepted")
        self.serial = serial
        self.artifacts_dir = artifacts_dir
        self.artifacts_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.artifacts_dir, 0o700)
        self.selected = ""
        self.events: list[dict] = []
        self.artifacts: dict[str, dict] = {}
        self.jdb: subprocess.Popen | None = None
        self.jdb_reader: threading.Thread | None = None
        self.jdb_output: list[str] = []
        self.forward_port: int | None = None
        self.debug_target = ""
        self.ndk_home = os.environ.get("ANDROID_NDK_HOME", "")
        # The operator must verify a real host firewall / isolated namespace.
        # This environmental assertion is NOT a technical isolation proof.
        self.host_egress_attested = (
            os.environ.get("ASTER_LAB_EGRESS_ISOLATED") ==
            "YES_I_VERIFIED_HOST_FIREWALL"
        )
        self.sandbox: dict = {"status": "idle"}
        self.sandbox_cancel = threading.Event()
        self.sandbox_worker: threading.Thread | None = None
        self.net_state = "unverified"  # Never imply a reliable VM network kill switch.
        self.trace_proc: subprocess.Popen | None = None
        self.trace_lines: list[str] = []
        self.trace_package = ""
        self.trace_pid: int | None = None
        self.log("bridge_start", "Guest controller started. Host network isolation UNVERIFIED.")

    def cleanup_artifacts(self, force: bool = False) -> None:
        """Erase expired sensitive HPROF artifacts, including after a bridge restart."""
        now = time.time()
        for artifact_id, meta in list(self.artifacts.items()):
            if force or now - meta["created"] > 45*60:
                Path(meta["path"]).unlink(missing_ok=True)
                del self.artifacts[artifact_id]
        # Orphaned dumps from bridge crash are never presented for retrieval.
        for pattern in ("*.hprof", "*.so", "aster_sandbox_*.apk", "aster_report_*.json", "aster_report_*.html"):
            for path in self.artifacts_dir.glob(pattern):
                try:
                    if force or now - path.stat().st_mtime > 45*60:
                        path.unlink(missing_ok=True)
                except OSError:
                    pass

    def adb(self, *args: str, timeout: int = 12, limit: int = 64000) -> str:
        return run(["adb", "-s", self.serial, *args], timeout=timeout, limit=limit)

    def log(self, action: str, detail: str):
        self.events.append({"time": round(time.time(), 3), "kind": action,
                            "detail": str(detail)[:240]})
        del self.events[:-EVENT_LIMIT]

    def root_required(self):
        uid = self.adb("shell", "id", "-u", timeout=5)
        if uid.strip() != "0":
            raise PermissionError(
                "Guest adbd is not root. Use a rootable AOSP emulator image, "
                "run 'adb root' on the laboratory host, and check 'adb shell id -u'. "
                "Never root the real phone."
            )

    def status(self) -> dict:
        self.root_required()
        android = self.adb("shell", "getprop", "ro.build.version.release", timeout=5)
        arch = self.adb("shell", "getprop", "ro.product.cpu.abi", timeout=5)
        serial = self.adb("get-serialno", timeout=5)
        return {
            "guest": serial, "android": android, "architecture": arch, "root": True,
            "selected_package": self.selected, "pid": self.pid(self.selected) if self.selected else None,
            "network_isolation": self.net_state,
            "network_warning": "Soft Android toggles are NOT a verified host firewall. "
                               "Untrusted malware requires host-verified offline isolation.",
            "sandbox": self.sandbox_status(),
            "host_egress_attested": self.host_egress_attested,
            "debugger_attached": self.jdb is not None and self.jdb.poll() is None,
            "trace_running": self.trace_proc is not None and self.trace_proc.poll() is None,
            "features": ["logcat", "process snapshot", "native backtrace",
                         "JDWP (debuggable apps)", "bounded HPROF heap dump"],
        }

    def packages(self) -> list[str]:
        raw = self.adb("shell", "pm", "list", "packages", "-3", timeout=12)
        result = []
        for line in raw.splitlines():
            if line.startswith("package:"):
                pkg = line[8:].strip()
                if PACKAGE.fullmatch(pkg):
                    result.append(pkg)
        return result[:1200]

    def select(self, name: str) -> dict:
        name = clean_package(name)
        if name not in self.packages():
            raise ValueError("Choose a user-installed package inside the selected emulator")
        if self.selected != name:
            self.trace_stop()
            self.detach_debugger()
        self.selected = name
        self.log("select_package", name)
        return {"selected_package": name, "pid": self.pid(name)}

    def require_selected(self) -> str:
        if not self.selected:
            raise ValueError("Select an installed package first")
        return clean_package(self.selected)

    def pid(self, pkg: str) -> int | None:
        if not pkg:
            return None
        try:
            raw = self.adb("shell", "pidof", pkg, timeout=7)
        except RuntimeError:
            return None
        # pidof can return multiple PIDs. Select base process only when running.
        match = re.search(r"\b\d{1,7}\b", raw)
        return int(match.group(0)) if match else None

    def require_pid(self) -> int:
        pkg = self.require_selected()
        pid = self.pid(pkg)
        if pid is None:
            raise ValueError("Selected app is not running; start it first")
        return pid

    def network(self, allow: bool) -> dict:
        """Best-effort Android guest radio setting ONLY; not a host firewall.

        This does not substitute for an isolated network namespace or external
        egress firewall in malware experiments.
        """
        self.root_required()
        if not isinstance(allow, bool):
            raise ValueError("Expected JSON boolean allow")
        state = "disable" if not allow else "enable"
        responses = []
        # Do not expose general command strings: fixed list, constant args.
        commands = [
            ("shell", "svc", "wifi", state),
            ("shell", "svc", "data", state),
            ("shell", "cmd", "connectivity", "airplane-mode",
             "disable" if allow else "enable"),
        ]
        for argv in commands:
            try:
                responses.append(self.adb(*argv, timeout=8, limit=512))
            except (RuntimeError, subprocess.TimeoutExpired) as exc:
                responses.append("unsupported: " + str(exc)[:100])
        self.net_state = "guest_radio_on_unverified" if allow else "guest_radio_off_unverified"
        self.log("guest_radio", "on" if allow else "off")
        return {"allow": allow, "network_isolation": self.net_state,
                "guest_radio_results": responses,
                "warning": "Only guest radio state changed. A rootable Android emulator "
                           "can still have host-provided virtual network egress. "
                           "For real malware, enforce host-side firewall/namespace isolation."}

    def start(self) -> dict:
        pkg = self.require_selected()
        self.root_required()
        raw = self.adb("shell", "monkey", "-p", pkg, "-c",
                       "android.intent.category.LAUNCHER", "1", timeout=20)
        self.log("start_package", pkg)
        return {"package": pkg, "pid": self.pid(pkg), "output": raw[:3000]}

    def stop(self) -> dict:
        pkg = self.require_selected()
        self.root_required()
        self.adb("shell", "am", "force-stop", pkg, timeout=8)
        self.detach_debugger()
        self.trace_stop()
        self.log("stop_package", pkg)
        return {"stopped": pkg}

    def logs(self) -> dict:
        pid = self.require_pid()
        # Android logcat -d returns snapshot; --pid requires newer logcat variants.
        try:
            raw = self.adb("shell", "logcat", "-d", "-t", "250", "-v", "threadtime",
                           "--pid", str(pid), timeout=15, limit=LOG_LIMIT)
        except RuntimeError:
            raw = self.adb("shell", "logcat", "-d", "-t", "450", "-v", "threadtime",
                           timeout=15, limit=LOG_LIMIT)
            raw = "\n".join(line for line in raw.splitlines() if
                            re.search(r"\b" + str(pid) + r"\b", line))
        self.log("logcat_snapshot", f"{self.selected} pid={pid}")
        return {"package": self.selected, "pid": pid, "logcat": raw[:LOG_LIMIT],
                "scope": "Only available Android logcat entries, not every action."}

    def trace_start(self) -> dict:
        """Bounded in-memory live logcat for selected running guest PID.
        This is not system-call tracing, network interception or global log scraping.
        """
        pkg = self.require_selected()
        pid = self.require_pid()
        self.root_required()
        if self.trace_proc and self.trace_proc.poll() is None:
            if pkg == self.trace_package and pid == self.trace_pid:
                return {"running": True, "package": pkg, "pid": pid}
            self.trace_stop()
        self.trace_lines = []
        self.trace_package = pkg
        self.trace_pid = pid
        self.trace_proc = subprocess.Popen(
            ["adb", "-s", self.serial, "logcat", "-v", "threadtime",
             "--pid", str(pid)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, encoding="utf-8", errors="replace",
        )
        def collect():
            proc = self.trace_proc
            if proc is None or proc.stdout is None:
                return
            while proc.poll() is None:
                line = proc.stdout.readline()
                if not line:
                    break
                with LOCK:
                    self.trace_lines.append(line.rstrip()[:2000])
                    del self.trace_lines[:-750]
        threading.Thread(target=collect,daemon=True,name="aster-logcat").start()
        self.log("trace_started",pkg+" pid="+str(pid))
        return {"running": True, "package": pkg, "pid": pid,
                "note": "Logcat only: not every app action is logged."}

    def trace_view(self) -> dict:
        return {"running": self.trace_proc is not None and self.trace_proc.poll() is None,
                "package": self.trace_package,
                "pid": self.trace_pid,
                "lines": self.trace_lines[-180:],
                "scope": "Recent PID logcat from guest Android. Not a syscall/file/network audit."}

    def trace_stop(self) -> dict:
        proc=self.trace_proc
        self.trace_proc=None
        if proc is not None:
            try:
                proc.terminate()
                proc.wait(timeout=2)
            except (OSError,subprocess.TimeoutExpired):
                try:proc.kill()
                except OSError:pass
        previous=self.trace_package
        self.trace_package=""
        self.trace_pid=None
        if previous:
            self.log("trace_stopped",previous)
        return {"running": False, "lines_saved_in_memory": len(self.trace_lines)}

    def snapshot(self) -> dict:
        pid = self.require_pid()
        self.root_required()
        path = f"/proc/{pid}"
        info = self.adb("shell", "cat", f"{path}/status", timeout=8, limit=16000)
        maps = self.adb("shell", "cat", f"{path}/maps", timeout=8, limit=32000)
        try:
            backtrace = self.adb("shell", "debuggerd", "-b", str(pid),
                                 timeout=13, limit=12000)
        except (RuntimeError, subprocess.TimeoutExpired) as exc:
            backtrace = "Backtrace unavailable: " + str(exc)[:280]
        self.log("process_snapshot", f"{self.selected} pid={pid}")
        return {"package": self.selected, "pid": pid, "proc_status": info,
                "memory_map": maps, "native_backtrace": backtrace,
                "scope": "Instantaneous snapshot. Native debuggerd is not a complete execution trace."}

    def debug_attach(self) -> dict:
        pkg = self.require_selected()
        pid = self.require_pid()
        self.root_required()
        if self.jdb and self.jdb.poll() is None:
            return {"attached": True, "package": self.debug_target, "pid": pid}
        jdwp = self.adb("jdwp", timeout=8)
        if str(pid) not in jdwp.split():
            raise ValueError(
                "JDWP not available for this process. The APK must expose a debuggable "
                "Java VM; root of guest does not automatically enable JDWP on every app."
            )
        # Let adb select a local ephemeral port; return printed number.
        port = self.adb("forward", "tcp:0", "jdwp:" + str(pid), timeout=7)
        if not port.isdigit():
            raise RuntimeError("ADB did not allocate a JDWP port: " + port[:100])
        self.forward_port = int(port)
        try:
            self.jdb = subprocess.Popen(
                ["jdb", "-attach", "localhost:" + port],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, bufsize=1,
                text=True, encoding="utf-8", errors="replace",
            )
        except Exception:
            self.adb("forward", "--remove", "tcp:" + port)
            self.forward_port = None
            raise
        self.jdb_output = []
        self.debug_target = pkg
        self.jdb_reader = threading.Thread(target=self._read_jdb, daemon=True)
        self.jdb_reader.start()
        self.log("jdwp_attached", pkg + " pid=" + str(pid))
        return {"attached": True, "package": pkg, "pid": pid,
                "warning": "JDWP breakpoints only for debuggable guest processes."}

    def _read_jdb(self):
        proc = self.jdb
        if not proc or not proc.stdout:
            return
        try:
            # jdb output is line-oriented except its prompt; prompt appears when a command runs.
            while proc.poll() is None:
                line = proc.stdout.readline()
                if not line:
                    break
                with LOCK:
                    self.jdb_output.append(line.rstrip()[:2000])
                    del self.jdb_output[:-350]
        except Exception:
            return

    def debug_command(self, command: str, target: str = "") -> dict:
        if not self.jdb or self.jdb.poll() is not None or not self.jdb.stdin:
            raise ValueError("Attach the JDWP debugger first")
        if self.debug_target != self.require_selected():
            raise ValueError("Debugger belongs to a different package")
        # Strict command whitelist: no generic jdb/OS command injection.
        singles = {"threads": "threads", "where": "where all", "classes": "classes",
                   "cont": "cont", "next": "next", "step": "step",
                   "suspend": "suspend", "resume": "resume"}
        if command in singles:
            cmd = singles[command]
        elif command in ("break", "clear"):
            if not isinstance(target, str) or ":" not in target:
                raise ValueError("Expected class:line target")
            klass, _, number = target.rpartition(":")
            klass = clean_class(klass)
            if not re.fullmatch(r"\d{1,6}", number):
                raise ValueError("Invalid breakpoint line")
            cmd = ("stop at " if command == "break" else "clear ") + klass + ":" + number
        else:
            raise ValueError("Debugger command not permitted")
        self.jdb.stdin.write(cmd + "\n")
        self.jdb.stdin.flush()
        self.log("jdwp_command", command + ((" " + target) if target else ""))
        return {"command": command, "target": target, "sent": True,
                "note": "Read debugger output in follow-up query."}

    def debugger_output(self) -> dict:
        return {"attached": bool(self.jdb and self.jdb.poll() is None),
                "package": self.debug_target,
                "lines": self.jdb_output[-120:],
                "scope": "JDWP Java debugger; not all native or hidden code paths are visible."}

    def detach_debugger(self) -> dict:
        proc = self.jdb
        self.jdb = None
        if proc is not None:
            try:
                if proc.stdin:
                    proc.stdin.write("exit\n")
                    proc.stdin.flush()
            except OSError:
                pass
            try:
                proc.terminate()
                proc.wait(timeout=2)
            except (OSError, subprocess.TimeoutExpired):
                proc.kill()
        if self.forward_port is not None:
            try:
                self.adb("forward", "--remove", "tcp:" + str(self.forward_port))
            except Exception:
                pass
        self.forward_port = None
        self.debug_target = ""
        self.log("jdwp_detached", self.selected)
        return {"attached": False}

    def heap_dump(self) -> dict:
        self.root_required()
        pkg = self.require_selected()
        pid = self.require_pid()
        artifact_id = uuid.uuid4().hex
        guest = "/data/local/tmp/aster_heap_" + artifact_id + ".hprof"
        host = self.artifacts_dir / (artifact_id + ".hprof")
        # Android may deny dumpheap on nondebuggable apps even with guest root.
        try:
            output = self.adb("shell", "am", "dumpheap", pkg, guest, timeout=35)
            if "fail" in output.lower() or "error" in output.lower():
                raise RuntimeError(output[:1000])
            time.sleep(1.0)
            self.adb("pull", guest, str(host), timeout=65, limit=3000)
            size = host.stat().st_size
            if size <= 0 or size > MAX_ARTIFACT:
                raise RuntimeError("Heap dump is empty or exceeds 128 MiB limit")
            digest = hashlib.sha256()
            with host.open("rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    digest.update(chunk)
            self.artifacts[artifact_id] = {
                "path": str(host), "name": f"{pkg}-{pid}-heap.hprof",
                "size": size, "sha256": digest.hexdigest(),
                "created": time.time(), "package": pkg,
            }
            self.log("heap_dump", f"{pkg} {size} bytes")
            return {"artifact_id": artifact_id, "file_name": f"{pkg}-{pid}-heap.hprof",
                    "bytes": size, "sha256": digest.hexdigest(),
                    "privacy_warning": "Heap dumps may contain tokens, passwords and private data. "
                                       "Save only to a secure destination."}
        finally:
            try:
                self.adb("shell", "rm", "-f", guest, timeout=8)
            except Exception:
                pass
            if host.exists() and artifact_id not in self.artifacts:
                host.unlink()

    def native_status(self) -> dict:
        # Compilation is independent of emulator root and guest runtime.
        from native_builder import ndk_status
        return ndk_status(self.ndk_home)

    def native_build(self, payload: dict) -> dict:
        from native_builder import build_native
        response=build_native(payload,self.artifacts_dir,self.ndk_home)
        for built in response["outputs"]:
            artifact_id=built["artifact_id"]
            file_name=built["name"]
            self.artifacts[artifact_id]={
                "path":built.pop("host_path"), "name":file_name,
                "size":built["bytes"], "sha256":built["sha256"],
                "abi":built["abi"], "created":time.time(),"kind":"native_so",
            }
        self.log("ndk_build","ABIs:"+",".join(x["abi"] for x in response["outputs"]) +
                 " · errors:"+str(len(response["failures"])))
        return response


    # === ASTER Sandbox Analyzer: bounded, one active guest session ===

    def sandbox_stage(self, blob: bytes) -> dict:
        """Stage an explicitly selected APK. NEVER install here."""
        if self.sandbox.get("status") in ("queued", "running", "restoring"):
            raise ValueError("Analysis already active; wait for restore")
        if len(blob) < 4 or len(blob) > MAX_UPLOAD or blob[:4] != b"PK\x03\x04":
            raise ValueError("Choose a valid APK ZIP, maximum 96 MiB")
        identifier = uuid.uuid4().hex
        path = self.artifacts_dir / ("aster_sandbox_" + identifier + ".apk")
        path.write_bytes(blob)
        path.chmod(0o600)
        digest = hashlib.sha256(blob).hexdigest()
        self.artifacts[identifier] = {
            "path": str(path), "size": len(blob), "sha256": digest,
            "name": "selected.apk", "created": time.time(), "kind": "staged_apk",
        }
        self.log("sandbox_apk_staged", f"{identifier[:8]} {len(blob)} bytes")
        return {
            "artifact_id": identifier, "size": len(blob), "sha256": digest,
            "installed": False, "executed": False,
            "note": "APK staged privately. Installation and execution require a separate explicit command.",
        }

    def sandbox_status(self) -> dict:
        state = self.sandbox
        return {
            "session_id": state.get("session_id", ""),
            "status": state.get("status", "idle"),
            "phase": state.get("phase", ""),
            "package": state.get("package", ""),
            "percent": state.get("percent", 0),
            "summary": state.get("summary", {}),
            "report_json_artifact": state.get("report_json_artifact", ""),
            "report_html_artifact": state.get("report_html_artifact", ""),
            "errors": state.get("errors", [])[-5:],
            "events": state.get("timeline", [])[-25:],
            "host_egress_attested": self.host_egress_attested,
            "safety_warning": "The host egress declaration is operator-provided, not verified by ASTER. "
                              "Root emulator snapshots and logcat do not prove full malware containment.",
        }

    def sandbox_begin(self, payload: dict) -> dict:
        """Asynchronously run snapshot → install → observe → diff → restore."""
        from sandbox_analyzer import ALLOWED_SECONDS
        aid = payload.get("artifact_id", "")
        seconds = payload.get("duration_seconds", 30)
        consent = payload.get("acknowledge_lab_risk") is True
        if not isinstance(aid, str) or not re.fullmatch("[0-9a-f]{32}", aid):
            raise ValueError("Invalid staged APK artifact")
        if type(seconds) is not int or seconds not in ALLOWED_SECONDS:
            raise ValueError("Duration must be 15, 30, 60 or 120 seconds")
        meta = self.artifacts.get(aid)
        if not meta or meta.get("kind") != "staged_apk":
            raise ValueError("Stage a fresh selected APK first")
        if self.sandbox.get("status") in ("queued", "running", "restoring"):
            raise ValueError("A guest sandbox analysis is already running")
        if not self.host_egress_attested:
            raise PermissionError("Sandbox execution BLOCKED: the lab host has not attested "
                                  "to verified external network egress isolation. Set "
                                  "ASTER_LAB_EGRESS_ISOLATED=YES_I_VERIFIED_HOST_FIREWALL "
                                  "ONLY after configuring and verifying host firewall/namespace.")
        if not consent:
            raise PermissionError("Explicit confirmation of guest execution and host risk required")
        self.root_required()
        # Clean starting state required, rather than silently replacing an installed app.
        session_id = uuid.uuid4().hex
        self.sandbox_cancel = threading.Event()
        self.sandbox = {
            "session_id": session_id, "status": "queued",
            "phase": "waiting", "percent": 0, "errors": [],
            "timeline": [], "package": "", "duration_seconds": seconds,
            "artifact_id": aid,
        }
        self.sandbox_worker = threading.Thread(
            target=self._sandbox_execute,
            args=(session_id, str(meta["path"]), str(meta["sha256"]), seconds,
                  self.sandbox_cancel),
            name="aster-sandbox-" + session_id[:6], daemon=True
        )
        self.sandbox_worker.start()
        self.log("sandbox_started", session_id[:12])
        return self.sandbox_status()

    def sandbox_cancel_run(self) -> dict:
        if self.sandbox.get("status") not in ("queued", "running", "restoring"):
            return self.sandbox_status()
        self.sandbox_cancel.set()
        self.log("sandbox_cancel_requested", self.sandbox.get("session_id", "")[:12])
        return self.sandbox_status()

    def _sandbox_execute(self, session_id: str, apk: str, apk_sha: str,
                         seconds: int, cancelled: threading.Event):
        from sandbox_analyzer import snapshot, diff, report_json, report_html, summary, utc
        checkpoint = "aster_" + session_id[:18]
        report = {
            "format": "aster-sandbox-v1",
            "session_id": session_id, "started_at": utc(),
            "apk_sha256": apk_sha, "duration_requested_seconds": seconds,
            "status": "running", "package": "", "timeline": [],
            "errors": [], "limitations": [
                "Only selected guest snapshot metadata, selected package files, AppOps, "
                "permissions, process names, and limited logcat are observed.",
                "This is NOT exhaustive syscall / filesystem / memory / HTTPS inspection.",
                "Guest networking and hypervisor safety depend on external host isolation; "
                "an operator attestation cannot be verified by this application.",
                "File names, sizes and modification timestamps are compared; these are "
                "not complete file-content hashes.",
            ],
            "isolation": "host firewall declared verified by lab operator; NOT automatically verified",
            "restore": {"attempted": False, "verified": False},
        }
        checkpoint_saved = False
        baseline_packages: set[str] = set()
        target = ""
        def event(phase: str, detail: str, percent: int):
            report["timeline"].append({"time": utc(), "phase": phase,
                                      "detail": str(detail)[:300]})
            del report["timeline"][:-1500]
            with LOCK:
                if self.sandbox.get("session_id") == session_id:
                    self.sandbox.update({"status": "running", "phase": phase,
                                         "percent": percent,
                                         "timeline": report["timeline"][-30:],
                                         "package": target})
        def fail_if_cancelled():
            if cancelled.is_set():
                raise InterruptedError("Analysis cancelled by user; restoring clean checkpoint")
        try:
            self.root_required()
            event("checkpoint", "Saving clean emulator snapshot BEFORE installation", 5)
            raw = self.adb("emu", "avd", "snapshot", "save", checkpoint,
                           timeout=110, limit=2000)
            if "KO:" in raw or "error" in raw.lower():
                raise RuntimeError("Guest snapshot save was rejected: " + raw[:500])
            # Stronger check: emulator must list the named checkpoint.
            listing = self.adb("emu", "avd", "snapshot", "list", timeout=35, limit=8000)
            if checkpoint not in listing:
                raise RuntimeError("Guest snapshot was not confirmed by emulator; "
                                   "aborting before APK installation")
            checkpoint_saved = True
            fail_if_cancelled()
            event("pre_install", "Collecting package and system baseline", 13)
            report["pre_install"] = snapshot(self)
            baseline_packages = set(report["pre_install"]["third_party_packages"])
            fail_if_cancelled()
            event("install", "Installing selected APK ONLY into disposable guest", 25)
            result = self.adb("install", apk, timeout=95, limit=3000)
            if "Success" not in result:
                raise RuntimeError("Guest APK install failed: " + result[:800])
            report["install"] = {"installed": True, "output": result[:1200]}
            installed = set(self.packages()) - baseline_packages
            if len(installed) != 1:
                raise RuntimeError("Expected precisely one newly installed user package; "
                                   "observed " + str(len(installed)) +
                                   ". An upgrade/ambiguous install will NOT be executed.")
            target = next(iter(installed))
            report["package"] = target
            event("post_install", "New package " + target + " installed", 36)
            report["post_install"] = snapshot(self, target)
            report["install_delta"] = diff(report["pre_install"], report["post_install"])
            fail_if_cancelled()
            # Optional soft guest radios. NOT security isolation; host firewall is mandatory.
            self.adb("shell", "svc", "wifi", "disable", timeout=8)
            self.adb("shell", "svc", "data", "disable", timeout=8)
            event("launch", "Launching " + target + " for controlled observation", 43)
            start_output = self.adb(
                "shell", "monkey", "-p", target, "-c",
                "android.intent.category.LAUNCHER", "1",
                timeout=25, limit=3200)
            report["launch_output"] = start_output[:1500]
            pid_history: list[dict] = []
            # Capture multiple moments rather than pretend endpoint sampling is complete.
            for second in range(seconds):
                fail_if_cancelled()
                if second % 5 == 0 or second == seconds - 1:
                    pid = self.pid(target)
                    pid_history.append({"elapsed_seconds": second, "pid": pid})
                    event("observe", f"t={second}s · selected PID: {pid}", 45 + int(35 * second/seconds))
                cancelled.wait(1)
            report["pid_samples"] = pid_history
            final_pid = self.pid(target)
            if final_pid:
                lines, ok = ("", False)
                try:
                    lines = self.adb(
                        "shell", "logcat", "-d", "-t", "1200", "-v",
                        "threadtime", "--pid", str(final_pid), timeout=22, limit=85000)
                    ok = True
                except Exception as exc:
                    report["limitations"].append("PID logcat unavailable: " + str(exc)[:150])
                report["logcat_excerpt"] = lines[:85000] if ok else ""
            else:
                report["logcat_excerpt"] = ""
                report["limitations"].append("Process already exited before logcat snapshot")
            event("post_run", "Collecting package files, AppOps, processes and settings", 84)
            report["post_run"] = snapshot(self, target)
            report["comparison"] = diff(report["post_install"], report["post_run"])
            report["overall_delta"] = diff(report["pre_install"], report["post_run"])
            report["status"] = "completed"
        except InterruptedError as exc:
            report["status"] = "cancelled"
            report["errors"].append(str(exc))
        except Exception as exc:
            report["status"] = "failed"
            report["errors"].append(type(exc).__name__ + ": " + str(exc)[:450])
        finally:
            # Always attempt to terminate guest process before reverting checkpoint.
            if target:
                try:
                    self.adb("shell", "am", "force-stop", target, timeout=10)
                except Exception as exc:
                    report["errors"].append("force-stop: " + type(exc).__name__)
            if checkpoint_saved:
                with LOCK:
                    if self.sandbox.get("session_id") == session_id:
                        self.sandbox.update({"status": "restoring", "phase": "restore",
                                             "percent": 92})
                report["restore"]["attempted"] = True
                try:
                    result = self.adb("emu", "avd", "snapshot", "load", checkpoint,
                                      timeout=110, limit=1500)
                    if "KO:" in result or "error" in result.lower():
                        raise RuntimeError(result[:500])
                    self.adb("wait-for-device", timeout=70)
                    self.root_required()
                    after_restore = set(self.packages())
                    restored = after_restore == baseline_packages
                    report["restore"]["verified"] = restored
                    if not restored:
                        report["errors"].append(
                            "Post-restore package inventory differs from pre-install baseline")
                    else:
                        try:
                            self.adb("emu", "avd", "snapshot", "delete", checkpoint,
                                     timeout=35, limit=1000)
                        except Exception:
                            report["limitations"].append("Checkpoint deletion failed")
                except Exception as exc:
                    report["errors"].append("Snapshot restore failed: " + str(exc)[:400])
            else:
                # No APK was installed unless the checkpoint was confirmed saved.
                report["restore"]["reason"] = "no checkpoint created; install never attempted"
            if report["status"] == "completed" and not report["restore"]["verified"]:
                report["status"] = "completed_restore_unverified"
            report["finished_at"] = utc()
            event("finalize", "Writing JSON/HTML report and restore status", 97)
            # Keep evidence bounded and private, not in GitHub or public endpoints.
            try:
                for kind, extension, contents in (
                    ("sandbox_json", ".json", report_json(report)),
                    ("sandbox_html", ".html", report_html(report)),
                ):
                    if len(contents) > 2 * 1024 * 1024:
                        raise ValueError("Report larger than 2 MiB; audit details too large")
                    artifact_id = uuid.uuid4().hex
                    output = self.artifacts_dir / ("aster_report_" + artifact_id + extension)
                    output.write_bytes(contents)
                    output.chmod(0o600)
                    digest = hashlib.sha256(contents).hexdigest()
                    with LOCK:
                        self.artifacts[artifact_id] = {
                            "path": str(output), "name": "ASTER-sandbox-report" + extension,
                            "size": len(contents), "sha256": digest,
                            "kind": kind, "created": time.time(),
                        }
                    report[kind + "_artifact"] = artifact_id
            except Exception as exc:
                report["errors"].append("Report storage failed: " + str(exc)[:120])
            with LOCK:
                if self.sandbox.get("session_id") == session_id:
                    self.sandbox.update({
                        "status": report["status"], "phase": "finished", "percent": 100,
                        "summary": summary(report), "errors": report["errors"],
                        "report_json_artifact": report.get("sandbox_json_artifact", ""),
                        "report_html_artifact": report.get("sandbox_html_artifact", ""),
                        "timeline": report["timeline"][-30:],
                        "package": target,
                    })
            self.log("sandbox_finished", session_id[:10] + " " + report["status"])

    def upload_apk(self, blob: bytes) -> dict:
        self.root_required()
        if len(blob) < 4 or len(blob) > MAX_UPLOAD:
            raise ValueError("APK must be 4 bytes–96 MiB")
        # ZIP signature check prevents obvious accidental uploads. No execution on host.
        if blob[:4] != b"PK\x03\x04":
            raise ValueError("File does not look like an APK ZIP")
        with tempfile.NamedTemporaryFile(
            prefix="aster_import_", suffix=".apk", dir=self.artifacts_dir, delete=False
        ) as fp:
            fp.write(blob)
            path = fp.name
        try:
            result = self.adb("install", "-r", path, timeout=90, limit=3000)
            self.log("install_guest_apk", f"{len(blob)} bytes · {result[:70]}")
            return {"installed": "Success" in result, "output": result[:1500],
                    "note": "APK installed in selected emulator ONLY. Choose package afterward."}
        finally:
            Path(path).unlink(missing_ok=True)

    def journal(self) -> dict:
        return {"events": self.events[-200:], "selected_package": self.selected,
                "warning": "This is controller/ADB activity, not a complete syscall trace."}


class Handler(BaseHTTPRequestHandler):
    server_version = "AsterLab/0.1"
    def log_message(self, fmt, *args):
        # Do not print secret auth headers or APK contents to stdout.
        sys.stderr.write("[ASTER] " + fmt % args + "\n")

    def _auth(self) -> bool:
        supplied = self.headers.get("Authorization", "")
        valid = "Bearer " + self.server.lab_token  # type: ignore[attr-defined]
        return secrets.compare_digest(supplied, valid)

    def _json(self, status: int, obj: dict | list):
        data = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(data)

    def _read(self, limit: int = MAX_JSON) -> bytes:
        size = int(self.headers.get("Content-Length", "0"))
        if size <= 0 or size > limit:
            raise ValueError("Invalid request size")
        return self.rfile.read(size)

    def _guard(self, fn):
        if not self._auth():
            return self._json(401, {"error": "Pairing token invalid"})
        try:
            with LOCK:
                self.server.lab.cleanup_artifacts()
                return fn()
        except (ValueError, PermissionError) as e:
            self._json(400, {"error": str(e)})
        except (RuntimeError, OSError, subprocess.TimeoutExpired) as e:
            self._json(503, {"error": str(e)[:1600]})
        except Exception as e:
            self._json(500, {"error": e.__class__.__name__ + ": " + str(e)[:300]})

    def do_GET(self):
        def run_get():
            lab = self.server.lab  # type: ignore[attr-defined]
            path = urlparse(self.path).path
            if path == "/v1/sandbox/status":
                return self._json(200, lab.sandbox_status())
            if path == "/v1/native/status":
                return self._json(200, lab.native_status())
            if path == "/v1/status":
                return self._json(200, lab.status())
            if path == "/v1/packages":
                return self._json(200, {"packages": lab.packages()})
            if path == "/v1/logs":
                return self._json(200, lab.logs())
            if path == "/v1/trace":
                return self._json(200, lab.trace_view())
            if path == "/v1/process":
                return self._json(200, lab.snapshot())
            if path == "/v1/debug":
                return self._json(200, lab.debugger_output())
            if path == "/v1/events":
                return self._json(200, lab.journal())
            if path.startswith("/v1/artifacts/"):
                artifact_id = path.rsplit("/", 1)[-1]
                if not re.fullmatch(r"[0-9a-f]{32}", artifact_id):
                    raise ValueError("Invalid artifact identifier")
                meta = lab.artifacts.get(artifact_id)
                if not meta:
                    return self._json(404, {"error": "Artifact unavailable"})
                # Expire memory-bearing artifacts after 45 minutes.
                if time.time() - meta["created"] > 45*60:
                    Path(meta["path"]).unlink(missing_ok=True)
                    del lab.artifacts[artifact_id]
                    return self._json(410, {"error": "Artifact expired"})
                path = Path(meta["path"])
                size = path.stat().st_size
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Length", str(size))
                name=meta.get("name","aster-heap.hprof")
                if not re.fullmatch(r"(?:lib[A-Za-z0-9_]{1,48}\.so|aster-heap\.hprof|[a-zA-Z0-9_.-]{1,140}\.hprof|ASTER-sandbox-report\.(?:json|html))",name):
                    name="aster-artifact.bin"
                self.send_header("Content-Disposition", 'attachment; filename="'+name+'"')
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                with path.open("rb") as f:
                    shutil.copyfileobj(f, self.wfile)
                lab.log("download_artifact", artifact_id[:10])
                return
            self._json(404, {"error": "Unknown endpoint"})
        self._guard(run_get)

    def do_POST(self):
        def run_post():
            lab = self.server.lab  # type: ignore[attr-defined]
            path = urlparse(self.path).path
            if path == "/v1/sandbox/stage":
                blob = self._read(MAX_UPLOAD)
                return self._json(200, lab.sandbox_stage(blob))
            if path == "/v1/upload":
                blob = self._read(MAX_UPLOAD)
                return self._json(200, lab.upload_apk(blob))
            if self.headers.get("Content-Type", "").split(";")[0].strip() != "application/json":
                raise ValueError("Expected application/json")
            request_cap=150000 if path == "/v1/native/build" else MAX_JSON
            obj = json.loads(self._read(request_cap))
            if not isinstance(obj, dict):
                raise ValueError("Expected JSON object")
            if path == "/v1/sandbox/begin":
                return self._json(200, lab.sandbox_begin(obj))
            if path == "/v1/sandbox/cancel":
                return self._json(200, lab.sandbox_cancel_run())
            if path == "/v1/native/build":
                return self._json(200, lab.native_build(obj))
            if path == "/v1/select":
                return self._json(200, lab.select(obj.get("package", "")))
            if path == "/v1/network":
                if type(obj.get("allow")) is not bool:
                    raise ValueError("Expected boolean allow")
                return self._json(200, lab.network(obj["allow"]))
            if path == "/v1/start":
                return self._json(200, lab.start())
            if path == "/v1/stop":
                return self._json(200, lab.stop())
            if path == "/v1/trace/start":
                return self._json(200, lab.trace_start())
            if path == "/v1/trace/stop":
                return self._json(200, lab.trace_stop())
            if path == "/v1/debug/attach":
                return self._json(200, lab.debug_attach())
            if path == "/v1/debug/command":
                return self._json(200, lab.debug_command(obj.get("command", ""),
                                                          obj.get("target", "")))
            if path == "/v1/debug/detach":
                return self._json(200, lab.detach_debugger())
            if path == "/v1/heap":
                return self._json(200, lab.heap_dump())
            return self._json(404, {"error": "Unknown endpoint"})
        self._guard(run_post)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--serial", default="emulator-5554")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8742)
    parser.add_argument("--cert", type=Path, required=True)
    parser.add_argument("--key", type=Path, required=True)
    parser.add_argument("--token-file", type=Path, required=True)
    parser.add_argument("--artifact-dir", type=Path, default=Path("lab/artifacts"))
    parser.add_argument("--allow-lan", action="store_true",
                        help="Bind private LAN interface only after securing network/firewall")
    args = parser.parse_args()
    if args.host not in ("127.0.0.1", "::1") and not args.allow_lan:
        parser.error("Non-loopback listener requires --allow-lan and private firewall")
    if not args.cert.is_file() or not args.key.is_file():
        parser.error("Generate HTTPS certificate/key via lab/setup.sh first")
    token_path = args.token_file
    if token_path.exists():
        token = token_path.read_text().strip()
    else:
        token = secrets.token_urlsafe(32)
        token_path.parent.mkdir(parents=True, exist_ok=True)
        token_path.write_text(token)
        os.chmod(token_path, 0o600)
    if len(token) < 32:
        parser.error("Pairing token is too short; require at least 32 chars")
    lab = Lab(args.serial, args.artifact_dir)
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    server.lab, server.lab_token = lab, token
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
    ssl_context.load_cert_chain(args.cert, args.key)
    server.socket = ssl_context.wrap_socket(server.socket, server_side=True)
    fingerprint = hashlib.sha256(ssl.PEM_cert_to_DER_cert(
        args.cert.read_text())).hexdigest().upper()
    print("ASTER Lab: HTTPS secure controller; NOT a VM inside the phone", flush=True)
    print(f"URL https://{args.host}:{args.port}", flush=True)
    print(f"Certificate SHA-256 {fingerprint}", flush=True)
    print(f"Pairing token {token}", flush=True)
    print("Never publish token; use private tunnel, do not expose Internet", flush=True)
    stop_cleaner = threading.Event()
    def clean_loop():
        while not stop_cleaner.wait(60):
            with LOCK:
                lab.cleanup_artifacts()
    cleaner = threading.Thread(target=clean_loop,daemon=True,name="aster-heap-purge")
    cleaner.start()
    try:
        server.serve_forever(poll_interval=0.3)
    finally:
        stop_cleaner.set()
        lab.sandbox_cancel.set()
        if lab.sandbox_worker is not None:
            lab.sandbox_worker.join(timeout=150)
        with LOCK:
            lab.detach_debugger()
            lab.trace_stop()
            if not (lab.sandbox_worker is not None and lab.sandbox_worker.is_alive()):
                lab.cleanup_artifacts(force=True)
        server.server_close()


if __name__ == "__main__":
    main()
