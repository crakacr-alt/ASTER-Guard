"""ASTER Sandbox Analyzer: bounded, auditable snapshots and behaviour report.

Execution target: *separate, disposable, rootable Android Emulator*.
The phone holds ONLY the controller UI. Never run suspect APK on the phone.
No complete syscall trace, packet capture or kernel-level sandbox guarantee.

The module issues only fixed ADB operations. The shell uses $1 for the
validated package argument, so untrusted names cannot become commands.
"""
from __future__ import annotations

import hashlib
import html
import ipaddress
import json
import re
import time
from datetime import datetime, timezone
from typing import Any

PKG = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+$")
MAX_FILES = 350
MAX_LOG_LINES = 1200
MAX_EVENTS = 2000
ALLOWED_SECONDS = (15, 30, 60, 120)
# Only these settings are collected, never a raw dump of private tokens.
SETTINGS = {
    "global": ("airplane_mode_on", "private_dns_mode", "development_settings_enabled"),
    "secure": ("enabled_accessibility_services", "enabled_notification_listeners"),
}

FILES_SCRIPT = r"""
pkg="$1"
for root in "/data/user/0/$pkg" "/data/user_de/0/$pkg" "/sdcard/Android/data/$pkg"; do
  if [ -d "$root" ]; then
    find "$root" -maxdepth 6 -type f 2>/dev/null | head -n 350 |
      while IFS= read -r item; do
        case "$item" in *'|'*|*'
'*) continue;; esac
        stat -c '%n|%s|%Y' "$item" 2>/dev/null
      done
  fi
done
"""
GUEST_APP_DIRS_SCRIPT = r"""ls -1 /data/user/0 2>/dev/null"""
# Do not print raw system settings that may include secrets in a report.

def safe_package(value: str) -> str:
    if not isinstance(value, str) or len(value) > 180 or not PKG.fullmatch(value):
        raise ValueError("Expected a validated Android package identifier")
    return value


def capped(value: str, limit: int = 12000) -> str:
    return str(value)[:limit]


def utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def _optional_adb(lab, *args: str, timeout: int = 8, limit: int = 16000) -> tuple[str, bool]:
    try:
        return lab.adb(*args, timeout=timeout, limit=limit), True
    except Exception as exc:
        return f"UNAVAILABLE: {type(exc).__name__}: {str(exc)[:160]}", False


def file_metadata(raw: str) -> dict[str, dict]:
    """File metadata, not file contents. No false claim to complete tracking."""
    result: dict[str, dict] = {}
    for line in raw.splitlines()[:MAX_FILES * 3]:
        fields = line.rsplit("|", 2)
        if len(fields) != 3:
            continue
        path, size, modified = fields
        if len(path) > 500 or not path.startswith((
            "/data/user/0/", "/data/user_de/0/", "/sdcard/Android/data/"
        )) or not size.isdigit() or not modified.isdigit():
            continue
        result[path] = {"size": int(size), "mtime": int(modified)}
        if len(result) >= MAX_FILES:
            break
    return result


def parse_remote_endpoints(raw: str, table: str) -> list[str]:
    """Passive /proc/net snapshot. Connections belong to entire guest, not one app."""
    if table not in ("tcp", "tcp6", "udp", "udp6"):
        return []
    result: set[str] = set()
    for line in raw.splitlines()[1:300]:
        fields = line.split()
        if len(fields) < 4 or ":" not in fields[2]:
            continue
        ip_hex, _, port_hex = fields[2].partition(":")
        try:
            port = int(port_hex, 16)
            raw_bytes = bytes.fromhex(ip_hex)
            if port == 0:
                continue
            if table in ("tcp", "udp") and len(raw_bytes) == 4:
                address = str(ipaddress.IPv4Address(raw_bytes[::-1]))
                if address == "0.0.0.0":
                    continue
            elif table in ("tcp6", "udp6") and len(raw_bytes) == 16:
                # Linux /proc/net/tcp6 hex stores little-endian 32-bit words.
                host_bytes = b"".join(raw_bytes[x:x+4][::-1] for x in range(0, 16, 4))
                address = str(ipaddress.IPv6Address(host_bytes))
                if address == "::":
                    continue
            else:
                continue
            if not 0 < port <= 65535:
                continue
            result.add(table + "://" + address + ":" + str(port))
            if len(result) >= 120:
                break
        except (ValueError, IndexError):
            continue
    return sorted(result)


def snapshot(lab, package: str = "") -> dict[str, Any]:
    """Capture limited guest observables; never interpret absence as safe."""
    lab.root_required()
    if package:
        package = safe_package(package)
    quality: list[str] = []
    system: dict[str, Any] = {}
    for key, args in {
        "android": ("shell", "getprop", "ro.build.version.release"),
        "api": ("shell", "getprop", "ro.build.version.sdk"),
        "abi": ("shell", "getprop", "ro.product.cpu.abi"),
    }.items():
        data, ok = _optional_adb(lab, *args)
        system[key] = capped(data, 100).strip()
        if not ok:
            quality.append(key + " unavailable")
    packages, ok = _optional_adb(lab, "shell", "pm", "list", "packages", "-3",
                                 timeout=12, limit=128000)
    if not ok:
        quality.append("package inventory unavailable")
    installed = sorted(set(
        row.removeprefix("package:").strip()
        for row in packages.splitlines() if row.startswith("package:")
        and PKG.fullmatch(row.removeprefix("package:").strip())
    ))[:1500]
    roots, ok = _optional_adb(lab, "shell", "sh", "-c", GUEST_APP_DIRS_SCRIPT)
    if not ok:
        quality.append("global app data directory list unavailable")
    app_dirs = sorted(set(
        x.strip() for x in roots.splitlines() if re.fullmatch(r"[a-zA-Z0-9_.-]{1,180}", x.strip())
    ))[:1500]
    processes, ok = _optional_adb(lab, "shell", "ps", "-A", "-o", "PID,NAME", limit=24000)
    if not ok:
        quality.append("process snapshot unavailable")
    names: list[str] = []
    for line in processes.splitlines()[1:]:
        parts = line.strip().split(None, 1)
        if len(parts) == 2 and parts[0].isdigit():
            names.append(parts[1][:180])
    system["process_names"] = sorted(set(names))[:1000]

    settings = {}
    for ns, nameset in SETTINGS.items():
        for name in nameset:
            value, ok = _optional_adb(lab, "shell", "settings", "get", ns, name)
            if not ok:
                quality.append(ns + ":" + name + " unavailable")
            # Store only a digest so diffs can detect changes without leaking tokens.
            settings[ns + "/" + name] = hashlib.sha256(value.encode()).hexdigest() if ok else None

    network: dict[str, str] = {}
    endpoints: set[str] = set()
    for name in ("tcp", "tcp6", "udp", "udp6"):
        value, ok = _optional_adb(lab, "shell", "cat", "/proc/net/" + name,
                                  timeout=6, limit=16000)
        # Passive guest-wide kernel table only; no packet payload, no per-app attribution.
        network[name] = hashlib.sha256(value.encode()).hexdigest() if ok else ""
        if ok:
            endpoints.update(parse_remote_endpoints(value, name))
        else:
            quality.append("/proc/net/" + name + " unavailable")

    data: dict[str, Any] = {
        "timestamp": utc(),
        "selected_package": package or None,
        "system": system,
        "third_party_packages": installed,
        "app_data_root_names": app_dirs,
        "settings_sha256": settings,
        "network_table_sha256": network,
        "network_guest_endpoints": sorted(endpoints)[:120],
        "coverage": {
            "root_guest": True,
            "file_metadata_only": True,
            "global_file_contents": False,
            "observed_events_complete": False,
            "packet_capture": False,
            "kernel_syscall_trace": False,
            "max_target_files": MAX_FILES,
            "warnings": quality,
        },
    }
    if package:
        files, ok = _optional_adb(lab, "shell", "sh", "-c", FILES_SCRIPT, "_", package,
                                  timeout=25, limit=95000)
        if not ok:
            quality.append("target file metadata unavailable")
        data["target_files"] = file_metadata(files) if ok else {}
        appops, ok = _optional_adb(lab, "shell", "cmd", "appops", "get", package,
                                   limit=24000)
        data["appops"] = capped(appops, 24000) if ok else ""
        if not ok:
            quality.append("appops unavailable")
        pmdump, ok = _optional_adb(lab, "shell", "dumpsys", "package", package,
                                   limit=45000)
        if not ok:
            quality.append("package permissions unavailable")
        # Avoid exporting full dumpsys package which might contain unrelated data.
        interesting = []
        for line in pmdump.splitlines():
            if ("permission" in line.lower() or "granted=" in line or
                "targetSdk=" in line or "versionCode=" in line):
                interesting.append(line.strip()[:240])
            if len(interesting) >= 140:
                break
        data["package_permission_lines"] = interesting
    else:
        data["target_files"] = {}
        data["appops"] = ""
        data["package_permission_lines"] = []
    return data


def diff(before: dict, after: dict) -> dict[str, Any]:
    """Explicitly scoped comparison. May not see ephemeral/transient changes."""
    start_pkgs = set(before.get("third_party_packages", []))
    end_pkgs = set(after.get("third_party_packages", []))
    start_roots = set(before.get("app_data_root_names", []))
    end_roots = set(after.get("app_data_root_names", []))
    pre_files = before.get("target_files") or {}
    post_files = after.get("target_files") or {}
    pre_keys, post_keys = set(pre_files), set(post_files)
    added = sorted(post_keys - pre_keys)
    removed = sorted(pre_keys - post_keys)
    modified = sorted(
        x for x in pre_keys & post_keys if pre_files[x] != post_files[x]
    )
    start_settings = before.get("settings_sha256", {})
    end_settings = after.get("settings_sha256", {})
    changed_settings = sorted(
        name for name in set(start_settings) | set(end_settings)
        if start_settings.get(name) != end_settings.get(name)
    )
    start_net = before.get("network_table_sha256", {})
    end_net = after.get("network_table_sha256", {})
    network_changed = sorted(
        name for name in set(start_net) | set(end_net)
        if start_net.get(name) != end_net.get(name)
    )
    start_process = set((before.get("system") or {}).get("process_names", []))
    end_process = set((after.get("system") or {}).get("process_names", []))
    return {
        "installed_packages": sorted(end_pkgs - start_pkgs),
        "removed_packages": sorted(start_pkgs - end_pkgs),
        "created_app_data_roots": sorted(end_roots - start_roots),
        "removed_app_data_roots": sorted(start_roots - end_roots),
        "target_files_created": added[:MAX_FILES],
        "target_files_removed": removed[:MAX_FILES],
        "target_files_modified": modified[:MAX_FILES],
        "settings_changed": changed_settings,
        "network_tables_changed": network_changed,
        "network_endpoints_appeared": sorted(
            set(after.get("network_guest_endpoints", [])) -
            set(before.get("network_guest_endpoints", []))
        )[:120],
        "processes_appeared_at_endpoint": sorted(end_process - start_process)[:120],
        "processes_disappeared_at_endpoint": sorted(start_process - end_process)[:120],
        "appops_changed": before.get("appops", "") != after.get("appops", ""),
        "permission_state_changed": (
            before.get("package_permission_lines", []) !=
            after.get("package_permission_lines", [])
        ),
        "limitations": (
            "Only before/after snapshots. A file created and deleted between "
            "snapshots may be missed. mtime/size changes are NOT content hashes. "
            "Network table hashes show change, not actual destinations. "
            "Unlisted system paths, kernel events, or transient processes can be missed."
        ),
    }


def report_json(report: dict[str, Any]) -> bytes:
    raw = json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2)
    return raw.encode("utf-8")


def report_html(report: dict[str, Any]) -> bytes:
    """Offline-only, escaped HTML: no script, remote styles, trackers or requests."""
    def pretty(value: Any) -> str:
        return html.escape(json.dumps(value, ensure_ascii=False, indent=2))
    rows = [
        ("Сеанс", report.get("session_id", "")),
        ("Приложение", report.get("package", "")),
        ("Статус", report.get("status", "")),
        ("Изоляция", report.get("isolation", "")),
        ("Изменения", report.get("comparison", {})),
        ("Хронология", report.get("timeline", [])),
        ("Ограничения", report.get("limitations", [])),
        ("Ошибки", report.get("errors", [])),
    ]
    body = "\n".join(
        "<section><h2>" + html.escape(title) + "</h2><pre>" +
        pretty(value) + "</pre></section>" for title, value in rows
    )
    content = ("<!doctype html><html lang='ru'><head><meta charset='utf-8'>"
               "<meta name='viewport' content='width=device-width,initial-scale=1'>"
               "<meta http-equiv='Content-Security-Policy' "
               "content=\"default-src 'none'; style-src 'unsafe-inline'\">"
               "<title>ASTER Sandbox report</title><style>"
               "body{font:15px system-ui;background:#101b27;color:#e9f5f6;max-width:850px;"
               "margin:3em auto;padding:1em}section{border:1px solid #325061;"
               "border-radius:10px;padding:1em;margin:1em 0}"
               "pre{overflow-x:auto;white-space:pre-wrap;overflow-wrap:anywhere}"
               "</style></head><body><h1>ASTER Sandbox Analyzer</h1>" +
               body + "</body></html>")
    return content.encode("utf-8")


def summary(report: dict[str, Any]) -> dict[str, Any]:
    comp = report.get("comparison") or {}
    end = report.get("post_run") or {}
    return {
        "session_id": report.get("session_id"),
        "status": report.get("status"),
        "package": report.get("package"),
        "installed": (report.get("install") or {}).get("installed", False),
        "created_files": len(comp.get("target_files_created", [])),
        "changed_files": len(comp.get("target_files_modified", [])),
        "removed_files": len(comp.get("target_files_removed", [])),
        "new_packages": len(comp.get("installed_packages", [])),
        "changed_settings": len(comp.get("settings_changed", [])),
        "network_tables_changed": len(comp.get("network_tables_changed", [])),
        "guest_endpoints_appeared": len(comp.get("network_endpoints_appeared", [])),
        "restored": (report.get("restore") or {}).get("verified", False),
        "events": len(report.get("timeline", [])),
        "errors": report.get("errors", [])[-5:],
        "coverage_warning": "Partial observation. Not all actions or system modifications are recorded.",
        "sampling_warnings": (end.get("coverage") or {}).get("warnings", [])[:8],
    }
