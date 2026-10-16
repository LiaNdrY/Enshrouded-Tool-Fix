#!/usr/bin/env python3
"""
Enshrouded Tool Fix - Linux (Steam / Proton) edition
Based on the Windows PowerShell tool by LiaNdrY (v1.1.13).

Enshrouded has no native Linux client, so this assumes the game runs through
Steam Play (Proton). Run it as your normal user (NOT root), with Steam and the
game closed. Standard library only, Python 3.8+.

Usage:
    python3 enshrouded_tool_fix_linux.py [--resolution WxH] [--skip-gpu-cache]
"""
from __future__ import annotations

import argparse
import datetime
import fnmatch
import glob
import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import uuid

TOOL_VERSION = "1.1.13-linux"
GAME_ID = 1203620
LOG_FILE_PATH = os.path.join(tempfile.gettempdir(), "Enshrouded_Tool_Fix.log")

# --------------------------------------------------------------------------- #
# Logging
# --------------------------------------------------------------------------- #
_COLORS = {"gray": "37", "green": "92", "yellow": "93", "red": "91", "cyan": "96"}
_USE_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def log(message: str = "", color: str = "gray", end: str = "\n") -> None:
    if message is None or not str(message).strip():
        sys.stdout.write("\n")
        sys.stdout.flush()
        with open(LOG_FILE_PATH, "a", encoding="utf-8") as fh:
            fh.write("\n")
        return
    with open(LOG_FILE_PATH, "a", encoding="utf-8") as fh:
        fh.write(message + end)
    if _USE_COLOR:
        sys.stdout.write(f"\x1b[{_COLORS.get(color, '37')}m{message}\x1b[0m{end}")
    else:
        sys.stdout.write(message + end)
    sys.stdout.flush()


# --------------------------------------------------------------------------- #
# Small helpers
# --------------------------------------------------------------------------- #
def read_text(path: str) -> str | None:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read().strip()
    except OSError:
        return None


def read_game_json(path: str):
    with open(path, "r", encoding="utf-8-sig") as fh:
        return json.loads(fh.read())


def save_formatted_json(obj, path: str) -> None:
    json_text = json.dumps(obj, indent=2, ensure_ascii=False)
    json.loads(json_text)
    directory = os.path.dirname(path)
    if not directory or not os.path.isdir(directory):
        raise RuntimeError(f"The destination directory does not exist: {directory}")

    temporary = os.path.join(directory, f".{os.path.basename(path)}.{uuid.uuid4().hex}.tmp")
    backup = path + ".bak"
    try:
        if os.path.isfile(path):
            compact = lambda o: json.dumps(o, separators=(",", ":"), ensure_ascii=False)
            if compact(read_game_json(path)) == compact(obj):
                return
            if not os.path.exists(backup):
                shutil.copy2(path, backup)
        mode = stat.S_IMODE(os.stat(path).st_mode) if os.path.isfile(path) else 0o644
        with open(temporary, "w", encoding="utf-8", newline="") as fh:
            fh.write(json_text + "\n")
        read_game_json(temporary)
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    except Exception as exc:
        raise RuntimeError(f"Failed to save JSON file '{path}': {exc}") from exc
    finally:
        if os.path.exists(temporary):
            try:
                os.remove(temporary)
            except OSError:
                pass


def run_cmd(cmd: list, timeout: int = 15) -> str | None:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        return None
    return proc.stdout if proc.returncode == 0 else None


def parse_version(text) -> tuple | None:
    m = re.fullmatch(r"\s*(\d+(?:\.\d+){1,3})\s*", str(text))
    return tuple(int(x) for x in m.group(1).split(".")) if m else None


def find_ci(base: str, *parts: str) -> str | None:
    """Case-insensitive path lookup (Wine prefixes are case-insensitive, Linux is not)."""
    cur = base
    for part in parts:
        if not os.path.isdir(cur):
            return None
        try:
            names = os.listdir(cur)
        except OSError:
            return None
        match = next((n for n in names if n.lower() == part.lower()), None)
        if match is None:
            return None
        cur = os.path.join(cur, match)
    return cur


# --------------------------------------------------------------------------- #
# Steam discovery
# --------------------------------------------------------------------------- #
def steam_root_candidates() -> list:
    home = os.path.expanduser("~")
    xdg = os.environ.get("XDG_DATA_HOME", os.path.join(home, ".local", "share"))
    return [
        os.path.join(xdg, "Steam"),
        os.path.join(home, ".steam", "steam"),
        os.path.join(home, ".steam", "root"),
        os.path.join(home, ".var", "app", "com.valvesoftware.Steam", ".local", "share", "Steam"),
        os.path.join(home, "snap", "steam", "common", ".local", "share", "Steam"),
    ]


def find_steam_roots() -> list:
    roots, seen = [], set()
    for cand in steam_root_candidates():
        real = os.path.realpath(cand)
        if real in seen or not os.path.isdir(os.path.join(real, "steamapps")):
            continue
        seen.add(real)
        roots.append(real)
    return roots


def get_steam_library_paths_from_vdf(content: str, steam_path: str) -> list:
    paths, seen = [steam_path], {steam_path}
    matches = list(re.finditer(r'(?im)^\s*"path"\s+"(?P<value>(?:\\.|[^"])*)"\s*$', content))
    if not matches:
        matches = list(re.finditer(r'(?im)^\s*"\d+"\s+"(?P<value>(?:\\.|[^"])*)"\s*$', content))
    for m in matches:
        lib = m.group("value").replace("\\\\", "\\").replace('\\"', '"').strip()
        if not lib:
            continue
        lib = os.path.realpath(os.path.expanduser(lib))
        if lib not in seen:
            seen.add(lib)
            paths.append(lib)
    return paths


def get_steam_library_paths(steam_root: str) -> list:
    paths, seen = [steam_root], {steam_root}
    for vdf in (os.path.join(steam_root, "config", "libraryfolders.vdf"),
                os.path.join(steam_root, "steamapps", "libraryfolders.vdf")):
        text = read_text(vdf)
        if not text:
            continue
        for p in get_steam_library_paths_from_vdf(text, steam_root):
            if p not in seen:
                seen.add(p)
                paths.append(p)
    return paths


def get_install_dir_from_manifest(content: str) -> str | None:
    m = re.search(r'(?im)^\s*"installdir"\s+"(?P<value>(?:\\.|[^"])*)"\s*$', content)
    return m.group("value").replace("\\\\", "\\").replace('\\"', '"') if m else None


def find_steam_app_installation(app_id: int, exe_name: str) -> dict | None:
    for root in find_steam_roots():
        for library in get_steam_library_paths(root):
            steamapps = os.path.join(library, "steamapps")
            manifest = os.path.join(steamapps, f"appmanifest_{app_id}.acf")
            text = read_text(manifest)
            if not text:
                continue
            install_dir = get_install_dir_from_manifest(text)
            if not install_dir:
                continue
            game_dir = os.path.join(steamapps, "common", install_dir)
            exe_path = find_ci(game_dir, exe_name)
            if exe_path and os.path.isfile(exe_path):
                return {"SteamRoot": root, "LibraryPath": library, "SteamAppsPath": steamapps,
                        "GameDirectory": game_dir, "ExecutablePath": exe_path}
    return None


# --------------------------------------------------------------------------- #
# Config files inside the Proton prefix
# --------------------------------------------------------------------------- #
def resolve_game_configuration_paths(game_directory: str, prefix: str | None) -> dict:
    local_path = user_path = None
    saved_games = find_ci(prefix, "drive_c", "users", "steamuser", "Saved Games") if prefix else None

    if saved_games:
        for rel in (("keen games", "Enshrouded", "local_settings.json"),):
            p = find_ci(saved_games, *rel)
            if p and os.path.isfile(p):
                local_path = p
                break
        for rel in (("Enshrouded", "migrated", "enshrouded_user.json"),
                    ("Enshrouded", "enshrouded_user.json")):
            p = find_ci(saved_games, *rel)
            if p and os.path.isfile(p):
                user_path = p
                break

    if not local_path:  # legacy location
        legacy = find_ci(game_directory, "enshrouded_local.json")
        if legacy and os.path.isfile(legacy):
            local_path = legacy
    return {"LocalPath": local_path, "UserPath": user_path}


def set_native_resolution_configuration(cfg: dict, width: int, height: int) -> dict:
    graphics = cfg.get("graphics")
    if not graphics:
        raise RuntimeError("The 'graphics' object does not exist in the local settings JSON.")
    window_size = graphics.get("windowSize")
    if not window_size:
        raise RuntimeError("The 'graphics.windowSize' object does not exist in the local settings JSON.")
    if "x" not in window_size or "y" not in window_size:
        raise RuntimeError("The 'graphics.windowSize' object does not contain both 'x' and 'y' properties.")
    window_size["x"] = width
    window_size["y"] = height
    return cfg


def set_minimum_fov_configuration(cfg: dict) -> dict:
    if not cfg.get("graphics"):
        cfg["graphics"] = {}
    cfg["graphics"]["fov"] = "42480000"
    return cfg


def get_primary_display_resolution() -> tuple | None:
    """Current mode of the primary output via xrandr (works on X11 and XWayland)."""
    out = run_cmd(["xrandr", "--current"])
    if not out:
        return None
    current, first = None, None
    for line in out.splitlines():
        m = re.match(r"^(\S+) connected( primary)?", line)
        if m:
            current = bool(m.group(2))
            continue
        if re.match(r"^\S", line):
            current = None
            continue
        if current is None:
            continue
        m = re.match(r"^\s+(\d+)x(\d+)\S*\s+.*\*", line)
        if m:
            res = (int(m.group(1)), int(m.group(2)))
            if current:
                return res
            first = first or res
    return first


# --------------------------------------------------------------------------- #
# Cache cleanup
# --------------------------------------------------------------------------- #
def get_cache_cleanup_status(existing, initial, remaining, errors, verified=True) -> str:
    if not verified:
        return "Failed"
    if existing == 0:
        return "Missing"
    if initial == 0:
        return "Failed" if errors > 0 else "Empty"
    if remaining == 0:
        return "Done"
    if remaining < initial:
        return "Partial"
    return "Failed"


def _scan(path: str, recursive: bool) -> list:
    items, stack = [], [path]
    while stack:
        cur = stack.pop()
        with os.scandir(cur) as it:
            for entry in it:
                is_dir = entry.is_dir(follow_symlinks=False)
                items.append((entry.path, is_dir))
                if recursive and is_dir:
                    stack.append(entry.path)
    return items


def _rmtree_onerror(func, path, _exc):
    os.chmod(path, stat.S_IWRITE | stat.S_IREAD | stat.S_IEXEC)
    func(path)


def _force_remove(path: str) -> None:
    if os.path.isdir(path) and not os.path.islink(path):
        shutil.rmtree(path, onerror=_rmtree_onerror)
    else:
        os.remove(path)


def _filtered_files(path: str, pattern: str) -> list:
    return [p for p, is_dir in _scan(path, False)
            if not is_dir and fnmatch.fnmatch(os.path.basename(p).lower(), pattern.lower())]


def clear_cache_paths(paths: list, file_filter: str | None = None) -> dict:
    existing = [p for p in paths if p and os.path.isdir(p)]
    if not existing:
        return {"Status": "Missing", "InitialItemCount": 0, "RemainingItemCount": 0, "ErrorCount": 0,
                "VerificationSucceeded": True, "Errors": [], "RemainingItems": []}

    errors, initial, initial_ok = [], 0, True
    for path in existing:
        try:
            if not file_filter:
                initial += len(_scan(path, True))
                to_remove = [p for p, _ in _scan(path, False)]
            else:
                to_remove = _filtered_files(path, file_filter)
                initial += len(to_remove)
        except OSError as exc:
            initial_ok = False
            errors.append(f"{path}: {exc}")
            continue
        for item in to_remove:
            try:
                _force_remove(item)
            except Exception as exc:
                errors.append(f"{item}: {exc}")

    remaining, remaining_items, verified_ok = 0, [], True
    for path in existing:
        try:
            items = _scan(path, True) if not file_filter else [(p, False) for p in _filtered_files(path, file_filter)]
            for p, is_dir in items:
                remaining += 1
                if len(remaining_items) < 10:
                    remaining_items.append(f"{'Directory' if is_dir else 'File'}: {p}")
        except OSError as exc:
            verified_ok = False
            errors.append(f"{path}: {exc}")

    verified = verified_ok and initial_ok
    return {"Status": get_cache_cleanup_status(len(existing), initial, remaining, len(errors), verified),
            "InitialItemCount": initial, "RemainingItemCount": remaining, "ErrorCount": len(errors),
            "VerificationSucceeded": verified, "Errors": errors, "RemainingItems": remaining_items}


def write_cache_cleanup_result(result: dict) -> None:
    status = result["Status"]
    if status == "Done":
        log("Done", "green")
    elif status == "Partial":
        log(f"Partially cleared ({result['RemainingItemCount']} cache item(s) remain)", "yellow")
    elif status == "Empty":
        log("Nothing to clear", "green")
    elif status == "Missing":
        log("Nothing to clear (cache path not found)", "yellow")
    elif not result["VerificationSucceeded"]:
        log("Not Done (cache contents could not be fully verified)", "red")
    else:
        log(f"Not Done ({result['RemainingItemCount']} cache item(s) remain after cleanup)", "red")

    if status in ("Partial", "Failed"):
        if result["RemainingItems"]:
            log("  Remaining cache entries:", "yellow")
            for entry in result["RemainingItems"]:
                log(f"    {entry}", "yellow")
        if result["Errors"]:
            log("  Cleanup errors:", "yellow")
            for err in result["Errors"][:10]:
                log(f"    {err}", "yellow")
            if result["ErrorCount"] > 10:
                log(f"    ({result['ErrorCount'] - 10} more errors omitted)", "yellow")


# --------------------------------------------------------------------------- #
# Vulkan
# --------------------------------------------------------------------------- #
def test_vulkan_version_outdated(version: str) -> bool:
    parsed = parse_version(version)
    return parsed is not None and parsed < (1, 2)


def vulkan_manifest_dirs(kind: str) -> list:
    """kind: 'icd.d' or 'implicit_layer.d'"""
    home = os.path.expanduser("~")
    data_home = os.environ.get("XDG_DATA_HOME", os.path.join(home, ".local", "share"))
    data_dirs = os.environ.get("XDG_DATA_DIRS", "/usr/local/share:/usr/share").split(":")
    config_dirs = os.environ.get("XDG_CONFIG_DIRS", "/etc/xdg").split(":")
    dirs = ["/etc/vulkan/" + kind, os.path.join(data_home, "vulkan", kind)]
    dirs += [os.path.join(d, "vulkan", kind) for d in data_dirs if d]
    dirs += [os.path.join(d, "vulkan", kind) for d in config_dirs if d]
    out, seen = [], set()
    for d in dirs:
        real = os.path.realpath(d)
        if real not in seen and os.path.isdir(real):
            seen.add(real)
            out.append(real)
    return out


def get_vulkan_layer_metadata(json_path: str) -> list:
    content = read_game_json(json_path)
    meta = []
    if "layer" in content:
        layers = [content["layer"]]
    elif "layers" in content:
        layers = content["layers"] or []
    else:
        layers = []
    for layer in layers:
        meta.append({"ApiVersion": layer.get("api_version"), "Description": layer.get("description") or layer.get("name"),
                     "LibraryPath": layer.get("library_path")})
    if "ICD" in content:
        icd = content["ICD"]
        meta.append({"ApiVersion": icd.get("api_version"), "Description": None, "LibraryPath": icd.get("library_path")})
    return meta


def parse_vulkaninfo_summary(text: str) -> dict:
    instance = None
    m = re.search(r"Vulkan Instance Version:\s*([\d.]+)", text)
    if m:
        instance = m.group(1)
    devices, current = [], None
    for line in text.splitlines():
        if re.match(r"^GPU\d+:", line.strip()):
            current = {}
            devices.append(current)
            continue
        if current is not None:
            kv = re.match(r"^\s*(\w+)\s*=\s*(.*?)\s*$", line)
            if kv:
                current[kv.group(1)] = kv.group(2)
    return {"Instance": instance, "Devices": devices}


def check_vulkan() -> None:
    log("Checking Vulkan layer API versions...")
    found_any = False
    for kind, is_driver in (("implicit_layer.d", False), ("icd.d", True)):
        for directory in vulkan_manifest_dirs(kind):
            for json_path in sorted(glob.glob(os.path.join(directory, "*.json"))):
                found_any = True
                try:
                    metadata = get_vulkan_layer_metadata(json_path)
                except Exception:
                    log(f"Failed to parse Vulkan JSON: {json_path}", "red")
                    continue
                if not metadata:
                    log(f"File {json_path} contains no supported Vulkan metadata.", "red")
                    continue
                for md in metadata:
                    version = str(md["ApiVersion"]) if md["ApiVersion"] else "unknown"
                    desc = md["Description"] or os.path.basename(json_path)
                    if not test_vulkan_version_outdated(version):
                        if not is_driver:
                            log(desc, end="")
                            log(f" (v{version})", "green")
                    elif is_driver:
                        log(f"{desc} (v{version}) - The Vulkan driver is out of date, please update your video driver.", "red")
                    else:
                        log(desc, "red", end="")
                        log(f" (v{version}) - outdated layer; update or uninstall the package providing {json_path}",
                            "yellow")
    if not found_any:
        log("No Vulkan manifests found. Install your GPU's Vulkan driver package (e.g. mesa-vulkan-drivers / "
            "nvidia-utils).", "red")

    log()
    out = run_cmd(["vulkaninfo", "--summary"], timeout=30)
    if out is None:
        log("vulkaninfo not available (install vulkan-tools to see the detected Vulkan GPUs and driver versions).",
            "yellow")
        return
    info = parse_vulkaninfo_summary(out)
    log("Vulkan instance version: ", end="")
    log(info["Instance"] or "unknown", "green")
    for dev in info["Devices"]:
        name = dev.get("deviceName", "unknown device")
        api = dev.get("apiVersion", "unknown").split(" ")[0]
        driver = " ".join(x for x in (dev.get("driverName"), dev.get("driverInfo")) if x)
        is_software = "llvmpipe" in name.lower() or "software" in dev.get("deviceType", "").lower() \
            or "CPU" in dev.get("deviceType", "")
        if is_software:
            log(f"Device: {name} (Vulkan {api}) - SOFTWARE RENDERER, the game will not use your GPU!", "red")
        elif test_vulkan_version_outdated(api):
            log(f"Device: {name} (Vulkan {api}) {driver} - driver is out of date.", "red")
        else:
            log(f"Device: {name} (Vulkan {api}) {driver}", "green")


# --------------------------------------------------------------------------- #
# CPU / Intel microcode (read-only)
# --------------------------------------------------------------------------- #
_INTEL_RE = re.compile(r"(?i)\bi(?P<tier>[3579])-(?P<number>1[34][0-9]{3})(?P<suffix>[a-z0-9]*)\b")


def parse_cpuinfo(text: str | None = None) -> dict:
    text = text if text is not None else (read_text("/proc/cpuinfo") or "")
    info = {}
    for line in text.splitlines():
        if not line.strip():
            break  # first processor block only
        key, _, value = line.partition(":")
        info[key.strip()] = value.strip()
    return info


def get_intel_vmin_processor_classification(processor_name: str, manufacturer: str) -> dict:
    is_intel = bool(re.match(r"(?i)^(GenuineIntel|Intel)$", manufacturer or "")) or bool(
        re.search(r"(?i)\bIntel\b", processor_name or ""))
    if not is_intel:
        return {"Category": "NotIntel", "Model": None}
    m = _INTEL_RE.search(processor_name or "")
    if not m:
        cat = "Review" if re.search(r"(?i)\b(?:13th|14th)\s+Gen\b", processor_name or "") else "NotApplicable"
        return {"Category": cat, "Model": None}

    tier, number, suffix = m.group("tier"), m.group("number"), m.group("suffix").upper()
    model = f"i{tier}-{number}{suffix}"
    if re.fullmatch(r"(?i)(HX|HK|H|U|P|Y|G[0-9]*)", suffix):
        return {"Category": "NotApplicable", "Model": model}
    affected = (
        (tier == "9" and number in ("13900", "14900") and suffix in ("", "F", "K", "KF", "KS")) or
        (tier == "7" and number in ("13700", "14700") and suffix in ("", "F", "K", "KF")) or
        (tier == "7" and number in ("13790", "14790") and suffix == "F") or
        (tier == "5" and number in ("13600", "14600") and suffix in ("K", "KF"))
    )
    if affected:
        return {"Category": "Affected", "Model": model}
    if tier == "3" or (tier == "5" and not re.match(r"(?i)^K", suffix)):
        return {"Category": "NotApplicable", "Model": model}
    return {"Category": "Review", "Model": model}


def get_microcode_revision(cpuinfo: dict) -> int | None:
    raw = cpuinfo.get("microcode")
    if not raw:
        return None
    try:
        value = int(raw, 16)
    except ValueError:
        return None
    return value or None


def get_intel_vmin_assessment(name: str, vendor: str, revision) -> dict:
    cls = get_intel_vmin_processor_classification(name, vendor)
    status = cls["Category"]
    if status == "Affected":
        if not revision:
            status = "UnknownRevision"
        elif revision < 0x12F:
            status = "UpdateRecommended"
        else:
            status = "RecommendedRevisionLoaded"
    return {"Category": cls["Category"], "Model": cls["Model"], "Status": status, "MicrocodeRevision": revision}


def write_intel_vmin_assessment(a: dict) -> None:
    if a["Category"] in ("NotIntel", "NotApplicable"):
        return
    log()
    log("================ INTEL CPU MICROCODE CHECK ================", "yellow")
    log(f"CPU model: {a['Model'] or 'Unknown 13th/14th Gen Intel model'}")
    if a["MicrocodeRevision"]:
        log(f"Active microcode revision: 0x{a['MicrocodeRevision']:X}")
    else:
        log("Active microcode revision: Unknown", "yellow")

    board = " ".join(filter(None, (read_text("/sys/class/dmi/id/board_vendor"), read_text("/sys/class/dmi/id/board_name"))))
    bios = read_text("/sys/class/dmi/id/bios_version")
    if board:
        log(f"Motherboard: {board}")
    if bios:
        log(f"BIOS version: {bios}")

    status = a["Status"]
    if status == "UpdateRecommended":
        log("WARNING: This Intel processor is on the published Vmin Shift list.", "red")
        log("The active microcode is older than Intel recommendation 0x12F.", "red")
        log("Update your BIOS from the motherboard vendor (and the intel-ucode / microcode package for your distro).",
            "yellow")
    elif status == "UnknownRevision":
        log("WARNING: This Intel processor is on the published Vmin Shift list.", "red")
        log("The active microcode revision could not be verified.", "yellow")
        log("Check your latest BIOS and microcode version with the manufacturer.", "yellow")
    elif status == "RecommendedRevisionLoaded":
        log("Active microcode meets the Intel 0x12F minimum recommendation.", "green")
        log("This does not establish that the BIOS itself is current (the OS may be loading newer microcode).",
            "yellow")
    elif status == "Review":
        log("This 13th/14th Gen Intel model could not be confidently classified.", "yellow")
        log("Review its applicability and BIOS updates with the manufacturer.", "yellow")

    log("Enable Intel Default Settings and follow your system vendor BIOS guidance.", "yellow")
    log("This tool will never install or modify BIOS firmware.", "yellow")
    log("Intel guidance: https://www.intel.com/content/www/us/en/support/articles/000102331/processors.html", "cyan")
    log("===========================================================", "yellow")


# --------------------------------------------------------------------------- #
# Memory / swap / GPU
# --------------------------------------------------------------------------- #
def get_mem_total_gb() -> int | None:
    text = read_text("/proc/meminfo") or ""
    m = re.search(r"MemTotal:\s+(\d+)\s*kB", text)
    return round(int(m.group(1)) / 1024 ** 2) if m else None


def get_swap_info() -> dict:
    text = read_text("/proc/swaps") or ""
    total_kib, zram = 0, False
    for line in text.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 3 and parts[2].isdigit():
            total_kib += int(parts[2])
            zram = zram or "zram" in parts[0]
    return {"TotalGiB": total_kib / 1024 ** 2, "Zram": zram}


def get_max_map_count() -> int | None:
    value = read_text("/proc/sys/vm/max_map_count")
    return int(value) if value and value.isdigit() else None


_VENDORS = {"0x10de": "NVIDIA", "0x1002": "AMD", "0x8086": "Intel"}


def _lspci_name(slot: str | None) -> str | None:
    if not slot:
        return None
    out = run_cmd(["lspci", "-s", slot, "-mm"])
    if not out:
        return None
    try:
        fields = shlex.split(out.splitlines()[0])
    except (ValueError, IndexError):
        return None
    return f"{fields[2]} {fields[3]}" if len(fields) >= 4 else None


def list_gpus() -> list:
    gpus = []
    for card in sorted(glob.glob("/sys/class/drm/card*")):
        if not re.fullmatch(r"card\d+", os.path.basename(card)):
            continue
        dev = os.path.join(card, "device")
        vendor_id = (read_text(os.path.join(dev, "vendor")) or "").lower()
        if not vendor_id:
            continue
        uevent = read_text(os.path.join(dev, "uevent")) or ""
        slot = re.search(r"PCI_SLOT_NAME=(\S+)", uevent)
        slot = slot.group(1) if slot else None
        vram = read_text(os.path.join(dev, "mem_info_vram_total"))
        driver_link = os.path.join(dev, "driver")
        gpus.append({
            "Vendor": _VENDORS.get(vendor_id, vendor_id),
            "Name": _lspci_name(slot) or f"{_VENDORS.get(vendor_id, vendor_id)} GPU ({read_text(os.path.join(dev, 'device'))})",
            "VramBytes": int(vram) if vram and vram.isdigit() else None,
            "KernelDriver": os.path.basename(os.path.realpath(driver_link)) if os.path.exists(driver_link) else None,
            "DriverVersion": None,
        })

    out = run_cmd(["nvidia-smi", "--query-gpu=name,memory.total,driver_version", "--format=csv,noheader,nounits"])
    if out:
        smi = [[c.strip() for c in line.split(",")] for line in out.strip().splitlines() if line.strip()]
        nvidia = [g for g in gpus if g["Vendor"] == "NVIDIA"]
        for gpu, row in zip(nvidia, smi):
            if len(row) >= 3:
                gpu["Name"] = row[0]
                if row[1].isdigit():
                    gpu["VramBytes"] = int(row[1]) * 1024 ** 2
                gpu["DriverVersion"] = row[2]
    return gpus


def is_game_running() -> list:
    pids = []
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        try:
            with open(os.path.join("/proc", entry, "cmdline"), "rb") as fh:
                argv = fh.read().decode("utf-8", errors="replace").split("\0")
        except OSError:
            continue
        # Match an argument that IS the exe (Wine passes Z:\...\enshrouded.exe), not any text mentioning it.
        if any(re.split(r"[\\/]", a)[-1].lower() == "enshrouded.exe" for a in argv if a):
            pids.append(int(entry))
    return pids


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def run(args) -> int:
    if os.path.exists(LOG_FILE_PATH):
        os.remove(LOG_FILE_PATH)

    log(f"Script version: {TOOL_VERSION}")
    log(f"Hostname: {os.uname().nodename}", "green")
    log()

    running = is_game_running()
    if running:
        log(f"Enshrouded appears to be running (PID {', '.join(map(str, running))}). "
            "Close the game first so settings and caches are not overwritten.", "red")
        return 1

    installation = find_steam_app_installation(GAME_ID, "enshrouded.exe")
    if not installation:
        if not find_steam_roots():
            log("Steam was not found (checked ~/.local/share/Steam, ~/.steam/steam, Flatpak and Snap locations).", "red")
        else:
            log(f"Enshrouded (Steam AppID {GAME_ID}) was not found in any configured Steam library.", "red")
        return 1

    game_directory = installation["GameDirectory"]
    steamapps = installation["SteamAppsPath"]
    prefix = os.path.join(steamapps, "compatdata", str(GAME_ID), "pfx")
    prefix = prefix if os.path.isdir(prefix) else None

    log(f"Found installed game in: {game_directory}")
    if prefix:
        log(f"Proton prefix: {prefix}")
    else:
        log("Proton prefix not found. Launch the game once through Steam Play so it is created, then re-run.",
            "yellow")
    log()

    # ---- Vulkan ------------------------------------------------------------
    check_vulkan()
    log()

    # ---- Caches ------------------------------------------------------------
    cache_home = os.environ.get("XDG_CACHE_HOME", os.path.join(os.path.expanduser("~"), ".cache"))

    if not args.skip_gpu_cache:
        nvidia_paths = [os.path.join(os.path.expanduser("~"), ".nv", "GLCache"),
                        os.path.join(cache_home, "nvidia", "GLCache")]
        if any(os.path.exists(p) for p in nvidia_paths):
            log("Clearing nVidia GPU cache: ", end="")
            write_cache_cleanup_result(clear_cache_paths(nvidia_paths))

        mesa_paths = [os.path.join(cache_home, "mesa_shader_cache"), os.path.join(cache_home, "mesa_shader_cache_db")]
        if any(os.path.exists(p) for p in mesa_paths):
            log("Clearing Mesa (AMD/Intel) shader cache: ", end="")
            write_cache_cleanup_result(clear_cache_paths(mesa_paths))
        log("(GPU driver caches are shared by all games; they rebuild automatically.)", "yellow")

    steam_shader_cache = os.path.join(steamapps, "shadercache", str(GAME_ID))
    log(f"Clearing Steam shader cache in {steam_shader_cache}/: ", end="")
    write_cache_cleanup_result(clear_cache_paths([steam_shader_cache]))

    game_cache = find_ci(prefix, "drive_c", "users", "steamuser", "AppData", "Local", "enshrouded", "caches") \
        if prefix else None
    game_cache_label = game_cache or "<prefix>/.../AppData/Local/enshrouded/caches"
    log(f"Clearing game shader cache in {game_cache_label}/: ", end="")
    write_cache_cleanup_result(clear_cache_paths([game_cache] if game_cache else [], "*.bin"))

    log()
    log("After starting the game, it will start recompiling shaders after entering your world, shader compilation "
        "will continue (this will take some time ~10 min), you can observe the progress at the bottom of the menu "
        "by pressing ESC", "yellow")

    # ---- Config files ------------------------------------------------------
    log()
    config_paths = resolve_game_configuration_paths(game_directory, prefix)

    log("Set the native resolution for the game: ", end="")
    if config_paths["LocalPath"]:
        try:
            resolution = args.resolution or get_primary_display_resolution()
            if not resolution:
                raise RuntimeError("Could not detect the display resolution (xrandr missing?). "
                                   "Pass --resolution WxH.")
            cfg = read_game_json(config_paths["LocalPath"])
            cfg = set_native_resolution_configuration(cfg, resolution[0], resolution[1])
            save_formatted_json(cfg, config_paths["LocalPath"])
            log(f"Done ({resolution[0]}x{resolution[1]}) [{config_paths['LocalPath']}]", "green")
        except Exception as exc:
            log(f"Not Done ({exc})", "red")
    else:
        log("Not Done (local_settings.json and legacy enshrouded_local.json not found)", "yellow")

    log()
    log("Set the minimum FOV in the game: ", end="")
    if config_paths["UserPath"]:
        try:
            cfg = read_game_json(config_paths["UserPath"])
            cfg = set_minimum_fov_configuration(cfg)
            save_formatted_json(cfg, config_paths["UserPath"])
            log(f"Done [{config_paths['UserPath']}]", "green")
            log("In the future, you can increase the FOV in the game settings if it stops crashing.", "yellow")
        except Exception as exc:
            log(f"Not Done ({exc})", "red")
    else:
        log("Not Done (migrated and legacy enshrouded_user.json not found)", "yellow")

    # ---- CPU governor / GameMode (advice only) ----------------------------
    log()
    governor = read_text("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor")
    log("CPU frequency governor: ", end="")
    if governor is None:
        log("unknown", "yellow")
    elif governor == "performance":
        log(governor, "green")
    else:
        log(governor, "yellow")
        log("For best performance while gaming: `powerprofilesctl set performance` or "
            "`sudo cpupower frequency-set -g performance`.", "yellow")
    log("Feral GameMode: ", end="")
    if shutil.which("gamemoderun"):
        log("installed - set the Steam launch option to `gamemoderun %command%`", "green")
    else:
        log("not installed (optional; provides `gamemoderun %command%` for Steam launch options)", "yellow")

    # ---- CPU ---------------------------------------------------------------
    log()
    log("CPU Info...")
    cpu = parse_cpuinfo()
    cpu_name = cpu.get("model name", "Unknown")
    cpu_vendor = cpu.get("vendor_id", "")
    log(f"Name CPU: {cpu_name}")
    log("AVX support: ", end="")
    if "avx" in cpu.get("flags", "").split():
        log("Yes", "green")
    else:
        log("No", "red")
        log()
        log("Unfortunately, your processor does not support the AVX instruction set, the game will not be able "
            "to start without this set.", "red")

    classification = get_intel_vmin_processor_classification(cpu_name, cpu_vendor)
    if classification["Category"] in ("Affected", "Review"):
        write_intel_vmin_assessment(get_intel_vmin_assessment(cpu_name, cpu_vendor, get_microcode_revision(cpu)))

    # ---- Memory / swap / max_map_count ------------------------------------
    log()
    oom_found = None
    game_log = find_ci(game_directory, "enshrouded.log")
    if game_log and os.path.isfile(game_log):
        oom_found = "Could not allocate new memory block, error: out of memory" in (read_text(game_log) or "")

    swap = get_swap_info()
    log("Swap: ", end="")
    if swap["TotalGiB"] > 0:
        log(f"{swap['TotalGiB']:.1f} GiB{' (zram)' if swap['Zram'] else ''}", "green")
    else:
        log("none configured", "yellow")
    if oom_found:
        log("The message 'Out of memory' was found in the game log file.", "yellow")
        if swap["TotalGiB"] == 0:
            log("If the game crashes immediately, enable swap or zram (e.g. systemd-zram-generator / zram-tools).",
                "yellow")
    elif oom_found is False:
        log("The message 'Out of memory' was not found in the game log file.", "yellow")

    max_map = get_max_map_count()
    log("vm.max_map_count: ", end="")
    if max_map is None:
        log("unknown", "yellow")
    elif max_map >= 1048576:
        log(str(max_map), "green")
    else:
        log(f"{max_map} (low)", "red")
        log("Low values are a common cause of out-of-memory style crashes in Proton games. To raise it:", "yellow")
        log("  sudo sysctl -w vm.max_map_count=1048576", "cyan")
        log("  echo 'vm.max_map_count=1048576' | sudo tee /etc/sysctl.d/80-gamecompatibility.conf", "cyan")

    log()
    ram_gb = get_mem_total_gb()
    log("RAM: ", end="")
    if ram_gb is None:
        log("unknown", "yellow")
    elif ram_gb < 16:
        log(f"{ram_gb} GB", "red")
        log("Attention: the amount of RAM is less than 16 GB", "yellow")
        log("It is very likely that the game will show you a warning that your system does not meet the minimum "
            "requirements. You can acknowledge this message and proceed at your own risk.", "yellow")
    else:
        log(f"{ram_gb} GB", "green")

    # ---- GPU ---------------------------------------------------------------
    log()
    gpus = list_gpus()
    if not gpus:
        log("Video Card: Unknown", "yellow")
    for gpu in gpus:
        vram_gb = round(gpu["VramBytes"] / 1024 ** 3) if gpu["VramBytes"] else None
        extra = f", driver {gpu['KernelDriver']}" if gpu["KernelDriver"] else ""
        if gpu["DriverVersion"]:
            extra += f" {gpu['DriverVersion']}"
        log("Video Card: ", end="")
        if vram_gb is None:
            log(f"{gpu['Name']} (VRAM unknown{extra})", "yellow")
        elif vram_gb < 6:
            log(f"{gpu['Name']} ({vram_gb} GB{extra})", "red")
            log("Attention: the amount of video memory is less than 6 GB", "yellow")
        else:
            log(f"{gpu['Name']} ({vram_gb} GB{extra})", "green")

    log()
    log("The Texture Resolution setting affects the amount of video memory consumed by the game:", "yellow")
    log("Performance (~5 GB), Balanced (~5.5 GB), Quality (~6.5 GB), Max.Quality (~8.5 GB)", "yellow")
    log()
    log("It's recommended to update your video card drivers if you have an older version and a newer one is "
        "available.", "yellow")
    log("After that, you must run this utility again to check the Vulkan API version.", "yellow")
    log()

    vendors = {g["Vendor"] for g in gpus}
    if "NVIDIA" in vendors:
        log("Link to the latest video driver: ", end="")
        log("(https://www.nvidia.com/Download/index.aspx)", "green")
        log("You can also try the beta driver for Vulkan: ", end="")
        log("(https://developer.nvidia.com/vulkan-driver)", "green")
    if "AMD" in vendors or "Intel" in vendors:
        log("AMD/Intel use the open-source Mesa driver; update it through your distro (or a Mesa PPA/Copr).", "green")
    if not vendors:
        log("Video card not recognized.")

    # ---- Wrap up -----------------------------------------------------------
    log()
    log('Even if after all the corrections you have made, the game continues to crash after some time, most likely '
        'the problem is in the game itself. Either you have a very large and complex "castle", or you have a large '
        'number of crops. (This problem seems to be known to developers and it remains only to wait for patches.)',
        "yellow")
    log()

    stamp = datetime.datetime.now().strftime("%Y-%m-%dT%H-%M-%S")
    log_directory = os.path.join(game_directory, "Enshrouded_Tool_Fix")
    try:
        os.makedirs(log_directory, exist_ok=True)
        destination = os.path.join(log_directory, f"Enshrouded_Tool_Fix_{stamp}.log")
        shutil.copy2(LOG_FILE_PATH, destination)
        os.remove(LOG_FILE_PATH)
        print(f"Log saved to: {destination}")
    except OSError as exc:
        print(f"Could not save the log into the game folder ({exc}); it remains at {LOG_FILE_PATH}")
    return 0


def _resolution_arg(text: str) -> tuple:
    m = re.fullmatch(r"(\d{3,5})[xX](\d{3,5})", text)
    if not m:
        raise argparse.ArgumentTypeError("expected WIDTHxHEIGHT, e.g. 2560x1440")
    return int(m.group(1)), int(m.group(2))


def main() -> None:
    parser = argparse.ArgumentParser(description="Enshrouded Tool Fix (Linux / Proton)")
    parser.add_argument("--resolution", type=_resolution_arg, metavar="WxH",
                        help="use this resolution instead of detecting it with xrandr")
    parser.add_argument("--skip-gpu-cache", action="store_true",
                        help="do not clear the shared NVIDIA/Mesa driver shader caches")
    args = parser.parse_args()

    if not sys.platform.startswith("linux"):
        print("This edition is for Linux only.")
        sys.exit(1)
    if os.geteuid() == 0:
        print("Do not run this as root: it would create root-owned files in your Steam/Proton folders. "
              "Run it as your normal user.")
        sys.exit(1)
    sys.exit(run(args))


if __name__ == "__main__":
    main()
