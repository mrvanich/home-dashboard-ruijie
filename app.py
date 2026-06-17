#!/usr/bin/env python3
"""Wake-on-LAN Dashboard - Flask backend with persistence, LAN scan, and monitoring."""

import os
import json
import subprocess
import re
import socket
import glob
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from flask import Flask, render_template, request, jsonify

app = Flask(__name__)

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
DATA_FILE = os.path.join(DATA_DIR, "machines.json")
RUIJIE_WAN_SCRIPT = os.path.join(os.path.dirname(__file__), "scripts", "ruijie_wan.js")
WAN_CACHE_TTL = 600  # 10 minutes
_wan_cache = {"ts": 0, "data": None}
os.makedirs(DATA_DIR, exist_ok=True)

MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$")
IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def load_machines():
    if not os.path.exists(DATA_FILE):
        return []
    try:
        with open(DATA_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, list) else []
    except Exception:
        return []


def save_machines(machines):
    with open(DATA_FILE, "w", encoding="utf-8") as f:
        json.dump(machines, f, indent=2, ensure_ascii=False)


def normalize_mac(mac: str):
    if not mac:
        return None
    cleaned = re.sub(r"[^0-9a-fA-F]", "", mac)
    if len(cleaned) != 12:
        return None
    return ":".join(cleaned[i : i + 2].upper() for i in range(0, 12, 2))


def find_by_mac(machines, mac):
    for m in machines:
        if m.get("mac") == mac:
            return m
    return None


def ip_to_int(ip: str) -> int:
    parts = ip.split(".")
    return (int(parts[0]) << 24) + (int(parts[1]) << 16) + (int(parts[2]) << 8) + int(parts[3])


def ping_host(ip: str, timeout: float = 1.0) -> bool:
    if not IP_RE.match(ip):
        return False
    try:
        proc = subprocess.run(
            ["ping", "-c", "1", "-W", str(max(1, int(timeout))), ip],
            capture_output=True,
            text=True,
            timeout=timeout + 2,
        )
        return proc.returncode == 0
    except Exception:
        return False


def resolve_netbios(ip: str) -> str:
    """Resolve NetBIOS / Windows computer name for an IP."""
    # nmblookup -A <ip>
    try:
        proc = subprocess.run(
            ["nmblookup", "-A", ip],
            capture_output=True,
            text=True,
            timeout=4,
        )
        for line in (proc.stdout or "").splitlines():
            line = line.strip()
            if "<00>" in line and "GROUP" not in line.upper():
                name = line.split()[0].strip()
                if name and name != "*":
                    return name
    except Exception:
        pass

    # nbtscan fallback (single host)
    try:
        proc = subprocess.run(
            ["nbtscan", "-v", "-s", ":", ip],
            capture_output=True,
            text=True,
            timeout=5,
        )
        for line in (proc.stdout or "").splitlines():
            if line.startswith("IP address"):
                continue
            parts = line.split(":")
            if len(parts) >= 2 and parts[0].strip() == ip:
                name = parts[1].strip()
                if name and name != "<unknown>":
                    return name
    except Exception:
        pass

    return ""


def resolve_hostname(ip: str) -> str:
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        if host and not host.startswith(ip):
            return host.split(".")[0]
    except Exception:
        pass
    return ""


def resolve_device_name(ip: str) -> dict:
    netbios = resolve_netbios(ip)
    hostname = resolve_hostname(ip)
    display = netbios or hostname or ""
    return {"netbios": netbios, "hostname": hostname, "display_name": display}


def get_arp_table() -> dict:
    """Return MAC -> IP mapping from ARP cache."""
    mac_to_ip = {}
    try:
        proc = subprocess.run(
            ["ip", "-4", "neigh", "show"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        for line in (proc.stdout or "").splitlines():
            m = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+dev\s+\S+\s+lladdr\s+([0-9a-f:]+)", line, re.I)
            if m:
                mac_to_ip[m.group(2).upper()] = m.group(1)
    except Exception:
        pass
    return mac_to_ip


def enrich_machine(m: dict, arp_table: dict | None = None) -> dict:
    out = dict(m)
    mac = out.get("mac", "")
    ip = out.get("ip") or (arp_table or {}).get(mac, "")
    out["ip"] = ip
    online = ping_host(ip) if ip else False
    out["online"] = online
    if ip:
        names = resolve_device_name(ip)
        out.update(names)
    else:
        out.update({"netbios": "", "hostname": "", "display_name": ""})
    return out


def parse_arp_scan(text: str):
    devices = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("Interface", "Starting", "Ending")) or "packets received" in line:
            continue
        parts = re.split(r"\s+", line, maxsplit=2)
        if len(parts) >= 2 and MAC_RE.match(parts[1]):
            devices.append(
                {
                    "ip": parts[0],
                    "mac": parts[1].upper().replace("-", ":"),
                    "vendor": parts[2] if len(parts) > 2 else "",
                }
            )
    seen, out = set(), []
    for d in devices:
        if d["mac"] not in seen:
            seen.add(d["mac"])
            out.append(d)
    return out


def enrich_devices(devices: list) -> list:
    """Add netbios, hostname, online status to scanned devices."""
    if not devices:
        return []

    def _enrich_one(d):
        ip = d["ip"]
        online = ping_host(ip)
        names = resolve_device_name(ip)
        return {**d, "online": online, **names}

    enriched = []
    with ThreadPoolExecutor(max_workers=min(16, len(devices))) as pool:
        futures = {pool.submit(_enrich_one, d): d for d in devices}
        for fut in as_completed(futures):
            try:
                enriched.append(fut.result())
            except Exception:
                enriched.append({**futures[fut], "online": False, "netbios": "", "hostname": "", "display_name": ""})

    enriched.sort(key=lambda x: ip_to_int(x["ip"]))
    return enriched


def read_cpu_temps() -> list:
    temps = []
    for path in sorted(glob.glob("/sys/class/thermal/thermal_zone*/temp")):
        zone_dir = os.path.dirname(path)
        zone_type = "unknown"
        type_path = os.path.join(zone_dir, "type")
        if os.path.exists(type_path):
            with open(type_path, encoding="utf-8") as f:
                zone_type = f.read().strip()
        try:
            with open(path, encoding="utf-8") as f:
                raw = int(f.read().strip())
            temps.append({"zone": zone_type, "celsius": round(raw / 1000, 1)})
        except Exception:
            continue
    return temps


def read_system_stats() -> dict:
    stats = {"hostname": socket.gethostname(), "timestamp": datetime.now().isoformat(timespec="seconds")}

    # Uptime
    try:
        with open("/proc/uptime", encoding="utf-8") as f:
            secs = float(f.read().split()[0])
        days, rem = divmod(int(secs), 86400)
        hours, rem = divmod(rem, 3600)
        mins, _ = divmod(rem, 60)
        stats["uptime"] = f"{days}d {hours}h {mins}m"
        stats["uptime_seconds"] = int(secs)
    except Exception:
        stats["uptime"] = "—"

    # Load average
    try:
        with open("/proc/loadavg", encoding="utf-8") as f:
            parts = f.read().split()
        stats["load"] = {"1m": float(parts[0]), "5m": float(parts[1]), "15m": float(parts[2])}
    except Exception:
        stats["load"] = {}

    # Memory
    try:
        mem = {}
        with open("/proc/meminfo", encoding="utf-8") as f:
            for line in f:
                k, v = line.split(":", 1)
                mem[k.strip()] = int(v.strip().split()[0])
        total = mem.get("MemTotal", 0)
        avail = mem.get("MemAvailable", mem.get("MemFree", 0))
        stats["memory"] = {
            "total_mb": round(total / 1024),
            "available_mb": round(avail / 1024),
            "used_mb": round((total - avail) / 1024),
            "used_pct": round((total - avail) / total * 100, 1) if total else 0,
        }
    except Exception:
        stats["memory"] = {}

    # Disk
    try:
        proc = subprocess.run(["df", "-h", "/"], capture_output=True, text=True, timeout=5)
        lines = proc.stdout.strip().splitlines()
        if len(lines) >= 2:
            parts = lines[1].split()
            stats["disk"] = {"size": parts[1], "used": parts[2], "avail": parts[3], "use_pct": parts[4]}
    except Exception:
        stats["disk"] = {}

    stats["temperatures"] = read_cpu_temps()
    if stats["temperatures"]:
        stats["cpu_temp"] = stats["temperatures"][0]["celsius"]
    else:
        stats["cpu_temp"] = None

    # CPU count
    try:
        stats["cpu_cores"] = os.cpu_count() or 1
    except Exception:
        stats["cpu_cores"] = 1

    return stats


@app.route("/")
def index():
    machines = load_machines()
    return render_template("index.html", machines=machines, subnet="192.168.24.0/24")


@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html", subnet="192.168.24.0/24")


@app.route("/api/machines")
def api_machines():
    arp = get_arp_table()
    machines = [enrich_machine(m, arp) for m in load_machines()]
    return jsonify(machines)


@app.route("/api/add", methods=["POST"])
def api_add():
    payload = request.get_json(silent=True) or request.form
    name = (payload.get("name") or "Device").strip()[:64]
    mac = normalize_mac(payload.get("mac", ""))
    ip = (payload.get("ip") or "").strip()
    if ip and not IP_RE.match(ip):
        ip = ""
    if not mac:
        return jsonify({"error": "Invalid MAC address"}), 400
    machines = load_machines()
    if find_by_mac(machines, mac):
        return jsonify({"error": "This MAC is already saved"}), 409
    entry = {"name": name, "mac": mac, "last_wake": None}
    if ip:
        entry["ip"] = ip
    machines.append(entry)
    save_machines(machines)
    return jsonify({"ok": True, "machines": machines})


@app.route("/api/update", methods=["POST"])
def api_update():
    payload = request.get_json(silent=True) or {}
    mac = normalize_mac(payload.get("mac", ""))
    name = (payload.get("name") or "").strip()[:64]
    ip = (payload.get("ip") or "").strip()
    if not mac or not name:
        return jsonify({"error": "Name and MAC required"}), 400
    machines = load_machines()
    m = find_by_mac(machines, mac)
    if m:
        m["name"] = name
        if ip and IP_RE.match(ip):
            m["ip"] = ip
        save_machines(machines)
    return jsonify({"ok": True, "machines": machines})


@app.route("/api/delete", methods=["POST"])
def api_delete():
    payload = request.get_json(silent=True) or {}
    mac = normalize_mac(payload.get("mac", ""))
    machines = [m for m in load_machines() if m.get("mac") != mac]
    save_machines(machines)
    return jsonify({"ok": True, "machines": machines})


@app.route("/api/wake", methods=["POST"])
def api_wake():
    payload = request.get_json(silent=True) or {}
    mac = normalize_mac(payload.get("mac", ""))
    if not mac:
        return jsonify({"success": False, "error": "Invalid MAC"}), 400
    try:
        proc = subprocess.run(["wakeonlan", mac], capture_output=True, text=True, timeout=12)
        success = proc.returncode == 0
        out = (proc.stdout or "") + (proc.stderr or "")
    except Exception as exc:
        success = False
        out = str(exc)
    now = datetime.now().isoformat(timespec="seconds")
    machines = load_machines()
    m = find_by_mac(machines, mac)
    if m and success:
        m["last_wake"] = now
        save_machines(machines)
    return jsonify(
        {
            "success": success,
            "output": out.strip(),
            "time": now if success else None,
            "machines": machines if success else None,
        }
    )


@app.route("/api/scan")
def api_scan():
    try:
        res = subprocess.run(
            ["sudo", "-n", "arp-scan", "--localnet", "--quiet"],
            capture_output=True,
            text=True,
            timeout=28,
        )
        if res.returncode == 0 and res.stdout.strip():
            devs = enrich_devices(parse_arp_scan(res.stdout))
            return jsonify({"devices": devs, "method": "arp-scan"})
        res2 = subprocess.run(
            ["ip", "-4", "neigh", "show", "nud", "reachable", "stale", "delay"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        devs = []
        for line in (res2.stdout or "").splitlines():
            m = re.search(r"(\d+\.\d+\.\d+\.\d+).+lladdr\s+([0-9a-f:]+)", line, re.I)
            if m:
                devs.append({"ip": m.group(1), "mac": m.group(2).upper(), "vendor": "(ARP cache)"})
        devs = enrich_devices(devs)
        return jsonify({"devices": devs, "method": "ip-neigh"})
    except Exception as e:
        return jsonify({"error": str(e), "devices": []}), 500


@app.route("/api/system")
def api_system():
    return jsonify(read_system_stats())


def fetch_wan_stats(force: bool = False) -> dict:
    global _wan_cache
    now = time.time()
    if not force and _wan_cache["data"] and (now - _wan_cache["ts"]) < WAN_CACHE_TTL:
        out = dict(_wan_cache["data"])
        out["cached"] = True
        out["cache_age_sec"] = int(now - _wan_cache["ts"])
        return out
    try:
        proc = subprocess.run(
            ["node", RUIJIE_WAN_SCRIPT],
            capture_output=True,
            text=True,
            timeout=25,
            cwd=os.path.dirname(RUIJIE_WAN_SCRIPT),
        )
        data = json.loads((proc.stdout or "").strip() or "{}")
    except Exception as exc:
        data = {"ok": False, "error": str(exc), "upload_bps": None, "download_bps": None}
    if data.get("ok"):
        _wan_cache = {"ts": now, "data": data}
    data["cached"] = False
    return data


@app.route("/api/wan")
def api_wan():
    force = request.args.get("refresh") == "1"
    return jsonify(fetch_wan_stats(force=force))


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5002, debug=False)
