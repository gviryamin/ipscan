#!/usr/bin/env python3
"""
Site Network Scanner - Multi Range Field MVP

Local browser-based scanner for authorized field work.
Supports multiple targets:
- 192.168.1.0/24
- 192.168.1.10
- 192.168.1.10-192.168.1.50
- 172.19.1.0-172.19.65.0/24  -> scans every /24 from 172.19.1.0/24 to 172.19.65.0/24

Use only on networks you own or are explicitly authorized to scan.
"""

from __future__ import annotations

import csv
import html
import ipaddress
import json
import platform
import re
import socket
import subprocess
import threading
import urllib.request
import webbrowser
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Dict, List, Tuple

APP_HOST = "127.0.0.1"
APP_PORT = 8765
REPORTS_DIR = Path("reports")
REPORTS_DIR.mkdir(exist_ok=True)

DEFAULT_PORTS = [21, 22, 23, 80, 443, 554, 8000, 8080, 8443, 37777, 8899]

VENDOR_HINTS = {
    "44:19:B6": "Hikvision", "BC:AD:28": "Hikvision", "E0:CA:3C": "Hikvision", "C0:56:E3": "Hikvision",
    "24:52:6A": "Dahua", "3C:EF:8C": "Dahua", "90:02:A9": "Dahua",
    "FC:EC:DA": "Ubiquiti", "78:8A:20": "Ubiquiti", "24:A4:3C": "Ubiquiti", "F0:9F:C2": "Ubiquiti", "E0:63:DA": "Ubiquiti",
    "00:1B:2F": "Cisco", "00:1E:13": "Cisco", "00:23:04": "Cisco", "00:25:45": "Cisco",
    "A0:F3:C1": "TP-Link", "50:C7:BF": "TP-Link", "D8:47:32": "TP-Link",
    "00:90:2B": "PLANET", "00:30:4F": "PLANET",
}

CAMERA_KEYWORDS = ["hikvision", "dahua", "axis", "hanwha", "vivotek", "rtsp", "camera", "ip camera", "nvr", "dvr"]
NETWORK_KEYWORDS = ["cisco", "ubiquiti", "mikrotik", "tp-link", "switch", "router", "gateway", "planet", "d-link", "netgear"]

SCAN_STATE = {
    "running": False,
    "started_at": None,
    "finished_at": None,
    "progress": 0,
    "total": 0,
    "message": "Idle",
    "targets_text": "",
    "target_ranges": [],
    "results": [],
    "last_report_csv": None,
    "last_report_html": None,
}

STATE_LOCK = threading.Lock()


@dataclass
class DeviceResult:
    ip: str
    alive: bool
    hostname: str = ""
    mac: str = ""
    vendor: str = ""
    open_ports: str = ""
    http_title: str = ""
    device_type: str = "Unknown"
    confidence: str = "Low"
    notes: str = ""


def get_local_network_guess() -> str:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(("8.8.8.8", 80))
        local_ip = sock.getsockname()[0]
        sock.close()
        return ".".join(local_ip.split(".")[:3]) + ".0/24"
    except Exception:
        return "192.168.1.0/24"


def split_target_lines(targets_text: str) -> List[str]:
    items: List[str] = []
    for line in targets_text.splitlines():
        clean = line.split("#", 1)[0].strip()
        if clean:
            items.extend(part.strip() for part in clean.split(",") if part.strip())
    return items


def expand_subnet_range(raw: str) -> List[str]:
    left, right_with_prefix = raw.split("-", 1)
    right, prefix_text = right_with_prefix.split("/", 1)
    prefix = int(prefix_text)
    start_net = ipaddress.ip_network(f"{left.strip()}/{prefix}", strict=False)
    end_net = ipaddress.ip_network(f"{right.strip()}/{prefix}", strict=False)
    if start_net.version != 4 or end_net.version != 4:
        raise ValueError("Only IPv4 is supported")
    if int(start_net.network_address) > int(end_net.network_address):
        raise ValueError("Subnet range start must be lower than end")
    step = start_net.num_addresses
    current = int(start_net.network_address)
    end = int(end_net.network_address)
    ips: List[str] = []
    while current <= end:
        network = ipaddress.ip_network((current, prefix), strict=False)
        ips.extend(str(ip) for ip in network.hosts())
        current += step
    return ips


def expand_ip_range(raw: str) -> List[str]:
    left, right = raw.split("-", 1)
    start = ipaddress.ip_address(left.strip())
    end = ipaddress.ip_address(right.strip())
    if start.version != 4 or end.version != 4:
        raise ValueError("Only IPv4 is supported")
    if int(start) > int(end):
        raise ValueError("IP range start must be lower than end")
    return [str(ipaddress.ip_address(value)) for value in range(int(start), int(end) + 1)]


def parse_scan_targets(targets_text: str) -> Tuple[List[str], List[str]]:
    items = split_target_lines(targets_text) or [get_local_network_guess()]
    seen = set()
    ordered_ips: List[str] = []
    normalized_ranges: List[str] = []
    for item in items:
        try:
            if "-" in item and "/" in item:
                ips = expand_subnet_range(item)
                normalized_ranges.append(item)
            elif "-" in item:
                ips = expand_ip_range(item)
                normalized_ranges.append(item)
            elif "/" in item:
                network = ipaddress.ip_network(item, strict=False)
                if network.version != 4:
                    raise ValueError("Only IPv4 is supported")
                ips = [str(ip) for ip in network.hosts()]
                normalized_ranges.append(str(network))
            else:
                ip = ipaddress.ip_address(item)
                if ip.version != 4:
                    raise ValueError("Only IPv4 is supported")
                ips = [str(ip)]
                normalized_ranges.append(str(ip))
        except Exception as exc:
            raise ValueError(f"Invalid target '{item}': {exc}") from exc
        for ip in ips:
            if ip not in seen:
                seen.add(ip)
                ordered_ips.append(ip)
    return ordered_ips, normalized_ranges


def normalize_mac(mac: str) -> str:
    mac = mac.strip().upper().replace("-", ":")
    parts = mac.split(":")
    return ":".join(part.zfill(2) for part in parts) if len(parts) == 6 else mac


def vendor_from_mac(mac: str) -> str:
    prefix = ":".join(normalize_mac(mac).split(":")[:3])
    return VENDOR_HINTS.get(prefix, "")


def ping_host(ip: str, timeout_ms: int = 800) -> bool:
    system = platform.system().lower()
    cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip] if "windows" in system else ["ping", "-c", "1", "-W", "1", ip]
    try:
        return subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3).returncode == 0
    except Exception:
        return False


def tcp_port_open(ip: str, port: int, timeout: float = 0.45) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except Exception:
        return False


def resolve_hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def read_arp_table() -> Dict[str, str]:
    arp_map: Dict[str, str] = {}
    try:
        output = subprocess.check_output(["arp", "-a"], stderr=subprocess.DEVNULL, text=True, encoding="utf-8", errors="ignore")
    except Exception:
        return arp_map
    ip_re = re.compile(r"(\d+\.\d+\.\d+\.\d+)")
    mac_re = re.compile(r"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})")
    for line in output.splitlines():
        ip_match = ip_re.search(line)
        mac_match = mac_re.search(line)
        if ip_match and mac_match:
            arp_map[ip_match.group(1)] = normalize_mac(mac_match.group(0))
    return arp_map


def fetch_http_title(ip: str, port: int, timeout: float = 1.2) -> str:
    scheme = "https" if port in (443, 8443) else "http"
    try:
        req = urllib.request.Request(f"{scheme}://{ip}:{port}/", headers={"User-Agent": "SiteNetworkScanner/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as response:
            content = response.read(8192).decode("utf-8", errors="ignore")
            match = re.search(r"<title[^>]*>(.*?)</title>", content, re.IGNORECASE | re.DOTALL)
            return re.sub(r"\s+", " ", match.group(1)).strip()[:120] if match else ""
    except Exception:
        return ""


def classify_device(hostname: str, vendor: str, open_ports: List[int], http_title: str) -> Tuple[str, str, str]:
    text = " ".join([hostname, vendor, http_title, " ".join(map(str, open_ports))]).lower()
    notes: List[str] = []
    has_rtsp = 554 in open_ports
    has_camera_service = 8000 in open_ports or 37777 in open_ports
    has_web = any(port in open_ports for port in [80, 443, 8080, 8443])
    has_network_mgmt = 22 in open_ports or 23 in open_ports
    if any(k in text for k in CAMERA_KEYWORDS) or has_rtsp or has_camera_service:
        if has_rtsp: notes.append("RTSP open, common for IP cameras/NVRs")
        if 8000 in open_ports: notes.append("Port 8000 open, common on Hikvision devices")
        if 37777 in open_ports: notes.append("Port 37777 open, common on Dahua devices")
        return "IP Camera / NVR", "High", "; ".join(notes)
    if any(k in text for k in NETWORK_KEYWORDS) or has_network_mgmt:
        if has_network_mgmt: notes.append("SSH/Telnet open, possible managed network device")
        if has_web: notes.append("Web management interface detected")
        return "Managed Network Device", "High" if any(k in text for k in NETWORK_KEYWORDS) else "Medium", "; ".join(notes)
    if has_web:
        return "Web Device", "Medium", "Web interface detected; manual verification recommended"
    return "Unknown", "Low", "Active device; not automatically classified"


def scan_one(ip: str, ports: List[int]) -> DeviceResult:
    alive = ping_host(ip)
    open_ports = [port for port in ports if tcp_port_open(ip, port)]
    if not alive and not open_ports:
        return DeviceResult(ip=ip, alive=False)
    hostname = resolve_hostname(ip)
    http_title = ""
    for web_port in [80, 443, 8080, 8443]:
        if web_port in open_ports:
            http_title = fetch_http_title(ip, web_port)
            if http_title:
                break
    return DeviceResult(ip=ip, alive=True, hostname=hostname, open_ports=",".join(map(str, open_ports)), http_title=http_title)


def enrich_results(results: List[DeviceResult]) -> None:
    arp = read_arp_table()
    for item in results:
        item.mac = arp.get(item.ip, "")
        item.vendor = vendor_from_mac(item.mac) if item.mac else ""
        ports = [int(port) for port in item.open_ports.split(",") if port.strip().isdigit()]
        item.device_type, item.confidence, item.notes = classify_device(item.hostname, item.vendor, ports, item.http_title)


def generate_reports(results: List[DeviceResult], site_name: str, target_ranges: List[str]) -> Tuple[str, str]:
    label = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    safe_site = re.sub(r"[^\w\-א-ת]+", "_", site_name.strip() or "site")
    csv_path = REPORTS_DIR / f"{safe_site}_network_scan_{label}.csv"
    html_path = REPORTS_DIR / f"{safe_site}_network_scan_{label}.html"
    fields = list(asdict(DeviceResult(ip="", alive=False)).keys())
    with csv_path.open("w", newline="", encoding="utf-8-sig") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=fields)
        writer.writeheader()
        for result in results:
            writer.writerow(asdict(result))
    cameras = [r for r in results if r.device_type == "IP Camera / NVR"]
    network = [r for r in results if r.device_type == "Managed Network Device"]
    unknown = [r for r in results if r.device_type not in ("IP Camera / NVR", "Managed Network Device")]
    range_list = "".join(f"<li>{html.escape(r)}</li>" for r in target_ranges)
    rows = "".join(f"""
        <tr><td>{html.escape(r.ip)}</td><td>{html.escape(r.device_type)}</td><td>{html.escape(r.confidence)}</td><td>{html.escape(r.vendor)}</td><td>{html.escape(r.mac)}</td><td>{html.escape(r.hostname)}</td><td>{html.escape(r.open_ports)}</td><td>{html.escape(r.http_title)}</td><td>{html.escape(r.notes)}</td></tr>
    """ for r in sorted(results, key=lambda x: tuple(int(p) for p in x.ip.split("."))))
    html_doc = f"""<!doctype html><html lang="he" dir="rtl"><head><meta charset="utf-8" />
<title>דוח סריקת רשת - {html.escape(site_name)}</title>
<style>
body{{font-family:Arial,sans-serif;margin:28px;background:#f6f7fb;color:#111827}} h1{{margin-bottom:6px}} .meta{{color:#4b5563;margin-bottom:18px}} .cards{{display:grid;grid-template-columns:repeat(4,minmax(140px,1fr));gap:12px;margin-bottom:22px}} .card{{background:white;border-radius:14px;padding:16px;box-shadow:0 6px 18px rgba(15,23,42,.08)}} .card strong{{display:block;font-size:28px;margin-bottom:5px}} .ranges{{background:white;border-radius:14px;padding:16px;margin-bottom:18px;box-shadow:0 6px 18px rgba(15,23,42,.08)}} table{{width:100%;border-collapse:collapse;background:white;border-radius:14px;overflow:hidden;box-shadow:0 6px 18px rgba(15,23,42,.08)}} th,td{{padding:10px;border-bottom:1px solid #e5e7eb;text-align:right;font-size:13px;vertical-align:top}} th{{background:#111827;color:white}} .footer{{margin-top:20px;color:#6b7280;font-size:12px}}
</style></head><body>
<h1>דוח סריקת רשת - {html.escape(site_name)}</h1>
<div class="meta">נוצר בתאריך {datetime.now().strftime('%d/%m/%Y %H:%M:%S')} | כלי שטח מקומי</div>
<div class="cards"><div class="card"><strong>{len(results)}</strong>סה״כ ציוד שזוהה</div><div class="card"><strong>{len(cameras)}</strong>מצלמות / NVR</div><div class="card"><strong>{len(network)}</strong>ציוד תקשורת מנוהל</div><div class="card"><strong>{len(unknown)}</strong>לא מסווג / דורש בדיקה</div></div>
<div class="ranges"><b>טווחים שנסרקו:</b><ul>{range_list}</ul></div>
<table><thead><tr><th>IP</th><th>סוג ציוד</th><th>ביטחון</th><th>יצרן</th><th>MAC</th><th>Hostname</th><th>פורטים פתוחים</th><th>כותרת WEB</th><th>הערות</th></tr></thead><tbody>{rows}</tbody></table>
<div class="footer">הדוח מבוסס על סריקת זמינות, פורטים, ARP, זיהוי בסיסי לפי MAC וכותרות WEB. יש לאמת ידנית ציוד קריטי בשטח.</div>
</body></html>"""
    html_path.write_text(html_doc, encoding="utf-8")
    return str(csv_path), str(html_path)


def run_scan(site_name: str, targets_text: str, ports: List[int], max_workers: int) -> None:
    try:
        ips, target_ranges = parse_scan_targets(targets_text)
    except Exception as exc:
        with STATE_LOCK:
            SCAN_STATE.update({"running": False, "message": f"Invalid scan targets: {exc}"})
        return
    with STATE_LOCK:
        SCAN_STATE.update({"running": True, "started_at": datetime.now().isoformat(timespec="seconds"), "finished_at": None, "progress": 0, "total": len(ips), "message": "Scanning...", "targets_text": targets_text, "target_ranges": target_ranges, "results": [], "last_report_csv": None, "last_report_html": None})
    found: List[DeviceResult] = []
    max_workers = max(8, min(max_workers, 256))
    completed = 0
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(scan_one, ip, ports): ip for ip in ips}
        for future in as_completed(futures):
            completed += 1
            try:
                result = future.result()
                if result.alive:
                    found.append(result)
            except Exception:
                pass
            if completed % 10 == 0 or completed == len(ips):
                with STATE_LOCK:
                    SCAN_STATE["progress"] = completed
                    SCAN_STATE["results"] = [asdict(item) for item in found]
                    SCAN_STATE["message"] = f"Scanning {completed}/{len(ips)} | Found {len(found)} devices"
    enrich_results(found)
    csv_path, html_path = generate_reports(found, site_name, target_ranges)
    with STATE_LOCK:
        SCAN_STATE.update({"running": False, "finished_at": datetime.now().isoformat(timespec="seconds"), "progress": len(ips), "results": [asdict(item) for item in found], "last_report_csv": csv_path, "last_report_html": html_path, "message": f"Done. Scanned {len(ips)} IPs. Found {len(found)} active devices."})


class AppHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        return

    def send_json(self, payload, status: int = 200) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_html(self, body: str, status: int = 200) -> None:
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        if self.path == "/":
            self.send_html(INDEX_HTML.replace("__CIDR_GUESS__", html.escape(get_local_network_guess())))
            return
        if self.path == "/api/state":
            with STATE_LOCK:
                self.send_json(SCAN_STATE.copy())
            return
        if self.path.startswith("/download?"):
            params = dict(part.split("=", 1) for part in self.path.split("?", 1)[1].split("&") if "=" in part)
            kind = params.get("type", "")
            with STATE_LOCK:
                file_path = SCAN_STATE.get("last_report_csv") if kind == "csv" else SCAN_STATE.get("last_report_html")
            if not file_path or not Path(file_path).exists():
                self.send_error(404, "Report not found")
                return
            content = Path(file_path).read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "text/csv; charset=utf-8" if kind == "csv" else "text/html; charset=utf-8")
            self.send_header("Content-Disposition", f"attachment; filename={Path(file_path).name}")
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
            return
        self.send_error(404)

    def do_POST(self) -> None:
        if self.path != "/api/scan":
            self.send_error(404)
            return
        length = int(self.headers.get("Content-Length", "0"))
        payload = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
        with STATE_LOCK:
            if SCAN_STATE["running"]:
                self.send_json({"ok": False, "error": "Scan already running"}, 409)
                return
        raw_ports = payload.get("ports", "")
        try:
            ports = sorted({int(port.strip()) for port in str(raw_ports).split(",") if port.strip()}) if raw_ports else DEFAULT_PORTS
        except Exception:
            ports = DEFAULT_PORTS
        thread = threading.Thread(target=run_scan, args=(payload.get("site_name", "לקוח"), payload.get("targets", get_local_network_guess()), ports, int(payload.get("workers", 96))), daemon=True)
        thread.start()
        self.send_json({"ok": True})


INDEX_HTML = """<!doctype html><html lang="he" dir="rtl"><head><meta charset="utf-8" /><meta name="viewport" content="width=device-width, initial-scale=1" /><title>Site Network Scanner</title>
<style>
*{box-sizing:border-box} body{margin:0;font-family:Arial,sans-serif;background:linear-gradient(135deg,#0f172a,#1e293b);color:#fff}.header{padding:28px;max-width:1200px;margin:auto}.header h1{margin:0 0 8px;font-size:32px}.header p{margin:0;color:#cbd5e1}.wrap{max-width:1200px;margin:auto;padding:0 28px 28px}.panel{background:#fff;color:#111827;border-radius:22px;padding:22px;box-shadow:0 18px 50px rgba(0,0,0,.25)}.form{display:grid;grid-template-columns:1fr 1.7fr 1.2fr .7fr auto;gap:12px;align-items:end}label{display:block;font-weight:700;margin-bottom:6px}input,textarea{width:100%;padding:12px;border:1px solid #cbd5e1;border-radius:12px;font-size:15px;font-family:Arial,sans-serif}textarea{min-height:92px;resize:vertical;direction:ltr;text-align:left}button{padding:13px 18px;border:0;border-radius:12px;background:#111827;color:#fff;font-weight:700;cursor:pointer}button:disabled{opacity:.55;cursor:not-allowed}.help{margin-top:10px;color:#64748b;font-size:13px;line-height:1.6}.status{margin-top:18px;padding:14px;border-radius:14px;background:#f8fafc;border:1px solid #e5e7eb;color:#334155}.progress{height:12px;background:#e5e7eb;border-radius:999px;overflow:hidden;margin-top:10px}.bar{height:100%;width:0%;background:#2563eb;transition:.2s}.actions{display:flex;gap:10px;flex-wrap:wrap;margin:16px 0}.actions a{text-decoration:none;background:#e2e8f0;color:#111827;padding:10px 12px;border-radius:10px;font-weight:700}.summary{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:16px 0}.sum{background:#f8fafc;border:1px solid #e5e7eb;border-radius:14px;padding:14px}.sum strong{display:block;font-size:26px}table{width:100%;border-collapse:collapse;margin-top:14px}th,td{padding:10px;border-bottom:1px solid #e5e7eb;text-align:right;font-size:13px;vertical-align:top}th{background:#f1f5f9}.badge{padding:4px 8px;border-radius:999px;display:inline-block;font-size:12px;font-weight:700}.cam{background:#dbeafe;color:#1e40af}.net{background:#dcfce7;color:#166534}.unk{background:#f1f5f9;color:#334155}.footer{color:#cbd5e1;margin-top:16px;font-size:12px}@media(max-width:1000px){.form,.summary{grid-template-columns:1fr}}
</style></head><body><div class="header"><h1>Site Network Scanner</h1><p>סריקת רשת מקומית לזיהוי מצלמות IP וציוד תקשורת מנוהל, עם תמיכה בכמה טווחים.</p></div><div class="wrap"><div class="panel"><div class="form"><div><label>שם אתר / לקוח</label><input id="site" value="לקוח" /></div><div><label>טווחים לסריקה</label><textarea id="targets">__CIDR_GUESS__</textarea></div><div><label>פורטים לבדיקה</label><input id="ports" value="21,22,23,80,443,554,8000,8080,8443,37777,8899" /></div><div><label>מהירות</label><input id="workers" value="96" /></div><button id="start">התחל סריקה</button></div><div class="help">אפשר לכתוב כמה שורות. דוגמאות: <code>192.168.1.0/24</code> | <code>192.168.1.10-192.168.1.50</code> | <code>172.19.1.0-172.19.65.0/24</code></div><div class="status"><div id="msg">Idle</div><div class="progress"><div id="bar" class="bar"></div></div></div><div class="actions" id="downloads"></div><div class="summary"><div class="sum"><strong id="total">0</strong>סה״כ זוהו</div><div class="sum"><strong id="cams">0</strong>מצלמות / NVR</div><div class="sum"><strong id="nets">0</strong>ציוד תקשורת</div><div class="sum"><strong id="unknown">0</strong>דורש בדיקה</div></div><table><thead><tr><th>IP</th><th>סוג</th><th>ביטחון</th><th>יצרן</th><th>MAC</th><th>Hostname</th><th>פורטים</th><th>WEB</th><th>הערות</th></tr></thead><tbody id="rows"></tbody></table></div><div class="footer">מיועד לסריקה ברשתות מורשות בלבד. הכל רץ מקומית על הלפטופ.</div></div><script>
const $=id=>document.getElementById(id);$('start').onclick=async()=>{$('start').disabled=true;await fetch('/api/scan',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({site_name:$('site').value,targets:$('targets').value,ports:$('ports').value,workers:$('workers').value})});};function badge(type){let c=type.includes('Camera')?'cam':type.includes('Managed')?'net':'unk';return `<span class="badge ${c}">${type}</span>`}async function refresh(){const s=await fetch('/api/state').then(r=>r.json());$('msg').textContent=s.message||'Idle';const pct=s.total?Math.round((s.progress/s.total)*100):0;$('bar').style.width=pct+'%';$('start').disabled=!!s.running;const results=s.results||[];$('total').textContent=results.length;$('cams').textContent=results.filter(x=>x.device_type==='IP Camera / NVR').length;$('nets').textContent=results.filter(x=>x.device_type==='Managed Network Device').length;$('unknown').textContent=results.filter(x=>!['IP Camera / NVR','Managed Network Device'].includes(x.device_type)).length;$('rows').innerHTML=results.sort((a,b)=>a.ip.localeCompare(b.ip,undefined,{numeric:true})).map(r=>`<tr><td>${r.ip||''}</td><td>${badge(r.device_type||'Unknown')}</td><td>${r.confidence||''}</td><td>${r.vendor||''}</td><td>${r.mac||''}</td><td>${r.hostname||''}</td><td>${r.open_ports||''}</td><td>${r.http_title||''}</td><td>${r.notes||''}</td></tr>`).join('');$('downloads').innerHTML=s.last_report_csv?`<a href="/download?type=csv">הורד CSV</a><a href="/download?type=html">הורד דוח HTML</a>`:'';}setInterval(refresh,1200);refresh();
</script></body></html>"""


def main() -> None:
    server = ThreadingHTTPServer((APP_HOST, APP_PORT), AppHandler)
    url = f"http://{APP_HOST}:{APP_PORT}"
    print(f"Site Network Scanner running at {url}")
    print("Use only on networks you are authorized to scan.")
    webbrowser.open(url)
    server.serve_forever()


if __name__ == "__main__":
    main()
