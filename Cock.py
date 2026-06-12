#!/usr/bin/env python3
"""
IP Camera Scanner - Legitimate Maintenance & Security Audit Tool
================================================================
For authorized network administrators and camera maintenance personnel only.
Always obtain proper authorization before scanning any network or device.
"""

import socket
import threading
import ipaddress
import subprocess
import sys
import json
import time
import re
import ssl
import http.client
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from itertools import zip_longest
from datetime import datetime
from collections import defaultdict

# ─────────────────────────────────────────────
#  Configuration
# ─────────────────────────────────────────────

CAMERA_PORTS = {
    80:   "HTTP (web interface)",
    443:  "HTTPS (secure web interface)",
    554:  "RTSP (video stream)",
    8080: "HTTP Alt / Admin panel",
    8443: "HTTPS Alt",
    8554: "RTSP Alt",
    37777:"Dahua TCP",
    34567:"Generic DVR",
    5000: "UPnP / Synology",
    9000: "Hikvision SDK",
    1935: "RTMP stream",
    22:   "SSH",
    23:   "Telnet (INSECURE)",
    21:   "FTP (firmware/logs)",
}

DEFAULT_CREDENTIALS = [
    ("admin",    "admin"),
    ("admin",    ""),
    ("admin",    "12345"),
    ("admin",    "123456"),
    ("admin",    "password"),
    ("root",     "root"),
    ("root",     ""),
    ("root",     "12345"),
    ("user",     "user"),
    ("guest",    "guest"),
]

CAMERA_BANNERS = [
    "hikvision", "dahua", "axis", "bosch", "hanwha", "vivotek",
    "reolink", "amcrest", "foscam", "uniview", "cp plus", "honeywell",
    "pelco", "panasonic", "sony", "rtsp", "ipcam", "dvr", "nvr",
    "camera", "webcam", "netcam", "ip cam",
]

TIMEOUT   = 3     # seconds per port check
MAX_WORKERS = 100 # concurrent threads

# ANSI colors
R  = "\033[91m"
G  = "\033[92m"
Y  = "\033[93m"
B  = "\033[94m"
M  = "\033[95m"
C  = "\033[96m"
W  = "\033[97m"
DIM= "\033[2m"
RST= "\033[0m"
BOLD="\033[1m"

# ─────────────────────────────────────────────
#  Helpers
# ─────────────────────────────────────────────

def banner():
    with open("cock.txt", "r", encoding="utf-8") as f:
        cock = f.read().splitlines()

    with open("cigarra.txt", "r", encoding="utf-8") as f:
        roach = f.read().splitlines()

    width = max(len(line) for line in cock)

    for left, right in zip_longest(cock, roach, fillvalue=""):
        print(f"{C}{BOLD}{left.ljust(width + 4)}{right}{RST}")

    print()
    print(f"{C}{BOLD}-> Created by: {W}DreamsignX{C}")
    print(f"{C}{BOLD}-> Twitter: {W}https://x.com/DreamsignXx{C}")
    print(f"{C}{BOLD}-> Report errors at: {W}DreamsignX@proton.me{RST}")
    
    print()
    print(f"{R}---------------- New Scan ----------------{RST}")

def ts():
    return datetime.now().strftime("%H:%M:%S")

def log(level, msg):
    colors = {"INFO": B, "OK": G, "WARN": Y, "CRIT": R, "SCAN": C}
    c = colors.get(level, W)
    print(f"  {DIM}[{ts()}]{RST} {c}[{level}]{RST} {msg}")

def resolve_host(target):
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return None

def expand_targets(raw):
    """Accept IPs, CIDR ranges, hostnames, comma-separated or newline-separated."""
    targets = []
    for part in re.split(r"[,\s]+", raw.strip()):
        part = part.strip()
        if not part:
            continue
        try:
            net = ipaddress.ip_network(part, strict=False)
            targets.extend(str(h) for h in net.hosts())
        except ValueError:
            ip = resolve_host(part)
            if ip:
                targets.append(ip)
            else:
                log("WARN", f"Cannot resolve: {part}")
    return list(set(targets))

# ─────────────────────────────────────────────
#  Port Scanner
# ─────────────────────────────────────────────

def check_port(ip, port):
    try:
        with socket.create_connection((ip, port), timeout=TIMEOUT) as s:
            s.settimeout(TIMEOUT)
            try:
                banner_raw = s.recv(1024).decode(errors="ignore").strip()
            except Exception:
                banner_raw = ""
            return True, banner_raw
    except Exception:
        return False, ""

def grab_http_banner(ip, port, use_ssl=False):
    """Try to fetch HTTP title/server header for fingerprinting."""
    proto = "https" if use_ssl else "http"
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        url = f"{proto}://{ip}:{port}/"
        req = urllib.request.Request(url, headers={"User-Agent": "CameraScanner/1.0"})
        resp = urllib.request.urlopen(req, timeout=TIMEOUT, context=ctx if use_ssl else None)
        body = resp.read(2048).decode(errors="ignore")
        server = resp.headers.get("Server", "")
        title_m = re.search(r"<title>(.*?)</title>", body, re.I)
        title = title_m.group(1).strip() if title_m else ""
        return server, title, body
    except Exception:
        return "", "", ""

def is_camera_fingerprint(server, title, body, tcp_banner):
    combined = (server + title + body + tcp_banner).lower()
    return any(kw in combined for kw in CAMERA_BANNERS)

# ─────────────────────────────────────────────
#  Vulnerability / Maintenance Checks
# ─────────────────────────────────────────────

def check_default_credentials(ip, port, use_ssl=False):
    """Test common default credentials on the HTTP interface."""
    found = []
    proto = "https" if use_ssl else "http"
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    for user, pwd in DEFAULT_CREDENTIALS:
        try:
            passman = urllib.request.HTTPPasswordMgrWithDefaultRealm()
            url = f"{proto}://{ip}:{port}/"
            passman.add_password(None, url, user, pwd)
            auth_handler = urllib.request.HTTPBasicAuthHandler(passman)
            if use_ssl:
                opener = urllib.request.build_opener(auth_handler,
                    urllib.request.HTTPSHandler(context=ctx))
            else:
                opener = urllib.request.build_opener(auth_handler)
            resp = opener.open(url, timeout=TIMEOUT)
            if resp.status in (200, 301, 302):
                found.append((user, pwd))
                break   # one hit is enough for the report
        except urllib.error.HTTPError as e:
            if e.code == 401:
                continue
        except Exception:
            continue
    return found

def check_rtsp_stream(ip, port=554):
    """Check whether an RTSP stream is accessible without credentials."""
    try:
        with socket.create_connection((ip, port), timeout=TIMEOUT) as s:
            s.sendall(b"OPTIONS rtsp://" + ip.encode() + b"/ RTSP/1.0\r\nCSeq: 1\r\n\r\n")
            resp = s.recv(512).decode(errors="ignore")
            if "RTSP/1.0 200" in resp:
                return True, "Unauthenticated RTSP OPTIONS accepted"
            if "RTSP/1.0 401" in resp:
                return False, "RTSP requires authentication (good)"
            return False, resp[:80]
    except Exception:
        return False, ""

def check_telnet(ip):
    open_, banner_raw = check_port(ip, 23)
    return open_, banner_raw

def check_ssh_version(ip):
    open_, banner_raw = check_port(ip, 22)
    if open_ and banner_raw:
        old = any(v in banner_raw for v in ["SSH-1.", "OpenSSH_5", "OpenSSH_4", "OpenSSH_3"])
        return True, banner_raw[:80], old
    return open_, "", False

def check_ftp_anon(ip):
    try:
        with socket.create_connection((ip, 21), timeout=TIMEOUT) as s:
            s.recv(256)
            s.sendall(b"USER anonymous\r\n")
            r1 = s.recv(256).decode(errors="ignore")
            s.sendall(b"PASS scanner@scan.local\r\n")
            r2 = s.recv(256).decode(errors="ignore")
            if "230" in r2:
                return True, "Anonymous FTP login accepted!"
            return False, "Authentication required"
    except Exception:
        return False, ""

# ─────────────────────────────────────────────
#  Per-host scan
# ─────────────────────────────────────────────

def scan_host(ip):
    result = {
        "ip": ip,
        "open_ports": {},
        "is_camera": False,
        "fingerprint": {},
        "vulnerabilities": [],
        "maintenance": [],
        "risk": "LOW",
    }

    # 1. Port sweep
    for port, desc in CAMERA_PORTS.items():
        open_, tcp_banner = check_port(ip, port)
        if open_:
            result["open_ports"][port] = {"desc": desc, "banner": tcp_banner}

    if not result["open_ports"]:
        return result  # host unreachable / no relevant ports

    # 2. HTTP fingerprinting on web ports
    for port in (80, 8080, 8443, 443):
        if port not in result["open_ports"]:
            continue
        use_ssl = port in (443, 8443)
        server, title, body = grab_http_banner(ip, port, use_ssl)
        if server or title:
            result["fingerprint"][port] = {"server": server, "title": title}
            tcp_banner = result["open_ports"][port]["banner"]
            if is_camera_fingerprint(server, title, body, tcp_banner):
                result["is_camera"] = True

    # Also check TCP banners
    for port, info in result["open_ports"].items():
        if is_camera_fingerprint("", "", "", info["banner"]):
            result["is_camera"] = True

    # 3. Vulnerability checks
    vulns  = result["vulnerabilities"]
    maint  = result["maintenance"]

    # Telnet open
    if 23 in result["open_ports"]:
        vulns.append({
            "severity": "CRITICAL",
            "issue":    "Telnet (port 23) is open — unencrypted remote access",
            "fix":      "Disable Telnet immediately. Use SSH instead.",
        })

    # FTP anonymous
    if 21 in result["open_ports"]:
        anon, msg = check_ftp_anon(ip)
        if anon:
            vulns.append({
                "severity": "HIGH",
                "issue":    "FTP anonymous login accepted on port 21",
                "fix":      "Disable anonymous FTP. Enable authentication.",
            })
        else:
            maint.append("FTP port 21 open — ensure firmware/log access is restricted.")

    # SSH version
    if 22 in result["open_ports"]:
        _, ssh_banner, old_ssh = check_ssh_version(ip)
        if old_ssh:
            vulns.append({
                "severity": "HIGH",
                "issue":    f"Outdated SSH version detected: {ssh_banner}",
                "fix":      "Update SSH server to OpenSSH 8.x+ and disable SSHv1.",
            })
        else:
            maint.append(f"SSH open — verify key-based auth is enforced. Banner: {ssh_banner[:60]}")

    # Default credentials on HTTP
    for port in (80, 8080):
        if port in result["open_ports"]:
            creds = check_default_credentials(ip, port, use_ssl=False)
            if creds:
                u, p = creds[0]
                vulns.append({
                    "severity": "CRITICAL",
                    "issue":    f"Default credentials work on port {port}: {u}/{p}",
                    "fix":      "Change password immediately to a strong unique password.",
                })
    for port in (443, 8443):
        if port in result["open_ports"]:
            creds = check_default_credentials(ip, port, use_ssl=True)
            if creds:
                u, p = creds[0]
                vulns.append({
                    "severity": "CRITICAL",
                    "issue":    f"Default credentials work on port {port}: {u}/{p}",
                    "fix":      "Change password immediately to a strong unique password.",
                })

    # Unauthenticated RTSP
    if 554 in result["open_ports"]:
        rtsp_open, rtsp_msg = check_rtsp_stream(ip)
        if rtsp_open:
            vulns.append({
                "severity": "HIGH",
                "issue":    f"RTSP stream accessible without authentication: {rtsp_msg}",
                "fix":      "Enable RTSP authentication in camera settings.",
            })
        else:
            maint.append(f"RTSP port 554 open — {rtsp_msg}")

    # HTTP without HTTPS
    has_http  = 80  in result["open_ports"] or 8080 in result["open_ports"]
    has_https = 443 in result["open_ports"] or 8443 in result["open_ports"]
    if has_http and not has_https:
        vulns.append({
            "severity": "MEDIUM",
            "issue":    "Web interface only on plain HTTP — credentials sent in cleartext",
            "fix":      "Enable HTTPS (port 443) and redirect HTTP to HTTPS.",
        })

    # HTTPS without HTTP (good, note it)
    if has_https and not has_http:
        maint.append("HTTPS only — good. Verify TLS certificate is valid and not self-signed.")

    # Both HTTP and HTTPS
    if has_http and has_https:
        maint.append("Both HTTP and HTTPS open — ensure HTTP redirects to HTTPS.")

    # General maintenance
    if result["is_camera"]:
        maint.append("Schedule regular firmware update checks (monthly recommended).")
        maint.append("Verify NTP time sync — timestamps matter for incident review.")
        maint.append("Check motion detection zones and recording schedule are correct.")
        maint.append("Confirm video retention policy meets compliance requirements.")

    # Risk scoring
    crit = sum(1 for v in vulns if v["severity"] == "CRITICAL")
    high = sum(1 for v in vulns if v["severity"] == "HIGH")
    med  = sum(1 for v in vulns if v["severity"] == "MEDIUM")
    if crit:
        result["risk"] = "CRITICAL"
    elif high:
        result["risk"] = "HIGH"
    elif med:
        result["risk"] = "MEDIUM"
    elif maint:
        result["risk"] = "LOW"
    else:
        result["risk"] = "OK"

    return result

# ─────────────────────────────────────────────
#  Reporting
# ─────────────────────────────────────────────

RISK_COLOR = {
    "CRITICAL": R, "HIGH": R, "MEDIUM": Y, "LOW": B, "OK": G
}
SEV_COLOR  = {"CRITICAL": R, "HIGH": R, "MEDIUM": Y, "LOW": B}

def print_host_report(r):
    rc = RISK_COLOR.get(r["risk"], W)
    cam_tag = f"{C}[CAMERA]{RST}" if r["is_camera"] else f"{DIM}[device]{RST}"
    print(f"\n  {BOLD}{r['ip']}{RST}  {cam_tag}  Risk: {rc}{BOLD}{r['risk']}{RST}")

    if r["open_ports"]:
        print(f"    {DIM}Open ports:{RST}")
        for port, info in sorted(r["open_ports"].items()):
            fp = r["fingerprint"].get(port, {})
            detail = fp.get("title") or fp.get("server") or info["banner"][:60]
            detail_str = f"  {detail}" if detail else ""
            print(f"      {G}{port:5}{RST}  {info['desc']}{DIM}{detail_str}{RST}")

    if r["vulnerabilities"]:
        print(f"    {R}Vulnerabilities:{RST}")
        for v in r["vulnerabilities"]:
            sc = SEV_COLOR.get(v["severity"], W)
            print(f"      {sc}[{v['severity']}]{RST} {v['issue']}")
            print(f"        {DIM} Fix: {v['fix']}{RST}")

    if r["maintenance"]:
        print(f"    {Y}Maintenance notes:{RST}")
        for m in r["maintenance"]:
            print(f"      {Y}•{RST} {m}")

def print_summary(results, elapsed):
    total       = len(results)
    reachable   = [r for r in results if r["open_ports"]]
    cameras     = [r for r in results if r["is_camera"]]
    crit_hosts  = [r for r in results if r["risk"] == "CRITICAL"]
    high_hosts  = [r for r in results if r["risk"] == "HIGH"]
    med_hosts   = [r for r in results if r["risk"] == "MEDIUM"]
    ok_hosts    = [r for r in results if r["risk"] in ("LOW", "OK")]

    total_vulns = sum(len(r["vulnerabilities"]) for r in results)
    crit_vulns  = sum(1 for r in results for v in r["vulnerabilities"] if v["severity"]=="CRITICAL")
    high_vulns  = sum(1 for r in results for v in r["vulnerabilities"] if v["severity"]=="HIGH")

    print(f"\n{C}{BOLD}{'═'*60}")
    print(f"  SCAN SUMMARY")
    print(f"{'═'*60}{RST}")
    print(f"  Scanned:    {total} hosts   ({elapsed:.1f}s)")
    print(f"  Reachable:  {len(reachable)}")
    print(f"  Cameras:    {C}{len(cameras)}{RST}")
    print(f"  Findings:   {R}{total_vulns} vulnerabilities{RST}  "
          f"({R}{crit_vulns} critical{RST}, {R}{high_vulns} high{RST})")
    print(f"\n  Risk breakdown:")
    print(f"    {R}CRITICAL: {len(crit_hosts)}{RST}   "
          f"{R}HIGH: {len(high_hosts)}{RST}   "
          f"{Y}MEDIUM: {len(med_hosts)}{RST}   "
          f"{G}OK/LOW: {len(ok_hosts)}{RST}")

    if crit_hosts:
        print(f"\n  {R}{BOLD}⚠  Hosts requiring IMMEDIATE attention:{RST}")
        for r in crit_hosts:
            creds_issues = [v for v in r["vulnerabilities"] if "credentials" in v["issue"].lower()]
            for v in r["vulnerabilities"]:
                sc = SEV_COLOR.get(v["severity"], W)
                print(f"    {r['ip']:18} {sc}[{v['severity']}]{RST} {v['issue']}")

    if cameras and not crit_hosts and not high_hosts:
        print(f"\n  {G}All cameras appear to be in good security posture.{RST}")

    print(f"\n  {DIM}Report generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{RST}")
    print(f"{C}{BOLD}{'═'*60}{RST}\n")

def save_json_report(results, path="camera_scan_report.json"):
    with open(path, "w") as f:
        json.dump({
            "scan_time": datetime.now().isoformat(),
            "hosts": results
        }, f, indent=2)
    return path

# ─────────────────────────────────────────────
#  Main
# ─────────────────────────────────────────────

def main():
    banner()

    print(f"{Y}(!) Use this tool carefully!")
    print(f"(!) I hope you are anonymous")
    print(f"(-) The developer does not assume responsibility for the misuse of this tool{RST}\n")

    # ── Target input ──
    if len(sys.argv) > 1:
        raw = " ".join(sys.argv[1:])
    else:
        print("Enter targets (IPs, CIDR ranges, hostnames — comma or space separated):")
        print("  Examples:  192.168.1.0/24   10.0.0.1,10.0.0.2   mycamera.local")
        raw = input(f"  {B}Targets>{RST} ").strip()
        if not raw:
            print("No targets provided. Exiting.")
            sys.exit(0)

    targets = expand_targets(raw)
    if not targets:
        print("No valid targets found. Exiting.")
        sys.exit(1)

    print(f"\n  {G}Expanded to {len(targets)} host(s){RST}")
    print(f"  Checking {len(CAMERA_PORTS)} ports per host with {MAX_WORKERS} threads…\n")
    print(f"  {'─'*56}")

    t0 = time.time()
    results = []
    completed = 0

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = {pool.submit(scan_host, ip): ip for ip in targets}
        for future in as_completed(futures):
            completed += 1
            ip = futures[future]
            try:
                r = future.result()
                results.append(r)
                if r["open_ports"]:
                    print_host_report(r)
                else:
                    print(f"  {DIM}{ip:18} — no camera ports open{RST}")
            except Exception as e:
                print(f"  {R}Error scanning {ip}: {e}{RST}")

            # Progress ticker every 10 hosts
            if completed % 10 == 0:
                pct = completed / len(targets) * 100
                print(f"  {DIM}[{ts()}] Progress: {completed}/{len(targets)} ({pct:.0f}%){RST}")

    elapsed = time.time() - t0
    print_summary(results, elapsed)

    # Save JSON
    report_path = save_json_report(results)
    print(f"  Full JSON report saved {G}{report_path}{RST}\n")

if __name__ == "__main__":
    main()
