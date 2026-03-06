"""
scanner.py — Network scanning engine.

This is the core scanning logic extracted from packetpulse.py.
It has no knowledge of HTTP, auth, or the database — it just
scans and returns results. Routes call into this module.

Public API:
    get_network_details() -> dict
    run_scan(subnet, start, end, ports) -> list[dict]
"""

import socket
import platform
import subprocess
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

log = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────
#  PORT MAP  — port: (label, category)
# ─────────────────────────────────────────────────────────────
PORT_MAP = {
    # Remote Access
    22:    ("SSH",           "remote"),
    23:    ("Telnet",        "remote"),
    3389:  ("RDP",           "remote"),
    5900:  ("VNC",           "remote"),
    5901:  ("VNC-1",         "remote"),
    # Web
    80:    ("HTTP",          "web"),
    443:   ("HTTPS",         "web"),
    8080:  ("HTTP-ALT",      "web"),
    8443:  ("HTTPS-ALT",     "web"),
    8888:  ("HTTP-DEV",      "web"),
    3000:  ("Node/React",    "web"),
    4000:  ("Dev Server",    "web"),
    # File Transfer
    21:    ("FTP",           "file"),
    69:    ("TFTP",          "file"),
    139:   ("NetBIOS",       "file"),
    445:   ("SMB",           "file"),
    2049:  ("NFS",           "file"),
    # Database
    1433:  ("MSSQL",         "database"),
    1521:  ("Oracle",        "database"),
    3306:  ("MySQL",         "database"),
    5432:  ("PostgreSQL",    "database"),
    5984:  ("CouchDB",       "database"),
    6379:  ("Redis",         "database"),
    9200:  ("Elasticsearch", "database"),
    27017: ("MongoDB",       "database"),
    # Mail
    25:    ("SMTP",          "mail"),
    110:   ("POP3",          "mail"),
    143:   ("IMAP",          "mail"),
    465:   ("SMTPS",         "mail"),
    587:   ("SMTP-TLS",      "mail"),
    993:   ("IMAPS",         "mail"),
    995:   ("POP3S",         "mail"),
    # Infrastructure
    53:    ("DNS",           "infra"),
    67:    ("DHCP",          "infra"),
    123:   ("NTP",           "infra"),
    161:   ("SNMP",          "infra"),
    389:   ("LDAP",          "infra"),
    636:   ("LDAPS",         "infra"),
    # DevOps
    2375:  ("Docker",        "devops"),
    2376:  ("Docker-TLS",    "devops"),
    6443:  ("Kubernetes",    "devops"),
    9090:  ("Prometheus",    "devops"),
    9100:  ("Node Exporter", "devops"),
    # Proxies / Tunnels
    1080:  ("SOCKS5",        "proxy"),
    3128:  ("Squid",         "proxy"),
    8118:  ("Privoxy",       "proxy"),
    1194:  ("OpenVPN",       "proxy"),
    # Dangerous / Suspicious
    4444:  ("Metasploit",    "danger"),
    5555:  ("ADB",           "danger"),
    7777:  ("Backdoor?",     "danger"),
    31337: ("Elite/Back",    "danger"),
}

# ─────────────────────────────────────────────────────────────
#  TUNING CONSTANTS
# ─────────────────────────────────────────────────────────────
TCP_TIMEOUT    = 0.25   # seconds per port probe
BANNER_TIMEOUT = 0.5    # seconds for banner grab
MAX_WORKERS    = 150    # threads for port scanning phase
PING_WORKERS   = 100    # threads for host discovery phase
PROBE_PORTS    = (80, 443, 22, 445, 3389, 8080, 23, 21)  # fast discovery probes


# ─────────────────────────────────────────────────────────────
#  NETWORK DETAILS
# ─────────────────────────────────────────────────────────────
def get_network_details() -> dict:
    """
    Detect the server's local IP and derive the subnet prefix.
    Returns a dict safe to send directly to the frontend.
    """
    import urllib.request
    details = {
        "local_ip":      "Unavailable",
        "public_ip":     "Unavailable",
        "subnet_prefix": "192.168.1",
    }
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            details["local_ip"]      = s.getsockname()[0]
            details["subnet_prefix"] = ".".join(details["local_ip"].split(".")[:-1])
        req = urllib.request.Request("https://api.ipify.org?format=json")
        with urllib.request.urlopen(req, timeout=3) as resp:
            import json
            details["public_ip"] = json.loads(resp.read())["ip"]
    except Exception as e:
        log.debug("get_network_details partial failure: %s", e)
    return details


# ─────────────────────────────────────────────────────────────
#  PHASE 1 — HOST DISCOVERY
# ─────────────────────────────────────────────────────────────
def _is_host_up(ip: str) -> bool:
    """
    TCP knock on common ports first (fast, no root needed).
    Falls back to ICMP ping if all TCP probes fail.
    """
    for port in PROBE_PORTS:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(TCP_TIMEOUT)
                if s.connect_ex((ip, port)) == 0:
                    return True
        except OSError:
            pass

    # ICMP fallback — may require elevated privileges on some systems
    try:
        param = ["-n", "1", f"-w{300}"] if platform.system().lower() == "windows" \
                else ["-c", "1", "-W", "1"]
        return subprocess.call(
            ["ping"] + param + [ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=2,
        ) == 0
    except Exception:
        return False


# ─────────────────────────────────────────────────────────────
#  PHASE 2 — BANNER GRABBING
# ─────────────────────────────────────────────────────────────
def _grab_banner(ip: str, port: int) -> str:
    """
    Attempt to read a service banner from an open port.
    Returns the server version string if found, empty string otherwise.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(BANNER_TIMEOUT)
            s.connect((ip, port))
            if port in (80, 8080, 8888, 3000, 4000):
                s.sendall(b"GET / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
            elif port in (443, 8443):
                return "TLS/SSL"
            raw    = s.recv(256)
            banner = raw.decode("utf-8", errors="replace").strip()
            for line in banner.splitlines():
                if line.lower().startswith("server:"):
                    return line.split(":", 1)[1].strip()[:80]
            return banner.splitlines()[0][:80] if banner else ""
    except Exception:
        return ""


# ─────────────────────────────────────────────────────────────
#  PHASE 2 — PORT SCAN (called only on confirmed live hosts)
# ─────────────────────────────────────────────────────────────
def _resolve_hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def _scan_ports(ip: str, ports: list[int]) -> list[dict]:
    """
    Probe each port in the list. Returns only the open ones,
    each with label, category, and banner.
    """
    open_ports = []
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(TCP_TIMEOUT)
                if s.connect_ex((ip, port)) == 0:
                    label, category = PORT_MAP.get(port, ("Unknown", "infra"))
                    open_ports.append({
                        "port":     port,
                        "label":    label,
                        "category": category,
                        "banner":   _grab_banner(ip, port),
                    })
        except OSError:
            pass
    return open_ports


# ─────────────────────────────────────────────────────────────
#  PUBLIC: run_scan
# ─────────────────────────────────────────────────────────────
def run_scan(
    subnet: str,
    start:  int,
    end:    int,
    ports:  list[int] | None = None,
) -> list[dict]:
    """
    Execute a two-phase scan against subnet.start–end.

    Phase 1 — discovery sweep across the full range in parallel.
    Phase 2 — full port scan only on confirmed live hosts.

    Args:
        subnet: e.g. "192.168.1"
        start:  first host octet, 1–254
        end:    last host octet,  1–254
        ports:  list of port numbers to scan; None = all ports in PORT_MAP

    Returns:
        List of host dicts:
        [
          {
            "ip":       "192.168.1.1",
            "is_up":    True,
            "hostname": "router.local",
            "ports":    [{"port": 80, "label": "HTTP", ...}, ...]
          },
          ...
        ]
        Dead hosts are included with is_up=False and empty ports list
        so the frontend can show total hosts scanned vs alive.
    """
    if ports is None:
        ports = list(PORT_MAP.keys())

    all_ips  = [f"{subnet}.{i}" for i in range(start, end + 1)]
    ip_index = {ip: i for i, ip in enumerate(all_ips)}

    # Pre-fill all as dead; live results overwrite below
    results: list[dict] = [
        {"ip": ip, "is_up": False, "hostname": "", "ports": []}
        for ip in all_ips
    ]

    # ── Phase 1: host discovery ──────────────────────────────
    log.info("Scan phase 1: discovering %d hosts on %s", len(all_ips), subnet)
    alive: list[str] = []
    with ThreadPoolExecutor(max_workers=PING_WORKERS) as ex:
        futures = {ex.submit(_is_host_up, ip): ip for ip in all_ips}
        for future in as_completed(futures):
            ip = futures[future]
            try:
                if future.result():
                    alive.append(ip)
            except Exception as e:
                log.debug("Discovery error for %s: %s", ip, e)

    log.info("Scan phase 1 complete: %d/%d hosts alive", len(alive), len(all_ips))

    if not alive:
        return results

    # ── Phase 2: port scan on live hosts only ────────────────
    log.info("Scan phase 2: port scanning %d live hosts", len(alive))
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futures = {ex.submit(_scan_ports, ip, ports): ip for ip in alive}
        for future in as_completed(futures):
            ip = futures[future]
            try:
                open_ports = future.result()
                hostname   = _resolve_hostname(ip)
                results[ip_index[ip]] = {
                    "ip":       ip,
                    "is_up":    True,
                    "hostname": hostname,
                    "ports":    open_ports,
                }
            except Exception as e:
                log.debug("Port scan error for %s: %s", ip, e)

    alive_count = sum(1 for r in results if r["is_up"])
    port_count  = sum(len(r["ports"]) for r in results)
    log.info("Scan phase 2 complete: %d open ports across %d hosts", port_count, alive_count)

    return results