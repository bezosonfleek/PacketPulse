import socket
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

log = logging.getLogger(__name__)

def get_active_subnet() -> str:
    """
    Finds the IP address of the interface currently connected to the internet
    to avoid scanning virtual Docker or Loopback interfaces.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Does not actually send data; just checks routing table
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        # Converts "192.168.1.15" -> "192.168.1"
        return ".".join(ip.split(".")[:-1])
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()

def run_scan(
    start: int = 1,
    end: int = 254,
    ports: list[int] | None = None,
    subnet: str | None = None
) -> list[dict]:
    """
    Execute a two-phase scan against the local network.
    If no subnet is provided, it auto-detects the active physical network.
    """
    # 1. Auto-detect subnet if not provided
    if subnet is None:
        subnet = get_active_subnet()
        log.info("Auto-detected active subnet: %s", subnet)

    if ports is None:
        # Assuming PORT_MAP is defined globally elsewhere in your project
        ports = list(PORT_MAP.keys()) if 'PORT_MAP' in globals() else [80, 443, 22]

    all_ips = [f"{subnet}.{i}" for i in range(start, end + 1)]
    ip_index = {ip: i for i, ip in enumerate(all_ips)}

    # Pre-fill results with 'down' status
    results: list[dict] = [
        {
            "ip": ip, "is_up": False, "hostname": "", "mac": "", 
            "vendor": "", "ports": [], "os_guess": None
        }
        for ip in all_ips
    ]

    # Phase 1: Host Discovery
    log.info("Phase 1: Discovery sweep on %s", subnet)
    alive_ips: list[str] = []
    
    # Using a smaller pool for pings to avoid OS socket exhaustion
    with ThreadPoolExecutor(max_workers=50) as ex:
        futures = {ex.submit(_is_host_up, ip): ip for ip in all_ips}
        for future in as_completed(futures):
            ip = futures[future]
            if future.result():
                alive_ips.append(ip)

    if not alive_ips:
        log.warning("No hosts found on subnet %s", subnet)
        return results

    # Phase 2: Detailed Scan (Live hosts only)
    log.info("Phase 2: Analyzing %d live hosts", len(alive_ips))
    with ThreadPoolExecutor(max_workers=20) as ex:
        futures = {ex.submit(_scan_ports, ip, ports): ip for ip in alive_ips}
        for future in as_completed(futures):
            ip = futures[future]
            try:
                open_ports = future.result()
                hostname = _resolve_hostname(ip)
                os_info = _fingerprint_os(ip, open_ports, hostname)
                mac, vendor = _get_mac(ip)

                results[ip_index[ip]].update({
                    "is_up": True,
                    "hostname": hostname,
                    "mac": mac,
                    "vendor": vendor,
                    "ports": open_ports,
                    "os_guess": os_info.get("os_guess")
                })
            except Exception as e:
                log.error("Error detailing %s: %s", ip, e)

    return results