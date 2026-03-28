"""
scanner/utils.py — NetGuard utilities (clean UTF-8)
Phase 1: Multi-interface IP detection, Groq safety, .env hardening
Phase 2: MAC OUI vendor lookup, friendly device names, OS inference
"""

import platform
import socket
import subprocess
import os
import re
import functools
import uuid


# ── MAC OUI vendor lookup ─────────────────────────────────────────────────────
try:
    from mac_vendor_lookup import MacLookup
    _mac_lookup = MacLookup()
    try:
        _mac_lookup.load_vendors()   # pre-load OUI database once at startup
    except Exception:
        pass
    _MAC_VENDOR_AVAILABLE = True
except ImportError:
    _MAC_VENDOR_AVAILABLE = False


@functools.lru_cache(maxsize=512)
def get_mac_vendor(mac: str) -> str:
    """
    Return the OUI vendor name for a MAC address using mac-vendor-lookup.
    Returns 'Unknown Device' on any error — never raises.
    """
    if not mac or mac.upper() in ('N/A', 'UNKNOWN', ''):
        return 'Unknown Device'
    if not _MAC_VENDOR_AVAILABLE:
        return 'Unknown Device'
    try:
        result = _mac_lookup.lookup(mac)
        return result if result else 'Unknown Device'
    except Exception:
        return 'Unknown Device'


# ── Friendly device profiler ──────────────────────────────────────────────────
VENDOR_DEVICE_MAP = {
    'apple':      {'icon': '🍎', 'label': 'Apple Device'},
    'samsung':    {'icon': '📱', 'label': 'Samsung Device'},
    'xiaomi':     {'icon': '📱', 'label': 'Xiaomi Device'},
    'huawei':     {'icon': '📱', 'label': 'Huawei Device'},
    'oneplus':    {'icon': '📱', 'label': 'OnePlus Device'},
    'google':     {'icon': '📱', 'label': 'Google Device'},
    'intel':      {'icon': '💻', 'label': 'PC / Laptop (Intel NIC)'},
    'realtek':    {'icon': '💻', 'label': 'PC / Laptop'},
    'tp-link':    {'icon': '📡', 'label': 'TP-Link Router / AP'},
    'netgear':    {'icon': '📡', 'label': 'Netgear Router'},
    'asus':       {'icon': '💻', 'label': 'ASUS Device'},
    'dell':       {'icon': '🖥️',  'label': 'Dell PC / Laptop'},
    'hp':         {'icon': '🖥️',  'label': 'HP Device'},
    'lenovo':     {'icon': '💻', 'label': 'Lenovo Device'},
    'microsoft':  {'icon': '🪟', 'label': 'Microsoft Device'},
    'raspberry':  {'icon': '🍓', 'label': 'Raspberry Pi'},
    'espressif':  {'icon': '⚡', 'label': 'ESP IoT Device'},
    'amazon':     {'icon': '📦', 'label': 'Amazon Device'},
    'sony':       {'icon': '🎮', 'label': 'Sony Device'},
    'nintendo':   {'icon': '🎮', 'label': 'Nintendo Device'},
    'd-link':     {'icon': '📡', 'label': 'D-Link Router / AP'},
    'cisco':      {'icon': '🔗', 'label': 'Cisco Network Device'},
    'aruba':      {'icon': '📡', 'label': 'Aruba AP'},
}


def get_device_profile(mac: str, hostname: str = '') -> dict:
    """
    Returns a dict with keys: vendor, device_label, icon.
    Uses OUI database first, then hostname fallback, never raises.
    """
    vendor = get_mac_vendor(mac)
    vendor_lower = vendor.lower()

    for keyword, profile in VENDOR_DEVICE_MAP.items():
        if keyword in vendor_lower:
            return {
                'vendor': vendor,
                'device_label': profile['label'],
                'icon': profile['icon'],
            }

    # Fallback: use hostname when vendor is unknown
    label = (hostname.strip()
             if hostname and hostname.strip() not in ('', '-', 'N/A')
             else 'Unknown Device')
    return {'vendor': vendor, 'device_label': label, 'icon': '🔌'}



def check_privileges():
    """
    Check if running with administrative/root privileges.
    Returns dict: {'ok': bool, 'warning': str}
    """
    sys_name = platform.system()
    try:
        if sys_name == 'Windows':
            import ctypes
            try:
                is_admin = ctypes.windll.shell32.IsUserAnAdmin()
                if not is_admin:
                    return {
                        'ok': False,
                        'warning': 'Running without Administrator privileges. Some scans may fail.'
                    }
            except Exception:
                return {'ok': False, 'warning': 'Could not determine privilege level.'}
        else:
            is_root = os.geteuid() == 0
            if not is_root:
                return {
                    'ok': False,
                    'warning': 'Running without root privileges. Some scans may fail.'
                }
        return {'ok': True, 'warning': ''}
    except Exception as e:
        return {'ok': False, 'warning': f'Privilege check error: {str(e)}'}


def get_local_ip():
    """
    Get primary local IP by connecting to public DNS server.
    Returns string (IPv4 address) or 'Unknown'.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return 'Unknown'


def get_all_local_ips():
    """
    FIX 1: Enumerate ALL non-loopback IPv4 addresses across all interfaces.
    Returns set of IP addresses (string).
    Uses netifaces library for comprehensive interface enumeration.
    Gracefully falls back if netifaces unavailable.
    """
    ips = set()
    
    # Try netifaces first (most reliable)
    try:
        import netifaces
        for interface in netifaces.interfaces():
            try:
                if_addrs = netifaces.ifaddresses(interface)
                if netifaces.AF_INET in if_addrs:
                    for addr_info in if_addrs[netifaces.AF_INET]:
                        ip = addr_info.get('addr', '')
                        # Skip loopback
                        if ip and not ip.startswith('127.'):
                            ips.add(ip)
            except Exception:
                continue
        if ips:
            return ips
    except ImportError:
        pass
    
    # Fallback for Windows (ipconfig)
    if platform.system() == 'Windows':
        try:
            result = subprocess.run(
                ['ipconfig'], capture_output=True, text=True, timeout=10)
            pattern = r'IPv4 Address.*?:\s*(\d+\.\d+\.\d+\.\d+)'
            for match in re.finditer(pattern, result.stdout):
                ip = match.group(1)
                if not ip.startswith('127.'):
                    ips.add(ip)
        except Exception:
            pass
    else:
        # Fallback for Linux/Unix
        try:
            result = subprocess.run(
                ['ip', 'addr'], capture_output=True, text=True, timeout=10)
            pattern = r'inet\s+(\d+\.\d+\.\d+\.\d+)'
            for match in re.finditer(pattern, result.stdout):
                ip = match.group(1)
                if not ip.startswith('127.'):
                    ips.add(ip)
        except Exception:
            pass
    
    # Last resort: primary IP only
    if not ips:
        primary = get_local_ip()
        if primary != 'Unknown':
            ips.add(primary)
    
    return ips


def get_mac_vendor(mac_address):
    """
    Lookup MAC address vendor using built-in OUI map + online API fallback.
    Returns string (vendor name) or 'Unknown Vendor'.
    """
    if not mac_address or mac_address == 'N/A':
        return 'Unknown Vendor'
    
    mac_clean = mac_address.replace(':', '').replace('-', '').upper()[:6]
    
    # Inline OUI hardmap (most common vendors)
    oui_map = {
        '000000': 'Xerox',
        '000001': 'Xerox',
        '000004': 'Nortel',
        '00000B': 'Nortel',
        '00000D': 'Cisco',
        '00000F': 'NextLevel',
        '000011': '3Com',
        '000014': 'Cisco',
        '000016': 'Johnson Electric',
        '000017': 'Cisco',
        '000018': 'Cisco',
        '00001D': 'Ciena',
        '00001E': 'Extreme Networks',
        '00001F': 'Extreme Networks',
        '000020': 'Nortel',
        '088002': 'Viavi',
        '00AA00': 'Intel',
        '00B003': 'Adtran',
        '08002B': 'Digital Equipment',
        '08005A': 'IBM',
        '0CA900': 'Cisco',
        '444453': 'Microsoft',
        'AABBCC': 'Broadcast',
    }
    
    vendor = oui_map.get(mac_clean, '')
    if vendor:
        return vendor
    
    # Fallback to online OUI lookup
    try:
        url = f'https://api.macvendors.com/{mac_clean}'
        response = __import__('urllib.request', fromlist=['urlopen']).urlopen(url, timeout=2)
        return response.read().decode().strip() or 'Unknown Vendor'
    except Exception:
        return 'Unknown Vendor'


def nmap_os_mac_args(target_ip, ports_str):
    """
    Construct optimized nmap command for OS detection with specified ports.
    Uses safe flags: -Pn (skip ping), -sS (SYN scan), -O (OS detection).
    Returns string (full command).
    """
    cmd = (
        f'nmap -Pn -sS -O -p {ports_str} '
        f'--osscan-limit --max-retries 1 {target_ip}'
    )
    return cmd


def get_host_mac() -> str:
    """
    Resolve the primary MAC address using 5 methods in order.
    Returns a normalised XX:XX:XX:XX:XX:XX string or 'N/A'.
    """
    def _valid(mac: str) -> bool:
        return bool(re.match(
            r'^([0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}$', mac))

    def _norm(mac: str) -> str:
        return mac.replace('-', ':').upper()

    # Method 1 – Windows getmac
    if platform.system() == 'Windows':
        try:
            r = subprocess.run(
                ['getmac', '/fo', 'csv', '/nh'],
                capture_output=True, text=True, timeout=5)
            for line in r.stdout.strip().splitlines():
                parts = line.split(',')
                if len(parts) >= 1:
                    raw = parts[0].strip().strip('"')
                    mac = _norm(raw)
                    if _valid(mac) and 'Disconnected' not in line and 'N/A' not in raw:
                        return mac
        except Exception:
            pass

    # Method 2 – Linux: ip link show
    try:
        r = subprocess.run(['ip', 'link'], capture_output=True, text=True, timeout=5)
        for block in r.stdout.split('\n\n'):
            if 'LOOPBACK' not in block and 'link/ether' in block:
                m = re.search(r'link/ether\s+([0-9a-f:]{17})', block)
                if m:
                    return m.group(1).upper()
    except Exception:
        pass

    # Method 3 – macOS / older Linux: ifconfig
    try:
        r = subprocess.run(['ifconfig'], capture_output=True, text=True, timeout=5)
        m = re.search(r'ether\s+([0-9a-f:]{17})', r.stdout)
        if m:
            return m.group(1).upper()
    except Exception:
        pass

    # Method 4 – netifaces (cross-platform)
    try:
        import netifaces
        for iface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(iface)
            mac = addrs.get(netifaces.AF_LINK, [{}])[0].get('addr', '')
            if _valid(mac) and mac.lower() not in ('00:00:00:00:00:00', 'ff:ff:ff:ff:ff:ff'):
                return _norm(mac)
    except Exception:
        pass

    # Method 5 – uuid.getnode() last resort
    try:
        raw = hex(uuid.getnode())[2:].upper().zfill(12)
        return ':'.join(raw[i:i+2] for i in range(0, 12, 2))
    except Exception:
        return 'N/A'
