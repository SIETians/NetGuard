import platform
import socket
import subprocess
import os
import re
import uuid
from functools import lru_cache

try:
    from mac_vendor_lookup import MacLookup
    mac_lookup = MacLookup()
    MAC_LOOKUP_AVAILABLE = True
except ImportError:
    MAC_LOOKUP_AVAILABLE = False


def check_privileges():
    sys_name = platform.system()
    try:
        if sys_name == 'Windows':
            import ctypes
            try:
                if not ctypes.windll.shell32.IsUserAnAdmin():
                    return {'ok': False, 'warning': 'Running without Administrator privileges. Some scans may fail.'}
            except Exception:
                return {'ok': False, 'warning': 'Could not determine privilege level.'}
        else:
            if os.geteuid() != 0:
                return {'ok': False, 'warning': 'Running without root privileges. Some scans may fail.'}
        return {'ok': True, 'warning': ''}
    except Exception as e:
        return {'ok': False, 'warning': f'Privilege check error: {str(e)}'}


def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return 'Unknown'


def get_all_local_ips():
    ips = set()
    try:
        import netifaces
        for interface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(interface).get(netifaces.AF_INET, [])
            for info in addrs:
                ip = info.get('addr', '')
                if ip and not ip.startswith('127.'):
                    ips.add(ip)
        if ips:
            return ips
    except ImportError:
        pass
    if not ips:
        primary = get_local_ip()
        if primary != 'Unknown':
            ips.add(primary)
    return ips


@lru_cache(maxsize=1000)
def get_mac_vendor(mac_address):
    if not mac_address or mac_address == 'N/A':
        return 'Unknown Vendor'
    if not MAC_LOOKUP_AVAILABLE:
        return 'Unknown Vendor'
    try:
        return mac_lookup.lookup(mac_address)
    except Exception:
        return 'Unknown Vendor'


def get_host_mac():
    try:
        sys_name = platform.system()
        if sys_name == 'Windows':
            result = subprocess.run(['getmac', '/fo', 'csv', '/nh'], capture_output=True, text=True, timeout=10)
            for line in result.stdout.splitlines():
                parts = line.split(',')
                if parts:
                    mac = parts[0].strip().strip('"').replace('-', ':').upper()
                    if re.match(r'^([0-9A-F]{2}:){5}[0-9A-F]{2}$', mac):
                        return mac
        else:
            result = subprocess.run(['ip', 'link'], capture_output=True, text=True, timeout=10)
            m = re.search(r'link/ether\s+([0-9a-f:]+)', result.stdout)
            if m:
                return m.group(1).upper()
    except Exception:
        pass
    try:
        raw = hex(uuid.getnode())[2:].upper().zfill(12)
        return ':'.join(raw[i:i+2] for i in range(0, 12, 2))
    except Exception:
        return 'N/A'


def nmap_os_mac_args(target_ip, ports_str):
    return f'nmap -Pn -sS -O -p {ports_str} --osscan-limit --max-retries 1 {target_ip}'


@lru_cache(maxsize=1000)
def get_device_profile(mac_address, hostname=None, vendor_from_nmap=None):
    vendor = vendor_from_nmap or get_mac_vendor(mac_address)
    device_label = hostname or vendor or 'Unknown Device'
    icon = '🔌'  # default

    vendor_lower = vendor.lower()
    if 'apple' in vendor_lower:
        icon = '🍎'
        if not hostname:
            device_label = 'Apple Device'
    elif 'samsung' in vendor_lower:
        icon = '📱'
        if not hostname:
            device_label = 'Samsung Device'
    elif 'google' in vendor_lower or 'android' in vendor_lower:
        icon = '🤖'
        if not hostname:
            device_label = 'Android Device'
    elif 'microsoft' in vendor_lower or 'windows' in vendor_lower:
        icon = '🪟'
        if not hostname:
            device_label = 'Windows PC'
    elif 'cisco' in vendor_lower:
        icon = '🔀'
        if not hostname:
            device_label = 'Cisco Device'
    elif 'tp-link' in vendor_lower or 'netgear' in vendor_lower:
        icon = '📡'
        if not hostname:
            device_label = 'Router'
    elif 'raspberry' in vendor_lower:
        icon = '🍓'
        if not hostname:
            device_label = 'Raspberry Pi'
    elif 'intel' in vendor_lower:
        icon = '💻'
        if not hostname:
            device_label = 'Intel Device'
    elif 'broadcom' in vendor_lower:
        icon = '📶'
        if not hostname:
            device_label = 'Broadcom Device'
    elif 'lenovo' in vendor_lower:
        icon = '💻'
        if not hostname:
            device_label = 'Lenovo Device'
    # Add more mappings as needed

    return {
        'vendor': vendor,
        'device_label': device_label,
        'icon': icon
    }
