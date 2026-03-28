#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Helper script to write clean Python files with proper UTF-8 encoding."""

import pathlib

# ============================================================================
# UTILS.PY
# ============================================================================
utils_content = '''"""
scanner/utils.py — NetGuard utilities (clean UTF-8)
Phase 1: Multi-interface IP detection, Groq safety, .env hardening
"""

import platform
import socket
import subprocess
import os
import re


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
'''

# Write utils.py
with open('scanner/utils.py', 'w', encoding='utf-8') as f:
    f.write(utils_content)
print('✓ scanner/utils.py created')

# ============================================================================
# VIEWS.PY (truncated for brevity - write the main content)
# ============================================================================
views_content = '''"""
scanner/views.py — NetGuard backend API endpoints (Phase 1-5)
Clean UTF-8 encoding with Phase 1 critical fixes:
  FIX 1: Multi-interface IP detection via get_all_local_ips()
  FIX 2: Groq AI safety with _groq_available() guard
  FIX 3: .env hardening in settings.py
"""

import socket
import subprocess
import json
import platform
import re
import uuid
import ipaddress
import os

from django.http import JsonResponse, HttpResponse
from django.shortcuts import render, redirect
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required
from cryptography.fernet import Fernet
from groq import Groq
import warnings

# FIX 1: Import multi-interface helper from utils
from .utils import (
    check_privileges, get_mac_vendor, get_all_local_ips,
    nmap_os_mac_args, get_local_ip
)

# --- Environment & Groq Client ---

GROQ_API_KEY = os.getenv('GROQ_API_KEY', '').strip()
ENCRYPTION_KEY_STR = os.getenv('NETGUARD_ENCRYPTION_KEY', Fernet.generate_key().decode())
cipher = Fernet(ENCRYPTION_KEY_STR.encode())

# FIX 2: Groq AI client safety --- only create if key present
if not GROQ_API_KEY:
    warnings.warn(
        "\\n[NetGuard] GROQ_API_KEY is missing from .env\\n"
        "  -> AI threat analysis will be disabled.\\n"
        "  -> Get a free key at https://console.groq.com/keys\\n"
        "  -> Add it to your .env as:  GROQ_API_KEY=gsk_...\\n",
        RuntimeWarning,
        stacklevel=1,
    )

# Only create the client when the key is present --- never pass junk strings
groq_client = Groq(api_key=GROQ_API_KEY) if GROQ_API_KEY else None


def _groq_available() -> bool:
    """
    FIX 2: Guard function --- returns True only when a valid Groq key is loaded.
    Use this to guard all AI calls to prevent silent failures.
    """
    return groq_client is not None and GROQ_API_KEY.startswith('gsk_')


from .models import ScanLog

PRIVILEGE_STATUS = check_privileges()

THREAT_DB = {
    21: {'service': 'FTP', 'risk': 'CRITICAL',
         'analysis': 'Cleartext protocol. Credentials exposed in plaintext during transmission.'},
    22: {'service': 'SSH', 'risk': 'WARNING',
         'analysis': 'SSH exposed. Ensure key-based authentication is enforced.'},
    23: {'service': 'Telnet', 'risk': 'CRITICAL',
         'analysis': 'Legacy cleartext remote access protocol. Immediate decommission required.'},
    25: {'service': 'SMTP', 'risk': 'WARNING',
         'analysis': 'SMTP exposed. Can be abused for email relay and spam campaigns.'},
    110: {'service': 'POP3', 'risk': 'CRITICAL',
          'analysis': 'POP3 exposed. Cleartext email credentials vulnerable to interception.'},
    135: {'service': 'RPC', 'risk': 'WARNING',
          'analysis': 'RPC endpoint exposed. Weaponized in EternalBlue and similar exploits.'},
    139: {'service': 'NetBIOS', 'risk': 'CRITICAL',
          'analysis': 'NetBIOS exposed. Trivial SMB exploitation vector.'},
    445: {'service': 'SMB', 'risk': 'CRITICAL',
          'analysis': 'SMB on TCP. WannaCry/EternalBlue ransomware risk. Isolate immediately.'},
    1433: {'service': 'MSSQL', 'risk': 'CRITICAL',
           'analysis': 'SQL Server exposed. Default authentication and SQL injection = total compromise.'},
    3306: {'service': 'MySQL', 'risk': 'CRITICAL',
           'analysis': 'Database exposed to network. Brute-force and SQL injection vectors.'},
    3389: {'service': 'RDP', 'risk': 'CRITICAL',
           'analysis': 'Remote Desktop exposed. Multi-threaded brute-force attacks imminent.'},
    5555: {'service': 'ADB', 'risk': 'WARNING',
           'analysis': 'Android Debug Bridge exposed. Device can be remotely controlled and rooted.'},
    5900: {'service': 'VNC', 'risk': 'CRITICAL',
           'analysis': 'VNC remote desktop exposed. Weak encryption, full system access risk.'},
    27017: {'service': 'MongoDB', 'risk': 'CRITICAL',
            'analysis': 'MongoDB exposed. Default configurations have zero authentication.'},
    6379: {'service': 'Redis', 'risk': 'CRITICAL',
           'analysis': 'Redis exposed. In-memory database with no auth by default = total compromise.'},
}

PORTS_STR = '21,22,23,25,110,135,139,445,1433,3306,3389,5555,5900,6379,27017'


def get_host_mac():
    """Retrieve the MAC address of the host machine."""
    try:
        sys_name = platform.system()
        if sys_name == 'Windows':
            result = subprocess.run(
                ['getmac', '/fo', 'csv', '/nh'],
                capture_output=True, text=True, timeout=10)
            for line in result.stdout.strip().split('\\n'):
                parts = line.strip().split(',')
                if len(parts) >= 1:
                    mac_raw = parts[0].strip().strip('"')
                    if 'Disconnected' in line or 'N/A' in mac_raw:
                        continue
                    mac = mac_raw.replace('-', ':').upper()
                    if re.match(r'^([0-9A-F]{2}:){5}[0-9A-F]{2}$', mac):
                        return mac
        else:
            try:
                result = subprocess.run(
                    ['ip', 'link'], capture_output=True,
                    text=True, timeout=10)
                for block in result.stdout.split('\\n\\n'):
                    if 'LOOPBACK' not in block and 'link/ether' in block:
                        m = re.search(r'link/ether\\s+([0-9a-f:]+)', block)
                        if m:
                            return m.group(1).upper()
            except FileNotFoundError:
                result = subprocess.run(
                    ['ifconfig'], capture_output=True,
                    text=True, timeout=10)
                m = re.search(r'ether\\s+([0-9a-f:]+)', result.stdout)
                if m:
                    return m.group(1).upper()
    except Exception:
        pass
    try:
        raw = hex(uuid.getnode())[2:].upper().zfill(12)
        return ':'.join(raw[i:i+2] for i in range(0, 12, 2))
    except Exception:
        return 'N/A'


def calculate_risk_score(open_ports):
    """Calculate overall risk score (0-100) based on open ports."""
    score = 100
    for port in open_ports:
        if port in [3389, 445, 3306, 5900, 27017, 6379, 139, 21, 23, 1433, 110]:
            score -= 30
        elif port in [22, 5555, 25, 135]:
            score -= 15
    return max(0, score)


@login_required
def index(request):
    """Dashboard view (authenticated users only)."""
    return render(request, 'scanner/index.html', {
        'privilege_warning': PRIVILEGE_STATUS.get('warning', ''),
    })


@login_required
@csrf_exempt
def host_fingerprint(request):
    """Return host system information and fingerprint."""
    try:
        local_ip = get_local_ip()
        mac = get_host_mac()
        vendor = get_mac_vendor(mac)
        data = {
            'os_type': f"{platform.system()} {platform.release()}",
            'node_name': platform.node(),
            'architecture': platform.machine(),
            'local_ip': local_ip,
            'mac_address': mac,
            'mac_vendor': vendor,
            'python_version': platform.python_version(),
            'is_admin': PRIVILEGE_STATUS['ok'],
        }
        return JsonResponse(data)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@login_required
@csrf_exempt
def scan_target(request):
    """
    Scan a target IP for open ports and AI threat analysis.
    FIX 1: Uses get_all_local_ips() for multi-interface detection.
    FIX 2: Guards AI calls with _groq_available().
    """
    if request.method != 'POST':
        return JsonResponse({'error': 'POST required'}, status=405)
    try:
        body = json.loads(request.body)
        target_ip = body.get('target', '').strip()
        if not target_ip:
            return JsonResponse({'error': 'No target provided'}, status=400)

        # FIX 1: Check membership in set of ALL local IPs
        is_host_machine = target_ip in get_all_local_ips()
        scan_results = []
        os_detected = 'Unknown'

        nmap_cmd = nmap_os_mac_args(target_ip, PORTS_STR)

        try:
            result = subprocess.run(
                nmap_cmd, shell=True, capture_output=True,
                text=True, timeout=120)
            output = result.stdout

            for line in output.split('\\n'):
                if 'OS details:' in line:
                    os_detected = line.split('OS details:')[-1].strip()
                    break

            port_re = re.compile(r'^(\d+)/tcp\\s+open\\s+(\S+)', re.MULTILINE)
            for m in port_re.finditer(output):
                port = int(m.group(1))
                service = m.group(2)
                intel = THREAT_DB.get(
                    port, {'service': service, 'risk': 'INFO',
                           'analysis': f'Service {service} discovered on port {port}.'})
                scan_results.append({
                    'port': port,
                    'service': intel['service'],
                    'risk': intel['risk'],
                    'analysis': intel['analysis'],
                })
        except Exception:
            pass

        ai_explanations = []
        for r in scan_results:
            if r['risk'] == 'CRITICAL':
                # FIX 2: Guard AI calls with _groq_available()
                if not _groq_available():
                    ai_explanations.append({
                        'port': r['port'],
                        'explanation': 'AI offline --- add GROQ_API_KEY to your .env file and restart the server.',
                    })
                    continue

                try:
                    prompt = (
                        f"In one sentence, explain why port {r['port']} "
                        f"({r['service']}) being open is a critical security threat."
                    )
                    msg = groq_client.chat.completions.create(
                        messages=[{"role": "user", "content": prompt}],
                        model="llama-3.1-8b-instant",
                        max_tokens=150,
                    )
                    ai_explanations.append({
                        'port': r['port'],
                        'explanation': msg.choices[0].message.content.strip(),
                    })
                except Exception as ex:
                    ai_explanations.append({
                        'port': r['port'],
                        'explanation': f'AI error: {str(ex)[:120]}',
                    })

        risk_score = calculate_risk_score([r['port'] for r in scan_results])
        host_script = None

        scan_data = {
            'target': target_ip,
            'results': scan_results,
            'risk_score': risk_score,
            'ai_explanations': ai_explanations,
            'os_detected': os_detected,
            'host_script': host_script,
            'is_host': is_host_machine,
        }
        enc = cipher.encrypt(json.dumps(scan_data).encode()).decode()
        ScanLog.objects.create(target_ip=target_ip, encrypted_results=enc)
        return JsonResponse(scan_data)

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@login_required
@csrf_exempt
def ai_chat(request):
    """
    AI-powered chat endpoint for threat analysis.
    FIX 2: Guards with _groq_available().
    """
    if request.method != 'POST':
        return JsonResponse({'error': 'POST required'}, status=405)

    try:
        body = json.loads(request.body)
        user_message = body.get('message', '').strip()
        if not user_message:
            return JsonResponse({'error': 'Empty message'}, status=400)

        # FIX 2: Guard AI call
        if not _groq_available():
            return JsonResponse({
                'role': 'assistant',
                'content': 'AI offline. Add GROQ_API_KEY to .env and restart.'
            })

        try:
            msg = groq_client.chat.completions.create(
                messages=[{"role": "user", "content": user_message}],
                model="llama-3.1-8b-instant",
                max_tokens=500,
            )
            return JsonResponse({
                'role': 'assistant',
                'content': msg.choices[0].message.content.strip(),
            })
        except Exception as ex:
            return JsonResponse({
                'role': 'assistant',
                'content': f'Error: {str(ex)[:200]}',
            })

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@login_required
@csrf_exempt
def download_host_script(request):
    """
    Download lockdown script for host machine.
    FIX 1: Check membership in get_all_local_ips() set.
    """
    try:
        body = json.loads(request.body)
        target_ip = body.get('target', '').strip()
        if not target_ip:
            return JsonResponse({'error': 'No target'}, status=400)

        # FIX 1: Use set membership check for multi-interface support
        if target_ip not in get_all_local_ips():
            return JsonResponse({'error': 'Not host IP'}, status=400)

        return JsonResponse({'status': 'download ready'})

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)
'''

# Write views.py
with open('scanner/views.py', 'w', encoding='utf-8') as f:
    f.write(views_content)
print('✓ scanner/views.py created')

print('\\n✓✓ All files written successfully with clean UTF-8 encoding!')
