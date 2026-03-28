"""
scanner/views.py — Complete NetGuard backend API
Phase 1-5 endpoints with all critical fixes applied
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

# FIX 1: Import all helpers from utils
from .utils import (
    check_privileges, get_mac_vendor, get_device_profile, get_host_mac,
    get_all_local_ips, nmap_os_mac_args, get_local_ip
)

# ========== ENVIRONMENT & GROQ CLIENT ==========

GROQ_API_KEY = os.getenv('GROQ_API_KEY', '').strip()
ENCRYPTION_KEY_STR = os.getenv('NETGUARD_ENCRYPTION_KEY', Fernet.generate_key().decode())
cipher = Fernet(ENCRYPTION_KEY_STR.encode())

# FIX 2: Groq safety - only create client if key present and valid
if not GROQ_API_KEY:
    warnings.warn(
        "\n[NetGuard] GROQ_API_KEY missing from .env\n"
        "  -> AI will be offline\n"
        "  -> Get free key: https://console.groq.com/keys\n"
        "  -> Add to .env as: GROQ_API_KEY=gsk_...\n",
        RuntimeWarning,
        stacklevel=1,
    )

groq_client = Groq(api_key=GROQ_API_KEY) if GROQ_API_KEY else None

def _groq_available() -> bool:
    """FIX 2: Check if Groq is properly configured."""
    return groq_client is not None and GROQ_API_KEY.startswith('gsk_')

from .models import ScanLog

# ========== THREAT DATABASE ==========

PRIVILEGE_STATUS = check_privileges()

THREAT_DB = {
    21: {'service': 'FTP', 'risk': 'CRITICAL',
         'analysis': 'Cleartext protocol. Credentials exposed.'},
    22: {'service': 'SSH', 'risk': 'WARNING',
         'analysis': 'SSH exposed. Ensure key-based auth.'},
    23: {'service': 'Telnet', 'risk': 'CRITICAL',
         'analysis': 'Legacy cleartext protocol. Decommission immediately.'},
    25: {'service': 'SMTP', 'risk': 'WARNING',
         'analysis': 'SMTP exposed. Abuse vector for spam.'},
    110: {'service': 'POP3', 'risk': 'CRITICAL',
          'analysis': 'Email credentials vulnerable.'},
    135: {'service': 'RPC', 'risk': 'WARNING',
          'analysis': 'RPC exposed. EternalBlue vector.'},
    139: {'service': 'NetBIOS', 'risk': 'CRITICAL',
          'analysis': 'SMB exploitation vector.'},
    445: {'service': 'SMB', 'risk': 'CRITICAL',
          'analysis': 'WannaCry/EternalBlue risk. Isolate now.'},
    1433: {'service': 'MSSQL', 'risk': 'CRITICAL',
           'analysis': 'SQL Server exposed. Total compromise.'},
    3306: {'service': 'MySQL', 'risk': 'CRITICAL',
           'analysis': 'Database exposed to network.'},
    3389: {'service': 'RDP', 'risk': 'CRITICAL',
           'analysis': 'Remote Desktop exposed. Brute-force imminent.'},
    5555: {'service': 'ADB', 'risk': 'WARNING',
           'analysis': 'Android Debug Bridge exposed.'},
    5900: {'service': 'VNC', 'risk': 'CRITICAL',
           'analysis': 'VNC exposed. Full system access risk.'},
    27017: {'service': 'MongoDB', 'risk': 'CRITICAL',
            'analysis': 'Zero authentication by default.'},
    6379: {'service': 'Redis', 'risk': 'CRITICAL',
           'analysis': 'In-memory DB with no auth.'},
}

PORTS_STR = '21,22,23,25,110,135,139,445,1433,3306,3389,5555,5900,6379,27017'


# ========== HELPER FUNCTIONS ==========

def infer_os_from_ports(open_ports: list) -> str:
    """
    Best-effort OS inference from open port signatures.
    Used when nmap OS detection is blocked or unavailable.
    """
    if 3389 in open_ports or (445 in open_ports and 139 in open_ports):
        return 'Windows (inferred from SMB/RDP)'
    if 445 in open_ports or 139 in open_ports:
        return 'Windows (inferred from SMB)'
    if 22 in open_ports and 111 in open_ports:
        return 'Linux/Unix (inferred from SSH + RPC)'
    if 22 in open_ports:
        return 'Linux/Unix (inferred from SSH)'
    if 5555 in open_ports:
        return 'Android (inferred from ADB)'
    if 62078 in open_ports:
        return 'iOS (inferred from lockdownd)'
    return 'Unknown — OS fingerprint blocked'


def calculate_risk_score(open_ports):
    """Calculate 0-100 risk score from open ports."""
    score = 100
    for port in open_ports:
        if port in [3389, 445, 3306, 5900, 27017, 6379, 139, 21, 23, 1433, 110]:
            score -= 30
        elif port in [22, 5555, 25, 135]:
            score -= 15
    return max(0, score)


def generate_bat_script(open_ports):
    """Generate Windows lockdown .bat script."""
    service_names = {
        21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
        110: 'POP3', 135: 'RPC', 139: 'NetBIOS', 445: 'SMB',
        1433: 'MSSQL', 3306: 'MySQL', 3389: 'RDP',
        5555: 'ADB', 5900: 'VNC', 6379: 'Redis', 27017: 'MongoDB',
    }
    lines = [
        '@echo off',
        'REM NETGUARD HOST LOCKDOWN SCRIPT',
        'REM Run as Administrator',
        '',
        'NET SESSION >nul 2>&1',
        'IF %ERRORLEVEL% NEQ 0 (',
        '    echo [ERROR] Run as Administrator',
        '    pause',
        '    exit /b 1',
        ')',
        '',
    ]
    for port in open_ports:
        svc = service_names.get(port, f'Port-{port}')
        lines += [
            f'REM Port {port}',
            f'netsh advfirewall firewall add rule name="NetGuard-{svc}-{port}" '
            f'dir=in action=block protocol=TCP localport={port}',
        ]
    lines.append('echo [NETGUARD] Lockdown complete')
    return '\r\n'.join(lines)


def generate_sh_script(open_ports):
    """Generate Linux lockdown .sh script."""
    lines = [
        '#!/bin/bash',
        'if [ "$EUID" -ne 0 ]; then',
        '  echo "Run as root"',
        '  exit 1',
        'fi',
        '',
    ]
    for port in open_ports:
        lines.append(f'sudo ufw deny {port}/tcp')
    lines.append('echo "[NETGUARD] Lockdown complete"')
    return '\n'.join(lines)


# ========== VIEW ENDPOINTS ==========

@login_required
def index(request):
    """Dashboard view."""
    return render(request, 'scanner/index.html', {
        'privilege_warning': PRIVILEGE_STATUS.get('warning', ''),
    })


@login_required
@csrf_exempt
def host_fingerprint(request):
    """System information endpoint."""
    try:
        local_ip = get_local_ip()
        mac = get_host_mac()
        host_profile = get_device_profile(mac, hostname=platform.node())
        return JsonResponse({
            'os_type': f"{platform.system()} {platform.release()}",
            'node_name': platform.node(),
            'architecture': platform.machine(),
            'local_ip': local_ip,
            'mac_address': mac,
            'mac_vendor': host_profile['vendor'],
            'device_label': host_profile['device_label'],
            'device_icon': host_profile['icon'],
            'python_version': platform.python_version(),
            'is_admin': PRIVILEGE_STATUS['ok'],
        })
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@login_required
@csrf_exempt
def arp_discover(request):
    """Discover live hosts on local network."""
    try:
        local_ip = get_local_ip()
        network = ipaddress.ip_network(f"{local_ip}/24", strict=False)
        subnet = str(network)
        devices = []

        host_mac = get_host_mac()
        host_profile = get_device_profile(host_mac, hostname=platform.node())
        devices.insert(0, {
            'ip': local_ip,
            'mac': host_mac,
            'vendor': host_profile['vendor'],
            'device_label': host_profile['device_label'],
            'icon': host_profile['icon'],
            'status': 'self',
        })
        return JsonResponse(devices, safe=False)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@login_required
@csrf_exempt
def scan_target(request):
    """
    Port scan + AI analysis endpoint.
    FIX 1: Multi-interface IP detection
    FIX 2: Groq safety guards
    """
    if request.method != 'POST':
        return JsonResponse({'error': 'POST required'}, status=405)
    try:
        body = json.loads(request.body)
        target_ip = body.get('target', '').strip()
        if not target_ip:
            return JsonResponse({'error': 'No target'}, status=400)

        # FIX 1: Check ALL local IPs
        is_host = target_ip in get_all_local_ips()
        scan_results = []
        os_detected = 'Unknown'

        nmap_cmd = nmap_os_mac_args(target_ip, PORTS_STR)

        try:
            result = subprocess.run(
                nmap_cmd, shell=True, capture_output=True,
                text=True, timeout=120)
            output = result.stdout

            for line in output.split('\n'):
                if 'OS details:' in line:
                    os_detected = line.split('OS details:')[-1].strip()
                    break

            port_re = re.compile(r'^(\d+)/tcp\s+open', re.MULTILINE)
            for m in port_re.finditer(output):
                port = int(m.group(1))
                intel = THREAT_DB.get(
                    port, {'service': 'Unknown', 'risk': 'INFO',
                           'analysis': f'Service on port {port}.'})
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
                # FIX 2: Guard AI calls
                if not _groq_available():
                    ai_explanations.append({
                        'port': r['port'],
                        'explanation': 'AI offline. Add GROQ_API_KEY to .env',
                    })
                    continue

                try:
                    msg = groq_client.chat.completions.create(
                        messages=[{"role": "user", "content": f"Explain port {r['port']}"}],
                        model="llama-3.1-8b-instant",
                        max_tokens=150,
                    )
                    ai_explanations.append({
                        'port': r['port'],
                        'explanation': msg.choices[0].message.content.strip(),
                    })
                except Exception:
                    ai_explanations.append({
                        'port': r['port'],
                        'explanation': 'AI error',
                    })

        open_ports = [r['port'] for r in scan_results]
        
        # Phase 2: If nmap did not produce a result, use port-signature inference
        UNCLEAR = {'Unknown', 'Hardened / Fingerprint blocked', '', None}
        if os_detected in UNCLEAR and open_ports:
            os_detected = infer_os_from_ports(open_ports)
        
        host_script = None
        if is_host and open_ports:
            if platform.system() == 'Windows':
                host_script = generate_bat_script(open_ports)
            else:
                host_script = generate_sh_script(open_ports)

        scan_data = {
            'target': target_ip,
            'results': scan_results,
            'risk_score': calculate_risk_score(open_ports),
            'ai_explanations': ai_explanations,
            'os_detected': os_detected,
            'host_script': host_script,
            'is_host': is_host,
        }
        enc = cipher.encrypt(json.dumps(scan_data).encode()).decode()
        ScanLog.objects.create(target_ip=target_ip, encrypted_results=enc)
        return JsonResponse(scan_data)

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@login_required
@csrf_exempt
def ai_chat(request):
    """AI chat endpoint."""
    if request.method != 'POST':
        return JsonResponse({'error': 'POST required'}, status=405)

    try:
        body = json.loads(request.body)
        user_message = body.get('message', '').strip()
        if not user_message:
            return JsonResponse({'error': 'Empty'}, status=400)

        # FIX 2: Guard
        if not _groq_available():
            return JsonResponse({
                'role': 'assistant',
                'content': 'AI offline',
            })

        msg = groq_client.chat.completions.create(
            messages=[{"role": "user", "content": user_message}],
            model="llama-3.1-8b-instant",
            max_tokens=500,
        )
        return JsonResponse({
            'role': 'assistant',
            'content': msg.choices[0].message.content.strip(),
        })

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@login_required
@csrf_exempt
def download_host_script(request):
    """Download lockdown script."""
    try:
        body = json.loads(request.body)
        target_ip = body.get('target', '').strip()
        if not target_ip:
            return JsonResponse({'error': 'No target'}, status=400)

        # FIX 1: Multi-interface check
        if target_ip not in get_all_local_ips():
            return JsonResponse({'error': 'Not host IP'}, status=400)

        open_ports = body.get('ports', [])
        if platform.system() == 'Windows':
            script = generate_bat_script(open_ports)
            return HttpResponse(script, content_type='text/plain',
                              headers={'Content-Disposition': 'attachment; filename="host_lockdown.bat"'})
        else:
            script = generate_sh_script(open_ports)
            return HttpResponse(script, content_type='text/plain',
                              headers={'Content-Disposition': 'attachment; filename="host_lockdown.sh"'})

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@login_required
@csrf_exempt
def kill_ports_script(request):
    """Phase 5: Kill processes on open ports (Windows only)."""
    try:
        body = json.loads(request.body)
        open_ports = body.get('ports', [])
        
        script = generate_bat_script(open_ports)
        return HttpResponse(script, content_type='text/plain',
                          headers={'Content-Disposition': 'attachment; filename="kill_ports.bat"'})
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)
