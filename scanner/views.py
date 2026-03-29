import subprocess
import json
import platform
import re
import ipaddress
import os
from dotenv import load_dotenv
load_dotenv()

from django.contrib import messages
from django.contrib.auth import authenticate, login as auth_login, logout as auth_logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.http import JsonResponse, HttpResponse
from django.shortcuts import render, redirect
from django.views.decorators.csrf import csrf_exempt
from cryptography.fernet import Fernet
from groq import Groq
import warnings

from .models import ScanLog
from .utils import (
    check_privileges, get_device_profile, get_host_mac,
    get_all_local_ips, nmap_os_mac_args, get_local_ip
)

GROQ_API_KEY = os.getenv('GROQ_API_KEY', '').strip()
ENCRYPTION_KEY_STR = os.getenv('NETGUARD_ENCRYPTION_KEY', Fernet.generate_key().decode())
cipher = Fernet(ENCRYPTION_KEY_STR.encode())

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
    return groq_client is not None and GROQ_API_KEY.startswith('gsk_')


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


def generate_bat_script(open_ports):
    commands = [
        "@echo off",
        "setlocal",
        "echo NetGuard lockdown started",
    ]
    for port in sorted(set(open_ports)):
        commands.append(f'netsh advfirewall firewall add rule name="NetGuard-Port-{port}" dir=in action=block protocol=TCP localport={port}')
    commands.extend([
        "echo NetGuard lockdown complete",
        "pause",
    ])
    return "\r\n".join(commands)


def generate_sh_script(open_ports):
    commands = [
        "#!/bin/sh",
        "echo 'NetGuard lockdown started'",
    ]
    for port in sorted(set(open_ports)):
        commands.append(f"ufw deny {port}/tcp")
    commands.append("echo 'NetGuard lockdown complete'")
    return "\n".join(commands)


def infer_os_from_ports(open_ports: list) -> str:
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
    score = 100
    for port in open_ports:
        if port in [3389, 445, 3306, 5900, 27017, 6379, 139, 21, 23, 1433, 110]:
            score -= 30
        elif port in [22, 5555, 25, 135]:
            score -= 15
    return max(0, score)


def _register_context(request, error=None):
    return {
        'error': error,
        'form_data': {
            'username': request.POST.get('username', '').strip(),
            'email': request.POST.get('email', '').strip(),
            'full_name': request.POST.get('full_name', '').strip(),
        },
    }


@login_required(login_url='login')
def index(request):
    return render(request, 'scanner/index.html', {
        'privilege_warning': PRIVILEGE_STATUS.get('warning', ''),
        'user': request.user,
    })


def login_view(request):
    if request.user.is_authenticated:
        return redirect('index')

    if request.method == 'POST':
        username = request.POST.get('username', '').strip()
        password = request.POST.get('password', '')
        user = authenticate(request, username=username, password=password)
        if user is not None:
            auth_login(request, user)
            return redirect('index')
        return render(request, 'scanner/login.html', {'error': 'Invalid credentials'})
    return render(request, 'scanner/login.html')


def register_view(request):
    if request.user.is_authenticated:
        return redirect('index')

    if request.method == 'POST':
        username = request.POST.get('username', '').strip()
        email = request.POST.get('email', '').strip().lower()
        full_name = request.POST.get('full_name', '').strip()
        password = request.POST.get('password', '')
        password_confirm = request.POST.get('password_confirm', '')

        if not username:
            return render(request, 'scanner/register.html', _register_context(request, 'Username is required.'))

        if len(username) < 3:
            return render(request, 'scanner/register.html', _register_context(request, 'Username must be at least 3 characters.'))

        if User.objects.filter(username__iexact=username).exists():
            return render(request, 'scanner/register.html', _register_context(request, 'Username already exists.'))

        if email and User.objects.filter(email__iexact=email).exists():
            return render(request, 'scanner/register.html', _register_context(request, 'An account with that email already exists.'))

        if password != password_confirm:
            return render(request, 'scanner/register.html', _register_context(request, 'Passwords do not match.'))

        first_name = ''
        last_name = ''
        if full_name:
            name_parts = full_name.split(maxsplit=1)
            first_name = name_parts[0]
            last_name = name_parts[1] if len(name_parts) > 1 else ''

        try:
            temp_user = User(username=username, email=email, first_name=first_name, last_name=last_name)
            validate_password(password, user=temp_user)
        except ValidationError as exc:
            return render(request, 'scanner/register.html', _register_context(request, ' '.join(exc.messages)))

        user = User.objects.create_user(
            username=username,
            email=email,
            password=password,
            first_name=first_name,
            last_name=last_name,
        )
        auth_login(request, user)
        messages.success(request, 'Your account has been created successfully.')
        return redirect('index')

    return render(request, 'scanner/register.html', _register_context(request))


def logout_view(request):
    auth_logout(request)
    return redirect('login')


@login_required
@csrf_exempt
def host_fingerprint(request):
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
    try:
        local_ip = get_local_ip()
        if local_ip == 'Unknown':
            return JsonResponse({'error': 'Unable to resolve local IP'}, status=500)

        network = ipaddress.ip_network(f"{local_ip}/24", strict=False)
        target_cidr = str(network)

        nmap_cmd = [
            'nmap', '-sn', '-PR', '-PS1-100', '-PA1-100', '-PU53,67,123', '-T4',
            '--max-retries', '1', '--host-timeout', '180s', target_cidr
        ]

        proc = subprocess.run(nmap_cmd, capture_output=True, text=True, timeout=360)
        output = proc.stdout + '\n' + proc.stderr

        devices = []
        ip = None
        mac = None
        vendor_from_nmap = None

        for line in output.splitlines():
            if line.startswith('Nmap scan report for'):
                if ip and mac:
                    profile = get_device_profile(mac, vendor_from_nmap=vendor_from_nmap)
                    devices.append({
                        'ip': ip,
                        'mac': mac,
                        'vendor': profile['vendor'],
                        'device_label': profile['device_label'],
                        'icon': profile['icon'],
                        'status': 'up',
                    })
                parts = line.split()
                ip = parts[-1]
                mac = None
                vendor_from_nmap = None
            elif 'MAC Address:' in line:
                m = re.search(r'MAC Address:\s*([0-9A-Fa-f:]{17})\s*\((.*?)\)', line)
                if m:
                    mac = m.group(1).upper()
                    vendor_from_nmap = m.group(2).strip() if m.group(2) else None

        if ip and mac:
            profile = get_device_profile(mac, vendor_from_nmap=vendor_from_nmap)
            devices.append({
                'ip': ip,
                'mac': mac,
                'vendor': profile['vendor'],
                'device_label': profile['device_label'],
                'icon': profile['icon'],
                'status': 'up',
            })

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

        if not devices:
            return JsonResponse({'error': 'No hosts found; run as admin/root and ensure LAN access'}, status=503)

        return JsonResponse(devices, safe=False)

    except subprocess.TimeoutExpired:
        return JsonResponse({'error': 'ARP scan timed out'}, status=500)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@login_required
@csrf_exempt
def scan_target(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'POST required'}, status=405)
    try:
        body = json.loads(request.body)
        target_ip = body.get('target', '').strip()
        if not target_ip:
            return JsonResponse({'error': 'No target'}, status=400)

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
        patch_commands = []

        if platform.system() == 'Windows':
            patch_commands = [
                f'netsh advfirewall firewall add rule name="NetGuard-Port-{port}" dir=in action=block protocol=TCP localport={port}'
                for port in open_ports
            ]
        else:
            patch_commands = [f"sudo ufw deny {port}/tcp" for port in open_ports]

        unclear = {'Unknown', 'Hardened / Fingerprint blocked', '', None}
        if os_detected in unclear and open_ports:
            os_detected = infer_os_from_ports(open_ports)

        host_script = None
        if is_host and open_ports:
            host_script = generate_bat_script(open_ports) if platform.system() == 'Windows' else generate_sh_script(open_ports)

        risk_score = calculate_risk_score(open_ports)
        critical_count = sum(1 for result in scan_results if result['risk'] == 'CRITICAL')
        target_label = body.get('target_label', '').strip() or target_ip

        scan_data = {
            'target': target_ip,
            'target_label': target_label,
            'results': scan_results,
            'risk_score': risk_score,
            'ai_explanations': ai_explanations,
            'os_detected': os_detected,
            'os_inferred': infer_os_from_ports(open_ports) if open_ports else 'Unknown',
            'patch_commands': patch_commands,
            'host_script': host_script,
            'is_host': is_host,
        }
        enc = cipher.encrypt(json.dumps(scan_data).encode()).decode()
        ScanLog.objects.create(
            user=request.user,
            target_ip=target_ip,
            target_label=target_label,
            status='completed',
            risk_score=risk_score,
            open_port_count=len(open_ports),
            critical_count=critical_count,
            os_detected=os_detected,
            encrypted_results=enc,
        )
        return JsonResponse(scan_data)

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@login_required
def recent_scan_history(request):
    history = [
        log.summary()
        for log in ScanLog.objects.filter(user=request.user)[:10]
    ]
    return JsonResponse({'history': history})


@login_required
@csrf_exempt
def ai_chat(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'POST required'}, status=405)

    try:
        body = json.loads(request.body)
        user_message = body.get('message', body.get('prompt', '')).strip()
        if not user_message:
            return JsonResponse({'error': 'Empty message'}, status=400)

        if not groq_client:
            return JsonResponse({
                'response': 'AI offline - GROQ_API_KEY missing from .env',
            })

        msg = groq_client.chat.completions.create(
            messages=[{"role": "user", "content": user_message}],
            model="llama-3.1-8b-instant",
            max_tokens=500,
        )
        return JsonResponse({
            'response': msg.choices[0].message.content.strip(),
        })

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@login_required
@csrf_exempt
def download_host_script(request):
    try:
        body = json.loads(request.body)
        target_ip = body.get('target', '').strip()
        if not target_ip:
            return JsonResponse({'error': 'No target'}, status=400)

        if target_ip not in get_all_local_ips():
            return JsonResponse({'error': 'Not host IP'}, status=400)

        open_ports = body.get('ports', [])
        if not open_ports:
            return JsonResponse({'error': 'No ports to block'}, status=400)

        if not groq_client:
            return JsonResponse({'error': 'AI offline - GROQ_API_KEY missing'}, status=503)

        system = platform.system()

        if system == 'Windows':
            script = generate_bat_script(open_ports)
            filename = "host_lockdown.bat"
        else:
            script = generate_sh_script(open_ports)
            filename = "host_lockdown.sh"

        return HttpResponse(
            script,
            content_type='text/plain',
            headers={'Content-Disposition': f'attachment; filename="{filename}"'},
        )

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@login_required
@csrf_exempt
def kill_ports_script(request):
    try:
        body = json.loads(request.body)
        open_ports = body.get('ports', [])

        script = generate_bat_script(open_ports)
        return HttpResponse(
            script,
            content_type='text/plain',
            headers={'Content-Disposition': 'attachment; filename="kill_ports.bat"'},
        )
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)