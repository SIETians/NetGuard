import socket
import subprocess
import json
import platform
import concurrent.futures
import ipaddress
import re
from django.http import JsonResponse, HttpResponse
from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
from cryptography.fernet import Fernet
import os
from groq import Groq

# Encryption setup
ENCRYPTION_KEY = os.getenv('NETGUARD_ENCRYPTION_KEY', Fernet.generate_key().decode())
cipher = Fernet(ENCRYPTION_KEY.encode())

# Groq AI setup
groq_client = Groq(api_key=os.getenv("GROQ_API_KEY", ""))

from .models import ScanLog

THREAT_DB = {
    21: {'service': 'FTP', 'risk': 'CRITICAL', 'analysis': 'Cleartext protocol. Credentials exposed in plaintext during transmission.'},
    22: {'service': 'SSH', 'risk': 'WARNING', 'analysis': 'SSH exposed. Ensure key-based authentication is enforced.'},
    23: {'service': 'Telnet', 'risk': 'CRITICAL', 'analysis': 'Legacy cleartext remote access protocol. Immediate decommission required.'},
    25: {'service': 'SMTP', 'risk': 'WARNING', 'analysis': 'SMTP exposed. Can be abused for email relay and spam campaigns.'},
    110: {'service': 'POP3', 'risk': 'CRITICAL', 'analysis': 'POP3 exposed. Cleartext email credentials vulnerable to interception.'},
    135: {'service': 'RPC', 'risk': 'WARNING', 'analysis': 'RPC endpoint exposed. Weaponized in EternalBlue and similar exploits.'},
    139: {'service': 'NetBIOS', 'risk': 'CRITICAL', 'analysis': 'NetBIOS exposed. Trivial SMB exploitation vector.'},
    445: {'service': 'SMB', 'risk': 'CRITICAL', 'analysis': 'SMB on TCP. WannaCry/EternalBlue ransomware risk. Isolate immediately.'},
    1433: {'service': 'MSSQL', 'risk': 'CRITICAL', 'analysis': 'SQL Server exposed. Default authentication and SQL injection = total compromise.'},
    3306: {'service': 'MySQL', 'risk': 'CRITICAL', 'analysis': 'Database exposed to network. Brute-force and SQL injection vectors.'},
    3389: {'service': 'RDP', 'risk': 'CRITICAL', 'analysis': 'Remote Desktop exposed. Multi-threaded brute-force attacks imminent.'},
    5555: {'service': 'ADB', 'risk': 'WARNING', 'analysis': 'Android Debug Bridge exposed. Device can be remotely controlled and rooted.'},
    5900: {'service': 'VNC', 'risk': 'CRITICAL', 'analysis': 'VNC remote desktop exposed. Weak encryption, full system access risk.'},
    27017: {'service': 'MongoDB', 'risk': 'CRITICAL', 'analysis': 'MongoDB exposed. Default configurations have zero authentication.'},
    6379: {'service': 'Redis', 'risk': 'CRITICAL', 'analysis': 'Redis exposed. In-memory database with no auth by default = total compromise.'},
}

def calculate_risk_score(open_ports):
    score = 100
    critical_ports = [3389, 445, 3306, 5900, 27017, 6379, 139, 21, 23, 1433, 110]
    warning_ports = [22, 5555, 25, 135]
    for port in open_ports:
        if port in critical_ports:
            score -= 30
        elif port in warning_ports:
            score -= 15
    return max(0, score)

def index(request):
    return render(request, 'scanner/index.html')

@csrf_exempt
def host_fingerprint(request):
    try:
        data = {
            'os_type': f"{platform.system()} {platform.release()}",
            'node_name': platform.node(),
            'architecture': platform.machine(),
            'local_ip': socket.gethostbyname(socket.gethostname()),
            'python_version': platform.python_version()
        }
        return JsonResponse(data)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

@csrf_exempt
def arp_discover(request):
    try:
        local_ip = socket.gethostbyname(socket.gethostname())
        network = ipaddress.ip_network(f"{local_ip}/24", strict=False)
        subnet = str(network)
        
        # PILLAR 1: NMAP PING SWEEP FOR 100% DEVICE DISCOVERY
        devices = []
        try:
            nmap_cmd = f'nmap -sn {subnet} -oG -'
            result = subprocess.run(nmap_cmd, shell=True, capture_output=True, text=True, timeout=120)
            for line in result.stdout.split('\n'):
                if line.startswith('Host:'):
                    parts = line.split()
                    if len(parts) >= 2:
                        ip = parts[1]
                        mac = 'N/A'
                        if len(parts) >= 4 and parts[2] == '(MAC:':
                            mac = parts[3].rstrip(')')
                        if ip != subnet.split('/')[0] and not ip.endswith('.255') and not ip.endswith('.0') and ip != local_ip:
                            devices.append({'ip': ip, 'mac': mac, 'status': 'up'})
        except Exception as nmap_err:
            # FALLBACK: ARP-only if nmap unavailable
            try:
                output = subprocess.check_output(['arp', '-a'], text=True, shell=True)
                for line in output.split('\n'):
                    if 'dynamic' in line.lower():
                        parts = line.split()
                        if len(parts) >= 2:
                            ip = parts[0]
                            mac = parts[1]
                            if not mac.startswith('ff-') and not ip.endswith('.255'):
                                devices.append({'ip': ip, 'mac': mac, 'status': 'cached'})
            except:
                devices = []
        
        # Inject host as first device
        if not any(d['ip'] == local_ip for d in devices):
            devices.insert(0, {'ip': local_ip, 'mac': 'HOST', 'status': 'self'})
        
        return JsonResponse(devices, safe=False)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

@csrf_exempt
def scan_target(request):
    if request.method != 'POST': 
        return JsonResponse({'error': 'POST required'}, status=405)
    
    try:
        data = json.loads(request.body)
        target_ip = data.get('target', '').strip()
        if not target_ip: 
            return JsonResponse({'error': 'No target provided'}, status=400)

        scan_results = []
        os_detected = 'Unknown'
        local_ip = socket.gethostbyname(socket.gethostname())
        is_host_machine = (target_ip == local_ip)
        
        # PILLAR 1: NMAP DEEP PORT SCAN WITH OS DETECTION & SERVICE VERSION
        # Strict threat ports only (removed 80, 443, 53, 8080, 8443)
        ports_str = '21,22,23,25,110,135,139,445,1433,3306,3389,5555,5900,27017,6379'
        try:
            # OS Detection (-O) combined with Service Version (-sV)
            nmap_cmd = f'nmap -O -sV -p {ports_str} {target_ip} -oG -'
            result = subprocess.run(nmap_cmd, shell=True, capture_output=True, text=True, timeout=120)
            
            # Extract OS details from nmap output
            os_lines = [line for line in result.stdout.split('\n') if 'OS details:' in line or 'Running:' in line]
            if os_lines:
                for line in os_lines:
                    if 'OS details:' in line:
                        os_detected = line.split('OS details:')[-1].strip()
                        break
                    elif 'Running:' in line:
                        os_detected = line.split('Running:')[-1].strip()
                        break
            
            # Parse ports from nmap output
            for line in result.stdout.split('\n'):
                if 'Ports:' in line:
                    ports_match = re.findall(r'(\d+)/(open|closed|filtered)/(tcp|udp)//([a-zA-Z0-9\-_]{1,30})/', line)
                    for port_data in ports_match:
                        port = int(port_data[0])
                        state = port_data[1]
                        service = port_data[3] if port_data[3] else 'Unknown'
                        
                        if state == 'open':
                            intel = THREAT_DB.get(port, {'service': service, 'risk': 'INFO', 'analysis': f'Service {service} discovered on port {port}.'})
                            scan_results.append({'port': port, 'service': intel['service'], 'risk': intel['risk'], 'analysis': intel['analysis']})
        except Exception as nmap_err:
            # FALLBACK: Socket-based port scan if nmap unavailable
            ports_to_scan = [21, 22, 23, 25, 110, 135, 139, 445, 1433, 3306, 3389, 5555, 5900, 27017, 6379]
            for port in ports_to_scan:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.4)
                result = sock.connect_ex((target_ip, port))
                if result == 0:
                    intel = THREAT_DB.get(port, {'service': 'Unknown', 'risk': 'INFO', 'analysis': f'Unknown service on port {port}.'})
                    scan_results.append({'port': port, **intel})
                sock.close()
        
        # Return SECURE status if no vulnerable ports found
        if len(scan_results) == 0:
            scan_data = {
                'target': target_ip,
                'status': 'SECURE',
                'results': [],
                'risk_score': 100,
                'ai_explanations': [],
                'os_detected': os_detected,
                'os_inferred': 'Unknown',
                'patch_commands': [],
                'host_script': None,
                'is_host': is_host_machine
            }
            encrypted_data = cipher.encrypt(json.dumps(scan_data).encode()).decode()
            ScanLog.objects.create(target_ip=target_ip, encrypted_results=encrypted_data)
            return JsonResponse(scan_data)
        
        open_ports = [r['port'] for r in scan_results]
        risk_score = calculate_risk_score(open_ports)
        
        # PILLAR 2: GROQ AI THREAT ANALYSIS FOR CRITICAL PORTS
        ai_explanations = []
        for result in scan_results:
            if result['risk'] == 'CRITICAL':
                try:
                    prompt = f"In one sentence, explain why port {result['port']} ({result['service']}) being open is a critical security threat."
                    message = groq_client.chat.completions.create(
                        messages=[{"role": "user", "content": prompt}],
                        model="llama-3.1-8b-instant",
                        max_tokens=150
                    )
                    ai_explanation = message.choices[0].message.content.strip()
                    ai_explanations.append({'port': result['port'], 'explanation': ai_explanation})
                except Exception as groq_err:
                    ai_explanations.append({'port': result['port'], 'explanation': f'AI unavailable: {str(groq_err)[:50]}'})
        
        # PILLAR 3 & 4: OS INFERENCE & AUTO-PATCHER GENERATION
        os_inferred = 'Unknown'
        patch_commands = []
        
        if 3389 in open_ports or 445 in open_ports or 139 in open_ports:
            os_inferred = 'Windows'
            if 3389 in open_ports:
                patch_commands.append('netsh advfirewall firewall add rule name="Block-RDP" dir=in action=block protocol=TCP localport=3389')
            if 445 in open_ports:
                patch_commands.append('net stop "Server" && reg add HKLM\\System\\CurrentControlSet\\Services\\LanmanServer\\Parameters /v smb1 /t REG_DWORD /d 0 /f')
            if 139 in open_ports:
                patch_commands.append('netsh advfirewall firewall add rule name="Block-NetBIOS" dir=in action=block protocol=TCP localport=139')
        elif 22 in open_ports:
            os_inferred = 'Linux/Unix'
            patch_commands.append('sudo ufw deny 22')
            patch_commands.append('sed -i "s/#PasswordAuthentication yes/PasswordAuthentication no/" /etc/ssh/sshd_config')
            patch_commands.append('sudo systemctl restart sshd')
        elif 5555 in open_ports:
            os_inferred = 'Android'
            patch_commands.append('Settings > Developer Options > Disable Wireless Debugging')
        
        # PILLAR 3: HOST LOCKDOWN SCRIPT FOR LOCAL MACHINE
        host_script = None
        if is_host_machine:
            os_type = platform.system()
            if os_type == 'Windows':
                host_script = '@echo off\nREM NETGUARD HOST LOCKDOWN SCRIPT\nREM Generated for Windows\n\n'
                for port in open_ports:
                    if port in [3389, 445, 139, 23, 21, 22, 25, 135, 110]:
                        host_script += f'netsh advfirewall firewall add rule name="Lockdown-Port-{port}" dir=in action=block protocol=TCP localport={port} enable=yes\n'
                host_script += 'echo. && echo Firewall rules applied. Run "netsh advfirewall firewall show rule name=Lockdown-Port-*" to verify.\npause'
            else:
                host_script = '#!/bin/bash\n# NETGUARD HOST LOCKDOWN SCRIPT\n# Generated for Linux/Unix\n\n'
                for port in open_ports:
                    host_script += f'sudo ufw deny {port}/tcp\n'
                host_script += 'echo "Firewall rules applied. Run sudo ufw status to verify."'
        
        # PILLAR 6: ENCRYPTED STORAGE
        scan_data = {
            'target': target_ip,
            'results': scan_results,
            'risk_score': risk_score,
            'ai_explanations': ai_explanations,
            'os_detected': os_detected,
            'os_inferred': os_inferred,
            'patch_commands': patch_commands,
            'host_script': host_script,
            'is_host': is_host_machine
        }
        encrypted_data = cipher.encrypt(json.dumps(scan_data).encode()).decode()
        ScanLog.objects.create(target_ip=target_ip, encrypted_results=encrypted_data)

        return JsonResponse(scan_data)
    except Exception as e:
        return JsonResponse({'error': f'Scan error: {str(e)}'}, status=500)

@csrf_exempt
def ai_chat(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'POST required'}, status=405)
    try:
        data = json.loads(request.body)
        prompt = data.get('prompt', '').strip()
        if not prompt:
            return JsonResponse({'error': 'No prompt provided'}, status=400)
        
        # PILLAR 2: GROQ LLAMA 3 AI BACKEND
        try:
            message = groq_client.chat.completions.create(
                messages=[{"role": "user", "content": prompt}],
                model="llama-3.1-8b-instant",
                max_tokens=500,
                temperature=0.7
            )
            response_text = message.choices[0].message.content.strip()
            return JsonResponse({'response': response_text})
        except Exception as groq_err:
            return JsonResponse({'error': f'Groq API error: {str(groq_err)}'}, status=500)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

@csrf_exempt
def download_host_script(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'POST required'}, status=405)
    try:
        data = json.loads(request.body)
        target_ip = data.get('target', '')
        local_ip = socket.gethostbyname(socket.gethostname())
        if target_ip != local_ip:
            return JsonResponse({'error': 'Not host IP'}, status=400)
        # Get latest scan for host
        scan_log = ScanLog.objects.filter(target_ip=local_ip).last()
        if not scan_log:
            return JsonResponse({'error': 'No scan data'}, status=400)
        decrypted = json.loads(cipher.decrypt(scan_log.encrypted_results.encode()).decode())
        script = decrypted.get('host_script', '')
        if not script:
            return JsonResponse({'error': 'No script generated'}, status=400)
        response = HttpResponse(script, content_type='text/plain')
        response['Content-Disposition'] = 'attachment; filename="host_lockdown.bat"' if platform.system() == 'Windows' else 'attachment; filename="host_lockdown.sh"'
        return response
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)