// State Variables
let totalDevices = 0;
let totalCritical = 0;
let totalSafe = 0;
let hostLocalIp = null;

// DOM Elements
const radarBtn = document.getElementById('radar-btn');
const deviceList = document.getElementById('device-list');
const patchScript = document.getElementById('master-patch-script');
const hostInfoList = document.getElementById('host-info-list');
const chatMessages = document.getElementById('chat-messages');
const chatInput = document.getElementById('chat-input');
const chatSend = document.getElementById('chat-send');

// Initialize Dashboard on Load
window.addEventListener('DOMContentLoaded', async () => {
    try {
        const res = await fetch('/api/system/');
        const data = await res.json();
        if(data.error) throw new Error(data.error);
        
        hostLocalIp = data.local_ip;
        
        hostInfoList.innerHTML = `
            <li><strong>OS:</strong> ${data.os_type}</li>
            <li><strong>Node:</strong> ${data.node_name}</li>
            <li><strong>Arch:</strong> ${data.architecture}</li>
            <li><strong>Local IP:</strong> <span style="color:#6366f1; font-weight:bold;">${data.local_ip}</span></li>
        `;
    } catch (err) {
        hostInfoList.innerHTML = `<li class="text-red">System load failed: ${err.message}</li>`;
    }
});

// The Radar Button Event
radarBtn.addEventListener('click', async () => {
    // Reset State
    totalDevices = 0; totalCritical = 0; totalSafe = 0;
    updateKPIs();
    radarBtn.innerText = "SCANNING NETWORK...";
    radarBtn.style.opacity = "0.6";
    radarBtn.disabled = true;
    deviceList.innerHTML = '<p style="color: #6366f1;">🔍 Executing nmap ping sweep across /24 subnet...</p>';
    patchScript.innerText = "# NETGUARD AUTO-PATCHER INITIALIZED\n# Waiting for vulnerability detection...\n\n";

    try {
        // 1. Fetch ARP/Nmap Devices
        console.log('Radar scan starting - fetching devices');
        const res = await fetch('/api/arp/');
        const devices = await res.json();
        console.log('ARP results:', devices);
        
        if(devices.error) throw new Error(devices.error);
        if(devices.length === 0) {
            deviceList.innerHTML = '<p>No devices detected on network.</p>';
            resetBtn();
            return;
        }

        totalDevices = devices.length;
        document.getElementById('kpi-devices').innerText = totalDevices;
        document.getElementById('kpi-status').innerText = "SCANNING";
        deviceList.innerHTML = '';

        if (devices.length === 1 && (devices[0].ip === hostLocalIp || devices[0].ip === '127.0.0.1')) {
            deviceList.innerHTML = '<p>Only host detected; performing localhost scan.</p>';
        }

        // 2. Render Cards & Fire Async Scans
        devices.forEach((device, index) => {
            // Force host isolation by skipping host entries in Network Radar
            if (device.ip === hostLocalIp || device.ip === '127.0.0.1') {
                executePortScan(device.ip, null, true);
                return;
            }

            const cardId = `device-${index}`;
            const statusBadge = device.status === 'self' ? '🏠' : (device.status === 'up' ? '✅' : '📋');
            const cardHTML = `
                <div class="device-card" id="${cardId}">
                    <h3>${statusBadge} Device ${index + 1}</h3>
                    <p style="margin-bottom: 6px;">IP: <span style="font-family: 'JetBrains Mono', monospace; font-weight: 600; color: #06b6d4;">${device.ip}</span> | MAC: <span style="font-family: 'JetBrains Mono', monospace; font-size: 0.8rem;">${device.mac}</span></p>
                    <div id="${cardId}-results" style="margin-top: 8px;">
                        <span style="font-size: 0.8rem; color: #06b6d4; font-style: italic;">Scanning ports with nmap...</span>
                    </div>
                </div>
            `;
            deviceList.insertAdjacentHTML('beforeend', cardHTML);
            
            // Fire the port scan asynchronously for this specific IP
            executePortScan(device.ip, cardId, false);
        });

        resetBtn();

    } catch (err) {
        deviceList.innerHTML = `<p class="text-red">Discovery error: ${err.message}</p>`;
        resetBtn();
    }
});

async function executePortScan(ip, cardId = null, isHostOverride = false) {
    const isHostMachine = isHostOverride || ip === hostLocalIp || ip === '127.0.0.1';
    const resultsContainer = cardId ? document.getElementById(`${cardId}-results`) : null;

    console.log(`executePortScan(${ip}, cardId=${cardId}, host=${isHostMachine})`);

    try {
        const res = await fetch('/api/scan/', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target: ip })
        });
        const data = await res.json();

        if(data.error) {
            console.error('scan error for', ip, data.error);
            if(resultsContainer) resultsContainer.innerHTML = `<span class="text-red">Scan error: ${data.error}</span>`;
            else {
                const hostVulnDiv = document.getElementById('host-vulnerabilities');
                if(hostVulnDiv) hostVulnDiv.innerHTML = `<p class="text-red">Scan error: ${data.error}</p>`;
            }
            return;
        }

        if(isHostMachine) {
            if(cardId) {
                const cardEl = document.getElementById(cardId);
                if(cardEl) cardEl.style.display = 'none';
            }

            const hostVulnDiv = document.getElementById('host-vulnerabilities');
            if(!hostVulnDiv) return;

            let hostHTML = `
                <div style="margin-bottom: 14px; font-weight: 600; color: #06b6d4;">🛡️ Host Local Scan: ${ip}</div>
                <div style="margin-bottom: 8px;"><strong>True OS:</strong> <span style="font-family: 'JetBrains Mono', monospace;">${data.os_detected || 'Unknown'}</span></div>
                <div style="margin-bottom: 8px;"><strong>Inferred OS:</strong> <span style="font-family: 'JetBrains Mono', monospace;">${data.os_inferred || 'Unknown'}</span></div>
            `;

            if(data.results.length === 0) {
                hostHTML += `<div class="port-badge badge-INFO">Host has no exposed threat ports.</div>`;
                hostVulnDiv.innerHTML = hostHTML;
                return;
            }

            let criticalPorts = data.results.filter(p => p.risk === 'CRITICAL');
            hostHTML += `<div style="margin-bottom: 8px;"><strong>Risk Score:</strong> ${data.risk_score}/100</div>`;
            hostHTML += '<div style="display:grid;gap:6px;">';

            data.results.forEach(portData => {
                hostHTML += `
                    <div style="padding:10px;background:rgba(14, 165, 233, 0.1);border:1px solid rgba(6, 182, 212, 0.4);border-radius:6px;">
                        <span class="port-badge badge-${portData.risk}">Port ${portData.port} (${portData.service})</span>
                        <div style="font-size:0.82rem; margin-top:4px; color:#e2e8f0;">${portData.analysis}</div>
                    </div>
                `;
            });
            hostHTML += '</div>';

            if(criticalPorts.length > 0 && data.host_script) {
                hostHTML += `<button onclick="downloadHostLockdownScript(\`${data.host_script.replace(/`/g, '\\`')}\`, '${data.os_inferred}')" style="margin-top: 12px; padding: 10px 14px; background: linear-gradient(135deg, #ef4444, #c026d3); color: white; border: none; border-radius: 8px; cursor: pointer; font-weight: 700;">⬇️ Download Host Lockdown Script</button>`;
            }

            hostVulnDiv.innerHTML = hostHTML;
            updateKPIs();
            return;
        }

        // NETWORK DEVICE HANDLING (not host machine)
        if(data.results.length === 0) {
            resultsContainer.innerHTML = `<span class="port-badge badge-INFO">Secured — All target ports closed</span>`;
            return;
        }

        resultsContainer.innerHTML = '';
        let hasCritical = false;

        // Zero-Trust Auto-Patcher: Generate OS-specific commands for external devices
        let hasCriticalPorts = data.results.some(r => r.risk === 'CRITICAL');
        if(hasCriticalPorts) {
            let osType = 'Unknown';
            if(data.os_detected) {
                if(data.os_detected.includes('Windows')) osType = 'Windows';
                else if(data.os_detected.includes('Linux')) osType = 'Linux';
            } else if(data.os_inferred) osType = data.os_inferred;
            
            patchScript.innerText += `\n# ===== TARGET: ${ip} | OS: ${osType} | THREAT LEVEL: CRITICAL =====\n`;
            
            if(osType === 'Windows' || data.os_inferred === 'Windows') {
                data.results.forEach(portData => {
                    if(portData.risk === 'CRITICAL') {
                        patchScript.innerText += `netsh advfirewall firewall add rule name="Quarantine-${ip}-Port-${portData.port}" dir=in action=block protocol=TCP localport=${portData.port} remoteip=${ip} enable=yes\n`;
                    }
                });
            } else if(osType === 'Linux' || data.os_inferred === 'Linux') {
                data.results.forEach(portData => {
                    if(portData.risk === 'CRITICAL') {
                        patchScript.innerText += `sudo ufw deny from ${ip} to any port ${portData.port}\n`;
                    }
                });
                patchScript.innerText += `sudo ufw reload\n`;
            } else {
                data.results.forEach(portData => {
                    if(portData.risk === 'CRITICAL') {
                        patchScript.innerText += `# Block port ${portData.port} from ${ip}\n`;
                    }
                });
            }
            patchScript.innerText += `# Status: REMEDIATION APPLIED\n\n`;
        }

        data.results.forEach(portData => {
            if(portData.risk === 'CRITICAL' || portData.risk === 'WARNING') {
                totalCritical++;
                hasCritical = true;
            } else {
                totalSafe++;
            }

            resultsContainer.innerHTML += `
                <div style="margin-bottom: 8px;">
                    <span class="port-badge badge-${portData.risk}">Port ${portData.port} (${portData.service})</span>
                    <div class="ai-intel">
                        <strong>Analysis:</strong> ${portData.analysis}
                    </div>
                </div>
            `;
        });

        // Risk Score Visualization
        let riskClass = 'risk-green';
        if (data.risk_score < 50) riskClass = 'risk-red';
        else if (data.risk_score < 80) riskClass = 'risk-yellow';
        resultsContainer.innerHTML += `<div class="risk-score ${riskClass}">Risk Score: ${data.risk_score}/100</div>`;

        // AI Threat Analysis
        if (data.ai_explanations.length > 0) {
            resultsContainer.innerHTML += '<div style="margin-top: 12px; padding: 8px; background: #fef3c7; border-radius: 6px; font-size: 0.85rem;"><strong>🤖 AI Threat Brief:</strong></div>';
            data.ai_explanations.forEach(exp => {
                resultsContainer.innerHTML += `<div style="font-size: 0.8rem; color: #333; margin-top: 4px;">• ${exp.explanation || exp}</div>`;
            });
        }

        // Host Script Download
        if (data.host_script) {
            resultsContainer.innerHTML += `<button onclick="downloadScript('${ip}')" style="margin-top: 10px; padding: 8px 12px; background: linear-gradient(135deg, #10b981, #059669); color: white; border: none; border-radius: 8px; cursor: pointer; font-weight: 600;">⬇️ Download Host Lockdown Script</button>`;
        }

        if(hasCritical) {
            document.getElementById(cardId).style.borderLeft = "3px solid var(--critical-red)";
        }
        updateKPIs();

    } catch (err) {
        resultsContainer.innerHTML = `<span class="text-red">Connection error: ${err.message}</span>`;
    }
}

function updateKPIs() {
    document.getElementById('kpi-critical').innerText = totalCritical;
    document.getElementById('kpi-safe').innerText = totalSafe;
    if(totalCritical > 0) {
        document.getElementById('kpi-status').innerText = "VULNERABLE";
        document.getElementById('kpi-status').className = "text-red";
    } else {
        document.getElementById('kpi-status').innerText = "SECURE";
        document.getElementById('kpi-status').className = "text-green";
    }
}

function resetBtn() {
    radarBtn.innerText = "INITIATE NETWORK SCAN";
    radarBtn.style.opacity = "1";
    radarBtn.disabled = false;
}

// Quick action button handler
function setQuickPrompt(text) {
    chatInput.value = text;
    chatInput.focus();
    chatSend.click();
}

// Chat functionality
chatSend.addEventListener('click', async () => {
    const prompt = chatInput.value.trim();
    if (!prompt) return;
    chatMessages.innerHTML += `<div class="chat-message-user"><strong>You:</strong> ${prompt}</div>`;
    chatInput.value = '';
    try {
        const res = await fetch('/api/chat/', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ prompt })
        });
        const data = await res.json();
        if(data.error) {
            chatMessages.innerHTML += `<div class="chat-message-ai" style="color: #dc2626;"><strong>Error:</strong> ${data.error}</div>`;
        } else {
            chatMessages.innerHTML += `<div class="chat-message-ai"><strong>🤖 Groq AI:</strong> ${data.response}</div>`;
        }
        chatMessages.scrollTop = chatMessages.scrollHeight;
    } catch (err) {
        chatMessages.innerHTML += `<div class="chat-message-ai" style="color: #dc2626;"><strong>Error:</strong> ${err.message}</div>`;
    }
});

chatInput.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') chatSend.click();
});

// Download script
async function downloadScript(ip) {
    try {
        const res = await fetch('/api/download-script/', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target: ip })
        });
        if (res.ok) {
            const blob = await res.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = res.headers.get('Content-Disposition').split('filename=')[1].replace(/"/g, '');
            a.click();
            window.URL.revokeObjectURL(url);
        } else {
            alert('Failed to download script');
        }
    } catch (err) {
        alert('Error downloading script');
    }
}

// Download Host Lockdown Script as Blob (Windows .bat or Linux .sh)
function downloadHostLockdownScript(scriptContent, osType) {
    try {
        const filename = osType === 'Windows' ? 'host_lockdown.bat' : 'host_lockdown.sh';
        const blob = new Blob([scriptContent], { type: 'text/plain' });
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        a.click();
        window.URL.revokeObjectURL(url);
    } catch (err) {
        alert('Error downloading host lockdown script: ' + err.message);
    }
}