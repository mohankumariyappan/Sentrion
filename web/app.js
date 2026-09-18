// SecureExam Pro - Client Engine & Proctoring Bridge
const COMPANION_URL = "http://127.0.0.1:9999";
let sessionToken = null;
let pollTimer = null;
let lastHeartbeatTime = 0;
let watchdogTimer = null;

let totalKeystrokes = 0;
let hardwareMatches = 0;
let isExamLocked = false;

// Initialize on DOM load
document.addEventListener("DOMContentLoaded", () => {
    initSession();
    setupInputListener();
});

// View Navigation Switcher
function switchTab(tabName) {
    document.querySelectorAll('.nav-tab').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));

    document.getElementById(`tab-${tabName}`).classList.add('active');
    document.getElementById(`pane-${tabName}`).classList.add('active');
}

// 1. SESSION ESTABLISHMENT & HMAC HANDSHAKE
async function initSession() {
    updateCompanionPill(false, "Checking Companion (127.0.0.1:9999)...");
    
    try:
        // Step A: Health Check Ping (Unauthenticated)
        const healthRes = await fetch(`${COMPANION_URL}/health`, { method: "GET" });
        if (!healthRes.ok) throw new Error("Health check failed");
        
        const healthData = await healthRes.json();
        console.log("[+] Companion Liveness Confirmed:", healthData);

        // Step B: POST /session/start Trust Handshake (Generates signed HMAC token)
        const startRes = await fetch(`${COMPANION_URL}/session/start`, { method: "POST" });
        if (!startRes.ok) throw new Error("Session handshake rejected");
        
        const startData = await startRes.json();
        sessionToken = startData.token;
        
        console.log("[+] HMAC Session Token Established:", sessionToken);

        updateCompanionPill(true, "Companion Online (127.0.0.1:9999)");
        document.getElementById("hmac-text").textContent = `HMAC: ${sessionToken.substring(0, 10)}...`;
        document.getElementById("companion-offline-banner").classList.add("hidden");

        // Start continuous status polling & tamper watchdog
        startPolling();
        startSilenceWatchdog();
        
    } catch (err) {
        console.warn("[!] Companion Offline or Unreachable:", err.message);
        updateCompanionPill(false, "Companion Offline / Unreachable");
        document.getElementById("hmac-text").textContent = "No HMAC Session";
        document.getElementById("companion-offline-banner").classList.remove("hidden");
        
        // Lock exam if companion cannot be reached
        triggerLockout("COMPANION PROCESS UNREACHABLE", "The native security companion process (127.0.0.1:9999) is offline or blocked. You cannot proceed with the exam without the companion running.");
    }
}

// Update Companion Status Pill UI
function updateCompanionPill(isConnected, text) {
    const pill = document.getElementById("companion-pill");
    const label = document.getElementById("companion-text");
    label.textContent = text;

    if (isConnected) {
        pill.className = "status-pill status-connected";
    } else {
        pill.className = "status-pill status-disconnected";
    }
}

// 2. CONTINUOUS STATUS POLLING LOOP
function startPolling() {
    if (pollTimer) clearInterval(pollTimer);
    
    // Poll /status every 1.5 seconds
    pollStatus();
    pollTimer = setInterval(pollStatus, 1500);
}

async function pollStatus() {
    if (!sessionToken) return;
    
    const startTime = Date.now();
    try {
        const res = await fetch(`${COMPANION_URL}/status`, {
            method: "GET",
            headers: {
                "Authorization": `Bearer ${sessionToken}`
            }
        });

        if (res.status === 401) {
            // Token invalidated or expired
            console.error("[!] Token rejected by server.");
            triggerLockout("UNAUTHORIZED SESSION TOKEN", "The companion server rejected your session token. The session may have expired or been revoked.");
            return;
        }

        if (!res.ok) throw new Error(`HTTP ${res.status}`);

        const payload = await res.json();
        const latency = Date.now() - startTime;
        lastHeartbeatTime = Date.now();

        if (payload.status === "success" && payload.data) {
            updateDashboardUI(payload.data, latency);
        }
    } catch (err) {
        console.warn("[!] Status poll failed:", err.message);
        // Silence watchdog handles disconnect lockout if silence persists >3.5s
    }
}

// 3. TAMPER RESISTANCE & SILENCE WATCHDOG
function startSilenceWatchdog() {
    if (watchdogTimer) clearInterval(watchdogTimer);
    
    // Check every 1 second
    watchdogTimer = setInterval(() => {
        if (lastHeartbeatTime > 0) {
            const silenceSec = (Date.now() - lastHeartbeatTime) / 1000;
            
            if (silenceSec > 3.5 && !isExamLocked) {
                console.error(`[!] Silence watchdog triggered! (${silenceSec.toFixed(1)}s silence)`);
                updateCompanionPill(false, "Companion Terminated / Silent");
                triggerLockout("COMPANION PROCESS SILENCE DETECTED", `No status heartbeat received for ${silenceSec.toFixed(1)} seconds. The companion process may have been terminated, killed, or frozen by the user.`);
            }
        }
    }, 1000);
}

// Update Dashboard UI with latest state snapshot
function updateDashboardUI(data, latency) {
    const risk = data.overall_risk || "CLEAR";
    const modules = data.modules || {};
    const events = data.recent_events || [];

    // 1. Update Student Portal Risk Badge
    const badge = document.getElementById("exam-risk-badge");
    const badgeText = document.getElementById("exam-risk-text");
    
    badge.className = `risk-badge badge-${risk.toLowerCase()}`;
    badgeText.textContent = `SECURITY: ${risk}`;

    // 2. Update Proctor Metrics
    const riskMetric = document.getElementById("p-metric-risk");
    riskMetric.textContent = risk;
    if (risk === "CLEAR") riskMetric.className = "metric-value text-emerald";
    else if (risk === "WARNING") riskMetric.className = "metric-value text-amber";
    else riskMetric.className = "metric-value text-rose";

    document.getElementById("p-metric-latency").textContent = `${latency}ms`;

    // 3. Update Individual Module Cards in Proctor View
    updateModuleCard("overlay", modules.overlay_detection);
    updateModuleCard("vm", modules.vm_detection);
    updateModuleCard("process", modules.process_blacklist);
    updateModuleCard("hardware", modules.hardware_checks);
    updateModuleCard("keystroke", modules.keystroke_injection);

    // 4. Update Event Log Table
    renderEventLog(events);

    // 5. Check if Overall Violation triggered Lockout
    if (risk === "VIOLATION" && !isExamLocked) {
        // Locate offending module details
        let offendingModule = "Security Violation";
        let details = "An OS-level security rule was violated.";
        let findings = [];

        for (const [modKey, modVal] of Object.entries(modules)) {
            if (modVal.status === "VIOLATION") {
                offendingModule = modKey.toUpperCase().replace("_", " ");
                details = modVal.details;
                findings = modVal.findings || [];
                break;
            }
        }

        triggerLockout(`VIOLATION FLAG: ${offendingModule}`, details, findings);
    }
}

function updateModuleCard(modKey, modData) {
    if (!modData) return;
    const tag = document.getElementById(`mod-tag-${modKey}`);
    const details = document.getElementById(`mod-details-${modKey}`);

    const status = modData.status || "CLEAR";
    tag.textContent = status;
    tag.className = `status-tag tag-${status.toLowerCase()}`;
    details.textContent = modData.details || "Nominal";
}

// Render Event Log Table
function renderEventLog(events) {
    const tbody = document.getElementById("events-tbody");
    document.getElementById("events-count").textContent = `${events.length} event(s) logged`;

    if (!events || events.length === 0) {
        tbody.innerHTML = `<tr><td colspan="4" class="empty-table">No security events logged yet. Monitoring system active.</td></tr>`;
        return;
    }

    tbody.innerHTML = events.map(ev => {
        let tagClass = "tag-clear";
        if (ev.status === "WARNING") tagClass = "tag-warning";
        if (ev.status === "VIOLATION") tagClass = "tag-violation";

        let findingsHtml = "";
        if (ev.findings && ev.findings.length > 0) {
            findingsHtml = `<div style="font-family: var(--font-mono); font-size: 0.72rem; color: #cbd5e1; margin-top: 4px;">` +
                ev.findings.map(f => JSON.stringify(f)).join("<br>") + `</div>`;
        }

        return `
            <tr>
                <td style="font-family: var(--font-mono); font-size: 0.78rem;">${ev.timestamp}</td>
                <td><strong>${ev.module}</strong></td>
                <td><span class="status-tag ${tagClass}">${ev.status}</span></td>
                <td>
                    <div>${ev.details}</div>
                    ${findingsHtml}
                </td>
            </tr>
        `;
    }).join("");
}


// 4. SYNTHETIC KEYSTROKE INPUT MONITORING
function setupInputListener() {
    const textarea = document.getElementById("exam-input");
    
    textarea.addEventListener("input", async (e) => {
        const text = textarea.value;
        document.getElementById("char-count").textContent = text.length;

        if (e.inputType === "insertText" && e.data) {
            const char = e.data;
            totalKeystrokes++;

            // Report character input timestamp to Companion /keystroke/event endpoint
            if (sessionToken) {
                try {
                    const res = await fetch(`${COMPANION_URL}/keystroke/event`, {
                        method: "POST",
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify({
                            token: sessionToken,
                            char: char,
                            client_timestamp: Date.now() / 1000
                        })
                    });

                    const data = await res.json();
                    if (data.status === "success") {
                        if (data.is_hardware_confirmed) {
                            hardwareMatches++;
                        }
                        
                        const missCountElem = document.getElementById("miss-count");
                        missCountElem.textContent = data.consecutive_misses;
                        if (data.consecutive_misses > 0) {
                            missCountElem.className = "text-rose";
                        } else {
                            missCountElem.className = "text-success";
                        }

                        document.getElementById("p-metric-misses").textContent = data.consecutive_misses;
                        
                        const rate = Math.round((hardwareMatches / totalKeystrokes) * 100);
                        document.getElementById("hw-match-rate").textContent = `${rate}%`;
                    }
                } catch (err) {
                    console.warn("[!] Keystroke cross-reference failed:", err);
                }
            }
        }
    });
}

// Simulate Synthetic Paste (Generates un-hooked input characters for testing)
function simulatePaste() {
    const textarea = document.getElementById("exam-input");
    const fakeText = "Injected text via programmatic message queue without hardware keydown!";
    textarea.value += fakeText;
    document.getElementById("char-count").textContent = textarea.value.length;

    // Fire synthetic input event for each injected character
    for (let char of fakeText) {
        const evt = new InputEvent("input", { inputType: "insertText", data: char });
        textarea.dispatchEvent(evt);
    }
}


// 5. INTERACTIVE SIMULATION SUITE FOR DEMO / PROCTOR CONSOLE
async function triggerSim(moduleName, status, details, findings) {
    if (!sessionToken) {
        alert("Session token not established yet!");
        return;
    }

    try {
        const res = await fetch(`${COMPANION_URL}/simulate`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                token: sessionToken,
                module: moduleName,
                status: status,
                details: details,
                findings: findings
            })
        });

        const data = await res.json();
        console.log(`[+] Simulation Triggered for ${moduleName}:`, data);
        pollStatus(); // Immediate UI update
    } catch (err) {
        alert("Failed to send simulation request: " + err.message);
    }
}

async function clearSimulations() {
    if (!sessionToken) return;

    try {
        const res = await fetch(`${COMPANION_URL}/simulate`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                token: sessionToken,
                action: "clear_all"
            })
        });

        console.log("[+] All simulations cleared");
        dismissLockout();
        pollStatus();
    } catch (err) {
        console.error("Clear simulations failed:", err);
    }
}


// 6. EXAM LOCKOUT MODAL CONTROL
function triggerLockout(title, details, findings = []) {
    isExamLocked = true;
    document.getElementById("lockout-title").textContent = title;
    document.getElementById("lockout-details").textContent = details;

    const findingsBox = document.getElementById("lockout-findings");
    if (findings && findings.length > 0) {
        findingsBox.textContent = JSON.stringify(findings, null, 2);
        findingsBox.classList.remove("hidden");
    } else {
        findingsBox.classList.add("hidden");
    }

    document.getElementById("exam-input").disabled = true;
    document.getElementById("lockout-modal").classList.remove("hidden");
}

function dismissLockout() {
    isExamLocked = false;
    document.getElementById("exam-input").disabled = false;
    document.getElementById("lockout-modal").classList.add("hidden");
}

async function attemptResume() {
    if (sessionToken) {
        await clearSimulations();
    }
    dismissLockout();
    initSession();
}
