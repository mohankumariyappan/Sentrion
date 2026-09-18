const http = require('http');
const { WebSocketServer } = require('ws');

const candidates = new Map();
const monitors = new Set();
const passcodes = new Map();

function getTodayDateStr() {
  const d = new Date();
  const year = d.getFullYear();
  const month = String(d.getMonth() + 1).padStart(2, '0');
  const day = String(d.getDate()).padStart(2, '0');
  return `${year}-${month}-${day}`;
}

function generatePasscode(type = 'STANDARD') {
  let code;
  const isCam = (type || '').toUpperCase() === 'CAMERA';
  do {
    if (isCam) {
      // Camera passcodes start with 8 or 9 (800000 - 999999)
      code = Math.floor(800000 + Math.random() * 200000).toString();
    } else {
      // Standard passcodes start with 1, 3, 4, 5 (100000 - 599999)
      code = Math.floor(100000 + Math.random() * 500000).toString();
    }
  } while (passcodes.has(code));

  const today = getTodayDateStr();
  const entry = {
    code,
    type: isCam ? 'CAMERA' : 'STANDARD',
    isUsed: false,
    usedBy: null,
    createdAt: Date.now(),
    dateStr: today
  };
  passcodes.set(code, entry);
  return code;
}

function initDailyPasscodes() {
  passcodes.clear();
  const today = getTodayDateStr();

  // Master demo codes: 123456 (Standard) and 222222 (Camera-Proctored)
  passcodes.set("123456", { code: "123456", type: "STANDARD", isUsed: false, usedBy: null, createdAt: Date.now(), dateStr: today });
  passcodes.set("222222", { code: "222222", type: "CAMERA", isUsed: false, usedBy: null, createdAt: Date.now(), dateStr: today });

  // Pre-generate 5 Standard (No Camera) and 5 Camera-Proctored access codes
  for (let i = 0; i < 5; i++) {
    generatePasscode("STANDARD");
  }
  for (let i = 0; i < 5; i++) {
    generatePasscode("CAMERA");
  }
  console.log(`[${today}] Daily passcodes initialized. Total: ${passcodes.size}`);
}

function checkAndResetDailyPasscodes() {
  const today = getTodayDateStr();
  let needsReset = false;

  if (passcodes.size === 0) {
    needsReset = true;
  } else {
    for (const [, val] of passcodes) {
      if (val.dateStr !== today) {
        needsReset = true;
        break;
      }
    }
  }

  if (needsReset) {
    console.log(`[${today}] Auto-resetting daily passcodes for new day...`);
    initDailyPasscodes();
    return true;
  }
  return false;
}

// Initialize on server startup
initDailyPasscodes();

const server = http.createServer((req, res) => {
  // CORS & Security headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Content-Type', 'application/json');

  if (req.method === 'OPTIONS') {
    res.writeHead(200);
    res.end();
    return;
  }

  if (req.url === '/health' || req.url === '/') {
    checkAndResetDailyPasscodes();
    res.writeHead(200);
    res.end(JSON.stringify({
      status: 'ok',
      service: 'Sentrion Cloud Relay Hub',
      version: '1.2.0',
      activeCandidates: candidates.size,
      activeMonitors: monitors.size,
      totalPasscodes: passcodes.size,
      todayDate: getTodayDateStr(),
      uptime: process.uptime(),
      timestamp: Date.now()
    }));
    return;
  }

  res.writeHead(404);
  res.end(JSON.stringify({ error: 'Endpoint Not Found' }));
});

const PORT = process.env.PORT || 8080;
const wss = new WebSocketServer({ server });

server.listen(PORT, () => {
  console.log(`Sentrion Relay Hub HTTP & WebSocket server listening on port ${PORT}`);
  console.log('Active 6-Digit Passcodes for today:', Array.from(passcodes.keys()));
});

function getPasscodesList() {
  const list = [];
  passcodes.forEach((val, code) => {
    list.push({
      code,
      type: val.type || 'STANDARD',
      isUsed: val.isUsed,
      usedBy: val.usedBy,
      createdAt: val.createdAt,
      dateStr: val.dateStr || getTodayDateStr()
    });
  });
  return list;
}

// Auto-check and reset daily passcodes every 30 minutes
setInterval(() => {
  const wasReset = checkAndResetDailyPasscodes();
  if (wasReset) {
    const passcodeUpdate = JSON.stringify({
      type: 'PASSCODE_LIST_UPDATE',
      passcodes: getPasscodesList(),
      todayDate: getTodayDateStr()
    });
    monitors.forEach((m) => { if (m.readyState === 1) m.send(passcodeUpdate); });
  }
}, 30 * 60 * 1000);

wss.on('connection', (ws) => {
  ws.on('message', (data) => {
    try {
      const msg = JSON.parse(data);
      if (msg.type === 'REGISTER_ROLE') {
        if (msg.role === 'MONITOR') {
          monitors.add(ws);
          const wasReset = checkAndResetDailyPasscodes();
          const listPayload = JSON.stringify({
            type: 'PASSCODE_LIST_UPDATE',
            passcodes: getPasscodesList(),
            todayDate: getTodayDateStr()
          });
          ws.send(listPayload);

          if (wasReset) {
            monitors.forEach((m) => { if (m !== ws && m.readyState === 1) m.send(listPayload); });
          }

          candidates.forEach((candData, id) => {
            ws.send(JSON.stringify({
              type: 'CANDIDATE_LIST_UPDATE',
              candidateId: id,
              data: candData.lastState
            }));
          });
        } else if (msg.role === 'CANDIDATE') {
          checkAndResetDailyPasscodes();
          const code = (msg.passcode || '').trim();
          if (!passcodes.has(code)) {
            ws.send(JSON.stringify({ type: 'AUTH_ERROR', message: 'Invalid 6-digit access code. Please verify your passcode.' }));
            return;
          }
          const passcodeEntry = passcodes.get(code);
          if (passcodeEntry.isUsed) {
            ws.send(JSON.stringify({
              type: 'AUTH_ERROR',
              message: 'This 6-digit passcode has already been used! One-time access codes cannot be reused. Please request a new passcode from faculty.'
            }));
            return;
          }

          // Mark passcode as USED (One-Time Access Enforcement)
          passcodeEntry.isUsed = true;
          passcodeEntry.usedBy = msg.candidateId;

          const examType = passcodeEntry.type || 'STANDARD';
          candidates.set(msg.candidateId, { ws, lastState: null, passcode: code, examType });

          ws.send(JSON.stringify({
            type: 'AUTH_SUCCESS',
            candidateId: msg.candidateId,
            passcode: code,
            examType: examType
          }));

          // Broadcast updated passcodes list to all monitors
          const passcodeUpdate = JSON.stringify({
            type: 'PASSCODE_LIST_UPDATE',
            passcodes: getPasscodesList(),
            todayDate: getTodayDateStr()
          });
          monitors.forEach((m) => { if (m.readyState === 1) m.send(passcodeUpdate); });
        }
        return;
      }

      if (msg.type === 'GENERATE_PASSCODES') {
        checkAndResetDailyPasscodes();
        const count = msg.count || 5;
        const pType = (msg.passcodeType || msg.codeType || 'STANDARD').toUpperCase();
        for (let i = 0; i < count; i++) {
          generatePasscode(pType);
        }
        const passcodeUpdate = JSON.stringify({
          type: 'PASSCODE_LIST_UPDATE',
          passcodes: getPasscodesList(),
          todayDate: getTodayDateStr()
        });
        monitors.forEach((m) => { if (m.readyState === 1) m.send(passcodeUpdate); });
        return;
      }

      if (msg.type === 'RESET_DAILY_PASSCODES') {
        initDailyPasscodes();
        const passcodeUpdate = JSON.stringify({
          type: 'PASSCODE_LIST_UPDATE',
          passcodes: getPasscodesList(),
          todayDate: getTodayDateStr()
        });
        monitors.forEach((m) => { if (m.readyState === 1) m.send(passcodeUpdate); });
        return;
      }

      if (msg.type === 'REASSIGN_NEW_PASSCODE') {
        checkAndResetDailyPasscodes();
        const cand = candidates.get(msg.candidateId);
        const candType = (cand && cand.examType) ? cand.examType : 'STANDARD';
        const newCode = (msg.customCode && msg.customCode.trim().length === 6)
          ? msg.customCode.trim()
          : generatePasscode(candType);

        if (!passcodes.has(newCode)) {
          passcodes.set(newCode, {
            code: newCode,
            type: candType,
            isUsed: false,
            usedBy: null,
            createdAt: Date.now(),
            dateStr: getTodayDateStr()
          });
        }

        const passcodeUpdate = JSON.stringify({
          type: 'PASSCODE_LIST_UPDATE',
          passcodes: getPasscodesList(),
          todayDate: getTodayDateStr()
        });
        monitors.forEach((m) => { if (m.readyState === 1) m.send(passcodeUpdate); });

        const assignedNotification = JSON.stringify({
          type: 'CANDIDATE_NEW_CODE_ASSIGNED',
          candidateId: msg.candidateId,
          newCode: newCode,
          examType: candType
        });
        monitors.forEach((m) => { if (m.readyState === 1) m.send(assignedNotification); });

        if (cand && cand.ws && cand.ws.readyState === 1) {
          cand.ws.send(JSON.stringify({
            type: 'REAUTHORIZATION_REQUIRED',
            candidateId: msg.candidateId,
            newCode: newCode,
            examType: candType,
            message: 'Faculty has assigned a new 6-digit access code for your session.'
          }));
        }
        return;
      }

      if (msg.type === 'VERIFY_REAUTH_CODE') {
        const code = (msg.passcode || '').trim();
        const cand = candidates.get(msg.candidateId);

        // Prevent using previous expired code
        if (cand && cand.passcode === code && passcodes.get(code)?.isTerminated) {
          ws.send(JSON.stringify({
            type: 'REAUTH_ERROR',
            message: 'This old passcode has expired due to session lock. Please use the new code generated by faculty.'
          }));
          return;
        }

        if (!passcodes.has(code)) {
          ws.send(JSON.stringify({ type: 'REAUTH_ERROR', message: 'Invalid 6-digit reauthorization code.' }));
          return;
        }
        const passcodeEntry = passcodes.get(code);
        if (passcodeEntry.isUsed && passcodeEntry.usedBy !== msg.candidateId) {
          ws.send(JSON.stringify({ type: 'REAUTH_ERROR', message: 'This passcode has already been used!' }));
          return;
        }
        passcodeEntry.isUsed = true;
        passcodeEntry.isTerminated = false;
        passcodeEntry.usedBy = msg.candidateId;

        const examType = passcodeEntry.type || (cand && cand.examType) || 'STANDARD';

        if (candidates.has(msg.candidateId)) {
          const entry = candidates.get(msg.candidateId);
          entry.passcode = code;
          entry.examType = examType;
        } else {
          candidates.set(msg.candidateId, { ws, lastState: null, passcode: code, examType });
        }

        ws.send(JSON.stringify({
          type: 'REAUTH_SUCCESS',
          candidateId: msg.candidateId,
          passcode: code,
          examType: examType,
          message: 'Exam session successfully resumed!'
        }));

        const broadcastPayload = JSON.stringify({
          type: 'CANDIDATE_RESUMED_NOTIFICATION',
          candidateId: msg.candidateId,
          newCode: code,
          examType: examType
        });
        monitors.forEach((m) => { if (m.readyState === 1) m.send(broadcastPayload); });

        const passcodeUpdate = JSON.stringify({
          type: 'PASSCODE_LIST_UPDATE',
          passcodes: getPasscodesList(),
          todayDate: getTodayDateStr()
        });
        monitors.forEach((m) => { if (m.readyState === 1) m.send(passcodeUpdate); });
        return;
      }

      if (msg.type === 'REASSIGN_RESUME_CANDIDATE') {
        const cand = candidates.get(msg.candidateId);
        if (cand && cand.ws && cand.ws.readyState === 1) {
          cand.ws.send(JSON.stringify({
            type: 'SESSION_RESUMED_BY_FACULTY',
            candidateId: msg.candidateId,
            message: 'Your exam session has been re-authorized by faculty. You can now resume your test.'
          }));
        }
        const broadcastPayload = JSON.stringify({
          type: 'CANDIDATE_RESUMED_NOTIFICATION',
          candidateId: msg.candidateId
        });
        monitors.forEach((m) => { if (m.readyState === 1) m.send(broadcastPayload); });
        return;
      }

      if (msg.type === 'CLEAR_MONITORED_SESSIONS') {
        candidates.clear();
        const clearPayload = JSON.stringify({ type: 'ALL_SESSIONS_CLEARED' });
        monitors.forEach((m) => { if (m.readyState === 1) m.send(clearPayload); });
        return;
      }

      if (msg.type === 'CLEAR_CANDIDATE_SESSION') {
        if (candidates.has(msg.candidateId)) {
          candidates.delete(msg.candidateId);
        }
        const removePayload = JSON.stringify({ type: 'CANDIDATE_DISCONNECTED', candidateId: msg.candidateId });
        monitors.forEach((m) => { if (m.readyState === 1) m.send(removePayload); });
        return;
      }

      if (msg.type === 'TELEMETRY_UPDATE') {
        if (candidates.has(msg.candidateId)) {
          const cand = candidates.get(msg.candidateId);
          if (cand.lastState && cand.lastState.evidences && cand.lastState.evidences.length > 0) {
            if (!msg.payload.evidences || msg.payload.evidences.length === 0) {
              msg.payload.evidences = cand.lastState.evidences;
            } else {
              const merged = [...msg.payload.evidences, ...cand.lastState.evidences];
              msg.payload.evidences = [...new Set(merged)].slice(0, 30);
            }
          }
          cand.lastState = msg.payload;
        }
        const broadcastPayload = JSON.stringify({
          type: 'CANDIDATE_TELEMETRY',
          candidateId: msg.candidateId,
          payload: msg.payload
        });
        monitors.forEach((m) => { if (m.readyState === 1) m.send(broadcastPayload); });
      }
    } catch (err) {
      console.error('Message parsing error:', err);
    }
  });

  ws.on('close', () => {
    monitors.delete(ws);
    candidates.forEach((val, id) => {
      if (val.ws === ws) {
        candidates.delete(id);
        monitors.forEach((m) => {
          if (m.readyState === 1) {
            m.send(JSON.stringify({ type: 'CANDIDATE_DISCONNECTED', candidateId: id }));
          }
        });
      }
    });
  });
});
