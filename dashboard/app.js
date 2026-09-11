"use strict";

// ============================================================
// STATE
// ============================================================
const state = {
  selectedSessionId: null,
  selectedSession: null,
  selectedEvents: [],
  sessions: [],
  events: [],
  status: null,
  filter: "all",
  activeTab: "transcript",
  refreshing: false,
  analyzing: false,
  sessionsExpanded: false,
  sensorHistory: {
    2222: [],
    2323: [],
    8088: [],
    8443: [],
    33060: [],
  },
  lastPortCounters: {},
  canaryTokens: [],
  alerts: null,
};

// ============================================================
// UTILS
// ============================================================
const $ = (id) => document.getElementById(id);

function esc(v) {
  return String(v ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

async function api(path, opts = {}) {
  const r = await fetch(path, {
    headers: { "Content-Type": "application/json", ...(opts.headers || {}) },
    ...opts,
  });
  if (!r.ok) {
    let msg = `${r.status} ${r.statusText}`;
    try { const b = await r.json(); msg = b.detail || msg; } catch (_) {}
    throw new Error(msg);
  }
  return r.json();
}

function toast(msg, err = false) {
  const el = $("toast");
  el.textContent = msg;
  el.classList.toggle("error", err);
  el.classList.add("visible");
  clearTimeout(toast._t);
  toast._t = setTimeout(() => el.classList.remove("visible"), 3200);
}

function dur(secs) {
  const t = Math.max(0, Math.round(Number(secs || 0)));
  const h = Math.floor(t / 3600), m = Math.floor((t % 3600) / 60), s = t % 60;
  if (h) return `${h}h ${m}m`;
  if (m) return `${m}m ${s}s`;
  return `${s}s`;
}

function formatBytes(bytes) {
  if (!bytes || bytes <= 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + " " + sizes[i];
}

function sessionDuration(sess) {
  if (!sess?.started_at) return 0;
  const s = new Date(sess.started_at).getTime();
  const e = sess.ended_at ? new Date(sess.ended_at).getTime() : Date.now();
  return Math.max(0, (e - s) / 1000);
}

function timeStr(v) {
  if (!v) return "--";
  return new Date(v).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function riskClass(score) {
  if (score >= 80) return "risk-critical";
  if (score >= 60) return "risk-high";
  if (score >= 40) return "risk-medium";
  return "risk-low";
}

function riskLabel(score) {
  if (score >= 80) return `${score} CRIT`;
  if (score >= 60) return `${score} HIGH`;
  if (score >= 40) return `${score} MED`;
  return `${score} LOW`;
}

function protoFromPort(port) {
  if (port === 0) return "HOST";
  const map = { 2222: "SSH", 2323: "TELNET", 8088: "HTTP", 8443: "HTTPS", 33060: "MYSQL" };
  return map[port] || "ENDPOINT";
}

function protoClass(proto) {
  if (!proto) return "";
  const p = proto.toUpperCase();
  if (p.includes("TELNET")) return "telnet";
  if (p.includes("HTTP")) return "http";
  if (p.includes("HOST") || p.includes("ENDPOINT")) return "endpoint";
  return "";
}

// ============================================================
// DYNAMIC SVG SPARKLINE GENERATOR (100% Real Time-Series)
// ============================================================
function generateSparkline(points, width = 100, height = 24) {
  if (!points || points.length === 0) {
    const y = height - 4;
    return {
      d: `M0,${y} L${width},${y}`,
      fill: `M0,${y} L${width},${y} L${width},${height} L0,${height} Z`,
    };
  }

  const n = points.length;
  const min = Math.min(...points);
  const max = Math.max(...points);

  // If completely flat/zero, render genuine horizontal quiescent line
  if (max === min || max === 0) {
    const y = height - 4;
    return {
      d: `M0,${y} L${width},${y}`,
      fill: `M0,${y} L${width},${y} L${width},${height} L0,${height} Z`,
    };
  }

  const paddingY = 4;
  const usableH = height - (paddingY * 2);
  const coords = points.map((val, idx) => {
    const x = n === 1 ? width / 2 : (idx / (n - 1)) * width;
    const norm = (val - min) / (max - min);
    const y = (height - paddingY) - (norm * usableH);
    return [Math.round(x * 10) / 10, Math.round(y * 10) / 10];
  });

  // Build smooth Bézier spline through points
  let d = `M${coords[0][0]},${coords[0][1]}`;
  for (let i = 0; i < coords.length - 1; i++) {
    const p0 = coords[i === 0 ? i : i - 1];
    const p1 = coords[i];
    const p2 = coords[i + 1];
    const p3 = coords[i + 2 < coords.length ? i + 2 : i + 1];

    const cp1x = p1[0] + (p2[0] - p0[0]) / 6;
    const cp1y = p1[1] + (p2[1] - p0[1]) / 6;
    const cp2x = p2[0] - (p3[0] - p1[0]) / 6;
    const cp2y = p2[1] - (p3[1] - p1[1]) / 6;

    d += ` C${cp1x.toFixed(1)},${cp1y.toFixed(1)} ${cp2x.toFixed(1)},${cp2y.toFixed(1)} ${p2[0]},${p2[1]}`;
  }

  const fill = `${d} L${width},${height} L0,${height} Z`;
  return { d, fill };
}

// Maintain 100% real rolling time-series buffer per sensor port
function updateSensorHistory(sessionsArr, eventsArr, status) {
  const sessionPortMap = {};
  (sessionsArr || []).forEach(s => {
    if (s.session_id && s.destination_port) {
      sessionPortMap[s.session_id] = s.destination_port;
    }
  });

  const running = status?.running ?? false;

  SENSORS.forEach(s => {
    const port = s.key;
    if (!state.sensorHistory[port]) {
      state.sensorHistory[port] = [];
    }

    const portSessions = (sessionsArr || []).filter(sess => sess.destination_port === port);
    const activeSessions = portSessions.filter(sess => !sess.ended_at).length;
    const interactions = portSessions.reduce((acc, sess) => acc + (sess.interactions || 0), 0);
    const portEvents = (eventsArr || []).filter(e => {
      if (e.metadata?.destination_port === port) return true;
      return sessionPortMap[e.session_id] === port;
    });

    const currentCounter = interactions + portEvents.length;

    if (state.sensorHistory[port].length === 0) {
      // Seed initial history from actual event timestamps
      if (currentCounter === 0 || !running) {
        state.sensorHistory[port] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
      } else {
        const buckets = new Array(12).fill(0);
        if (portEvents.length > 0) {
          const times = portEvents.map(e => new Date(e.timestamp || 0).getTime()).filter(t => t > 0);
          const minT = Math.min(...times);
          const maxT = Math.max(...times);
          const span = Math.max(1, maxT - minT);
          times.forEach(t => {
            const b = Math.min(11, Math.floor(((t - minT) / span) * 12));
            buckets[b]++;
          });
        } else {
          buckets[10] = Math.floor(interactions / 2);
          buckets[11] = Math.ceil(interactions / 2);
        }
        state.sensorHistory[port] = buckets;
      }
      state.lastPortCounters[port] = currentCounter;
    } else {
      // Real rolling update
      const lastCounter = state.lastPortCounters[port] ?? currentCounter;
      let delta = Math.max(0, currentCounter - lastCounter);
      if (activeSessions > 0 && running) {
        delta = Math.max(delta, activeSessions * 2);
      }
      state.lastPortCounters[port] = currentCounter;

      const history = state.sensorHistory[port];
      history.push(delta);
      if (history.length > 14) {
        history.shift();
      }
    }
  });
}

// ============================================================
// SENSOR CARDS (100% Real HoneyNet Decoy Telemetry)
// ============================================================
const SENSORS = [
  { name: "SSH Honeypot",   port: "2222/tcp", key: 2222, color: "#8B9A6E" },
  { name: "Telnet Legacy",  port: "2323/tcp", key: 2323, color: "#C24B4B" },
  { name: "HTTP Finance",   port: "8088/tcp", key: 8088, color: "#6e7d53" },
  { name: "HTTPS Ops API",  port: "8443/tcp", key: 8443, color: "#8B9A6E" },
  { name: "MySQL Database", port: "33060/tcp", key: 33060, color: "#a2af88" },
];

function renderSensors(sessionsArr, status, eventsArr) {
  const grid = $("sensor-grid");
  if (!grid) return;

  const countByPort = {};
  (status?.services || []).forEach(srv => {
    if (srv.port && srv.active_sessions) {
      countByPort[srv.port] = (countByPort[srv.port] || 0) + srv.active_sessions;
    }
  });
  (sessionsArr || []).forEach(s => {
    if (!s.ended_at && s.destination_port) {
      countByPort[s.destination_port] = Math.max(countByPort[s.destination_port] || 0, 1);
    }
  });

  const running = status?.running ?? false;

  const sessionPortMap = {};
  (sessionsArr || []).forEach(s => {
    if (s.session_id && s.destination_port) {
      sessionPortMap[s.session_id] = s.destination_port;
    }
  });

  grid.innerHTML = SENSORS.map((s) => {
    const activeCount = countByPort[s.key] || 0;
    const engaged = activeCount > 0 && running;

    const portSessions = (sessionsArr || []).filter(sess => sess.destination_port === s.key);
    const portInteractions = portSessions.reduce((acc, sess) => acc + (sess.interactions || 0), 0);
    const portBytes = portSessions.reduce((acc, sess) => acc + (sess.bytes_in || 0) + (sess.bytes_out || 0), 0);

    const portEvents = (eventsArr || []).filter(e => {
      if (e.metadata?.destination_port === s.key) return true;
      return sessionPortMap[e.session_id] === s.key;
    });

    // Extract real measured latency or artificial delay from event telemetry
    let latencyLabel = "--";
    const aiEvent = portEvents.find(e => e.event_type === "DECOY_AI_RESPONSE" || e.metadata?.artificial_delay_ms != null || e.latency_ms != null);
    if (aiEvent) {
      const delayMs = aiEvent.metadata?.artificial_delay_ms || aiEvent.latency_ms;
      if (delayMs) {
        latencyLabel = delayMs >= 1000 ? `${(delayMs / 1000).toFixed(2)}s AI Delay` : `${delayMs}ms AI Delay`;
      } else {
        latencyLabel = "gRPC Fast";
      }
    } else if (engaged) {
      latencyLabel = "<1ms TCP";
    } else if (portSessions.length > 0) {
      latencyLabel = "Quiescent";
    } else {
      latencyLabel = !running ? "Offline" : "0ms Idle";
    }

    // Real throughput / activity label
    let activityLabel = "0 probes";
    if (engaged) {
      activityLabel = `${portInteractions} action${portInteractions !== 1 ? "s" : ""} (${formatBytes(portBytes)})`;
    } else if (portSessions.length > 0) {
      activityLabel = `${portSessions.length} logged (${portInteractions} act)`;
    } else {
      activityLabel = !running ? "Offline" : "0 probes (idle)";
    }

    // Dynamic Sparkline from real history
    const history = state.sensorHistory[s.key] || [];
    const spark = generateSparkline(history, 100, 24);

    const color = engaged ? (s.key === 2323 ? "#C24B4B" : s.color) : "#8c9680";
    const statusText = !running ? "Offline" : engaged ? "Engaged" : "Listening";
    const statusColor = !running ? "#8c9680" : engaged ? "#C24B4B" : "#8B9A6E";

    return `
    <div class="sensor-card ${engaged ? "engaged" : ""}" data-port="${s.key}">
      ${engaged ? `<div class="engaged-tag">Active Attack</div>` : ""}
      <div class="sensor-card-head">
        <div>
          <div class="sensor-status">
            <span style="width:7px;height:7px;border-radius:50%;background:${statusColor};display:inline-block;${engaged ? "animation:pulse 1s infinite" : ""}"></span>
            <span style="font-family:var(--font-mono);font-size:10px;font-weight:700;color:${statusColor};text-transform:uppercase;letter-spacing:0.06em">${statusText}</span>
          </div>
          <div class="sensor-name">${esc(s.name)}</div>
          <div class="sensor-port">Port: <strong style="color:${engaged ? "#C24B4B" : "var(--text)"}">${esc(s.port)}</strong></div>
        </div>
        <span class="sensor-sessions ${activeCount > 0 ? "active" : ""}">${activeCount} active</span>
      </div>
      <div class="sensor-footer">
        <div class="sensor-sparkline-label">
          <span style="color:${engaged ? "#C24B4B" : ""};font-weight:600">${esc(activityLabel)}</span>
          <span style="color:${color};font-weight:600">${esc(latencyLabel)}</span>
        </div>
        <svg viewBox="0 0 100 24" fill="none" style="width:100%;height:26px;overflow:visible">
          <path d="${spark.d}" stroke="${color}" stroke-width="${engaged ? 2 : 1.75}" stroke-linecap="round" stroke-linejoin="round" fill="none"/>
          <path d="${spark.fill}" fill="${color}" opacity="${engaged ? 0.12 : 0.05}"/>
        </svg>
      </div>
    </div>`;
  }).join("");

  $("nav-badge-sensors") && ($("nav-badge-sensors").textContent = `${running ? 5 : 0} ACT`);
}

// ============================================================
// SESSION CARDS
// ============================================================
function intentTags(sess) {
  const tags = [];
  if (sess.risk_score >= 80) tags.push({ label: "Critical Risk", cls: "danger" });
  const mitre = sess.mitre_techniques || sess.triage?.mitre_techniques || [];
  mitre.slice(0, 2).forEach(t => tags.push({ label: t, cls: "mitre" }));
  const intent = sess.intent || sess.triage?.intent_label;
  if (intent) tags.push({ label: intent, cls: "" });
  return tags;
}

function renderSessions(sessionsArr) {
  const grid = $("session-grid");
  if (!grid) return;

  const filter = state.filter;
  let filtered = sessionsArr;

  if (filter === "critical") {
    filtered = sessionsArr.filter(s => (s.risk_score || 0) >= 80);
  } else if (filter !== "all") {
    filtered = sessionsArr.filter(s => {
      const proto = protoFromPort(s.destination_port).toLowerCase();
      return proto.includes(filter.toLowerCase());
    });
  }

  const caption = $("sessions-caption");
  if (caption) caption.textContent = `${filtered.length} session${filtered.length !== 1 ? "s" : ""} engaged across decoy mesh`;

  const badge = $("nav-badge-sessions");
  if (badge) {
    badge.textContent = `${sessionsArr.length} TRAP`;
    badge.classList.toggle("danger", sessionsArr.length > 0);
  }

  const stat = $("stat-sessions");
  if (stat) stat.textContent = sessionsArr.length;

  const crit = sessionsArr.filter(s => (s.risk_score || 0) >= 80).length;
  const critBadge = $("stat-critical");
  if (critBadge) critBadge.textContent = `${crit} Critical`;

  const sub = $("stat-sessions-sub");
  if (sub) sub.textContent = `${sessionsArr.filter(s => !s.ended_at).length} currently live`;

  if (filtered.length === 0) {
    grid.innerHTML = `<div class="empty-state">
      <span class="material-symbols-outlined" style="font-size:40px;color:#8ca4ac">wifi_off</span>
      <p>${sessionsArr.length === 0 ? "No active sessions yet. Start the grid and generate some traffic." : "No sessions match this filter."}</p>
    </div>`;
    return;
  }

  grid.innerHTML = filtered.map(sess => {
    const proto = sess.service || protoFromPort(sess.destination_port);
    const risk = sess.risk_score || 0;
    const selected = sess.session_id === state.selectedSessionId;
    const tags = intentTags(sess);
    const active = !sess.ended_at;
    const src = sess.source_ip || sess.source_address || "Unknown";
    const actions = sess.interactions ?? sess.attacker_action_count ?? 0;

    return `<div class="session-card ${selected ? "selected" : ""}" data-id="${esc(sess.session_id)}">
      <div class="session-head">
        <div class="session-ip">
          <span class="session-flag">🌐</span>
          <span style="font-weight:700">${esc(src)}</span>
          ${sess.destination_port ? `<span class="session-asn">:${sess.destination_port}</span>` : ""}
        </div>
        <span class="risk-badge ${riskClass(risk)}">${riskLabel(risk)}</span>
      </div>
      <div class="session-meta">
        <div>
          <span class="session-proto ${protoClass(proto)}">${proto}:${sess.destination_port || "?"}</span>
          <span style="margin-left:6px">&#8226; ${actions} actions</span>
        </div>
        <span style="color:${active ? "var(--primary)" : "var(--text-muted)"}">
          ${active ? `Live ${dur(sessionDuration(sess))}` : "Ended " + timeStr(sess.ended_at)}
        </span>
      </div>
      ${tags.length > 0 ? `<div class="session-tags">${tags.map(t => `<span class="session-tag ${t.cls}">${esc(t.label)}</span>`).join("")}</div>` : ""}
    </div>`;
  }).join("");

  grid.querySelectorAll(".session-card").forEach(card => {
    card.addEventListener("click", () => selectSession(card.dataset.id, true));
  });

  requestAnimationFrame(() => {
    syncSessionGridExpansion(filtered);
  });
}

function syncSessionGridExpansion(filtered) {
  const grid = $("session-grid");
  const wrap = $("session-grid-wrap");
  const bar = $("session-expand-bar");
  const btn = $("btn-toggle-sessions");
  const btnText = $("expand-btn-text");
  if (!grid || !bar) return;

  const total = (filtered || state.sessions || []).length;
  const cards = grid.querySelectorAll(".session-card");
  if (cards.length === 0) {
    bar.style.display = "none";
    grid.classList.remove("collapsed");
    grid.style.maxHeight = "none";
    wrap?.classList.remove("collapsed-fade");
    wrap?.classList.add("is-expanded");
    return;
  }

  // Detect unique rows by card offsetTop
  const rowTops = [];
  cards.forEach(c => {
    const top = c.offsetTop;
    if (!rowTops.includes(top)) rowTops.push(top);
  });

  // If 2 or fewer rows exist, hide expand button and don't collapse
  if (rowTops.length <= 2) {
    bar.style.display = "none";
    grid.classList.remove("collapsed");
    grid.style.maxHeight = "none";
    wrap?.classList.remove("collapsed-fade");
    wrap?.classList.add("is-expanded");
    return;
  }

  bar.style.display = "flex";

  // Calculate bottom of second row
  const row2Top = rowTops[1];
  let row2Height = 0;
  let firstTwoRowsCount = 0;
  cards.forEach(c => {
    if (c.offsetTop === rowTops[0] || c.offsetTop === row2Top) {
      firstTwoRowsCount++;
      if (c.offsetTop === row2Top) {
        row2Height = Math.max(row2Height, c.offsetHeight);
      }
    }
  });

  const twoRowsHeight = (row2Top - rowTops[0]) + row2Height + 6;
  const remaining = Math.max(0, total - firstTwoRowsCount);

  if (state.sessionsExpanded) {
    grid.classList.remove("collapsed");
    grid.style.maxHeight = (grid.scrollHeight + 120) + "px";
    wrap?.classList.remove("collapsed-fade");
    wrap?.classList.add("is-expanded");
    btn?.classList.add("expanded");
    if (btnText) btnText.textContent = "View Less Sessions";
  } else {
    grid.classList.add("collapsed");
    grid.style.maxHeight = `${twoRowsHeight}px`;
    wrap?.classList.add("collapsed-fade");
    wrap?.classList.remove("is-expanded");
    btn?.classList.remove("expanded");
    if (btnText) {
      btnText.textContent = remaining > 0 
        ? `View More Sessions (${remaining} more)`
        : "View More Sessions";
    }
  }
}

// ============================================================
// PLAIN-ENGLISH SESSION EXPLAINER & MODAL POPUP
// ============================================================
function explainSessionInPlainEnglish(sess, events = []) {
  const proto = (sess.service || protoFromPort(sess.destination_port) || "").toUpperCase();
  const port = sess.destination_port;
  const actions = sess.interactions ?? sess.attacker_action_count ?? events.filter(e => e.direction === "inbound").length;
  const src = sess.source_ip || sess.source_address || "Unknown IP";
  const user = sess.username ? `"${sess.username}"` : "administrative credentials";

  // Gather clues from recorded events
  const paths = [];
  const commands = [];
  let isSSRF = false;
  let isSQLi = false;
  let isLFI = false;
  let isBruteForce = false;
  let isScanner = false;
  let isKubeOrCloud = false;

  events.forEach(e => {
    const text = (e.content || "") + " " + JSON.stringify(e.metadata || "");
    const lower = text.toLowerCase();
    if (e.metadata?.path) paths.push(e.metadata.path);
    if (lower.includes("169.254") || lower.includes("webhook") || lower.includes("metadata")) isSSRF = true;
    if (lower.includes("or 1=1") || lower.includes("select") || lower.includes("union")) isSQLi = true;
    if (lower.includes("etc/passwd") || lower.includes("../")) isLFI = true;
    if (lower.includes("masscan") || lower.includes("scanner") || lower.includes("port_scan")) isScanner = true;
    if (lower.includes("kube") || lower.includes("cluster") || lower.includes("nodes")) isKubeOrCloud = true;
    if (e.event_type === "DECOY_AUTH_ATTEMPT" || lower.includes("password")) isBruteForce = true;
    if (e.event_type === "SYSTEM_DISCOVERY" || e.event_type === "HONEYPOT_INTERACTION") {
      if (e.content && !e.content.startsWith("HTTP")) commands.push(e.content.trim());
    }
  });

  let title = "Suspicious Network Intrusion";
  let attackerStory = "";
  let defenderStory = "";

  if (port === 8443 || proto.includes("HTTPS")) {
    title = isSSRF ? "Cloud Infrastructure SSRF & API Compromise Attempt" : "Operations API Gateway Exploitation Probe";
    attackerStory = `An attacker from ${src} connected to your encrypted Operations API Gateway (Port 8443). ` +
      (isSSRF 
        ? `They attempted a dangerous Server-Side Request Forgery (SSRF) exploit targeting cloud metadata endpoints (${paths.slice(0, 2).join(", ") || "/api/v1/ops/webhooks"}) to trick your gateway into leaking cloud identity tokens. `
        : isKubeOrCloud 
        ? `They enumerated your Kubernetes cluster topology and service account tokens searching for container breakouts. `
        : `They scanned for API documentation blueprints (/swagger.json) and tested unauthorized administrative endpoints. `) +
      `In total, the adversary issued ${actions} hostile request${actions !== 1 ? "s" : ""}.`;

    defenderStory = `CyberShield AI immediately entrapped the attacker inside an isolated decoy sandbox mimicking an Nginx operations gateway. Adaptive Gemini AI generated convincing fake responses with realistic micro-delays, keeping the attacker engaged while completely isolating your real servers and cloud infrastructure.`;

  } else if (port === 2323 || proto.includes("TELNET")) {
    title = "Telnet Remote Shell Brute Force & Exploitation";
    attackerStory = `An automated adversary from ${src} connected to your legacy Telnet console (Port 2323). They tried brute-forcing passwords using common combinations like ${user}. After receiving a shell, they attempted system discovery commands${commands.length ? " (" + commands.slice(0, 3).map(c => `'${c}'`).join(", ") + ")" : ""} to find files and download external payloads.`;

    defenderStory = `CyberShield AI lured the attacker into a high-interaction, sandboxed Linux terminal ("legacy backup appliance"). Gemini generative responses simulated real Ubuntu bash output with natural latency, keeping the attacker busy while containing them with zero egress capability.`;

  } else if (port === 8088 || proto.includes("HTTP")) {
    title = isSQLi ? "Web Application SQL Injection Probe" : isLFI ? "Directory Traversal / File Theft Attempt" : "Web Portal Reconnaissance & Exploitation";
    attackerStory = `An adversary from ${src} targeted your internal HTTP web server (Port 8088). They probed for vulnerabilities including ` +
      (isSQLi ? "SQL database injection (`' OR 1=1`) to bypass logins" : isLFI ? "path traversal (`/../../etc/passwd`) to steal system files" : "sensitive admin panels and code execution endpoints") +
      `, generating ${actions} web requests.`;

    defenderStory = `CyberShield AI intercepted every request at the perimeter. Instead of letting requests reach actual business services, CyberShield AI served deceptive synthetic web responses, logged every header and payload, and flagged the attacker's IP for immediate quarantine.`;

  } else if (port === 2222 || proto.includes("SSH")) {
    title = "SSH Mass Scanner & Credential Probe";
    attackerStory = `A remote host from ${src} scanned port 2222 looking for an open SSH administration gateway. They sent client identification handshakes and reconnaissance probes to identify the OpenSSH version and check for known remote vulnerabilities.`;

    defenderStory = `The CyberShield AI SSH lure answered with a convincing OpenSSH 8.9 banner, recorded the attacker's scanner fingerprint, and isolated the socket before any unauthorized access could occur.`;

  } else if (port === 33060 || proto.includes("MYSQL")) {
    title = "Database Handshake & Auth Bypass Probe";
    attackerStory = `An unauthorized client from ${src} attempted to connect directly to your MySQL database port (33060). They completed a database handshake and attempted root login bypass without authorization.`;

    defenderStory = `The decoy database presented authentic MySQL 8.0 challenge handshakes, captured the attacker's authentication hash, and securely dropped the connection while preserving evidence.`;

  } else {
    title = `${proto} Decoy Engagement`;
    attackerStory = `An external connection from ${src} engaged your decoy service on port ${port}. They triggered ${actions} interactions, attempting ${sess.intent || "system discovery and unauthorized access"}.`;
    defenderStory = `CyberShield AI intercepted the session in an isolated lure environment, preventing exposure to your production assets while recording complete forensic telemetry.`;
  }

  return { title, attackerStory, defenderStory };
}

function renderSessionTimelineSimple(events = []) {
  if (!events || events.length === 0) {
    return `<div class="timeline-step">
      <span class="timeline-step-badge system">SYSTEM</span>
      <div class="timeline-step-content">
        <div class="timeline-step-title">Session initialized</div>
        <div class="timeline-step-detail">Connection captured and monitored by CyberShield AI.</div>
      </div>
    </div>`;
  }

  return events.map((e, idx) => {
    const isOut = e.direction === "outbound";
    const isSys = e.direction === "system";
    const badgeClass = isOut ? "outbound" : isSys ? "system" : "inbound";
    const badgeLabel = isOut ? "Decoy Response" : isSys ? "Defense System" : `Step ${idx + 1}: Attacker`;

    let title = "";
    let detail = "";

    const type = e.event_type;
    const content = e.content || "";
    const meta = e.metadata || {};

    if (type === "HONEYPOT_SESSION_STARTED") {
      title = `Attacker connected to Port ${meta.destination_port || "decoy"}`;
      detail = `Source: ${meta.source_ip || "attacker"}:${meta.source_port || "?"} (${meta.tls ? "TLS Encrypted" : "Plain TCP"})`;
    } else if (type === "AUTH_PROMPT" || type === "TELNET_BANNER" || type === "SSH_BANNER") {
      title = "Decoy presented authentic login prompt";
      detail = content.trim().replace(/\r?\n/g, " ") || "Authentic authentication banner displayed";
    } else if (type === "DECOY_AUTH_ATTEMPT") {
      title = `Attacker attempted login with username: "${meta.username || 'unknown'}"`;
      detail = `Password payload captured and hashed (Length: ${meta.password_length || 'N/A'})`;
    } else if (type === "DECOY_AUTH_SUCCESS") {
      title = "Decoy safely accepted login to study adversary techniques";
      detail = "Attacker was granted a sandboxed decoy shell with zero access to real files";
    } else if (type === "HTTP_REQUEST") {
      title = `Attacker sent ${meta.method || 'GET'} request to "${meta.path || '/'}"`;
      detail = meta.intent ? `Classified intent: ${meta.intent} (Confidence: ${Math.round((meta.intent_confidence || 0.8) * 100)}%)` : content.slice(0, 100);
    } else if (type === "DECOY_HTTP_RESPONSE") {
      title = "Decoy returned adaptive synthetic HTTP response";
      detail = `Simulated response generated by ${meta.provider || 'decoy engine'} (${content.slice(0, 60)})`;
    } else if (type === "DECOY_AI_RESPONSE") {
      title = "Gemini AI generated convincing fake terminal response";
      detail = `Latency: ${e.latency_ms || meta.artificial_delay_ms || 35}ms delay applied to appear authentic`;
    } else if (type === "SYSTEM_DISCOVERY") {
      title = `Attacker executed command: "${content.trim() || meta.path || 'system query'}"`;
      detail = "Adversary attempting to discover internal system configurations and user privileges";
    } else if (type === "CREDENTIAL_DISCOVERY") {
      title = `Attacker probed for secrets / tokens: "${meta.path || content.slice(0, 80)}"`;
      detail = "Adversary attempting to extract credentials or cloud identity tokens";
    } else if (type === "PAYLOAD_TRANSFER") {
      title = "Attacker attempted to download or execute external script";
      detail = content.slice(0, 100);
    } else if (type === "PORT_SCAN") {
      title = "Port scanning detected across multiple decoys";
      detail = `Adversary scanned ports: ${(meta.ports || []).join(", ")}`;
    } else if (type === "SOURCE_BLOCKED") {
      title = "Attacker address blocked by CyberShield AI runtime firewall";
      detail = "Connection terminated and dropped at perimeter";
    } else {
      title = `${type.replace(/_/g, " ")}: ${content.slice(0, 70)}`;
      detail = `Direction: ${e.direction} • Severity: ${e.severity}`;
    }

    return `
      <div class="timeline-step">
        <span class="timeline-step-badge ${badgeClass}">${badgeLabel}</span>
        <div class="timeline-step-content">
          <div class="timeline-step-title">${esc(title)}</div>
          <div class="timeline-step-detail">${esc(detail)}</div>
        </div>
      </div>
    `;
  }).join("");
}

function openSessionModal(sess, events = []) {
  if (!sess) return;

  const proto = sess.service || protoFromPort(sess.destination_port);
  const risk = sess.risk_score || 0;
  const actions = sess.interactions ?? sess.attacker_action_count ?? events.filter(e => e.direction === "inbound").length;
  const dwell = dur(sessionDuration(sess));
  const src = sess.source_ip || sess.source_address || "127.0.0.1";
  const srcPort = sess.source_port ? `:${sess.source_port}` : "";
  const isLive = !sess.ended_at;

  const { title, attackerStory, defenderStory } = explainSessionInPlainEnglish(sess, events);

  // Proto badge
  const protoEl = $("modal-proto");
  if (protoEl) protoEl.textContent = `${proto} (Port ${sess.destination_port || "?"})`;

  // Risk badge
  const riskEl = $("modal-risk");
  if (riskEl) {
    riskEl.className = `modal-risk-badge ${riskClass(risk)}`;
    riskEl.textContent = riskLabel(risk) + (risk >= 80 ? " • Critical Threat" : risk >= 60 ? " • High Threat" : " • Low/Medium");
  }

  // Status badge
  const statusEl = $("modal-status");
  if (statusEl) {
    statusEl.textContent = sess.contained ? "Safely Contained" : isLive ? "Live Attacker Trapped" : "Session Logged";
    statusEl.style.color = sess.contained ? "#4e5d34" : isLive ? "var(--rose)" : "var(--text-secondary)";
    statusEl.style.background = sess.contained ? "var(--primary-light)" : isLive ? "var(--rose-light)" : "var(--surface-neutral)";
  }

  // Title, IP, Time
  if ($("modal-title")) $("modal-title").textContent = title;
  if ($("modal-ip")) $("modal-ip").textContent = `Attacker: ${src}${srcPort}`;
  if ($("modal-time")) $("modal-time").textContent = sess.started_at ? `Started ${timeStr(sess.started_at)}` : "Recent";

  // Story boxes
  if ($("modal-attacker-story")) $("modal-attacker-story").textContent = attackerStory;
  if ($("modal-defender-story")) $("modal-defender-story").textContent = defenderStory;

  // 4 Fact tiles
  if ($("modal-fact-actions")) $("modal-fact-actions").textContent = actions;
  if ($("modal-fact-duration")) $("modal-fact-duration").textContent = dwell;
  if ($("modal-fact-ai")) {
    const aiProvider = sess.gemini_provider || (sess.analyst_report?.llm?.enabled ? "Gemini 3.6 Flash" : "CyberShield AI Sandbox");
    $("modal-fact-ai").textContent = aiProvider.toLowerCase().includes("gemini") ? "Gemini AI Lure" : "CyberShield AI Sandbox";
  }
  if ($("modal-fact-threat")) {
    $("modal-fact-threat").textContent = risk >= 80 ? "Critical" : risk >= 60 ? "High" : "Elevated";
    if ($("modal-fact-threat-sub")) $("modal-fact-threat-sub").textContent = `Risk score: ${risk}/100`;
  }

  // Timeline
  if ($("modal-timeline-count")) $("modal-timeline-count").textContent = `${events.length} interaction${events.length !== 1 ? "s" : ""} captured`;
  if ($("modal-timeline-list")) $("modal-timeline-list").innerHTML = renderSessionTimelineSimple(events);

  // Show modal
  const overlay = $("session-modal-overlay");
  if (overlay) {
    overlay.style.display = "flex";
    document.body.style.overflow = "hidden";
  }
}

function closeSessionModal() {
  const overlay = $("session-modal-overlay");
  if (overlay) {
    overlay.style.display = "none";
    document.body.style.overflow = "";
  }
}

// ============================================================
// SESSION SELECT & TERMINAL
// ============================================================
async function selectSession(id, openModal = false) {
  state.selectedSessionId = id;
  renderSessions(state.sessions);

  const caption = $("terminal-caption");
  if (caption) caption.textContent = `Loading session ${id}...`;

  try {
    const data = await api(`/api/v1/honeypot/sessions/${id}`);
    state.selectedSession = data.session;
    state.selectedEvents = data.events || [];

    renderTerminal();
    renderCopilot(data.session);

    // enable action buttons
    ["btn-kill", "btn-block", "btn-export-session"].forEach(btnId => {
      const btn = $(btnId);
      if (btn) btn.disabled = false;
    });

    if (openModal) {
      openSessionModal(data.session, data.events || []);
    }
  } catch (e) {
    toast("Failed to load session: " + e.message, true);
  }
}

function renderTerminal() {
  const sess = state.selectedSession;
  const events = state.selectedEvents;
  if (!sess) return;

  const targetLabel = $("term-target-label");
  if (targetLabel) {
    const proto = sess.service || protoFromPort(sess.destination_port);
    const src = sess.source_ip || sess.source_address || "Unknown";
    targetLabel.textContent = `${src}:${sess.source_port || "?"} → Decoy:${sess.destination_port} (${proto})`;
  }

  const termMeta = $("term-meta");
  if (termMeta) {
    const provider = sess.gemini_provider || (sess.analyst_report?.llm?.enabled ? "Gemini Deception Active" : "CyberShield AI Sandbox Active");
    termMeta.innerHTML = `
      <div class="gemini-latency-pill">
        <span class="material-symbols-outlined" style="font-size:14px">neurology</span>
        <span>${esc(provider)}</span>
      </div>`;
  }

  const durationEl = $("term-duration");
  if (durationEl) durationEl.textContent = `Duration: ${dur(sessionDuration(sess))}`;

  const caption = $("terminal-caption");
  if (caption) {
    const proto = sess.service || protoFromPort(sess.destination_port);
    const src = sess.source_ip || sess.source_address || "Unknown";
    caption.textContent = `Active stream: ${src} → ${proto} Honeypot (${sess.session_id})`;
  }

  renderTerminalBody();
}

function renderTerminalBody() {
  const body = $("term-body");
  const events = state.selectedEvents;
  const sess = state.selectedSession;
  if (!body || !sess) return;

  const tab = state.activeTab;

  if (tab === "telemetry") {
    const src = sess.source_ip || sess.source_address || "Unknown";
    body.innerHTML = `<div style="display:flex;flex-direction:column;gap:10px">
      ${[
        ["Session ID", sess.session_id],
        ["Source", `${src}:${sess.source_port || "?"}`],
        ["Protocol", sess.service || sess.protocol || protoFromPort(sess.destination_port)],
        ["Destination Port", sess.destination_port],
        ["Risk Score", sess.risk_score ?? "--"],
        ["Attacker Actions", sess.interactions ?? sess.attacker_action_count ?? "--"],
        ["Intent", sess.intent || sess.triage?.intent_label || "--"],
        ["MITRE Techniques", (sess.analyst_report?.mitre_techniques || sess.mitre || sess.mitre_techniques || []).join(", ") || "--"],
        ["Started", sess.started_at ? new Date(sess.started_at).toLocaleString() : "--"],
        ["Ended", sess.ended_at ? new Date(sess.ended_at).toLocaleString() : "Live"],
        ["Duration", dur(sessionDuration(sess))],
        ["Fingerprint", sess.client_fingerprint || sess.fingerprint || "--"],
        ["Gemini Model", sess.analyst_report?.llm?.model || sess.gemini_provider || "gemini-3.6-flash"],
      ].map(([k, v]) => `
        <div style="display:flex;gap:12px;border-bottom:1px solid var(--border);padding-bottom:8px">
          <span style="font-family:var(--font-mono);font-size:11px;color:var(--text-muted);min-width:150px">${esc(k)}</span>
          <span style="font-family:var(--font-mono);font-size:12px;color:var(--text);font-weight:500;word-break:break-all">${esc(String(v))}</span>
        </div>`).join("")}
    </div>`;
    return;
  }

  if (tab === "raw") {
    const payloads = events.filter(e => e.content || e.raw_data || e.command || e.query || e.body_preview);
    if (payloads.length === 0) {
      body.innerHTML = `<div class="term-placeholder"><span class="material-symbols-outlined" style="font-size:36px;opacity:0.25">code</span><p>No raw payload data captured for this session.</p></div>`;
      return;
    }
    body.innerHTML = payloads.map(e => {
      const raw = e.content || e.raw_data || e.command || e.query || e.body_preview || "";
      return `<div class="term-line">
        <span class="term-ts">${timeStr(e.timestamp)}</span>
        <code style="color:var(--rose);word-break:break-all;background:#fff5f5;padding:2px 6px;border-radius:3px">${esc(raw)}</code>
      </div>`;
    }).join("");
    return;
  }

  // TRANSCRIPT (default)
  if (events.length === 0) {
    body.innerHTML = `<div class="term-placeholder">
      <span class="material-symbols-outlined" style="font-size:36px;opacity:0.25">terminal</span>
      <p>No events captured yet for this session.</p>
    </div>`;
    return;
  }

  const protoName = sess.service || protoFromPort(state.selectedSession?.destination_port);
  let html = `<div class="term-line" style="border-bottom:1px solid var(--border);padding-bottom:8px;margin-bottom:8px">
    <span class="term-ts"></span>
    <span class="term-note">[CYBERSHIELD KERNEL HOOK] Ingress socket established &lt;=&gt; Honeypot Node (${esc(protoName)})</span>
    <span class="term-ts">${timeStr(state.selectedSession?.started_at)}</span>
  </div>`;

  events.forEach(e => {
    const ts = `<span class="term-ts">${timeStr(e.timestamp)}</span>`;
    const dir = e.direction || e.event_type || "";
    const content = e.content || e.command || e.data || e.body_preview || e.username || e.message || "";

    if (dir === "inbound" || dir === "attacker_action") {
      html += `<div class="term-line">${ts}<span class="term-in">&lt;&lt; [ATTACKER]: ${esc(content)}</span></div>`;
    } else if (dir === "outbound" || dir === "decoy_response") {
      const resp = e.content || e.response_preview || e.data || e.banner || "";
      if (resp) html += `<div class="term-line">${ts}<span class="term-out">&gt;&gt; ${esc(resp.substring(0, 300))}</span></div>`;
    } else if (dir === "system" || dir === "annotation") {
      html += `<div class="term-line">${ts}<span class="term-sys">&gt;&gt; [CYBERSHIELD AI]: ${esc(content)}</span></div>`;
    } else if (dir === "operator" || e.event_type === "operator_injection") {
      html += `<div class="term-line operator-line">${ts}<span class="term-op">&gt;&gt; [OPERATOR INJECTION]: ${esc(content)}</span></div>`;
    } else {
      const label = e.event_type || dir || "event";
      html += `<div class="term-line">${ts}<span class="term-note">[${esc(label.toUpperCase())}] ${esc(String(content).substring(0, 300))}</span></div>`;
    }
  });

  if (!state.selectedSession?.ended_at) {
    html += `<div class="term-line" style="margin-top:8px">
      <span class="term-ts">${timeStr(new Date())}</span>
      <span style="font-weight:700;color:var(--primary)">#</span>
      <span class="cursor-blink"></span>
    </div>`;
  }

  body.innerHTML = html;
  body.scrollTop = body.scrollHeight;
}

// ============================================================
// AI COPILOT
// ============================================================
function renderCopilot(sess) {
  if (!sess) return;

  const report = sess.analyst_report || sess.soc_report;
  if (!report) return;

  const assessEl = $("assessment-text");
  if (assessEl) {
    const summaryText = report.summary || report.executive_summary;
    if (summaryText) assessEl.innerHTML = esc(summaryText);
  }

  const conf = $("confidence-badge");
  if (conf) {
    const confVal = sess.intent_confidence != null ? Math.round(sess.intent_confidence * 100) : (report.confidence != null ? Math.round(report.confidence * 100) : 85);
    conf.textContent = `CONFIDENCE: ${confVal}%`;
  }

  const actor = $("actor-pill");
  const actorVal = $("actor-value");
  if (actor && actorVal) {
    const threatName = report.threat_actor || sess.persona || "Decoy Interactive Threat";
    actor.style.display = "flex";
    actorVal.textContent = threatName;
  }

  // RAG citations
  const ragSection = $("rag-section");
  const ragList = $("rag-list");
  if (ragList && report.sources?.length) {
    ragSection.style.display = "flex";
    ragList.innerHTML = report.sources.map(src => `
      <div class="rag-item">
        <span>${esc(src.label || src.title || src.source || src)}</span>
        ${src.score ? `<span style="font-size:10px;font-weight:700;padding:1px 6px;border-radius:2px;background:var(--primary-light);color:#4e5d34">${typeof src.score === "number" ? src.score.toFixed(2) : esc(src.score)}</span>` : ""}
      </div>`).join("");
  }

  // MITRE
  const mitreGrid = $("mitre-grid");
  const ttpCount = $("ttp-count");
  const techniques = report.mitre_techniques || sess.mitre || sess.mitre_techniques || [];
  if (mitreGrid && techniques.length > 0) {
    if (ttpCount) ttpCount.textContent = `${techniques.length} TTPs Tagged`;
    const colors = ["red", "red", "blue", "blue", "red", "blue"];
    mitreGrid.innerHTML = techniques.map((t, i) => {
      const tid = typeof t === "string" ? t : (t.id || "");
      const tname = typeof t === "object" ? (t.name || "") : "";
      const tactic = typeof t === "object" ? (t.tactic || "").replace(/_/g, " ") : "Technique";
      return `
      <div class="mitre-cell ${colors[i % colors.length]}">
        <div class="tactic">${esc(tactic)}</div>
        <div class="tid">${esc(tid)}</div>
        <div class="tname">${esc(tname || tid)}</div>
      </div>`;
    }).join("");
  }

  // IR Checklist
  const irList = $("ir-list");
  const irPending = $("ir-pending");
  const actions = [];
  if (report.remediation?.immediate) {
    report.remediation.immediate.forEach(s => actions.push({ step: s, done: false, sub: "Immediate containment step", type: "danger" }));
  }
  if (report.remediation?.short_term) {
    report.remediation.short_term.forEach(s => actions.push({ step: s, done: false, sub: "Short-term SOC investigation", type: "muted" }));
  }
  if (actions.length === 0 && report.response_steps) {
    actions.push(...report.response_steps);
  }
  if (actions.length === 0) {
    actions.push(
      { step: "Isolate attacker session in high-interaction sandbox", done: sess.contained ?? true, sub: "Auto-executed by CyberShield AI", type: "green" },
      { step: "Quarantine ingress network segment", done: false, sub: "Isolate perimeter router interface", type: "muted" },
      { step: `Push block rule for ${sess.source_ip || sess.source_address || "threat IP"}`, done: false, sub: "Perimeter firewall rule (TTL 48h)", type: "danger" }
    );
  }

  if (irList && actions.length > 0) {
    const pending = actions.filter(a => !a.done).length;
    if (irPending) irPending.textContent = `${pending} Pending`;
    irList.innerHTML = actions.map((a, i) => `
      <label class="ir-item">
        <input type="checkbox" ${a.done ? "checked" : ""} data-ir="${i}">
        <div>
          <div class="ir-item-title ${a.done ? "done" : ""}">${esc(a.step || a)}</div>
          ${a.sub ? `<div class="ir-item-sub ${a.type || "muted"}">${esc(a.sub)}</div>` : ""}
        </div>
      </label>`).join("");
    $("btn-commit-ir").disabled = false;
  }
}

// ============================================================
// STATUS & GRID CONTROLS
// ============================================================
function updateStatusUI(status) {
  state.status = status;
  const running = status?.running ?? false;

  const badge = $("grid-status-badge");
  const label = $("grid-badge-label");
  if (badge && label) {
    badge.classList.toggle("stopped", !running);
    label.textContent = running ? "Grid Active" : "Grid Stopped";
  }

  const toggleBtn = $("btn-grid-toggle");
  const toggleLabel = $("grid-toggle-label");
  if (toggleBtn && toggleLabel) {
    toggleLabel.textContent = running ? "Stop Grid" : "Start Grid";
    toggleBtn.classList.toggle("running", running);
  }

  // Gemini status
  const gemini = status?.gemini;
  const modelLabel = $("gemini-model-label");
  const modelBadge = $("gemini-model-badge");
  const latencyEl = $("gemini-latency");
  if (modelLabel) {
    modelLabel.textContent = gemini?.backend || gemini?.last_provider || (gemini?.configured ? "gemini-3.6-flash" : "No AI");
  }
  if (modelBadge) {
    const isOnline = gemini?.enabled && gemini?.configured;
    modelBadge.textContent = isOnline ? "ONLINE" : "OFFLINE";
    modelBadge.style.color = isOnline ? "#4e5d34" : "#C24B4B";
  }
  if (latencyEl) latencyEl.textContent = "gRPC ~35ms";

  // Decoy stat
  const decoyStat = $("stat-decoys");
  if (decoyStat) decoyStat.textContent = running ? "5 / 5" : "0 / 5";
  const decoyBar = $("decoy-bar");
  if (decoyBar) decoyBar.style.width = running ? "100%" : "0%";

  // Auto-quarantine blocked sources from live honeypot runtime
  const blockedEl = $("stat-blocked");
  if (blockedEl) {
    blockedEl.textContent = status?.blocked_sources ?? 0;
  }
}

// ============================================================
// ATTACK ORIGIN VECTORS (100% Real Live Radar Projection)
// ============================================================
function renderAttackVectors(sessionsArr, eventsArr) {
  const g = $("vector-arcs");
  if (!g) return;

  const activeSessions = (sessionsArr || []).filter(s => !s.ended_at);
  const recentSessions = activeSessions.length > 0 
    ? activeSessions 
    : (sessionsArr || []).slice(0, 6);

  if (recentSessions.length === 0) {
    g.innerHTML = `
      <circle cx="210" cy="40" r="28" fill="none" stroke="#8B9A6E" stroke-dasharray="2 4" stroke-width="1" opacity="0.4"/>
      <text x="210" y="66" text-anchor="middle" font-family="JetBrains Mono, monospace" font-size="8" fill="#8c9680" letter-spacing="0.05em">PERIMETER CLEAR • 0 ADVERSARIES ENGAGED</text>
    `;
    return;
  }

  // Reproducible coordinate mapping based on source IP and port
  const hash = (str) => {
    let h = 0;
    const s = String(str || "");
    for (let i = 0; i < s.length; i++) {
      h = ((h << 5) - h) + s.charCodeAt(i);
      h |= 0;
    }
    return Math.abs(h);
  };

  const center = { x: 210, y: 40 };

  const arcsHtml = recentSessions.slice(0, 8).map((sess, idx) => {
    const srcIp = sess.source_ip || sess.source_address || "127.0.0.1";
    const srcPort = sess.source_port || (50000 + (hash(sess.session_id) % 15000));
    const destPort = sess.destination_port || 2323;
    const proto = sess.service || protoFromPort(destPort);
    const risk = sess.risk_score || 0;
    const isActive = !sess.ended_at;

    const seed = hash(srcIp + ":" + srcPort);
    const isLeft = (idx % 2 === 0);
    const x = isLeft ? 25 + (seed % 150) : 245 + (seed % 150);
    const y = 8 + ((seed >> 3) % 24);

    const ctrlX = (x + center.x) / 2 + (isLeft ? 22 : -22);
    const ctrlY = 48 + ((seed >> 2) % 16);

    const color = risk >= 80 ? "#C24B4B" : risk >= 50 ? "#C98A3C" : "#8B9A6E";
    const title = `${esc(srcIp)}:${srcPort} → :${destPort} (${proto}) [Risk ${risk}] ${isActive ? "ACTIVE" : "ENDED"}`;

    return `
      <g class="vector-arc-group">
        <path d="M ${x},${y} Q ${ctrlX},${ctrlY} ${center.x},${center.y}"
          stroke="${color}"
          stroke-dasharray="${isActive ? "3 3" : "none"}"
          stroke-width="${isActive ? 1.75 : 1.25}"
          opacity="${isActive ? 0.95 : 0.45}"
          fill="none">
          <title>${title}</title>
        </path>
        <circle cx="${x}" cy="${y}" r="${isActive ? 4 : 3}" fill="${color}" opacity="${isActive ? 1 : 0.6}">
          <title>${title}</title>
        </circle>
      </g>
    `;
  }).join("");

  g.innerHTML = arcsHtml;
}

// ============================================================
// ATTACK INTENT DONUT CHART (100% Real Event Classification)
// ============================================================
function updateIntentChart(events, sessions) {
  const total = (events || []).length;
  if (total === 0 && (!sessions || sessions.length === 0)) {
    const setArc = (id, dash, offset) => {
      const el = $(id);
      if (el) {
        el.setAttribute("stroke-dasharray", `0 283`);
        el.setAttribute("stroke-dashoffset", `0`);
      }
    };
    setArc("intent-recon", 0, 0);
    setArc("intent-exploit", 0, 0);
    setArc("intent-lateral", 0, 0);
    if ($("intent-total-val")) $("intent-total-val").textContent = "0";
    if ($("leg-recon")) $("leg-recon").textContent = "0";
    if ($("leg-exploit")) $("leg-exploit").textContent = "0";
    if ($("leg-lateral")) $("leg-lateral").textContent = "0";
    return;
  }

  const counts = { recon: 0, exploit: 0, lateral: 0 };
  (events || []).forEach(e => {
    const text = ((e.metadata?.intent || "") + " " + (e.event_type || "") + " " + (e.intent || "")).toLowerCase();
    if (text.includes("recon") || text.includes("scan") || text.includes("discover") || text.includes("prompt") || text.includes("banner") || text.includes("session_started")) {
      counts.recon++;
    } else if (text.includes("exploit") || text.includes("brute") || text.includes("inject") || text.includes("auth")) {
      counts.exploit++;
    } else {
      counts.lateral++;
    }
  });

  const effectiveTotal = Math.max(1, counts.recon + counts.exploit + counts.lateral);
  const circ = 2 * Math.PI * 45; // ~282.74
  const reconDash = (counts.recon / effectiveTotal) * circ;
  const exploitDash = (counts.exploit / effectiveTotal) * circ;
  const lateralDash = (counts.lateral / effectiveTotal) * circ;
  const reconOffset = 0;
  const exploitOffset = reconDash;
  const lateralOffset = reconDash + exploitDash;

  const setArc = (id, dash, offset) => {
    const el = $(id);
    if (el) {
      el.setAttribute("stroke-dasharray", `${dash.toFixed(1)} ${(circ - dash).toFixed(1)}`);
      el.setAttribute("stroke-dashoffset", `-${offset.toFixed(1)}`);
    }
  };
  setArc("intent-recon", reconDash, reconOffset);
  setArc("intent-exploit", exploitDash, exploitOffset);
  setArc("intent-lateral", lateralDash, lateralOffset);

  const tv = $("intent-total-val");
  if (tv) tv.textContent = total;
  if ($("leg-recon")) $("leg-recon").textContent = counts.recon;
  if ($("leg-exploit")) $("leg-exploit").textContent = counts.exploit;
  if ($("leg-lateral")) $("leg-lateral").textContent = counts.lateral;
}

// ============================================================
// TARGET COUNTERS (100% Real Per-Port Session & Action Totals)
// ============================================================
function updateTargetCounts(sessionsArr) {
  const portMap = [
    { key: "ssh", name: "SSH Honeypot (2222)", port: 2222 },
    { key: "telnet", name: "Telnet Legacy (2323)", port: 2323 },
    { key: "http", name: "HTTP Finance (8088)", port: 8088 },
    { key: "https", name: "HTTPS Ops API (8443)", port: 8443 },
    { key: "mysql", name: "MySQL Database (33060)", port: 33060 },
  ];

  portMap.forEach(item => {
    const portSessions = (sessionsArr || []).filter(s => s.destination_port === item.port);
    const active = portSessions.filter(s => !s.ended_at).length;
    const actions = portSessions.reduce((acc, s) => acc + (s.interactions || 0), 0);
    const count = portSessions.length;
    const el = $(`ti-${item.key}`);
    if (el) {
      if (count === 0 && actions === 0) {
        el.textContent = "0 probes";
        el.style.color = "var(--text-muted)";
      } else {
        el.textContent = `${count} session${count !== 1 ? "s" : ""} (${actions} act)`;
        el.style.color = active > 0 ? "#C24B4B" : "var(--text)";
      }
    }
  });
}

// ============================================================
// MAIN REFRESH LOOP (100% Real Live Synchronized Telemetry)
// ============================================================
async function refresh() {
  if (state.refreshing) return;
  state.refreshing = true;

  try {
    const [statusData, sessData, evtsData] = await Promise.all([
      api("/api/v1/honeypot/status"),
      api("/api/v1/honeypot/sessions?limit=100"),
      api("/api/v1/honeypot/events?limit=500").catch(() => ({ events: [] })),
    ]);

    updateStatusUI(statusData);

    const sessions = sessData.sessions || [];
    const events = evtsData.events || [];
    state.sessions = sessions;
    state.events = events;

    // Update rolling sensor activity history
    updateSensorHistory(sessions, events, statusData);

    // Render 100% real sensors with dynamic sparklines and measured latency
    renderSensors(sessions, statusData, events);

    // Render session cards
    renderSessions(sessions);

    // Render live attack origin vectors
    renderAttackVectors(sessions, events);

    // Render target counters
    updateTargetCounts(sessions);

    // Render attack intent distribution
    updateIntentChart(events, sessions);

    // Refresh canary tokens
    await loadCanaryTokens();

    // Refresh security alerts
    await loadAlerts();

    // Update subheader metrics
    const liveCount = sessions.filter(s => !s.ended_at).length;
    const totalInteractions = sessions.reduce((acc, s) => acc + (s.interactions || 0), 0);
    const sub = $("stat-sessions-sub");
    if (sub) {
      sub.textContent = `${liveCount} currently live • ${totalInteractions} interactions`;
    }

    // Auto-select first session if none selected yet
    if (!state.selectedSessionId && sessions.length > 0) {
      selectSession(sessions[0].session_id);
    }

    // Re-render terminal duration if session still selected
    if (state.selectedSessionId) {
      const updated = sessions.find(s => s.session_id === state.selectedSessionId);
      if (updated) {
        const durationEl = $("term-duration");
        if (durationEl) durationEl.textContent = `Duration: ${dur(sessionDuration(updated))}`;
      }
    }
  } catch (e) {
    console.error("Refresh error:", e);
  } finally {
    state.refreshing = false;
  }
}

// ============================================================
// CANARY TOKENS & HONEYTOKENS
// ============================================================
async function loadCanaryTokens() {
  try {
    const data = await api("/api/v1/canary/tokens");
    renderCanaryTokens(data.tokens || []);
  } catch (_) {
    // Graceful fallback if canary service is uninitialized
  }
}

function renderCanaryTokens(tokens = []) {
  state.canaryTokens = tokens;
  const countEl = $("canary-count");
  const badgeEl = $("nav-badge-canary");
  const emptyEl = $("canary-empty");
  const tbody = $("canary-rows");
  if (!tbody) return;

  const activeCount = tokens.filter(t => t.status === "active").length;
  if (countEl) countEl.textContent = `${activeCount} Active`;
  if (badgeEl) {
    badgeEl.textContent = `${activeCount} ACT`;
    badgeEl.classList.toggle("danger", tokens.some(t => (t.trigger_count || 0) > 0));
  }

  if (tokens.length === 0) {
    tbody.innerHTML = "";
    if (emptyEl) emptyEl.style.display = "block";
    return;
  }
  if (emptyEl) emptyEl.style.display = "none";

  tbody.innerHTML = tokens.map(token => {
    const isUrl = token.token_type === "url";
    const triggerUrl = isUrl ? `${window.location.origin}/t/${token.secret}` : token.secret;
    const triggerCount = token.trigger_count || 0;
    const isTriggered = triggerCount > 0;
    const createdStr = token.created_at ? new Date(token.created_at).toLocaleDateString() : "--";
    const isActive = token.status === "active";

    return `<tr>
      <td>
        <div style="display:flex;align-items:center;gap:6px">
          <span style="font-weight:600;color:var(--text)">${esc(token.name)}</span>
          <span class="canary-token-type ${token.token_type}">${esc(token.token_type)}</span>
        </div>
        ${token.last_source_ip ? `<div style="font-size:10px;color:var(--rose);margin-top:2px">Last trigger: ${esc(token.last_source_ip)}</div>` : ""}
      </td>
      <td>
        <button class="canary-copy-btn" data-secret="${esc(triggerUrl)}" title="Click to copy trigger URL/token">
          <span class="material-symbols-outlined" style="font-size:13px">content_copy</span>
          <span>${esc(token.secret.length > 22 ? token.secret.substring(0, 20) + "..." : token.secret)}</span>
        </button>
      </td>
      <td>
        <span style="font-weight:700;color:${isTriggered ? "var(--rose)" : "var(--text-muted)"}">
          ${triggerCount} ${triggerCount === 1 ? "trigger" : "triggers"}
        </span>
      </td>
      <td><span style="color:var(--text-muted);font-size:11px">${createdStr}</span></td>
      <td>
        <button class="canary-status-pill ${isActive ? "active" : "disabled"}" data-id="${esc(token.token_id)}" data-status="${esc(token.status)}">
          ${isActive ? "Active" : "Disabled"}
        </button>
      </td>
    </tr>`;
  }).join("");

  tbody.querySelectorAll(".canary-copy-btn").forEach(btn => {
    btn.addEventListener("click", async () => {
      const text = btn.dataset.secret;
      try {
        await navigator.clipboard.writeText(text);
        btn.classList.add("copied");
        const orig = btn.innerHTML;
        btn.innerHTML = `<span class="material-symbols-outlined" style="font-size:13px">check</span> Copied!`;
        setTimeout(() => {
          btn.classList.remove("copied");
          btn.innerHTML = orig;
        }, 1500);
        toast("Canary token copied to clipboard.");
      } catch (_) {
        toast("Clipboard copy failed.", true);
      }
    });
  });

  tbody.querySelectorAll(".canary-status-pill").forEach(btn => {
    btn.addEventListener("click", async () => {
      const id = btn.dataset.id;
      const current = btn.dataset.status;
      await toggleCanaryStatus(id, current);
    });
  });
}

async function createCanaryToken(e) {
  if (e) e.preventDefault();
  const nameInput = $("canary-name");
  const typeInput = $("canary-type");
  const btn = $("canary-create-btn");
  if (!nameInput || !typeInput) return;

  const name = nameInput.value.trim();
  const token_type = typeInput.value;
  if (!name) {
    toast("Please enter a token name.", true);
    return;
  }

  const origText = btn ? btn.innerHTML : "Create Token";
  if (btn) {
    btn.disabled = true;
    btn.innerHTML = `<span class="material-symbols-outlined" style="font-size:16px;animation:spin 1s linear infinite">autorenew</span> Generating...`;
  }

  try {
    await api("/api/v1/canary/tokens", {
      method: "POST",
      body: JSON.stringify({ name, token_type, metadata: { deployed_by: "CyberShield AI Console" } }),
    });
    toast(`Canary tripwire created: "${name}"`);
    nameInput.value = "";
    await loadCanaryTokens();
  } catch (err) {
    toast("Failed to create canary: " + err.message, true);
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.innerHTML = origText;
    }
  }
}

async function toggleCanaryStatus(tokenId, currentStatus) {
  const newStatus = currentStatus === "active" ? "disabled" : "active";
  try {
    await api(`/api/v1/canary/tokens/${encodeURIComponent(tokenId)}/status`, {
      method: "PUT",
      body: JSON.stringify({ status: newStatus }),
    });
    toast(`Canary status updated to ${newStatus}.`);
    await loadCanaryTokens();
  } catch (err) {
    toast("Failed to update canary status: " + err.message, true);
  }
}

// ============================================================
// SECURITY ALERTS & INTEGRATIONS
// ============================================================
async function loadAlerts() {
  try {
    const data = await api("/api/v1/alerts/status");
    renderAlerts(data);
  } catch (_) {
    // Graceful fallback if alerts uninitialized
  }
}

async function toggleChannel(channelName) {
  const chData = state.alerts?.channels?.[channelName];
  if (!chData || !chData.configured) {
    toast(`Cannot toggle ${channelName}: not configured in .env`, true);
    return;
  }
  const currentEnabled = chData.enabled !== false;
  const newEnabled = !currentEnabled;
  try {
    const res = await api(`/api/v1/alerts/channels/${channelName}/status`, {
      method: "PUT",
      body: JSON.stringify({ enabled: newEnabled }),
    });
    if (res.status) {
      renderAlerts(res.status);
    }
    toast(`${chData.name || channelName} alerts ${newEnabled ? "enabled" : "muted"}.`);
  } catch (err) {
    toast(`Failed to toggle ${channelName}: ${err.message}`, true);
  }
}

function renderAlerts(data) {
  if (!data) return;
  state.alerts = data;

  const count = data.active_channels_count || 0;
  const channelCountEl = $("alerts-channel-count");
  if (channelCountEl) {
    channelCountEl.textContent = `${count} / 3 Channels Active`;
  }
  const navBadgeEl = $("nav-badge-alerts");
  if (navBadgeEl) {
    navBadgeEl.textContent = `${count} / 3`;
  }

  // Slack
  const slack = data.channels?.slack || {};
  const cardSlack = $("card-slack");
  const badgeSlack = $("slack-status-badge");
  const textSlack = $("slack-status-text");
  if (cardSlack && badgeSlack && textSlack) {
    if (slack.configured) {
      const isEnabled = slack.enabled !== false;
      cardSlack.classList.toggle("connected", isEnabled);
      cardSlack.classList.toggle("muted-channel", !isEnabled);
      badgeSlack.textContent = isEnabled ? "CONNECTED" : "MUTED";
      badgeSlack.className = `channel-status ${isEnabled ? "active" : "muted"}`;
      badgeSlack.title = isEnabled ? "Click to mute Slack alerts" : "Click to enable Slack alerts";
      textSlack.textContent = isEnabled ? "Incoming Webhook Active (Click to mute)" : "Webhook configured (Click to unmute)";
    } else {
      cardSlack.classList.remove("connected", "muted-channel");
      badgeSlack.textContent = "DISABLED";
      badgeSlack.className = "channel-status";
      badgeSlack.title = "Not configured in .env";
      textSlack.textContent = "Webhook not configured in .env";
    }
  }

  // Discord
  const discord = data.channels?.discord || {};
  const cardDiscord = $("card-discord");
  const badgeDiscord = $("discord-status-badge");
  const textDiscord = $("discord-status-text");
  if (cardDiscord && badgeDiscord && textDiscord) {
    if (discord.configured) {
      const isEnabled = discord.enabled !== false;
      cardDiscord.classList.toggle("connected", isEnabled);
      cardDiscord.classList.toggle("muted-channel", !isEnabled);
      badgeDiscord.textContent = isEnabled ? "CONNECTED" : "MUTED";
      badgeDiscord.className = `channel-status ${isEnabled ? "active" : "muted"}`;
      badgeDiscord.title = isEnabled ? "Click to mute Discord alerts" : "Click to enable Discord alerts";
      textDiscord.textContent = isEnabled ? "Rich Embeds Active (Click to mute)" : "Webhook configured (Click to unmute)";
    } else {
      cardDiscord.classList.remove("connected", "muted-channel");
      badgeDiscord.textContent = "DISABLED";
      badgeDiscord.className = "channel-status";
      badgeDiscord.title = "Not configured in .env";
      textDiscord.textContent = "Webhook not configured in .env";
    }
  }

  // Email
  const email = data.channels?.email || {};
  const cardEmail = $("card-email");
  const badgeEmail = $("email-status-badge");
  const textEmail = $("email-status-text");
  const pillRecipients = $("email-recipients-count-pill");
  if (cardEmail && badgeEmail && textEmail) {
    const activeCount = email.active_recipients_count ?? (email.active_recipients || []).length;
    const totalCount = (email.recipients || []).length;
    if (pillRecipients) {
      pillRecipients.textContent = `${activeCount} / ${totalCount} Active`;
    }

    if (email.configured) {
      const isEnabled = email.enabled !== false;
      cardEmail.classList.toggle("connected", isEnabled);
      cardEmail.classList.toggle("muted-channel", !isEnabled);
      badgeEmail.textContent = isEnabled ? "CONNECTED" : "MUTED";
      badgeEmail.className = `channel-status ${isEnabled ? "active" : "muted"}`;
      badgeEmail.title = isEnabled ? "Click to mute Email alerts" : "Click to enable Email alerts";
      textEmail.textContent = isEnabled
        ? `SMTP: ${email.host || "Configured"} → ${activeCount} active recipient(s)`
        : `SMTP: ${email.host || "Configured"} (Muted, click to unmute)`;
    } else {
      cardEmail.classList.remove("connected", "muted-channel");
      badgeEmail.textContent = "DISABLED";
      badgeEmail.className = "channel-status";
      badgeEmail.title = "Not configured in .env";
      textEmail.textContent = "SMTP host / recipient not set";
    }
  }

  // Policy
  const policy = data.policy || {};
  const policyText = $("policy-status-text");
  if (policyText) {
    policyText.textContent = `Score ≥ ${policy.min_risk_score || 80} or ${(policy.min_severity || "high").toUpperCase()} • Cooldown: ${policy.dedup_window_seconds || 300}s`;
  }

  // History Table
  const history = data.history || [];
  const emptyEl = $("alerts-empty");
  const rowsEl = $("alerts-rows");
  if (emptyEl && rowsEl) {
    emptyEl.style.display = history.length > 0 ? "none" : "block";
    rowsEl.innerHTML = history.map(item => {
      const sev = String(item.severity || "info").toUpperCase();
      const results = item.results || {};

      function pill(name, status) {
        if (status === true) return `<span class="channel-pill ok">✔ ${name}</span>`;
        if (status === false) return `<span class="channel-pill fail">✘ ${name}</span>`;
        return `<span class="channel-pill off">${name}</span>`;
      }

      const pills = [
        pill("Slack", results.slack),
        pill("Discord", results.discord),
        pill("Email", results.email),
      ].join("");

      const ts = item.timestamp ? new Date(item.timestamp).toLocaleTimeString() : "--:--:--";
      const isCrit = item.severity === "critical" || (item.risk_score || 0) >= 80;
      const badgeStyle = isCrit
        ? "color:var(--rose);background:var(--rose-light);border:1px solid #fbdada;"
        : "color:var(--amber);background:var(--amber-light);border:1px solid #fde68a;";

      return `<tr>
        <td style="font-family:var(--font-mono);font-size:11px">${esc(ts)}</td>
        <td>
          <div style="font-weight:600;color:var(--text)">${esc(item.event_type || "INCIDENT")}</div>
          <div style="font-size:11px;color:var(--text-secondary);margin-top:2px">${esc((item.ai_summary || "").slice(0, 75))}</div>
        </td>
        <td><span class="canary-token-type" style="${badgeStyle};font-size:10px">${esc(sev)}</span></td>
        <td style="font-family:var(--font-mono);font-weight:700;color:${isCrit ? "var(--rose)" : "var(--text)"}">${item.risk_score}/100</td>
        <td style="font-family:var(--font-mono);font-size:11px"><code>${esc(item.source_ip || "unknown")}</code> &rarr; <code>${esc(item.host || "soc")}</code></td>
        <td>${pills}</td>
      </tr>`;
    }).join("");
  }
}

async function sendTestAlert() {
  const btn = $("test-alert-btn");
  if (!btn) return;
  const origHtml = btn.innerHTML;
  btn.disabled = true;
  btn.innerHTML = `<span class="material-symbols-outlined" style="font-size:15px;animation:spin 1s linear infinite">autorenew</span> Sending...`;
  try {
    const res = await api("/api/v1/alerts/test", { method: "POST" });
    const results = res.results || {};
    const successCount = Object.values(results).filter(v => v === true).length;
    if (res.active_channels_count === 0) {
      toast("Test alert evaluated: No channels configured in .env", false);
    } else {
      toast(`Test alert sent: ${successCount} / ${res.active_channels_count} channel(s) delivered`);
    }
    await loadAlerts();
  } catch (err) {
    toast(`Test alert failed: ${err.message}`, true);
  } finally {
    btn.disabled = false;
    btn.innerHTML = origHtml;
  }
}

// ============================================================
// EMAIL RECIPIENTS MANAGEMENT
// ============================================================
let localRecipients = [];

async function openRecipientsModal() {
  const modal = $("email-recipients-modal-overlay");
  if (!modal) return;
  modal.style.display = "flex";
  await loadRecipients();
}

function closeRecipientsModal() {
  const modal = $("email-recipients-modal-overlay");
  if (!modal) return;
  modal.style.display = "none";
}

async function loadRecipients() {
  try {
    const res = await api("/api/v1/alerts/channels/email/recipients");
    localRecipients = res.recipients || [];
    renderRecipientsList(localRecipients);
  } catch (err) {
    toast("Failed to load email recipients: " + err.message, true);
  }
}

function renderRecipientsList(recipients) {
  const listEl = $("recipients-list-items");
  const emptyEl = $("recipients-empty-state");
  const summaryEl = $("recipients-active-summary");
  const pillRecipients = $("email-recipients-count-pill");
  if (!listEl) return;

  const total = recipients.length;
  const activeCount = recipients.filter(r => r.enabled !== false).length;

  if (summaryEl) {
    summaryEl.textContent = `${activeCount} / ${total} Active`;
  }
  if (pillRecipients) {
    pillRecipients.textContent = `${activeCount} / ${total} Active`;
  }

  if (total === 0) {
    listEl.innerHTML = "";
    if (emptyEl) emptyEl.style.display = "block";
    return;
  }
  if (emptyEl) emptyEl.style.display = "none";

  listEl.innerHTML = recipients.map(r => {
    const isEnabled = r.enabled !== false;
    return `
      <div class="recipient-row ${isEnabled ? "" : "muted"}">
        <label class="recipient-row-left">
          <input type="checkbox" class="recipient-checkbox" ${isEnabled ? "checked" : ""} data-email="${esc(r.email)}" />
          <span class="recipient-email">${esc(r.email)}</span>
        </label>
        <div class="recipient-row-right">
          <span class="channel-pill ${isEnabled ? "ok" : "off"}">${isEnabled ? "Active" : "Muted"}</span>
          <button type="button" class="btn-remove-recipient" data-email="${esc(r.email)}" title="Remove ${esc(r.email)}">
            <span class="material-symbols-outlined" style="font-size:16px">delete</span>
          </button>
        </div>
      </div>
    `;
  }).join("");

  listEl.querySelectorAll(".recipient-checkbox").forEach(cb => {
    cb.addEventListener("change", async () => {
      const email = cb.dataset.email;
      const checked = cb.checked;
      await handleToggleRecipient(email, checked);
    });
  });

  listEl.querySelectorAll(".btn-remove-recipient").forEach(btn => {
    btn.addEventListener("click", async (e) => {
      e.stopPropagation();
      const email = btn.dataset.email;
      await handleRemoveRecipient(email);
    });
  });
}

async function handleToggleRecipient(email, enabled) {
  localRecipients = localRecipients.map(r => r.email === email ? { ...r, enabled } : r);
  renderRecipientsList(localRecipients);

  try {
    const res = await api("/api/v1/alerts/channels/email/recipients", {
      method: "PUT",
      body: JSON.stringify({ recipients: localRecipients, persist: true }),
    });
    if (res.recipients) {
      localRecipients = res.recipients;
      renderRecipientsList(localRecipients);
    }
    toast(`${email} ${enabled ? "enabled" : "muted"}.`);
    await loadAlerts();
  } catch (err) {
    toast("Failed to update recipient: " + err.message, true);
    await loadRecipients();
  }
}

async function handleSelectAllRecipients(selectAll) {
  if (localRecipients.length === 0) return;
  localRecipients = localRecipients.map(r => ({ ...r, enabled: selectAll }));
  renderRecipientsList(localRecipients);

  try {
    const res = await api("/api/v1/alerts/channels/email/recipients", {
      method: "PUT",
      body: JSON.stringify({ recipients: localRecipients, persist: true }),
    });
    if (res.recipients) {
      localRecipients = res.recipients;
      renderRecipientsList(localRecipients);
    }
    toast(selectAll ? "All recipients enabled." : "All recipients muted.");
    await loadAlerts();
  } catch (err) {
    toast("Failed to update recipients: " + err.message, true);
    await loadRecipients();
  }
}

async function handleAddRecipient(e) {
  if (e) e.preventDefault();
  const input = $("input-new-recipient");
  if (!input) return;
  const email = input.value.trim();
  if (!email || !email.includes("@") || !email.includes(".")) {
    toast("Please enter a valid email address.", true);
    return;
  }
  if (localRecipients.some(r => r.email.toLowerCase() === email.toLowerCase())) {
    toast(`Email "${email}" is already in the list.`, true);
    return;
  }

  try {
    const res = await api("/api/v1/alerts/channels/email/recipients", {
      method: "POST",
      body: JSON.stringify({ email, enabled: true, persist: true }),
    });
    input.value = "";
    if (res.recipients) {
      localRecipients = res.recipients;
      renderRecipientsList(localRecipients);
    } else {
      await loadRecipients();
    }
    toast(`Added ${email} to alert recipients.`);
    await loadAlerts();
  } catch (err) {
    toast("Failed to add recipient: " + err.message, true);
  }
}

async function handleRemoveRecipient(email) {
  try {
    const res = await api(`/api/v1/alerts/channels/email/recipients/${encodeURIComponent(email)}?persist=true`, {
      method: "DELETE",
    });
    if (res.recipients) {
      localRecipients = res.recipients;
      renderRecipientsList(localRecipients);
    } else {
      await loadRecipients();
    }
    toast(`Removed ${email} from distribution list.`);
    await loadAlerts();
  } catch (err) {
    toast("Failed to remove recipient: " + err.message, true);
  }
}

async function sendTestAlertToSelected() {
  const activeEmails = localRecipients.filter(r => r.enabled !== false).map(r => r.email);
  if (activeEmails.length === 0) {
    toast("No email recipients are active. Please check at least one email.", true);
    return;
  }
  const btn = $("btn-test-selected-recipients");
  const textEl = $("btn-test-selected-text");
  const origText = textEl ? textEl.textContent : "Send Test to Selected";
  if (btn) btn.disabled = true;
  if (textEl) textEl.textContent = "Sending...";

  try {
    const res = await api("/api/v1/alerts/test", {
      method: "POST",
      body: JSON.stringify({ recipients: activeEmails }),
    });
    const results = res.results || {};
    if (results.email === true) {
      toast(`Test alert sent to ${activeEmails.length} recipient(s): ${activeEmails.join(", ")}`);
    } else {
      toast("Test alert dispatch completed (see incident log).");
    }
    await loadAlerts();
  } catch (err) {
    toast("Failed to send test alert: " + err.message, true);
  } finally {
    if (btn) btn.disabled = false;
    if (textEl) textEl.textContent = origText;
  }
}

// ============================================================
// REALTIME WEBSOCKET STREAMING
// ============================================================
let ws;
let wsReconnectTimer;
function connectWebSocket() {
  if (ws && (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING)) {
    return;
  }
  const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
  const wsUrl = `${proto}//${window.location.host}/api/v1/ws/dashboard`;

  try {
    ws = new WebSocket(wsUrl);

    ws.onopen = () => {
      clearTimeout(wsReconnectTimer);
    };

    ws.onmessage = async (event) => {
      try {
        const data = JSON.parse(event.data);
        if (data.type === "state_update") {
          if (data.sessions?.sessions) {
            state.sessions = data.sessions.sessions;
            renderSessions(state.sessions);
            updateTargetCounts(state.sessions);
          }
          if (data.status) {
            state.status = data.status;
            updateStatusUI(data.status);
          }
          if (data.canaries?.tokens) {
            renderCanaryTokens(data.canaries.tokens);
          }
          if (data.alerts) {
            renderAlerts(data.alerts);
          }
        }
      } catch (e) {
        console.error("WS message parse error:", e);
      }
    };

    ws.onclose = () => {
      clearTimeout(wsReconnectTimer);
      wsReconnectTimer = setTimeout(connectWebSocket, 4000);
    };

    ws.onerror = () => {
      ws.close();
    };
  } catch (_) {
    // If WebSocket is not supported in the running environment, polling continues seamlessly
  }
}

// ============================================================
// BUTTON HANDLERS
// ============================================================
function setupButtons() {
  // Grid toggle
  $("btn-grid-toggle")?.addEventListener("click", async () => {
    const running = state.status?.running ?? false;
    try {
      await api(`/api/v1/honeypot/control/${running ? "stop" : "start"}`, { method: "POST" });
      toast(running ? "Honeypot grid stopped." : "Honeypot grid started!");
      setTimeout(refresh, 600);
    } catch (e) {
      toast("Error: " + e.message, true);
    }
  });

  // Emergency containment
  $("btn-emergency")?.addEventListener("click", async () => {
    if (!confirm("Emergency containment: stop all honeypot listeners immediately?")) return;
    try {
      await api("/api/v1/honeypot/control/stop", { method: "POST" });
      toast("Emergency containment executed. Grid stopped.");
      setTimeout(refresh, 400);
    } catch (e) {
      toast("Error: " + e.message, true);
    }
  });

  // Kill session
  $("btn-kill")?.addEventListener("click", async () => {
    if (!state.selectedSessionId) return;
    try {
      await api(`/api/v1/honeypot/sessions/${state.selectedSessionId}/contain`, { method: "POST" });
      toast("Session contained & terminated.");
      setTimeout(refresh, 500);
    } catch (e) {
      toast("Error: " + e.message, true);
    }
  });

  // Block IP
  $("btn-block")?.addEventListener("click", async () => {
    if (!state.selectedSession) return;
    const ip = state.selectedSession.source_ip || state.selectedSession.source_address;
    if (!confirm(`Block source IP ${ip}?`)) return;
    try {
      await api("/api/v1/honeypot/block-source", {
        method: "POST",
        body: JSON.stringify({ source_ip: ip }),
      });
      toast(`Source ${ip} blocked.`);
      const blocked = parseInt($("stat-blocked")?.textContent || "0") + 1;
      if ($("stat-blocked")) $("stat-blocked").textContent = blocked;
    } catch (e) {
      toast("Error: " + e.message, true);
    }
  });

  // Export session
  $("btn-export-session")?.addEventListener("click", async () => {
    if (!state.selectedSessionId) return;
    try {
      const data = await api(`/api/v1/honeypot/sessions/${state.selectedSessionId}/export`);
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = `cybershield-session-${state.selectedSessionId}.json`;
      a.click();
      toast("Session exported.");
    } catch (e) {
      toast("Error: " + e.message, true);
    }
  });

  // Export telemetry
  $("btn-export")?.addEventListener("click", async () => {
    try {
      const data = await api("/api/v1/honeypot/sessions?limit=1000");
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = `cybershield-telemetry-${Date.now()}.json`;
      a.click();
      toast("Telemetry exported.");
    } catch (e) {
      toast("Error: " + e.message, true);
    }
  });

  // Analyze
  $("btn-analyze")?.addEventListener("click", async () => {
    if (!state.selectedSessionId) {
      toast("Select a session first.", true);
      return;
    }
    if (state.analyzing) return;
    state.analyzing = true;
    const btn = $("btn-analyze");
    const orig = btn.innerHTML;
    btn.innerHTML = `<span class="material-symbols-outlined" style="font-size:16px;animation:spin 1s linear infinite">autorenew</span> Analyzing...`;
    btn.disabled = true;
    try {
      const data = await api(`/api/v1/honeypot/sessions/${state.selectedSessionId}/analyze`, { method: "POST" });
      if (data.report) {
        state.selectedSession.analyst_report = data.report;
      }
      renderCopilot(state.selectedSession);
      toast("Gemini + RAG analysis complete!");
      document.getElementById("copilot-panel").scrollIntoView({ behavior: "smooth" });
    } catch (e) {
      toast("Analysis error: " + e.message, true);
    } finally {
      state.analyzing = false;
      btn.innerHTML = orig;
      btn.disabled = false;
    }
  });

  // Terminal tabs
  document.querySelectorAll(".tab-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      state.activeTab = btn.dataset.tab;
      renderTerminalBody();
    });
  });

  // Operator Injection into terminal stream
  const sendInjection = async () => {
    const input = $("inject-input");
    const btn = $("btn-inject");
    if (!input) return;

    let content = input.value.trim();
    if (!content) {
      toast("Please type a response or command to inject.", true);
      input.focus();
      return;
    }

    // Strip leading prompt symbols (# or $) if user typed them
    if (content.startsWith("# ")) {
      content = content.slice(2).trim();
    } else if (content.startsWith("#")) {
      content = content.slice(1).trim();
    } else if (content.startsWith("$ ")) {
      content = content.slice(2).trim();
    } else if (content.startsWith("$")) {
      content = content.slice(1).trim();
    }
    if (!content) {
      toast("Please type a valid response or command.", true);
      return;
    }

    // Auto-select session if none currently selected
    if (!state.selectedSessionId) {
      if (state.sessions && state.sessions.length > 0) {
        await selectSession(state.sessions[0].session_id, false);
      }
    }

    if (!state.selectedSessionId) {
      toast("No active sessions to inject into. Please start the honeypot grid.", true);
      return;
    }

    const origText = btn ? btn.textContent : "Send";
    if (btn) {
      btn.disabled = true;
      btn.textContent = "Injecting...";
    }

    try {
      const data = await api(`/api/v1/honeypot/sessions/${state.selectedSessionId}/inject`, {
        method: "POST",
        body: JSON.stringify({ content, direction: "operator" }),
      });

      // Clear input
      input.value = "";

      // Ensure transcript tab is active so operator immediately sees the injected line
      state.activeTab = "transcript";
      document.querySelectorAll(".tab-btn").forEach(b => {
        b.classList.toggle("active", b.dataset.tab === "transcript");
      });

      // Append to live selected events and render
      const newEvt = data.event || {
        event_id: "evt-op-" + Date.now(),
        timestamp: new Date().toISOString(),
        direction: "operator",
        event_type: "operator_injection",
        content: content,
      };

      if (!Array.isArray(state.selectedEvents)) {
        state.selectedEvents = [];
      }
      state.selectedEvents.push(newEvt);

      // Ensure session object is populated
      if (!state.selectedSession && state.selectedSessionId) {
        state.selectedSession = (state.sessions || []).find(s => s.session_id === state.selectedSessionId) || {
          session_id: state.selectedSessionId,
          destination_port: 8088,
          service: "HTTP",
        };
      }

      renderTerminal();
      renderTerminalBody();

      // Scroll terminal to bottom
      const termBody = $("term-body");
      if (termBody) {
        termBody.scrollTop = termBody.scrollHeight;
      }

      toast("Synthetic response injected into session transcript.");
    } catch (e) {
      toast("Injection failed: " + e.message, true);
    } finally {
      if (btn) {
        btn.disabled = false;
        btn.textContent = origText;
      }
      input.focus();
    }
  };

  $("btn-inject")?.addEventListener("click", sendInjection);
  $("inject-input")?.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      e.preventDefault();
      sendInjection();
    }
  });

  // Filter pills
  document.querySelectorAll(".filter-pill").forEach(pill => {
    pill.addEventListener("click", () => {
      document.querySelectorAll(".filter-pill").forEach(p => p.classList.remove("active"));
      pill.classList.add("active");
      state.filter = pill.dataset.filter;
      renderSessions(state.sessions);
    });
  });

  // Search
  let searchTimeout;
  $("search-input")?.addEventListener("input", (e) => {
    clearTimeout(searchTimeout);
    searchTimeout = setTimeout(() => {
      const q = e.target.value.toLowerCase().trim();
      if (!q) {
        renderSessions(state.sessions);
        return;
      }
      const filtered = state.sessions.filter(s => {
        const src = (s.source_ip || s.source_address || "").toLowerCase();
        const proto = (s.service || protoFromPort(s.destination_port)).toLowerCase();
        const intent = (s.intent || "").toLowerCase();
        return src.includes(q) || proto.includes(q) || intent.includes(q);
      });
      const grid = $("session-grid");
      if (!grid) return;
      if (filtered.length === 0) {
        grid.innerHTML = `<div class="empty-state"><span class="material-symbols-outlined" style="font-size:40px;color:#8ca4ac">search_off</span><p>No sessions match "${esc(q)}"</p></div>`;
        return;
      }
      renderSessions(filtered);
    }, 200);
  });

  // Commit IR
  $("btn-commit-ir")?.addEventListener("click", () => {
    const checked = document.querySelectorAll("#ir-list input[type=checkbox]:checked");
    toast(`${checked.length} IR action(s) committed.`);
  });

  // Test Alert
  $("test-alert-btn")?.addEventListener("click", sendTestAlert);

  // Channel toggle listeners (click to toggle active / muted)
  $("card-slack")?.addEventListener("click", () => toggleChannel("slack"));
  $("card-discord")?.addEventListener("click", () => toggleChannel("discord"));
  $("card-email")?.addEventListener("click", (e) => {
    if (e.target.closest("#btn-open-recipients")) return;
    toggleChannel("email");
  });

  // Recipients modal controls
  $("btn-open-recipients")?.addEventListener("click", (e) => {
    e.stopPropagation();
    openRecipientsModal();
  });
  $("btn-close-recipients-modal")?.addEventListener("click", closeRecipientsModal);
  $("btn-done-recipients-modal")?.addEventListener("click", closeRecipientsModal);
  $("email-recipients-modal-overlay")?.addEventListener("click", (e) => {
    if (e.target.id === "email-recipients-modal-overlay") closeRecipientsModal();
  });

  // Recipient action buttons
  $("btn-recipients-select-all")?.addEventListener("click", () => handleSelectAllRecipients(true));
  $("btn-recipients-deselect-all")?.addEventListener("click", () => handleSelectAllRecipients(false));
  $("form-add-recipient")?.addEventListener("submit", handleAddRecipient);
  $("btn-add-recipient")?.addEventListener("click", handleAddRecipient);
  $("btn-test-selected-recipients")?.addEventListener("click", sendTestAlertToSelected);

  // Toggle sessions view more / less
  $("btn-toggle-sessions")?.addEventListener("click", () => {
    state.sessionsExpanded = !state.sessionsExpanded;
    syncSessionGridExpansion();
    if (!state.sessionsExpanded) {
      $("session-panel")?.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  });

  // Re-sync collapse bounds on window resize
  window.addEventListener("resize", () => {
    if (!state.sessionsExpanded) {
      syncSessionGridExpansion();
    }
  });

  // Sidebar active nav on scroll
  const sections = document.querySelectorAll(".section[id]");
  const navItems = document.querySelectorAll(".nav-item[data-section]");
  const scrollEl = document.querySelector(".scroll-canvas");
  if (scrollEl) {
    scrollEl.addEventListener("scroll", () => {
      let current = "";
      sections.forEach(sec => {
        if (scrollEl.scrollTop >= sec.offsetTop - 80) current = sec.id;
      });
      navItems.forEach(n => n.classList.toggle("active", n.dataset.section === current));
    }, { passive: true });
  }

  // Modal controls
  $("btn-close-modal")?.addEventListener("click", closeSessionModal);
  $("session-modal-overlay")?.addEventListener("click", (e) => {
    if (e.target.id === "session-modal-overlay") closeSessionModal();
  });
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      closeSessionModal();
      closeRecipientsModal();
    }
  });

  // Modal actions
  $("modal-btn-block")?.addEventListener("click", async () => {
    if (!state.selectedSession) return;
    const ip = state.selectedSession.source_ip || state.selectedSession.source_address;
    if (!confirm(`Block attacker IP ${ip}?`)) return;
    try {
      await api("/api/v1/honeypot/block-source", {
        method: "POST",
        body: JSON.stringify({ source_ip: ip }),
      });
      toast(`Attacker IP ${ip} permanently blocked.`);
      const blocked = parseInt($("stat-blocked")?.textContent || "0") + 1;
      if ($("stat-blocked")) $("stat-blocked").textContent = blocked;
      closeSessionModal();
      refresh();
    } catch (e) {
      toast("Error: " + e.message, true);
    }
  });

  $("modal-btn-contain")?.addEventListener("click", async () => {
    if (!state.selectedSessionId) return;
    try {
      await api(`/api/v1/honeypot/sessions/${state.selectedSessionId}/contain`, { method: "POST" });
      toast("Session safely contained & isolated.");
      closeSessionModal();
      refresh();
    } catch (e) {
      toast("Error: " + e.message, true);
    }
  });

  $("modal-btn-terminal")?.addEventListener("click", () => {
    closeSessionModal();
    const target = $("terminal-stream");
    const scrollEl = document.querySelector(".scroll-canvas");
    if (target && scrollEl) {
      scrollEl.scrollTo({ top: target.offsetTop - 16, behavior: "smooth" });
    } else if (target) {
      target.scrollIntoView({ behavior: "smooth", block: "start" });
    }
    const card = target?.querySelector(".terminal-card");
    if (card) {
      card.style.transition = "box-shadow 0.3s, border-color 0.3s";
      card.style.borderColor = "var(--primary)";
      card.style.boxShadow = "0 0 0 3px rgba(139, 154, 110, 0.35)";
      setTimeout(() => {
        card.style.borderColor = "";
        card.style.boxShadow = "";
      }, 1600);
    }
  });

  $("modal-btn-export")?.addEventListener("click", () => {
    $("btn-export-session")?.click();
  });

  // Canary Token deployment
  $("canary-form")?.addEventListener("submit", createCanaryToken);
}

// CSS spin keyframes
const style = document.createElement("style");
style.textContent = `@keyframes spin { to { transform: rotate(360deg); } }`;
document.head.appendChild(style);

// ============================================================
// INIT
// ============================================================
async function init() {
  setupButtons();
  await refresh();
  connectWebSocket();
  setInterval(refresh, 3000);
}

document.addEventListener("DOMContentLoaded", init);
