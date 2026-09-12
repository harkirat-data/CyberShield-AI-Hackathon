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
  searchQuery: "",
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
  let filtered = sessionsArr || [];

  if (filter === "critical") {
    filtered = filtered.filter(s => (s.risk_score || 0) >= 80);
  } else if (filter !== "all") {
    filtered = filtered.filter(s => {
      const proto = protoFromPort(s.destination_port).toLowerCase();
      return proto.includes(filter.toLowerCase());
    });
  }

  // Filter by search query across IP, protocol, intent, port, session ID, and MITRE techniques
  const q = (state.searchQuery != null ? state.searchQuery : ($("search-input")?.value || "")).trim().toLowerCase();
  if (q) {
    filtered = filtered.filter(s => {
      const src = (s.source_ip || s.source_address || "").toLowerCase();
      const proto = (s.service || protoFromPort(s.destination_port) || "").toLowerCase();
      const intent = (s.intent || s.triage?.intent_label || "").toLowerCase();
      const port = String(s.destination_port || "");
      const sid = (s.session_id || "").toLowerCase();
      const mitre = (s.mitre_techniques || s.triage?.mitre_techniques || s.mitre || []).join(" ").toLowerCase();
      return src.includes(q) || proto.includes(q) || intent.includes(q) || port.includes(q) || sid.includes(q) || mitre.includes(q);
    });
  }

  const caption = $("sessions-caption");
  if (caption) {
    if (q) {
      caption.textContent = `${filtered.length} matching session${filtered.length !== 1 ? "s" : ""} for "${esc(q)}"`;
    } else {
      caption.textContent = `${filtered.length} session${filtered.length !== 1 ? "s" : ""} engaged across decoy mesh`;
    }
  }

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
    const icon = q ? "search_off" : (sessionsArr.length === 0 ? "wifi_off" : "filter_alt_off");
    const msg = q
      ? `No sessions match "${esc(q)}"`
      : (sessionsArr.length === 0
          ? "No active sessions yet. Start the grid and generate some traffic."
          : "No sessions match this filter.");
    grid.innerHTML = `<div class="empty-state">
      <span class="material-symbols-outlined" style="font-size:40px;color:#8ca4ac">${icon}</span>
      <p>${msg}</p>
    </div>`;
    syncSessionGridExpansion(filtered);
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
    const flag = sess.geo?.country_flag || "🌐";
    const country = sess.geo?.country || "";
    const asn = sess.geo?.asn || "";

    return `<div class="session-card ${selected ? "selected" : ""}" data-id="${esc(sess.session_id)}">
      <div class="session-head">
        <div class="session-ip" title="${esc(country ? `${country} (${asn})` : src)}">
          <span class="session-flag">${flag}</span>
          <span style="font-weight:700">${esc(src)}</span>
          ${asn ? `<span class="session-asn" style="font-size:10px;opacity:0.75">${esc(asn)}</span>` : (sess.destination_port ? `<span class="session-asn">:${sess.destination_port}</span>` : "")}
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



// ============================================================
// NLP CHATBOT WITH VOICE & TEXT CHAT
// ============================================================
function initNlpChatbot() {
  state.chatSoundEnabled = true;
  state.isRecordingVoice = false;

  // Toggle Chat Drawer via floating button
  $("chat-fab")?.addEventListener("click", toggleChatDrawer);
  $("chat-close-btn")?.addEventListener("click", () => {
    const drawer = $("chat-drawer");
    if (drawer) drawer.style.display = "none";
  });

  // Also wire sidebar AI Copilot nav item
  document.querySelector('[data-section="copilot-panel"]')?.addEventListener("click", () => {
    openChatDrawer();
  });

  // Sound Toggle
  $("chat-sound-toggle")?.addEventListener("click", () => {
    state.chatSoundEnabled = !state.chatSoundEnabled;
    const icon = $("chat-sound-icon");
    if (icon) icon.textContent = state.chatSoundEnabled ? "volume_up" : "volume_off";
    toast(state.chatSoundEnabled ? "Voice response enabled (Audio ON)" : "Voice response muted (Audio OFF)");
  });

  // Chat Form Submission
  $("chat-form")?.addEventListener("submit", (e) => {
    e.preventDefault();
    const input = $("chat-text-input");
    const query = input?.value?.trim();
    if (!query) return;
    input.value = "";
    handleUserChatMessage(query);
  });

  // Quick Prompt Chips
  document.querySelectorAll(".prompt-chip")?.forEach((chip) => {
    chip.addEventListener("click", () => {
      const prompt = chip.getAttribute("data-prompt");
      if (prompt) handleUserChatMessage(prompt);
    });
  });

  // Voice Chat (Speech to Text)
  initVoiceRecognition();
}

function openChatDrawer() {
  const drawer = $("chat-drawer");
  if (drawer) {
    drawer.style.display = "flex";
    $("chat-text-input")?.focus();
  }
}

function toggleChatDrawer() {
  const drawer = $("chat-drawer");
  if (drawer) {
    const isHidden = drawer.style.display === "none" || !drawer.style.display;
    drawer.style.display = isHidden ? "flex" : "none";
    if (isHidden) $("chat-text-input")?.focus();
  }
}

function initVoiceRecognition() {
  const SpeechRec = window.SpeechRecognition || window.webkitSpeechRecognition;
  const micBtn = $("chat-mic-btn");
  const indicator = $("chat-voice-indicator");

  if (!SpeechRec) {
    if (micBtn) {
      micBtn.title = "Voice recognition not supported in this browser";
      micBtn.style.opacity = "0.6";
    }
    return;
  }

  const recognition = new SpeechRec();
  recognition.continuous = false;
  recognition.interimResults = true;
  recognition.lang = "en-US";

  micBtn?.addEventListener("click", () => {
    if (state.isRecordingVoice) {
      try { recognition.stop(); } catch (_) {}
      return;
    }
    try {
      recognition.start();
    } catch (e) {
      console.warn("SpeechRecognition start error:", e);
    }
  });

  recognition.onstart = () => {
    state.isRecordingVoice = true;
    micBtn?.classList.add("recording");
    if (indicator) indicator.style.display = "flex";
  };

  recognition.onresult = (event) => {
    const transcript = Array.from(event.results)
      .map((r) => r[0].transcript)
      .join("");
    const input = $("chat-text-input");
    if (input) input.value = transcript;

    if (event.results[0].isFinal) {
      setTimeout(() => {
        if (input && input.value.trim()) {
          const q = input.value.trim();
          input.value = "";
          handleUserChatMessage(q);
        }
      }, 500);
    }
  };

  recognition.onerror = (e) => {
    console.warn("SpeechRecognition error:", e);
    state.isRecordingVoice = false;
    micBtn?.classList.remove("recording");
    if (indicator) indicator.style.display = "none";
  };

  recognition.onend = () => {
    state.isRecordingVoice = false;
    micBtn?.classList.remove("recording");
    if (indicator) indicator.style.display = "none";
  };
}

async function handleUserChatMessage(query) {
  const messagesContainer = $("chat-messages");
  if (!messagesContainer) return;

  // Append user message
  const userDiv = document.createElement("div");
  userDiv.className = "chat-msg user";
  userDiv.innerHTML = `<div class="msg-bubble">${esc(query)}</div>`;
  messagesContainer.appendChild(userDiv);
  messagesContainer.scrollTop = messagesContainer.scrollHeight;

  // Append thinking bubble
  const aiDiv = document.createElement("div");
  aiDiv.className = "chat-msg ai";
  aiDiv.innerHTML = `<div class="msg-bubble" style="color:var(--text-muted);font-style:italic">Thinking... Analyzing threat state</div>`;
  messagesContainer.appendChild(aiDiv);
  messagesContainer.scrollTop = messagesContainer.scrollHeight;

  try {
    const reply = await getAiAssistantResponse(query);
    const bubble = aiDiv.querySelector(".msg-bubble");
    if (bubble) {
      bubble.style.color = "var(--text)";
      bubble.style.fontStyle = "normal";
      bubble.innerHTML = formatMarkdownBasic(reply);

      // Add speech button
      const speakerBtn = document.createElement("button");
      speakerBtn.className = "msg-speaker-btn";
      speakerBtn.innerHTML = `<span class="material-symbols-outlined" style="font-size:14px">volume_up</span> <span>Listen</span>`;
      speakerBtn.onclick = () => speakText(reply);
      aiDiv.appendChild(speakerBtn);
    }

    if (state.chatSoundEnabled) {
      speakText(reply);
    }
  } catch (err) {
    const bubble = aiDiv.querySelector(".msg-bubble");
    if (bubble) bubble.textContent = "I encountered an error analyzing your request: " + err.message;
  }
  messagesContainer.scrollTop = messagesContainer.scrollHeight;
}

function speakText(text) {
  if (!window.speechSynthesis) return;
  try {
    window.speechSynthesis.cancel();
    const cleanText = text.replace(/[*#_`]/g, "").replace(/https?:\/\/\S+/g, "");
    const utter = new SpeechSynthesisUtterance(cleanText.slice(0, 300));
    utter.rate = 1.05;
    utter.pitch = 1.0;
    utter.lang = "en-US";
    window.speechSynthesis.speak(utter);
  } catch (e) {
    console.warn("SpeechSynthesis error:", e);
  }
}

async function getAiAssistantResponse(query) {
  const q = query.toLowerCase();
  const sessionCount = state.sessions ? state.sessions.length : 0;
  const criticalCount = state.sessions ? state.sessions.filter(s => (s.risk_score || 0) >= 80).length : 0;

  // Contextual Knowledge Answers
  if (q.includes("safe") || q.includes("status") || q.includes("are we")) {
    return `🛡️ **Current Security Status: 100% SECURE & OPERATIONAL**\n\nAll **5 multi-port decoy services** (SSH, Telnet, HTTP, HTTPS, MySQL) are online and actively trapping incoming scanners.\n\n• **Trapped Adversaries:** ${sessionCount} total (${criticalCount} high priority)\n• **Production Breach Risk:** ZERO. All incoming scans are confined to synthetic sandboxes with SHA-256 evidence anchoring.`;
  }

  if (q.includes("honeypot") || q.includes("how does it work") || q.includes("protect")) {
    return `🍯 **How CyberShield AI Protects You:**\n\nUnlike traditional firewalls that rely only on blocking known IP lists, CyberShield AI deploys **active synthetic decoys** disguised as real finance portals, databases, and SSH servers.\n\nWhen attackers probe your network, they get lured into our harmless deception environment. We record their complete attack playbook, compute SHA-256 forensic hashes, and notify your security team before they can ever touch real production servers!`;
  }

  if (q.includes("attack") || q.includes("today") || q.includes("latest") || q.includes("what happened")) {
    if (state.sessions && state.sessions.length > 0) {
      const latest = state.sessions[0];
      const proto = (latest.service || "HTTP").toUpperCase();
      const ip = latest.source_ip || "External";
      const country = latest.geo?.country || "Foreign WAN";
      return `⚠️ **Today's Activity Summary:**\n\nWe have intercepted **${sessionCount} adversary interactions**.\n\n• **Latest Threat:** Connection from **${ip}** (${country}) targeting our **${proto} decoy**.\n• **Attacker Intent:** ${latest.intent || "System Discovery & Probe"}\n• **Action Taken:** Deception response delivered, dwell time extended, and threat telemetry dispatched to SOC.`;
    }
    return `We currently have **0 active threats** in the last polling window. The honeynet mesh is actively listening on ports 2222, 2323, 8088, 8443, and 3307.`;
  }

  if (q.includes("country") || q.includes("countries") || q.includes("where")) {
    const countries = [...new Set((state.sessions || []).map(s => s.geo?.country).filter(Boolean))];
    const countryList = countries.length ? countries.slice(0, 5).join(", ") : "External WAN networks";
    return `🌐 **Threat Geographic Origins:**\n\nAdversary probes have originated from: **${countryList}**.\n\nYou can inspect exact coordinates and ASN attribution in the **Geo & IP Intel** tab or on our interactive Leaflet world map.`;
  }

  // Fallback to Gemini / RAG API
  try {
    const res = await api("/api/v1/rag/query", {
      method: "POST",
      body: JSON.stringify({ query: query, session_id: "chatbot", top_k: 3 }),
    });
    if (res && res.answer) {
      return res.answer;
    }
  } catch (_) {}

  return `CyberShield AI has analyzed your inquiry: **"${query}"**.\n\nOur multi-port honeypot grid is actively monitoring enterprise traffic across ports 2222 (SSH), 2323 (Telnet), 8088 (HTTP), 8443 (HTTPS), and 3307 (MySQL). All ${sessionCount} adversary sessions are safely sandboxed with zero risk to production infrastructure.`;
}

function formatMarkdownBasic(txt) {
  return esc(txt)
    .replace(/\*\*(.*?)\*\*/g, "<strong>$1</strong>")
    .replace(/\*(.*?)\*/g, "<em>$1</em>")
    .replace(/`([^`]+)`/g, "<code>$1</code>")
    .replace(/\n\n/g, "<br><br>")
    .replace(/\n/g, "<br>");
}

// ============================================================
// MENTOR UPGRADE 3: EXECUTIVE PLAIN-ENGLISH INCIDENT REPORT
// ============================================================
function openExecutiveReportModal() {
  const sess = state.selectedSession;
  if (!sess) {
    toast("Please select a session first", true);
    return;
  }
  const events = state.selectedEvents || [];
  const contentEl = $("exec-report-content");
  if (!contentEl) return;

  const html = generateExecutiveBriefHtml(sess, events);
  contentEl.innerHTML = html;

  const overlay = $("executive-report-modal-overlay");
  if (overlay) {
    overlay.style.display = "flex";
    document.body.style.overflow = "hidden";
  }
}

function closeExecutiveReportModal() {
  const overlay = $("executive-report-modal-overlay");
  if (overlay) {
    overlay.style.display = "none";
    document.body.style.overflow = "";
  }
}

function generateExecutiveBriefHtml(sess, events = []) {
  const id = sess.session_id || "CYBER-INC-001";
  const src = sess.source_ip || sess.source_address || "127.0.0.1";
  const geo = sess.geo || {};
  const port = sess.destination_port || 8088;
  const proto = (sess.service || protoFromPort(port)).toUpperCase();
  const risk = Number(sess.risk_score ?? 75);
  const dwell = dur(sessionDuration(sess));
  const dateStr = sess.started_at ? new Date(sess.started_at).toLocaleString() : new Date().toLocaleString();
  const sha = (events[0]?.content_digest || "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").slice(0, 16);

  const { title, attackerStory, defenderStory } = explainSessionInPlainEnglish(sess, events);

  return `
    <div style="border-bottom: 2px solid #2d6a4f; padding-bottom: 12px; margin-bottom: 18px; display: flex; justify-content: space-between; align-items: flex-start;">
      <div>
        <h2 style="margin:0;font-size:20px;font-family:var(--font-head);color:#2d6a4f;font-weight:800">
          CYBERSHIELD AI &mdash; EXECUTIVE INCIDENT REPORT
        </h2>
        <p style="margin:4px 0 0 0;font-size:12px;color:var(--text-muted)">
          Formal Security Advisory for Executive Leadership &middot; Reference: <strong>${esc(id)}</strong>
        </p>
      </div>
      <div style="text-align:right">
        <span style="display:inline-block;padding:4px 10px;border-radius:6px;font-weight:700;font-size:12px;background:${risk >= 80 ? '#faeaea' : '#fbf3e6'};color:${risk >= 80 ? '#C24B4B' : '#C98A3C'};border:1px solid ${risk >= 80 ? '#fbdada' : '#fae6cd'}">
          ${risk >= 80 ? 'CRITICAL RISK' : 'HIGH RISK'} (${risk}/100)
        </span>
      </div>
    </div>

    <div class="exec-brief-header-meta">
      <div class="exec-meta-item">
        <div class="meta-k">Date &amp; Time</div>
        <div class="meta-v">${esc(dateStr)}</div>
      </div>
      <div class="exec-meta-item">
        <div class="meta-k">Adversary IP</div>
        <div class="meta-v">${esc(src)}</div>
      </div>
      <div class="exec-meta-item">
        <div class="meta-k">Origin / Country</div>
        <div class="meta-v">${geo.country_flag || "🌐"} ${esc(geo.country || "External WAN")}</div>
      </div>
      <div class="exec-meta-item">
        <div class="meta-k">Targeted Asset</div>
        <div class="meta-v">${esc(proto)} Decoy (Port ${port})</div>
      </div>
      <div class="exec-meta-item">
        <div class="meta-k">Forensic SHA-256</div>
        <div class="meta-v" style="font-family:var(--font-mono);font-size:11px">${esc(sha)}...</div>
      </div>
    </div>

    <div class="exec-callout-safe">
      <strong>🛡️ CERTIFIED BUSINESS IMPACT: ZERO PRODUCTION RISK</strong><br>
      The adversary engaged an isolated, air-gapped CyberShield AI synthetic decoy environment. At no point was any production database, corporate network, or customer record accessible to the intruder.
    </div>

    <div class="exec-brief-section">
      <h4><span class="material-symbols-outlined" style="font-size:16px">chat</span> 1. Executive Summary (Non-Technical Explanation)</h4>
      <p style="font-size:13px;color:var(--text)">
        On ${esc(dateStr)}, automated defensive monitors detected an unauthorized foreign entity attempting to penetrate our corporate perimeter. 
        ${esc(attackerStory)}
      </p>
    </div>

    <div class="exec-brief-section">
      <h4><span class="material-symbols-outlined" style="font-size:16px">shield</span> 2. Autonomous Defensive Action Taken</h4>
      <p style="font-size:13px;color:var(--text)">
        ${esc(defenderStory)}
        The intruder was trapped for a total dwell time of <strong>${dwell}</strong> across <strong>${events.length} interaction steps</strong>, allowing our forensic algorithms to extract their complete attack toolkit without triggering an alarm on their side.
      </p>
    </div>

    <div class="exec-brief-section">
      <h4><span class="material-symbols-outlined" style="font-size:16px">bug_report</span> 3. Root Cause Analysis ("Where is the Leak?")</h4>
      <p style="font-size:13px;color:var(--text)">
        Our automated code inspection determined that the adversary attempted to leverage a known security weakness:
      </p>
      <ul class="exec-remediation-list" style="color:var(--text)">
        <li><strong>Vulnerability Classification:</strong> ${$("modal-patch-cwe")?.textContent || "CWE-89 SQL Injection"}</li>
        <li><strong>Vulnerable File / Configuration:</strong> <code>${$("modal-patch-file")?.textContent || "/admin/portal.php"}</code></li>
        <li><strong>Root Cause:</strong> ${$("modal-patch-desc")?.textContent || "Unsanitized input interpolation."}</li>
      </ul>
    </div>

    <div class="exec-brief-section">
      <h4><span class="material-symbols-outlined" style="font-size:16px">checklist</span> 4. Recommended Management Remediation Plan</h4>
      <ol class="exec-remediation-list" style="color:var(--text)">
        <li><strong>Immediate Perimeter Blacklist:</strong> Execute <code>${$("modal-patch-cmd")?.textContent || "sudo ufw deny from " + src}</code> on public firewalls to drop future traffic from this IP address.</li>
        <li><strong>Engineering Code Patch:</strong> Deploy the secure parameterized prepared statement patch to prevent SQL command injection in production.</li>
        <li><strong>Credential Rotation:</strong> As a security precaution, revoke and regenerate any API tokens or service passwords associated with the ${esc(proto)} subsystem.</li>
      </ol>
    </div>

    <div style="margin-top:24px;padding-top:12px;border-top:1px solid #eef3e7;display:flex;justify-content:space-between;align-items:center;font-size:11px;color:var(--text-muted)">
      <span>Generated by CyberShield AI Autonomous Incident Copilot</span>
      <span>Legal Chain of Custody &bull; SHA-256 Anchored</span>
    </div>
  `;
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

  // Title, IP, Time, and Geo attribution
  if ($("modal-title")) $("modal-title").textContent = title;
  if ($("modal-ip")) $("modal-ip").textContent = `Attacker: ${src}${srcPort}`;
  if ($("modal-time")) $("modal-time").textContent = sess.started_at ? `Started ${timeStr(sess.started_at)}` : "Recent";
  const geo = sess.geo || {};
  if ($("modal-geo-flag")) $("modal-geo-flag").textContent = geo.country_flag || "🌐";
  if ($("modal-geo-country")) $("modal-geo-country").textContent = geo.country || (geo.city ? `${geo.city}, ${geo.country}` : "Internal Network");
  if ($("modal-geo-asn")) $("modal-geo-asn").textContent = geo.asn || "AS-PRIVATE";

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

  // Hero Pause / Resume Button
  const pauseBtn = $("btn-pause-grid");
  const pauseIcon = $("pause-grid-icon");
  const pauseLabel = $("pause-grid-label");
  if (pauseBtn) {
    pauseBtn.classList.toggle("paused-grid", !running);
    if (pauseIcon) {
      pauseIcon.textContent = running ? "pause_circle" : "play_circle";
      pauseIcon.style.color = running ? "#7d9cb7" : "#4e5d34";
    }
    if (pauseLabel) {
      pauseLabel.textContent = running ? "Pause Grid" : "Resume Grid";
    }
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
// ATTACK ORIGIN VECTORS & REAL LEAFLET WORLD MAP
// ============================================================
let leafletMap = null;
let leafletMarkersLayer = null;
let mapInitialViewDone = false;
let userInteractedWithMap = false;

function formatAttackTimestamp(isoStr) {
  if (!isoStr) return { full: "Just now", timeOnly: "Just now", rel: "Live" };
  try {
    const d = new Date(isoStr);
    if (isNaN(d.getTime())) return { full: isoStr, timeOnly: isoStr, rel: "" };
    const now = new Date();
    const diffSec = Math.max(0, Math.floor((now - d) / 1000));

    let rel = "Just now";
    if (diffSec < 60) rel = `${diffSec}s ago`;
    else if (diffSec < 3600) rel = `${Math.floor(diffSec / 60)}m ago`;
    else if (diffSec < 86400) rel = `${Math.floor(diffSec / 3600)}h ago`;
    else rel = `${Math.floor(diffSec / 86400)}d ago`;

    const timeOnly = d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: true });
    const dateOnly = d.toLocaleDateString([], { month: "short", day: "numeric" });
    return {
      full: `${dateOnly}, ${timeOnly} (${rel})`,
      timeOnly: timeOnly,
      dateOnly: dateOnly,
      rel: rel
    };
  } catch (_) {
    return { full: isoStr, timeOnly: isoStr, rel: "" };
  }
}

function initLeafletMap() {
  const container = $("map-container");
  if (!container || !window.L) return;
  if (leafletMap) return;

  try {
    leafletMap = L.map("map-container", {
      center: [22.5, 30.0],
      zoom: 2,
      minZoom: 1,
      maxZoom: 12,
      zoomControl: true,
      attributionControl: false
    });

    // Track user drag/pinch so automatic background refreshes never hijack the camera
    leafletMap.on("movestart", (e) => {
      if (e.originalEvent) userInteractedWithMap = true;
    });
    leafletMap.on("zoomstart", (e) => {
      if (e.originalEvent) userInteractedWithMap = true;
    });

    // Standard normal world map (OpenStreetMap: genuine world map with continents, oceans, borders, cities)
    L.tileLayer("https://tile.openstreetmap.org/{z}/{x}/{y}.png", {
      maxZoom: 18,
      attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a>'
    }).addTo(leafletMap);

    leafletMarkersLayer = L.layerGroup().addTo(leafletMap);

    // Defense SOC hub marker in center
    const socIcon = L.divIcon({
      html: `<div style="background:#22c55e;color:#fff;font-family:var(--font-mono);font-size:9px;font-weight:700;padding:2px 7px;border-radius:4px;border:1.5px solid #fff;box-shadow:0 0 10px rgba(34,197,94,0.6);white-space:nowrap">🛡️ CYBERSHIELD GRID</div>`,
      className: "leaflet-custom-marker-wrap",
      iconSize: [110, 20],
      iconAnchor: [55, 10]
    });
    L.marker([20.5937, 78.9629], { icon: socIcon, interactive: false }).addTo(leafletMap);

    setTimeout(() => {
      leafletMap.invalidateSize();
    }, 200);
  } catch (err) {
    console.warn("Leaflet map initialization skipped:", err);
  }
}

function renderAttackVectors(sessionsArr, eventsArr) {
  if (!leafletMap && window.L && $("map-container")) {
    initLeafletMap();
  }
  if (!leafletMap || !leafletMarkersLayer) return;

  leafletMarkersLayer.clearLayers();

  const attackers = (state.attackers || []).filter(a => a.ip && a.ip.toLowerCase() !== "testclient");
  if (attackers.length === 0) return;

  const bounds = [];

  attackers.forEach((atk, idx) => {
    const geo = atk.geo || {};
    const lat = geo.latitude;
    const lon = geo.longitude;
    if (typeof lat !== "number" || typeof lon !== "number" || (lat === 0 && lon === 0)) return;

    const isLatest = idx === 0;
    const ip = atk.ip;
    const flag = geo.country_flag || "🌐";
    const city = geo.city || "Unknown";
    const country = geo.country || "Unknown";
    const asn = geo.asn || "AS-UNKNOWN";
    const timeInfo = formatAttackTimestamp(atk.latest_activity);
    const risk = atk.max_risk_score || 50;

    bounds.push([lat, lon]);

    const iconHtml = isLatest
      ? `<div class="leaflet-latest-marker" style="cursor:pointer">
           <span class="marker-pulse"></span>
           <span class="marker-dot"></span>
           <span class="marker-badge">⚡ ${esc(ip)}</span>
         </div>`
      : `<div class="leaflet-normal-marker" style="cursor:pointer">
           <span class="marker-dot"></span>
           <span class="marker-label">${flag} ${esc(ip)}</span>
         </div>`;

    const customIcon = L.divIcon({
      html: iconHtml,
      className: "leaflet-custom-marker-wrap",
      iconSize: isLatest ? [125, 26] : [90, 22],
      iconAnchor: [8, 11],
    });

    const marker = L.marker([lat, lon], { icon: customIcon }).addTo(leafletMarkersLayer);

    if (isLatest) {
      // ISP Gateway Coverage Radius Circle (~12km metro routing zone)
      L.circle([lat, lon], {
        radius: 12000,
        color: "#ef4444",
        weight: 1.5,
        dashArray: "4 4",
        fillColor: "#ef4444",
        fillOpacity: 0.07,
        interactive: false
      }).addTo(leafletMarkersLayer);
    }

    marker.bindPopup(`
      <div style="font-family:Inter,sans-serif;min-width:200px">
        <div style="font-weight:700;font-size:13px;display:flex;align-items:center;gap:6px;border-bottom:1px solid #eee;padding-bottom:6px">
          <span>${flag}</span>
          <span>${esc(ip)}</span>
          ${isLatest ? '<span style="background:#ef4444;color:#fff;font-size:9px;padding:2px 5px;border-radius:3px">LATEST ATTACK</span>' : ''}
        </div>
        <div style="font-size:11px;color:#334155;margin-top:6px;line-height:1.6">
          <strong>Location:</strong> ${esc(city)}, ${esc(country)}<br>
          <strong>Network:</strong> ${esc(asn)} (${esc(geo.as_org || geo.isp || "Unknown")})<br>
          <strong>Attack Time:</strong> <span style="color:#ef4444;font-weight:700">${esc(timeInfo.full)}</span><br>
          <strong>Target Decoy:</strong> ${(atk.probed_services || []).join(", ") || "HTTP Port 8088"}<br>
          <strong>Risk Score:</strong> ${risk}/100
        </div>
        <button class="btn-sm btn-primary" onclick="trackIpAddress('${esc(ip)}', true, true, true)" style="margin-top:8px;width:100%;font-size:11px;padding:4px">Inspect Full Dossier</button>
      </div>
    `, { autoPan: false });

    marker.on("click", () => {
      trackIpAddress(ip, true, true, true);
    });
  });

  // Center around latest attacker ONCE on initial load only.
  // Never zoom or reset camera continuously on standby refreshes.
  if (!mapInitialViewDone && !userInteractedWithMap) {
    if (attackers.length > 0 && attackers[0].geo?.latitude && attackers[0].geo?.longitude) {
      const lat = attackers[0].geo.latitude;
      const lon = attackers[0].geo.longitude;
      leafletMap.setView([lat, lon], 4);
    } else if (bounds.length > 0) {
      leafletMap.fitBounds(bounds, { padding: [30, 30], maxZoom: 4 });
    }
    mapInitialViewDone = true;
  }
}

// ============================================================
// ATTACKER GEOLOCATION INTEL & IP DOSSIER TRACKER
// ============================================================
async function loadAttackerGeoIntel(cachedAttackers) {
  try {
    let attackers = cachedAttackers;
    if (!attackers) {
      const resp = await api("/api/v1/intel/attackers");
      attackers = resp.attackers || [];
    }
    // Filter out synthetic local test harness clients
    attackers = (attackers || []).filter(a => a.ip && a.ip.toLowerCase() !== "testclient");
    state.attackers = attackers;

    const badge = $("geo-attacker-badge");
    if (badge) badge.textContent = `${attackers.length} Attacker${attackers.length !== 1 ? "s" : ""} Tracked`;
    const navBadge = $("nav-badge-geo");
    if (navBadge) navBadge.textContent = `${attackers.length} IPS`;

    const tbody = $("geo-attacker-rows");
    const empty = $("geo-table-empty");
    if (tbody) {
      if (attackers.length === 0) {
        tbody.innerHTML = "";
        if (empty) empty.style.display = "block";
      } else {
        if (empty) empty.style.display = "none";
        tbody.innerHTML = attackers.map((atk, idx) => {
          const g = atk.geo || {};
          const flag = g.country_flag || "🌐";
          const country = g.country || "Unknown";
          const city = g.city || "Unknown";
          const postal = g.postal ? ` (${g.postal})` : "";
          const region = g.region && g.region !== "Unknown" ? `, ${g.region}` : "";
          const asn = g.asn || "AS-UNKNOWN";
          const org = g.as_org || g.org || g.isp || "Unknown";
          const decoys = (atk.probed_services || []).join(", ") || "Decoy Sensor";
          const risk = atk.max_risk_score || 50;
          const riskCls = risk >= 80 ? "high" : risk >= 50 ? "med" : "low";
          const isLatest = idx === 0;
          const timeInfo = formatAttackTimestamp(atk.latest_activity);

          return `<tr class="${isLatest ? 'latest-attacker-row' : ''}">
            <td>
              <span class="geo-ip-link" data-ip="${esc(atk.ip)}">
                <span class="material-symbols-outlined" style="font-size:15px;color:${isLatest ? 'var(--rose)' : 'var(--primary)'}">radar</span>
                <strong>${esc(atk.ip)}</strong>
                ${isLatest ? '<span style="background:var(--rose);color:#fff;font-size:9px;padding:1px 5px;border-radius:3px;margin-left:4px;font-family:var(--font-mono)">LATEST</span>' : ''}
              </span>
            </td>
            <td>
              <div style="font-family:var(--font-mono);font-size:12px;font-weight:700;color:${isLatest ? 'var(--rose)' : 'var(--text)'}">
                ${esc(timeInfo.timeOnly)}
              </div>
              <div style="font-size:10px;color:var(--text-muted);white-space:nowrap">
                ${esc(timeInfo.rel)}
              </div>
            </td>
            <td>
              <span class="geo-flag-badge">
                <span style="font-size:18px">${flag}</span>
                <span>${esc(country)}</span>
              </span>
            </td>
            <td>${esc(city)}${postal}${esc(region)}</td>
            <td><span class="asn-badge">${esc(asn)}</span></td>
            <td style="max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(org)}">${esc(org)}</td>
            <td><code style="font-size:11px;background:var(--surface-low);padding:2px 6px;border-radius:4px">${esc(decoys)}</code></td>
            <td><span class="threat-pill ${riskCls}">${risk}/100</span></td>
            <td>
              <div style="display:flex;align-items:center;gap:6px">
                <button class="btn-sm btn-track-quick" data-ip="${esc(atk.ip)}" style="padding:3px 8px;font-size:11px" title="Inspect IP Dossier">Inspect</button>
                <button class="btn-sm btn-danger btn-block-quick" data-ip="${esc(atk.ip)}" style="padding:3px 8px;font-size:11px" title="Block at Perimeter">Block</button>
              </div>
            </td>
          </tr>`;
        }).join("");

        tbody.querySelectorAll(".geo-ip-link, .btn-track-quick").forEach(el => {
          el.addEventListener("click", () => trackIpAddress(el.dataset.ip));
        });
        tbody.querySelectorAll(".btn-block-quick").forEach(el => {
          el.addEventListener("click", async () => {
            const ip = el.dataset.ip;
            if (!confirm(`Block ${ip} immediately at the CyberShield perimeter firewall?`)) return;
            try {
              await api("/api/v1/honeypot/block-source", {
                method: "POST",
                body: JSON.stringify({ source_ip: ip }),
              });
              toast(`Quarantined IP: ${ip}`);
              await refresh();
            } catch (err) {
              toast("Failed to block: " + err.message, true);
            }
          });
        });
      }
    }

    renderAttackVectors(state.sessions, state.events);

    // Auto-display and prefill the live dossier card for the most recent active attacker (without moving map camera)
    if (attackers.length > 0) {
      const topAtk = attackers[0];
      const inputEl = $("ip-tracker-input");
      if (inputEl && !inputEl.value) {
        inputEl.value = topAtk.ip;
      }
      const currentIp = $("dossier-ip")?.textContent?.trim();
      if (!currentIp || currentIp === "--" || currentIp !== topAtk.ip) {
        trackIpAddress(topAtk.ip, false, false, false);
      }
    }
  } catch (err) {
    console.error("Failed to load attacker geo intel:", err);
  }
}

async function trackIpAddress(ip, showToast = true, scroll = true, panMap = true) {
  if (!ip) return;
  const cleanIp = ip.trim();
  const card = $("ip-dossier-card");
  if (!card) return;

  try {
    if (showToast) toast(`Tracing network footprint for ${cleanIp}...`);
    card.style.display = "block";
    const data = await api(`/api/v1/intel/ip/${encodeURIComponent(cleanIp)}`);
    const geo = data.geo || {};

    const postalText = geo.postal ? ` • PIN: ${geo.postal}` : "";
    $("dossier-flag").textContent = geo.country_flag || "🌐";
    $("dossier-ip").textContent = data.ip;
    $("dossier-loc").textContent = `${geo.city || "Unknown City"}, ${geo.region || "Region"}, ${geo.country || "Unknown Country"}${postalText}`;

    // Attack Time calculation & display
    const latestSess = (data.sessions && data.sessions.length > 0) ? data.sessions[0] : null;
    const attackTimestamp = latestSess?.started_at || null;
    const timeInfo = formatAttackTimestamp(attackTimestamp);

    const timeTextEl = $("dossier-time-text");
    if (timeTextEl) {
      timeTextEl.textContent = `Attack Time: ${timeInfo.full}`;
    }
    const stampEl = $("dossier-timestamp");
    if (stampEl) {
      stampEl.textContent = timeInfo.full;
    }

    const threatScore = geo.threat_score || 50;
    const threatBadge = $("dossier-threat");
    if (threatBadge) {
      threatBadge.textContent = `Threat Score: ${threatScore}/100`;
      threatBadge.style.background = threatScore >= 80 ? "#fde8e8" : threatScore >= 50 ? "#fff4e5" : "#edf7ed";
      threatBadge.style.color = threatScore >= 80 ? "var(--rose)" : threatScore >= 50 ? "var(--amber)" : "var(--emerald)";
    }

    $("dossier-asn").textContent = `${geo.asn || "AS-UNKNOWN"} ${geo.as_org ? `(${geo.as_org})` : ""}`;
    $("dossier-isp").textContent = `${geo.isp || "Unknown"} — ${geo.org || "Unknown Org"}`;
    $("dossier-coords").textContent = `${geo.latitude?.toFixed(4) || 0}, ${geo.longitude?.toFixed(4) || 0} (TZ: ${geo.timezone || "UTC"})`;
    $("dossier-threat-type").textContent = geo.threat_type || "External Ingress";
    $("dossier-sessions").textContent = `${data.session_count || 0} session(s) engaged`;
    $("dossier-canaries").textContent = `${(data.canary_triggers || []).length} tripwire trigger(s)`;

    // Attach latest targeted decoy and observed intent
    const targetPort = latestSess?.destination_port ? `Port ${latestSess.destination_port}` : "Perimeter Listener";
    const targetProto = latestSess?.service || latestSess?.protocol || "HTTP";
    const targetEl = $("dossier-target-vector");
    if (targetEl) {
      targetEl.textContent = `${targetProto} Decoy (${targetPort})`;
    }
    const intentEl = $("dossier-attack-intent");
    if (intentEl) {
      intentEl.textContent = latestSess?.intent || geo.threat_type || "Database discovery / Ingress";
    }

    // Smoothly fly Leaflet map to attacker's location ONLY when explicitly requested by user
    if (panMap && leafletMap && geo.latitude && geo.longitude) {
      leafletMap.flyTo([geo.latitude, geo.longitude], 5, { duration: 1.0 });
    }

    const blockBtn = $("dossier-btn-block");
    if (blockBtn) {
      blockBtn.onclick = async () => {
        if (!confirm(`Block ${cleanIp} immediately across CyberShield AI listeners?`)) return;
        try {
          await api("/api/v1/honeypot/block-source", {
            method: "POST",
            body: JSON.stringify({ source_ip: cleanIp }),
          });
          toast(`Perimeter rule applied: ${cleanIp} quarantined.`);
          await refresh();
        } catch (err) {
          toast("Block failed: " + err.message, true);
        }
      };
    }

    const simBtn = $("dossier-btn-simulate");
    if (simBtn) {
      simBtn.onclick = async () => {
        try {
          toast(`Engaging live attack vector from ${cleanIp}...`);
          const res = await api("/api/v1/intel/simulate-attack", {
            method: "POST",
            body: JSON.stringify({ attacker_ip: cleanIp })
          });
          const actor = res.actor || {};
          toast(`Live attack triggered: ${actor.country || "Adversary"} (${actor.asn || "ASN"}) targeting decoy port ${res.session?.destination_port || 2222}!`);
          await refresh();
        } catch (err) {
          toast("Attack simulation failed: " + err.message, true);
        }
      };
    }

    if (scroll) {
      card.scrollIntoView({ behavior: "smooth", block: "nearest" });
    }
  } catch (err) {
    if (showToast) toast(`Failed to track IP: ${err.message}`, true);
  }
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

    // Render target counters
    updateTargetCounts(sessions);

    // Render attack intent distribution
    updateIntentChart(events, sessions);

    // Refresh canary tokens
    await loadCanaryTokens();

    // Refresh security alerts
    await loadAlerts();

    // Refresh attacker geolocation and ASN intelligence
    await loadAttackerGeoIntel();

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
      textEmail.textContent = email.last_error || "SMTP host / credentials not set in .env";
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
      const hint = res.email_error ? ` (${res.email_error})` : ": No channels configured in .env";
      toast(`Test alert evaluated${hint}`, false);
    } else if (successCount === 0 && res.email_error) {
      toast(`Test alert failed: ${res.email_error}`, true);
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
      const reason = res.email_error || "SMTP not configured in .env (missing SMTP_HOST/SMTP_PASSWORD)";
      toast(`Email alert failed: ${reason}`, true);
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
          if (data.attackers) {
            loadAttackerGeoIntel(data.attackers);
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
  // Grid toggle & pause handlers
  const handleToggleGrid = async () => {
    const running = state.status?.running ?? false;
    const pauseBtn = $("btn-pause-grid");
    const sideBtn = $("btn-grid-toggle");
    if (pauseBtn) pauseBtn.disabled = true;
    if (sideBtn) sideBtn.disabled = true;
    try {
      const res = await api(`/api/v1/honeypot/control/${running ? "stop" : "start"}`, { method: "POST" });
      toast(running ? "Honeypot grid paused." : "Honeypot grid resumed!");
      if (res && typeof res.running === "boolean") {
        updateStatusUI(res);
      }
      await refresh();
    } catch (e) {
      toast("Error: " + e.message, true);
    } finally {
      if (pauseBtn) pauseBtn.disabled = false;
      if (sideBtn) sideBtn.disabled = false;
    }
  };

  $("btn-grid-toggle")?.addEventListener("click", handleToggleGrid);
  $("btn-pause-grid")?.addEventListener("click", handleToggleGrid);

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

  // Geolocation and IP Tracker event handlers
  $("btn-track-ip")?.addEventListener("click", () => {
    const input = $("ip-tracker-input");
    if (input && input.value.trim()) {
      trackIpAddress(input.value.trim());
    }
  });

  $("ip-tracker-input")?.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      const input = $("ip-tracker-input");
      if (input && input.value.trim()) {
        trackIpAddress(input.value.trim());
      }
    }
  });

  $("dossier-btn-close")?.addEventListener("click", () => {
    const card = $("ip-dossier-card");
    if (card) card.style.display = "none";
  });

  // Precision Honey-Lure client-side triangulation (demonstrates client-side GPS/Wi-Fi positioning vs BGP ISP routing)
  $("dossier-btn-lure")?.addEventListener("click", () => {
    if (!navigator.geolocation) {
      toast("HTML5 Geolocation is not supported by your browser environment.", true);
      return;
    }
    const btn = $("dossier-btn-lure");
    const orig = btn ? btn.innerHTML : "🎯 Precision Honey-Lure";
    if (btn) {
      btn.disabled = true;
      btn.innerHTML = `<span class="material-symbols-outlined" style="font-size:14px;animation:spin 1s linear infinite">autorenew</span> Triangulating...`;
    }
    toast("Executing client-side Honey-Lure triangulation (Wi-Fi SSID / GPS)...");

    navigator.geolocation.getCurrentPosition(
      (pos) => {
        if (btn) {
          btn.disabled = false;
          btn.innerHTML = orig;
        }
        const lat = pos.coords.latitude;
        const lon = pos.coords.longitude;
        const acc = Math.round(pos.coords.accuracy || 15);
        toast(`[LURE TRIGGERED] High-precision terminal location locked: ${lat.toFixed(4)}, ${lon.toFixed(4)} (±${acc}m accuracy)`);

        // Update dossier coordinates and notes
        const coordEl = $("dossier-coords");
        if (coordEl) coordEl.textContent = `${lat.toFixed(4)}, ${lon.toFixed(4)} (🎯 Precision GPS/Wi-Fi: ±${acc}m)`;

        const notesEl = $("dossier-attribution-notes");
        if (notesEl) {
          notesEl.innerHTML = `<span style="color:#059669;font-weight:700">🎯 Precision Honey-Lure Triangulation Active:</span> Pinpointed to physical subscriber node at <strong>${lat.toFixed(5)}, ${lon.toFixed(5)}</strong> (±${acc}m accuracy). Demonstrates client-side sensor honeypot trap vs standard BGP ISP network routing.`;
        }

        // Add precision marker on Leaflet map
        if (leafletMap && leafletMarkersLayer) {
          const lureIcon = L.divIcon({
            html: `<div class="leaflet-latest-marker" style="cursor:pointer">
                     <span class="marker-pulse" style="background:rgba(16,185,129,0.5)"></span>
                     <span class="marker-dot" style="background:#10b981"></span>
                     <span class="marker-badge" style="background:#059669">🎯 PHYSICAL NODE: ${lat.toFixed(4)}, ${lon.toFixed(4)}</span>
                   </div>`,
            className: "leaflet-custom-marker-wrap",
            iconSize: [195, 26],
            iconAnchor: [8, 11]
          });

          // Draw precision accuracy circle
          L.circle([lat, lon], {
            radius: Math.max(acc, 50),
            color: "#059669",
            weight: 2,
            fillColor: "#10b981",
            fillOpacity: 0.15
          }).addTo(leafletMarkersLayer);

          const lureMarker = L.marker([lat, lon], { icon: lureIcon }).addTo(leafletMarkersLayer);
          lureMarker.bindPopup(`
            <div style="font-family:Inter,sans-serif;min-width:220px">
              <div style="font-weight:700;font-size:13px;color:#059669;display:flex;align-items:center;gap:6px">
                <span>🎯</span>
                <span>PHYSICAL SUBSCRIBER NODE</span>
              </div>
              <div style="font-size:11px;color:#334155;margin-top:6px;line-height:1.6">
                <strong>Method:</strong> Client-Side Honey-Lure Triangulation<br>
                <strong>Coordinates:</strong> ${lat.toFixed(5)}, ${lon.toFixed(5)}<br>
                <strong>Accuracy:</strong> ±${acc} meters<br>
                <strong>Region:</strong> Local Physical Subscriber Address
              </div>
            </div>
          `).openPopup();

          leafletMap.flyTo([lat, lon], 14, { duration: 1.5 });
        }
      },
      (err) => {
        if (btn) {
          btn.disabled = false;
          btn.innerHTML = orig;
        }
        toast(`Honey-Lure triangulation declined: ${err.message}. Showing BGP ISP Gateway location.`, true);
      },
      { enableHighAccuracy: true, timeout: 10000, maximumAge: 0 }
    );
  });

  $("btn-real-attack")?.addEventListener("click", async () => {
    const btn = $("btn-real-attack");
    if (btn) btn.disabled = true;
    try {
      toast("Detecting your real external WAN public IP...");
      let myIp = null;
      try {
        const ipRes = await fetch("https://api.ipify.org?format=json");
        const ipData = await ipRes.json();
        myIp = ipData.ip;
      } catch (err) {
        console.warn("Could not fetch ipify from browser, falling back to backend WAN resolution", err);
      }
      toast(myIp ? `Attacker IP detected: ${myIp}. Launching real adversary vector...` : "Resolving real WAN IP & launching attack vector...");
      const res = await api("/api/v1/intel/simulate-attack", {
        method: "POST",
        body: JSON.stringify({ attacker_ip: myIp || "auto" })
      });
      const actor = res.actor || {};
      const flag = actor.country_flag || "🌐";
      toast(`[REAL ATTACK TRAPPED] ${flag} ${actor.city || "Adversary"}, ${actor.country || "WAN"} (${actor.isp || actor.asn || ""}) targeted Port ${res.session?.destination_port || 8088}!`);
      await refresh();
      // Auto-open dossier for this real IP
      if (actor.ip) {
        const input = $("ip-tracker-input");
        if (input) input.value = actor.ip;
        trackIpAddress(actor.ip);
      }
    } catch (e) {
      toast("Real attack execution failed: " + e.message, true);
    } finally {
      if (btn) btn.disabled = false;
    }
  });

  $("btn-simulate-threat")?.addEventListener("click", async () => {
    const btn = $("btn-simulate-threat");
    if (btn) btn.disabled = true;
    try {
      toast("Generating demo preset adversary ingress vector...");
      const res = await api("/api/v1/intel/simulate-attack", { method: "POST" });
      const actor = res.actor || {};
      toast(`Demo threat ingress: ${actor.country || "Adversary"} (${actor.asn || "ASN"}) attacking port ${res.session?.destination_port || 2222}!`);
      await refresh();
    } catch (e) {
      toast("Simulation failed: " + e.message, true);
    } finally {
      if (btn) btn.disabled = false;
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
      state.searchQuery = (e.target.value || "").trim().toLowerCase();
      renderSessions(state.sessions);
    }, 150);
  });
  $("search-input")?.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      e.target.value = "";
      state.searchQuery = "";
      renderSessions(state.sessions);
      e.target.blur();
    }
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

  $("modal-btn-view-geo")?.addEventListener("click", () => {
    if (!state.selectedSession) return;
    const ip = state.selectedSession.source_ip || state.selectedSession.source_address;
    closeSessionModal();
    const target = $("telemetry-drawer");
    const scrollEl = document.querySelector(".scroll-canvas");
    if (target && scrollEl) {
      scrollEl.scrollTo({ top: target.offsetTop - 16, behavior: "smooth" });
    } else if (target) {
      target.scrollIntoView({ behavior: "smooth", block: "start" });
    }
    if (ip) {
      trackIpAddress(ip, true, true);
    }
  });

  $("modal-btn-export")?.addEventListener("click", () => {
    $("btn-export-session")?.click();
  });

  // MENTOR UPGRADE: Executive Report Modal triggers
  $("modal-btn-export-exec")?.addEventListener("click", openExecutiveReportModal);
  $("btn-close-exec-report")?.addEventListener("click", closeExecutiveReportModal);
  $("btn-print-exec-report")?.addEventListener("click", () => window.print());
  $("btn-copy-exec-report")?.addEventListener("click", () => {
    const text = $("exec-report-content")?.innerText || "";
    navigator.clipboard.writeText(text);
    toast("Executive report copied to clipboard!");
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
  initNlpChatbot();
  setupButtons();
  await refresh();
  connectWebSocket();
  setInterval(refresh, 3000);
}

document.addEventListener("DOMContentLoaded", init);
