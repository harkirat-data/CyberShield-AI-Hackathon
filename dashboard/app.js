"use strict";

const state = {
  selectedSessionId: null,
  selectedSession: null,
  selectedEvents: [],
  status: null,
  filter: "all",
  refreshing: false,
  analyzing: false,
  errorShown: false,
  lastGeminiError: null,
};

const $ = (id) => document.getElementById(id);

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
    ...options,
  });
  if (!response.ok) {
    let message = `${response.status} ${response.statusText}`;
    try {
      const body = await response.json();
      message = body.detail || message;
    } catch (_) {}
    throw new Error(message);
  }
  return response.json();
}

function showToast(message, error = false) {
  const toast = $("toast");
  toast.textContent = message;
  toast.classList.toggle("error", error);
  toast.classList.add("visible");
  clearTimeout(showToast.timer);
  showToast.timer = setTimeout(() => toast.classList.remove("visible"), 3200);
}

function formatNumber(value) {
  return new Intl.NumberFormat().format(Number(value || 0));
}

function formatBytes(value) {
  const bytes = Number(value || 0);
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 ** 2) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 ** 2).toFixed(1)} MB`;
}

function formatDuration(seconds) {
  const total = Math.max(0, Math.round(Number(seconds || 0)));
  const hours = Math.floor(total / 3600);
  const minutes = Math.floor((total % 3600) / 60);
  const secs = total % 60;
  if (hours) return `${hours}h ${minutes}m`;
  if (minutes) return `${minutes}m ${secs}s`;
  return `${secs}s`;
}

function sessionDuration(session) {
  if (!session?.started_at) return 0;
  const start = new Date(session.started_at).getTime();
  const end = session.ended_at ? new Date(session.ended_at).getTime() : Date.now();
  return Math.max(0, (end - start) / 1000);
}

function timeOnly(value) {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "—" : date.toISOString().slice(11, 19);
}

function shortId(value) {
  return value ? value.replace(/^ses_/, "").slice(0, 8).toUpperCase() : "—";
}

function riskColor(level) {
  return { critical: "var(--coral)", high: "var(--amber)", medium: "var(--cyan)", low: "var(--green)", info: "var(--muted)" }[String(level || "info").toLowerCase()] || "var(--muted)";
}

function serviceClass(name) {
  const key = String(name || "").toLowerCase();
  if (key.includes("ssh")) return "cyan";
  if (key.includes("http")) return "green";
  if (key.includes("telnet")) return "amber";
  if (key.includes("mysql")) return "violet";
  return "";
}

function renderStatus(status) {
  state.status = status;
  const listening = status.services.filter((service) => service.status === "listening").length;
  const failed = status.services.filter((service) => service.status === "failed").length;
  const isOnline = status.running && listening === status.services.length;
  $("grid-heading").textContent = isOnline ? "DECEPTION GRID ONLINE" : status.running ? "DECEPTION GRID DEGRADED" : "DECEPTION GRID OFFLINE";
  $("live-dot").className = `live-dot ${isOnline ? "online" : status.running ? "degraded" : ""}`;
  $("safety-message").textContent = status.running
    ? `All listeners sandboxed · ${status.bind_host} · input execution disabled`
    : "Sandboxed simulation · real host isolated · no input execution";
  $("runtime-control").textContent = status.running ? "Stop grid" : "Start grid";
  $("ports-summary").textContent = `${listening} / ${status.services.length} LISTENING${failed ? ` · ${failed} FAILED` : ""}`;
  const gemini = status.gemini || {};
  const geminiHealthy = gemini.configured && gemini.healthy !== false;
  $("gemini-status").textContent = !gemini.configured
    ? "No key"
    : gemini.healthy === false
      ? "Fallback"
      : gemini.healthy === true
        ? "Live"
        : "Ready";
  $("gemini-status").style.color = geminiHealthy ? "var(--green)" : "var(--amber)";
  $("gemini-status").title = gemini.last_error || `${gemini.backend || "Gemini"} has not handled a request yet`;
  if (gemini.healthy === false && gemini.last_error && state.lastGeminiError !== gemini.last_error) {
    state.lastGeminiError = gemini.last_error;
    showToast(`Gemini fallback: ${gemini.last_error}`, true);
  }

  $("port-grid").innerHTML = status.services.map((service) => {
    const engaged = Number(service.active_sessions || 0) > 0;
    const failedService = service.status === "failed";
    const stateClass = failedService ? "failed" : engaged ? "engaged" : "";
    const dotClass = failedService ? "coral-bg" : engaged ? "amber-bg" : service.status === "listening" ? "green-bg" : "";
    const stateText = failedService ? "failed" : engaged ? `${service.active_sessions} active` : service.status;
    const load = failedService ? 100 : Math.min(100, 18 + Number(service.active_sessions || 0) * 22);
    return `<article class="port-card ${stateClass}">
      <div class="port-name"><span>${escapeHtml(service.name)} :${escapeHtml(service.port)}</span><i class="dot ${dotClass}"></i></div>
      <div class="port-meta"><span title="${escapeHtml(service.product)}">${escapeHtml(service.product)}</span><span>${escapeHtml(stateText)}</span></div>
      <div class="port-meter"><i style="width:${load}%"></i></div>
    </article>`;
  }).join("");
}

function renderMetrics(metrics) {
  $("metric-active").textContent = String(metrics.active_sessions || 0).padStart(2, "0");
  $("metric-events").textContent = formatNumber(metrics.interactions_captured);
  $("metric-sources").textContent = formatNumber(metrics.unique_sources);
  $("metric-dwell").textContent = formatDuration(metrics.mean_dwell_seconds);
  $("metric-active-context").textContent = metrics.active_sessions ? "Sessions currently engaged" : "No active contacts";
  $("metric-event-context").textContent = `${formatNumber(metrics.telemetry_events)} telemetry events retained`;
  $("metric-critical").textContent = `${metrics.critical_sessions || 0} critical sessions`;
  renderDistribution(metrics.service_distribution || {});
}

function renderDistribution(distribution) {
  const ssh = Number(distribution.SSH || 0);
  const https = Number(distribution.HTTP || 0) + Number(distribution.HTTPS || 0);
  const other = Number(distribution.Telnet || 0) + Number(distribution.MySQL || 0);
  const total = Math.max(1, ssh + https + other);
  const values = [Math.round(ssh * 100 / total), Math.round(https * 100 / total), Math.round(other * 100 / total)];
  const cards = $("service-distribution").querySelectorAll("strong");
  values.forEach((value, index) => { cards[index].textContent = `${value}%`; });

  const ordered = ["SSH", "HTTP", "HTTPS", "Telnet", "MySQL"];
  const max = Math.max(1, ...ordered.map((key) => Number(distribution[key] || 0)));
  $("service-bars").innerHTML = ordered.map((key) => {
    const value = Number(distribution[key] || 0);
    const height = Math.max(4, Math.round(value * 100 / max));
    return `<div class="service-bar" style="height:${height}%" title="${key}: ${value} sessions"><span>${value}</span></div>`;
  }).join("");
}

function renderSessions(sessions) {
  const visible = state.filter === "active" ? sessions.filter((session) => session.status === "active") : sessions;
  $("sessions-empty").classList.toggle("visible", visible.length === 0);
  const active = sessions.filter((session) => session.status === "active").length;
  $("live-session-badge").textContent = `${active} LIVE`;

  if (state.selectedSessionId && !sessions.some((item) => item.session_id === state.selectedSessionId)) {
    state.selectedSessionId = null;
  }
  if (!state.selectedSessionId && visible.length) state.selectedSessionId = visible[0].session_id;

  $("session-rows").innerHTML = visible.map((session) => {
    const selected = session.session_id === state.selectedSessionId;
    const level = String(session.risk_level || "info").toUpperCase();
    return `<tr class="${selected ? "selected" : ""}" data-session-id="${escapeHtml(session.session_id)}" tabindex="0">
      <td><span class="cell-primary">${escapeHtml(session.source_ip)}</span><span class="cell-secondary">:${escapeHtml(session.source_port)} · ${escapeHtml(shortId(session.session_id))}</span></td>
      <td><span class="${serviceClass(session.service)}">${escapeHtml(session.service)}</span> :${escapeHtml(session.destination_port)}</td>
      <td><span class="cell-primary">${escapeHtml(session.intent || "Reconnaissance")}</span><span class="cell-secondary">${Math.round(Number(session.intent_confidence || 0) * 100)}% confidence</span></td>
      <td>${formatDuration(sessionDuration(session))}</td>
      <td>${escapeHtml(session.interactions || 0)}</td>
      <td><span class="risk-text" style="color:${riskColor(session.risk_level)}">${escapeHtml(level)}</span><span class="cell-secondary">${escapeHtml(session.risk_score || 0)} / 100</span></td>
    </tr>`;
  }).join("");

  $("session-rows").querySelectorAll("tr").forEach((row) => {
    const select = () => selectSession(row.dataset.sessionId);
    row.addEventListener("click", select);
    row.addEventListener("keydown", (event) => { if (event.key === "Enter" || event.key === " ") select(); });
  });
}

async function selectSession(sessionId) {
  state.selectedSessionId = sessionId;
  document.querySelectorAll("#session-rows tr").forEach((row) => row.classList.toggle("selected", row.dataset.sessionId === sessionId));
  await loadSession(sessionId);
}

async function loadSession(sessionId) {
  if (!sessionId) {
    renderSessionDetail(null, []);
    return;
  }
  try {
    const data = await api(`/api/v1/honeypot/sessions/${encodeURIComponent(sessionId)}`);
    if (sessionId !== state.selectedSessionId) return;
    state.selectedSession = data.session;
    state.selectedEvents = data.events || [];
    renderSessionDetail(data.session, data.events || []);
  } catch (error) {
    if (error.message.includes("not found")) state.selectedSessionId = null;
    showToast(`Could not load session: ${error.message}`, true);
  }
}

function renderSessionDetail(session, events) {
  const enabled = Boolean(session);
  ["contain-button", "block-button", "copy-ioc-button", "export-evidence-button", "export-button", "analyze-button"].forEach((id) => { $(id).disabled = !enabled; });
  if (!session) {
    $("transcript-title").textContent = "LIVE TRANSCRIPT";
    $("transcript-route").textContent = "No session selected";
    $("terminal-stream").innerHTML = '<div class="terminal-empty">Select a session to inspect the interaction transcript.</div>';
    $("recording-state").textContent = "IDLE";
    $("recording-state").className = "";
    renderIntelligence(null);
    renderAnalyst(null, null);
    renderTimeline([]);
    return;
  }

  $("transcript-title").textContent = `SESSION ${shortId(session.session_id)} · TRANSCRIPT`;
  $("transcript-route").textContent = `${session.source_ip} → ${session.service} :${session.destination_port}`;
  $("recording-state").textContent = session.status === "active" ? "● RECORDING" : session.status.toUpperCase();
  $("recording-state").className = session.status === "active" ? "live" : "";
  $("terminal-stats").textContent = `${events.length} events · ${formatBytes(Number(session.bytes_in || 0) + Number(session.bytes_out || 0))}`;

  const transcriptEvents = events.filter((event) => ["inbound", "outbound", "system"].includes(event.direction)).slice(-80);
  $("terminal-stream").innerHTML = transcriptEvents.length ? transcriptEvents.map((event) => {
    const role = event.direction === "inbound" ? "ATTACKER" : event.direction === "outbound" ? "DECOY AI" : "ARGUS";
    const latency = event.latency_ms != null ? ` · ${event.latency_ms}ms` : "";
    return `<div class="terminal-entry ${escapeHtml(event.direction)}">
      <div class="entry-meta"><span class="entry-role">${role}</span><span class="entry-time">${escapeHtml(timeOnly(event.timestamp))}${latency}</span></div>
      <div class="entry-content">${escapeHtml(event.content || event.event_type)}</div>
    </div>`;
  }).join("") : '<div class="terminal-empty">The session connected but has not sent data yet.</div>';
  $("terminal-stream").scrollTop = $("terminal-stream").scrollHeight;
  renderIntelligence(session);
  renderAnalyst(session.analyst_report, session);
  renderTimeline(events);
}

function renderIntelligence(session) {
  const analysis = session?.analysis;
  const score = Number(session?.risk_score || 0);
  const level = String(session?.risk_level || "info").toLowerCase();
  const confidence = Number(session?.intent_confidence || 0);
  $("session-short-id").textContent = session ? shortId(session.session_id) : "—";
  $("risk-score").textContent = String(score);
  $("risk-level").textContent = session ? level.toUpperCase() : "NO SIGNAL";
  $("risk-level").style.color = riskColor(level);
  $("intent-label").textContent = session?.intent || "Waiting for telemetry";
  $("intent-confidence").textContent = `${Math.round(confidence * 100)}%`;
  $("confidence-progress").style.width = `${Math.round(confidence * 100)}%`;
  $("risk-ring").style.setProperty("--risk-color", riskColor(level));
  $("risk-ring").style.setProperty("--risk-angle", `${score * 3.6}deg`);

  const techniques = analysis?.mitre || analysis?.investigation?.mitre?.techniques || [];
  $("technique-list").innerHTML = techniques.length
    ? techniques.map((technique) => `<span class="technique">${escapeHtml(technique)}</span>`).join("")
    : '<span class="placeholder-copy">No mapped techniques</span>';
  $("fact-source").textContent = session?.source_ip || "—";
  $("fact-fingerprint").textContent = session?.client_fingerprint || "—";
  $("fact-username").textContent = session?.username || "—";
  $("fact-bytes").textContent = formatBytes(Number(session?.bytes_in || 0) + Number(session?.bytes_out || 0));
  $("fact-interactions").textContent = String(session?.interactions || 0);
  $("fact-first-seen").textContent = timeOnly(session?.started_at);
  $("contain-button").disabled = !session || session.status !== "active";
  $("block-button").disabled = !session?.source_ip;
}

function renderAnalyst(report, session) {
  const button = $("analyze-button");
  const stale = Boolean(report && Number(report.evidence?.attacker_actions ?? 0) !== Number(session?.interactions || 0));
  button.disabled = !session || state.analyzing;
  button.textContent = state.analyzing ? "Analyzing evidence…" : stale ? "Update report" : report ? "Regenerate report" : "Analyze selected session";

  if (!session) {
    $("analyst-status").textContent = "SELECT A SESSION";
    $("analyst-generated").textContent = "No report generated";
    $("analyst-empty").textContent = "Select an attacker session, then generate a grounded SOC report from its captured evidence.";
    $("analyst-empty").hidden = false;
    $("analyst-content").hidden = true;
    return;
  }
  if (!report) {
    $("analyst-status").textContent = state.analyzing ? "ANALYZING" : "READY";
    $("analyst-generated").textContent = `${session.interactions || 0} attacker action(s) available`;
    $("analyst-empty").textContent = state.analyzing
      ? "Gemini and the ARGUS knowledge base are analyzing this session. The live honeypot remains responsive."
      : "Deterministic SOC scoring is already visible above. Generate the deeper Gemini + RAG report when you are ready.";
    $("analyst-empty").hidden = false;
    $("analyst-content").hidden = true;
    return;
  }

  const level = String(report.severity || "info").toLowerCase();
  const findings = Array.isArray(report.findings) ? report.findings : [];
  const techniques = Array.isArray(report.mitre_techniques) ? report.mitre_techniques : [];
  const remediation = report.remediation || {};
  const sources = Array.isArray(report.sources) ? report.sources : [];
  $("analyst-status").textContent = stale ? "REPORT OUTDATED" : report.status === "complete"
    ? (report.rag?.references ? "GROUNDED REPORT" : "GEMINI REPORT")
    : "EVIDENCE ONLY";
  $("analyst-generated").textContent = report.generated_at ? `Generated ${new Date(report.generated_at).toLocaleString()}` : "Report available";
  $("analyst-empty").hidden = true;
  $("analyst-content").hidden = false;
  $("analyst-severity").textContent = `${level.toUpperCase()} PRIORITY`;
  $("analyst-severity").style.color = riskColor(level);
  $("analyst-summary").textContent = report.summary || "No analyst summary returned.";
  $("analyst-techniques").innerHTML = techniques.length
    ? techniques.map((item) => `<span class="technique">${escapeHtml(item)}</span>`).join("")
    : '<span class="placeholder-copy">No additional MITRE techniques</span>';
  $("analyst-findings").innerHTML = findings.length
    ? findings.map((item) => `<li>${escapeHtml(item)}</li>`).join("")
    : "<li>No additional findings were produced.</li>";

  const groups = [["Immediate", remediation.immediate], ["Short term", remediation.short_term], ["Long term", remediation.long_term]];
  $("analyst-remediation").innerHTML = groups.filter(([, items]) => Array.isArray(items) && items.length).map(([label, items]) =>
    `<div class="recommendation-group"><strong>${label}</strong><ul>${items.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul></div>`
  ).join("") || '<span class="placeholder-copy">No response actions returned</span>';

  const rag = report.rag || {};
  const llm = report.llm || {};
  $("analyst-engine").innerHTML = `<span class="engine-chip ${llm.enabled ? "online" : "offline"}">Gemini ${llm.enabled ? escapeHtml(llm.model || "enabled") : "unavailable"}</span><span class="engine-chip ${rag.enabled ? "online" : "offline"}">RAG ${rag.enabled ? `${rag.references || 0} refs` : "unavailable"}</span>${llm.error ? `<span class="engine-error" title="${escapeHtml(llm.error)}">Provider fallback active</span>` : ""}`;
  $("analyst-sources").innerHTML = sources.length ? sources.map((source) =>
    `<div class="source-item"><div><strong>${escapeHtml(source.label)}</strong><span>${escapeHtml(source.source)}</span></div>${source.score == null ? "" : `<em>${escapeHtml(source.score)}</em>`}<p>${escapeHtml(source.snippet || "Reference matched")}</p></div>`
  ).join("") : '<span class="placeholder-copy">No RAG references matched this session.</span>';
}

function renderTimeline(events) {
  const timelineEvents = [...events].reverse().slice(0, 20);
  $("telemetry-count").textContent = `${events.length} EVENTS`;
  $("timeline").innerHTML = timelineEvents.length ? timelineEvents.map((event) => {
    const symbol = event.severity === "critical" ? "!" : event.direction === "inbound" ? "IN" : event.direction === "outbound" ? "OUT" : "SYS";
    return `<div class="timeline-item">
      <span class="timeline-time">${escapeHtml(timeOnly(event.timestamp))}</span>
      <span class="timeline-icon" style="color:${riskColor(event.severity)}">${symbol}</span>
      <div class="timeline-copy"><strong>${escapeHtml(event.event_type.replaceAll("_", " "))}</strong><span title="${escapeHtml(event.content)}">${escapeHtml(event.content || "Metadata recorded")}</span></div>
    </div>`;
  }).join("") : '<div class="lower-empty">Session telemetry will appear here.</div>';
}

async function refresh(showSuccess = false) {
  if (state.refreshing) return;
  state.refreshing = true;
  $("refresh-button").disabled = true;
  try {
    const [status, metrics, sessionData] = await Promise.all([
      api("/api/v1/honeypot/status"),
      api("/api/v1/honeypot/metrics"),
      api("/api/v1/honeypot/sessions?limit=100"),
    ]);
    renderStatus(status);
    renderMetrics(metrics);
    renderSessions(sessionData.sessions || []);
    if (state.selectedSessionId) await loadSession(state.selectedSessionId);
    else renderSessionDetail(null, []);
    if (showSuccess) showToast("Dashboard telemetry refreshed");
    state.errorShown = false;
  } catch (error) {
    if (!state.errorShown) showToast(`ARGUS API unavailable: ${error.message}`, true);
    state.errorShown = true;
  } finally {
    state.refreshing = false;
    $("refresh-button").disabled = false;
  }
}

async function toggleRuntime() {
  const action = state.status?.running ? "stop" : "start";
  $("runtime-control").disabled = true;
  try {
    const status = await api(`/api/v1/honeypot/control/${action}`, { method: "POST" });
    renderStatus(status);
    showToast(action === "start" ? "Five-service deception grid started" : "Deception grid stopped");
    await refresh();
  } catch (error) {
    showToast(`Could not ${action} grid: ${error.message}`, true);
  } finally {
    $("runtime-control").disabled = false;
  }
}

async function analyzeSelected() {
  const session = state.selectedSession;
  if (!session || state.analyzing) return;
  state.analyzing = true;
  renderAnalyst(session.analyst_report, session);
  try {
    const result = await api(`/api/v1/honeypot/sessions/${encodeURIComponent(session.session_id)}/analyze`, { method: "POST" });
    if (state.selectedSession?.session_id === session.session_id) {
      state.selectedSession.analyst_report = result.report;
      renderAnalyst(result.report, state.selectedSession);
    }
    showToast(result.report?.status === "complete" ? "Gemini + RAG analyst report generated" : "Evidence-only analyst report generated");
  } catch (error) {
    showToast(`SOC analysis failed: ${error.message}`, true);
  } finally {
    state.analyzing = false;
    if (state.selectedSession?.session_id === session.session_id) {
      renderAnalyst(state.selectedSession.analyst_report, state.selectedSession);
    }
  }
}

async function containSelected() {
  const session = state.selectedSession;
  if (!session || !confirm(`Contain decoy session ${shortId(session.session_id)}?`)) return;
  try {
    await api(`/api/v1/honeypot/sessions/${encodeURIComponent(session.session_id)}/contain`, { method: "POST" });
    showToast("Session contained and disconnected");
    await refresh();
  } catch (error) { showToast(`Containment failed: ${error.message}`, true); }
}

async function blockSelectedSource() {
  const sourceIp = state.selectedSession?.source_ip;
  if (!sourceIp || !confirm(`Block ${sourceIp} inside the ARGUS runtime?`)) return;
  try {
    const result = await api("/api/v1/honeypot/block-source", { method: "POST", body: JSON.stringify({ source_ip: sourceIp }) });
    showToast(`Runtime-blocked ${sourceIp}; contained ${result.contained_sessions} session(s)`);
    await refresh();
  } catch (error) { showToast(`Block failed: ${error.message}`, true); }
}

async function copyIoc() {
  const sourceIp = state.selectedSession?.source_ip;
  if (!sourceIp) return;
  try {
    await navigator.clipboard.writeText(sourceIp);
    showToast(`Copied IOC ${sourceIp}`);
  } catch (_) { showToast("Clipboard access was unavailable", true); }
}

async function exportEvidence() {
  const sessionId = state.selectedSession?.session_id;
  if (!sessionId) return;
  try {
    const response = await fetch(`/api/v1/honeypot/sessions/${encodeURIComponent(sessionId)}/export`);
    if (!response.ok) throw new Error(`${response.status} ${response.statusText}`);
    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `argus-${sessionId}.json`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
    showToast("Evidence bundle exported");
  } catch (error) { showToast(`Export failed: ${error.message}`, true); }
}

function bindEvents() {
  $("runtime-control").addEventListener("click", toggleRuntime);
  $("refresh-button").addEventListener("click", () => refresh(true));
  $("analyze-button").addEventListener("click", analyzeSelected);
  $("contain-button").addEventListener("click", containSelected);
  $("block-button").addEventListener("click", blockSelectedSource);
  $("copy-ioc-button").addEventListener("click", copyIoc);
  $("export-evidence-button").addEventListener("click", exportEvidence);
  $("export-button").addEventListener("click", exportEvidence);
  $("session-filter").addEventListener("click", () => {
    state.filter = state.filter === "all" ? "active" : "all";
    $("session-filter").textContent = state.filter === "all" ? "All sessions" : "Live only";
    refresh();
  });
  document.querySelectorAll(".nav-button[data-target]").forEach((button) => {
    button.addEventListener("click", () => {
      document.querySelectorAll(".nav-button").forEach((item) => item.classList.remove("active"));
      button.classList.add("active");
      document.getElementById(button.dataset.target)?.scrollIntoView({ behavior: "smooth", block: "start" });
    });
  });
}

function updateClock() {
  $("utc-clock").textContent = `${new Date().toISOString().slice(11, 19)} UTC`;
}

bindEvents();
updateClock();
setInterval(updateClock, 1000);
refresh();
setInterval(() => refresh(false), 3000);
