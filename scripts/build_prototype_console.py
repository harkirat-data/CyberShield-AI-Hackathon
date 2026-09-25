import re
from pathlib import Path

console_path = Path("dashboard/console.html")
prototype_path = Path("dashboard/prototype_console.html")

content = console_path.read_text(encoding="utf-8")

# 1. Update title and brand
content = content.replace(
    "<title>VALENS — Security Operations. Deception. Intelligence</title>",
    "<title>VALENS — Prototype Deception Grid</title>"
)
content = content.replace(
    '<span class="topbar-brand-badge">Security Operations. Deception. Intelligence</span>',
    '<span class="topbar-brand-badge">Prototype Deception Grid</span>'
)

# 2. Filter Nav Links in sidebar (Keep ONLY: overview, decoy-grid, session-panel, telemetry-drawer, canary-panel, alerts-panel)
nav_pattern = r'(<nav class="nav-links">)(.*?)(</nav>)'
def clean_nav(match):
    nav_inner = match.group(2)
    items = re.findall(r'<a href="#[^"]+" class="nav-item[^"]*" data-section="[^"]+">.*?</a>', nav_inner, re.DOTALL)
    filtered = []
    allowed = ["overview", "decoy-grid", "session-panel", "telemetry-drawer", "canary-panel", "alerts-panel"]
    for item in items:
        m = re.search(r'data-section="([^"]+)"', item)
        if m and m.group(1) in allowed:
            filtered.append(item)
    return match.group(1) + "\n      " + "\n      ".join(filtered) + "\n    " + match.group(3)

content = re.sub(nav_pattern, clean_nav, content, flags=re.DOTALL)

# 3. Remove unwanted sections: terminal-stream, copilot-panel, protected-apps-section
content = re.sub(
    r'<!-- ===== SECTION: TERMINAL ===== -->.*?<!-- ===== SECTION: GEOLOCATION & THREAT INTEL ===== -->',
    '<!-- ===== SECTION: GEOLOCATION & THREAT INTEL ===== -->',
    content,
    flags=re.DOTALL
)
content = re.sub(
    r'<!-- ===== SECTION: PROTECTED APPLICATIONS FLEET ===== -->.*?</section>',
    '<!-- SECTION: Protected Fleet omitted in prototype -->',
    content,
    flags=re.DOTALL
)

# 4. Remove WAF modals at the end
content = re.sub(
    r'<!-- REGISTER WEB ASSET MODAL -->.*?<!-- PLAIN-ENGLISH SESSION DETAIL POPUP MODAL -->',
    '<!-- PLAIN-ENGLISH SESSION DETAIL POPUP MODAL -->',
    content,
    flags=re.DOTALL
)
content = re.sub(
    r'<!-- WAF CONFIGURATION MODAL -->.*?<!-- SCRIPT LOADER -->',
    '<!-- SCRIPT LOADER -->',
    content,
    flags=re.DOTALL
)

prototype_path.write_text(content, encoding="utf-8")
print(f"Created {prototype_path}")
