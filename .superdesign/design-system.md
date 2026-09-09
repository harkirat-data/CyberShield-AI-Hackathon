# ARGUS Deception Grid — Design System

## Product

ARGUS is a defensive SOC workstation that combines host log investigation with a Gemini-powered, five-service deception grid. The primary user is a SOC analyst monitoring active intrusions. Their job is to notice a new session, understand attacker intent, inspect the evidence, and isolate or export the incident without losing the live thread.

The primary screen is a desktop command center with four zones: a slim global navigation rail, a high-signal posture header, a live attacker-session workspace, and a persistent intelligence/response sidebar. Honeypot data must be visibly labeled `DECOY` so simulated host responses can never be mistaken for real infrastructure state.

## Visual language

- Theme: dark graphite operations console; calm and precise, not neon sci-fi.
- Base canvas: `#080B0F`; raised surfaces: `#0D1218`, `#111821`; borders: `#202A35`.
- Primary text: `#E8EDF2`; secondary: `#8B98A7`; muted: `#5E6B79`.
- Operational cyan: `#37C8D5`; healthy green: `#45D483`; warning amber: `#F2B84B`; critical coral: `#FF625F`; deception violet: `#9A7BFF`.
- Never use gradients. Color is functional and sparse. Critical red is reserved for confirmed/high-risk activity.
- Typography: Inter for interface text; IBM Plex Mono for ports, IPs, commands, timestamps, session IDs, and telemetry.
- Type scale: 11 metadata, 12 table/supporting text, 14 body/control, 18 section title, 26 posture metric.
- Corners: 6px controls, 8px panels. Borders are 1px. Shadows are minimal; hierarchy comes from contrast and spacing.
- Spacing: 4px base unit; common gaps 8, 12, 16, 24.

## Components

- Status badge: compact uppercase mono label with a colored dot; variants live, investigating, contained, offline, decoy.
- Metric tile: label, primary value, short delta/context. No decorative charts when a number is clearer.
- Session table: dense 44px rows, sticky header, risk stripe, protocol icon, source IP, service, duration, command count, intent, status.
- Terminal transcript: black inset surface, mono text, explicit `ATTACKER` and `DECOY AI` markers, timestamps, token/latency metadata. Never render commands as executable controls.
- Timeline: ordered telemetry events with time, category, summary, and expandable raw payload.
- Port card: exactly five service cards (SSH 2222, Telnet 2323, HTTP 8088, HTTPS 8443, MySQL 33060), with health, active sessions, last contact, and capture counters.
- Buttons: primary cyan fill for a single main action; secondary dark with border; destructive coral outline. No pill-shaped primary buttons.
- Charts: thin strokes, low-saturation fills, direct labels, accessible legends. Avoid radial gauges.

## Layout

- Desktop-first at 1440×1000, responsive down to 1024px.
- Left navigation rail: 72px with ARGUS wordmark and icon labels.
- Main region: 12-column grid. Active session/transcript occupies 7–8 columns; intelligence rail occupies 4–5.
- Header presents `DECEPTION GRID ONLINE`, environment selector, UTC clock, Gemini state, and analyst avatar.
- Top metrics: active sessions, interactions captured, unique sources, and mean dwell time.
- Preserve readable density: 16px outer padding, 12px panel gaps, maximum two nested border levels.

## Motion and interaction

- 120–180ms ease-out for hover, selection, and expanding telemetry.
- New telemetry rows briefly tint cyan then settle; critical detections tint coral.
- Live indicators pulse subtly at 2.4s; no constant sweeping/scanning animations.
- Support keyboard navigation, visible focus rings, semantic table structure, and WCAG AA contrast.

## Content rules

- Use realistic defensive sample data with documentation IP ranges such as `198.51.100.42` and `203.0.113.17`.
- Never imply that an attacker can reach the real host. Use copy such as `sandboxed decoy`, `simulated filesystem`, and `egress blocked`.
- Surface uncertainty: intent classifications and AI summaries show confidence.
- Immediate response controls are `Contain session`, `Block source`, `Add IOC`, and `Export evidence`; they require confirmation in the real product.
