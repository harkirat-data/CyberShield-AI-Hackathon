# Telemetry Reference

ARGUS stores three logical record types in SQLite.

## Sessions

A session contains its ID, source/destination tuple, service, protocol, persona,
status, timestamps, byte totals, attacker-action count, fingerprint, username,
highest risk, dominant intent, confidence, and containment state.

One attacker action is one inbound request, command, login attempt, database
query, or client hello. Outbound banners/replies and system annotations remain
events but do not increment this counter.

## Events

Each event contains:

| Field | Meaning |
|---|---|
| `event_id` | Stable event identifier |
| `session_id` | Owning session |
| `timestamp` | Timezone-aware event time |
| `event_type` | Normalized activity class |
| `severity` | `info`, `low`, `medium`, `high`, or `critical` |
| `direction` | `inbound`, `outbound`, or `system` |
| `content` | Redacted, size-limited preview |
| `byte_count` | Associated byte count |
| `latency_ms` | Total response latency where applicable |
| `sha256` | Hash of the captured event content |
| `metadata` | Protocol, intent, provider, delay, and safety facts |

Important types include `HONEYPOT_SESSION_STARTED`, `PORT_SCAN`,
`DECOY_AUTH_ATTEMPT`, `HTTP_REQUEST`, `SYSTEM_DISCOVERY`,
`CREDENTIAL_DISCOVERY`, `DATABASE_DISCOVERY`, `PAYLOAD_TRANSFER`,
`PERSISTENCE_ATTEMPT`, `PRIVILEGE_ESCALATION`, and outbound decoy responses.

## Investigations

Meaningful inbound events receive deterministic SOC enrichment. An investigation
contains risk score/level, intent/confidence, MITRE technique IDs, rationale, and
the original agent outputs used to reach the verdict.

## Analyst reports

The latest on-demand Gemini + RAG report is stored per session. It includes the
executive summary, evidence-based findings, MITRE mappings, response actions,
retrieved reference snippets, provider state, and generation timestamp. The
report never changes the deterministic session risk score.

## Evidence integrity

Content hashes help detect accidental modification but are not a signed chain of
custody. Exported JSON should be transferred to an external evidence system if
formal integrity, immutability, or retention guarantees are required.

