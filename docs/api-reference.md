# API Reference

The default API base URL is `http://127.0.0.1:8000`.

## Runtime status

```http
GET /api/v1/honeypot/status
```

Returns listener state, bind address, active-session counts, runtime block count,
and Gemini configuration/health. `healthy` is `null` until the first model call,
then `true` for Gemini or `false` when fallback was required.

## Lifecycle

```http
POST /api/v1/honeypot/control/start
POST /api/v1/honeypot/control/stop
```

Both operations are idempotent and return the updated runtime status.

## Metrics

```http
GET /api/v1/honeypot/metrics
```

Returns active sessions, inbound attacker actions, total telemetry events, unique
sources, average dwell time, critical session count, total sessions, and service
distribution. Outbound decoy replies do not increment attacker actions.

## Sessions and events

```http
GET /api/v1/honeypot/sessions?limit=100&status=active
GET /api/v1/honeypot/sessions/{session_id}
GET /api/v1/honeypot/events?limit=200&session_id={session_id}
```

Detail responses include the session record, ordered transcript, latest SOC
analysis, saved analyst report, content hashes, latency, and protocol/provider
metadata.

## Gemini + RAG session analysis

```http
POST /api/v1/honeypot/sessions/{session_id}/analyze
```

Runs the existing ARGUS RAG pipeline against captured inbound evidence without
blocking the live decoy response. The result includes summary, severity,
findings, MITRE techniques, remediation, model/RAG state, and retrieved source
snippets. It is persisted and returned by later session-detail and export calls.
If Gemini or retrieval is unavailable, ARGUS saves an `evidence-only` report.

## Containment

```http
POST /api/v1/honeypot/sessions/{session_id}/contain
POST /api/v1/honeypot/block-source
Content-Type: application/json

{"source_ip":"192.0.2.10"}
```

Containment closes the selected live connection. Blocking is process-local and
does not alter Windows Firewall or nftables.

## Evidence export

```http
GET /api/v1/honeypot/sessions/{session_id}/export
```

Returns a downloadable JSON bundle containing the session, transcript, hashes,
metadata, and investigations.

## Existing ARGUS endpoints

```http
GET  /health
POST /api/v1/logs
POST /api/v1/logs/batch
POST /api/v1/rag/query
```

Interactive OpenAPI documentation is available at `/docs` while FastAPI is running.

