# Canary Tokens in CyberShield AI

CyberShield AI includes a modular Canary Token system designed to detect attackers who attempt to access fake credentials, URLs, or documents placed as bait.

## Architecture

1. **Manager (`canary/manager.py`)**: Handles the business logic for token creation, type generation (`url`, `credential`, `document`), and tracking triggers.
2. **Persistence (`honeypot/store.py`)**: Stores token metadata, configuration, and trigger states in the SQLite `canary_tokens` table.
3. **API & Triggers (`Ai/backend/api_server.py`)**: Provides endpoints for lifecycle management (`/api/v1/canary/tokens`) and fast-path triggers (`/t/{secret}`).
4. **SOC Integration**: A triggered canary automatically generates a high-severity `CANARY_TOKEN_TRIGGERED` event. This event bypasses standard ingestion delays and feeds directly into the AI Orchestrator (`Ai/orchestrator.py`) to map against MITRE ATT&CK, apply risk scores, and generate a SOC report.

## Token Types

- **URL Token**: Generates a fast web hook, e.g. `http://host/t/<secret>`. An attacker accessing the URL immediately triggers a critical alert.
- **Credential Token**: Generates a fake username or API key (e.g. `AKIA...`). Unlike URLs, credentials require out-of-band monitoring or API submission. CyberShield AI provides a `/api/v1/canary/test` endpoint to simulate their discovery and usage.
- **Document Token**: Similar to a credential token, this generates a unique embedded identifier (`doc_...`) that can be hidden within files.

## API Usage

### Create a Token
```bash
curl -X POST http://127.0.0.1:8000/api/v1/canary/tokens \
  -H "Content-Type: application/json" \
  -d '{"name": "Admin Panel Lure", "token_type": "url", "metadata": {"location": "wiki"}}'
```

### Trigger a URL Token
```bash
curl http://127.0.0.1:8000/t/<secret_from_creation>
```
*Note: This returns a 200 OK to the attacker, but alerts the SOC pipeline.*

### Simulate a Credential or Document Token
If an external system or operator spots the usage of a fake credential or document, they can submit it via the test/simulation endpoint:
```bash
curl -X POST http://127.0.0.1:8000/api/v1/canary/test \
  -H "Content-Type: application/json" \
  -d '{"secret": "AKIA..."}'
```

### List Tokens
```bash
curl http://127.0.0.1:8000/api/v1/canary/tokens
```
