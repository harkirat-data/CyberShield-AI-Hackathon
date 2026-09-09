"""
llm.py - Gemini API wrapper with structured JSON output and error handling.
The implementation gracefully supports both the modern google-genai SDK and a
REST fallback when the SDK is unavailable.
"""
import importlib
import json
import time
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional


class APIError(Exception):
    """Raised when the Gemini API returns an error."""


try:
    google_genai_module = importlib.import_module("google.genai")
    google_types_module = importlib.import_module("google.genai.types")
except Exception:
    google_genai_module = None
    google_types_module = None

try:
    from .config import (
        GEMINI_API_KEY, GEMINI_MODEL, GEMINI_MAX_TOKENS, GEMINI_TEMPERATURE
    )
except ImportError:
    from config import (
        GEMINI_API_KEY, GEMINI_MODEL, GEMINI_MAX_TOKENS, GEMINI_TEMPERATURE
    )


class GeminiClient:
    def __init__(self):
        if not GEMINI_API_KEY:
            raise ValueError("GEMINI_API_KEY not set in config")

        self.model_name = GEMINI_MODEL
        self.last_error: Optional[str] = None
        self.config: Dict[str, Any] = {
            "max_output_tokens": GEMINI_MAX_TOKENS,
            "temperature": GEMINI_TEMPERATURE,
            "response_mime_type": "application/json",
        }

        self.client = None
        self.backend = "rest"

        if google_genai_module is not None and hasattr(google_genai_module, "Client"):
            try:
                self.client = google_genai_module.Client(api_key=GEMINI_API_KEY)
                self.backend = "google_genai"
            except Exception as exc:
                print(f"[llm] google-genai SDK unavailable, falling back to REST: {exc}")
        elif google_genai_module is not None and hasattr(google_genai_module, "configure"):
            try:
                google_genai_module.configure(api_key=GEMINI_API_KEY)
                self.client = google_genai_module
                self.backend = "google_generativeai"
            except Exception as exc:
                print(f"[llm] google-generativeai SDK unavailable, falling back to REST: {exc}")

        print(f"[llm] Gemini client ready: {self.model_name} ({self.backend})")

    def generate(self, system: str, user: str, max_retries: int = 3) -> Optional[Dict]:
        """
        Generate structured JSON response.
        Returns parsed dict, or None on failure.
        """
        text = self.complete(
            system=system,
            user=user,
            max_retries=max_retries,
            response_mime_type="application/json",
        )
        if not text:
            return None
        return self._parse_json_response(text)

    def complete(
        self,
        system: str,
        user: str,
        max_retries: int = 3,
        response_mime_type: str = "text/plain",
    ) -> Optional[str]:
        self.last_error = None
        current_config = self._build_config(system, response_mime_type=response_mime_type)

        for attempt in range(max_retries):
            try:
                if self.backend in {"google_genai", "google_generativeai"}:
                    response = self._generate_with_sdk(user, current_config)
                    text = self._extract_text(response)
                else:
                    text = self._generate_with_rest(user, current_config)

                if not text:
                    raise ValueError("Received empty response text from Gemini API")

                self.last_error = None
                return text

            except APIError as ae:
                self.last_error = self._safe_error(ae)
                print(f"[llm] Gemini API Error (attempt {attempt + 1}): {self.last_error}")
                if attempt < max_retries - 1:
                    self._sleep_backoff(attempt)
            except Exception as e:
                self.last_error = self._safe_error(e)
                print(f"[llm] generation failed (attempt {attempt + 1}): {self.last_error}")
                if attempt < max_retries - 1:
                    self._sleep_backoff(attempt)

        return None

    @staticmethod
    def _safe_error(exc: Exception) -> str:
        """Return a dashboard-safe error without ever echoing the API key."""

        message = str(exc).strip() or exc.__class__.__name__
        if GEMINI_API_KEY:
            message = message.replace(GEMINI_API_KEY, "[REDACTED_API_KEY]")
        return message[:500]

    def _build_config(self, system: str, response_mime_type: str) -> Dict[str, Any]:
        config = self.config.copy()
        config["system_instruction"] = system
        config["response_mime_type"] = response_mime_type
        return config

    def _generate_with_sdk(self, user: str, config: Dict[str, Any]) -> Any:
        if self.client is None:
            raise RuntimeError("Gemini SDK client is not available")

        if hasattr(self.client, "models") and google_types_module is not None:
            sdk_config = None
            if hasattr(google_types_module, "GenerateContentConfig"):
                sdk_config = google_types_module.GenerateContentConfig(
                    max_output_tokens=config.get("max_output_tokens"),
                    temperature=config.get("temperature"),
                    response_mime_type=config.get("response_mime_type"),
                    system_instruction=config.get("system_instruction"),
                )
            return self.client.models.generate_content(
                model=self.model_name,
                contents=user,
                config=sdk_config or config,
            )

        if hasattr(self.client, "generate_text"):
            return self.client.generate_text(
                model=self.model_name,
                prompt=user,
                **config,
            )

        raise RuntimeError("Unsupported Gemini SDK client")

    def _generate_with_rest(self, user: str, config: Dict[str, Any]) -> str:
        endpoint = (
            f"https://generativelanguage.googleapis.com/v1beta/models/"
            f"{self.model_name}:generateContent?key={GEMINI_API_KEY}"
        )
        payload: Dict[str, Any] = {
            "contents": [{"role": "user", "parts": [{"text": user}]}],
            "generationConfig": {
                "maxOutputTokens": config.get("max_output_tokens"),
                "temperature": config.get("temperature"),
                "responseMimeType": config.get("response_mime_type"),
            },
        }
        if config.get("system_instruction"):
            payload["systemInstruction"] = {
                "parts": [{"text": config["system_instruction"]}]
            }

        request = urllib.request.Request(
            endpoint,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                body = response.read().decode("utf-8")
        except urllib.error.URLError as exc:
            raise APIError(f"REST request failed: {exc}") from exc

        data = json.loads(body)
        if data.get("error"):
            raise APIError(data["error"].get("message", "Gemini REST API error"))

        candidates = data.get("candidates", [])
        if not candidates:
            raise APIError("Gemini returned no candidates")

        parts = candidates[0].get("content", {}).get("parts", [])
        return "".join(part.get("text", "") for part in parts if isinstance(part, dict))

    def _extract_text(self, response: Any) -> str:
        if response is None:
            return ""
        if hasattr(response, "text"):
            text = getattr(response, "text")
            if text:
                return str(text)
        if hasattr(response, "result"):
            text = getattr(response, "result")
            if text:
                return str(text)
        return ""

    def _parse_json_response(self, text: str) -> Dict[str, Any]:
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            start = text.find("{")
            end = text.rfind("}")
            if start != -1 and end > start:
                return json.loads(text[start : end + 1])
            raise ValueError("Response was not valid JSON")

    def _sleep_backoff(self, attempt: int):
        wait = 2 ** attempt
        print(f"[llm] retrying in {wait}s...")
        time.sleep(wait)


SOC_ANALYST_SYSTEM = """You are a senior SOC analyst with 15 years of experience in incident response and threat detection. You work for a Security Operations Center that uses the MITRE ATT&CK and SIEM framework.

Your job: investigate security events and produce structured incident analyses.

Guidelines:
- Be precise and evidence-based. Cite specific indicators from the event data.
- Map findings to MITRE ATT&CK technique IDs when applicable (e.g., T1110, T1078, T1059).
- Assess severity carefully. Critical = active compromise or imminent damage. High = strong indicators of attack. Medium = suspicious but inconclusive. Low = likely benign.
- Provide actionable remediation steps. Each step must be specific and executable.
- When the event data is ambiguous, say so explicitly. Do not fabricate findings.
- Output MUST be valid JSON matching the schema provided in the user prompt.
- Keep total response under 1500 words to fit context window.

You have access to a knowledge base of MITRE ATT&CK techniques, Sigma detection rules, Wazuh rules, and remediation playbooks. Use the provided reference material to ground your analysis. Try to keep to the facts and avoid speculation. """


def build_soc_prompt(event: Dict, context: Dict, rag_chunks: List[Dict]) -> str:
    """
    Build the user prompt for SOC analysis.

    event: the triggering event
    context: correlated events, threat intel results
    rag_chunks: retrieved knowledge base chunks
    """
    refs_text = ""
    for i, chunk in enumerate(rag_chunks, 1):
        meta = chunk.get("metadata", {})
        source = meta.get("source", "unknown")
        title = meta.get("technique_id") or meta.get("rule_id") or meta.get("file", f"ref-{i}")
        refs_text += f"\n[Reference {i}: {source}/{title}]\n{chunk.get('text', '')}\n"

    corr_text = ""
    for ev in context.get("correlated_events", [])[:10]:
        corr_text += f"- {ev.get('timestamp', '?')}: {ev.get('event_type', '?')} from {ev.get('actor', {}).get('source_ip', '?')} user={ev.get('actor', {}).get('user', '?')}\n"

    threat_intel = context.get("threat_intel", {})

    return f"""Investigate the following security event and produce a structured analysis.

# TRIGGERING EVENT
```json
{json.dumps(event, indent=2)}
```

# CORRELATED EVENTS
{corr_text if corr_text else "None detected"}

# THREAT INTEL CONTEXT
{json.dumps(threat_intel, indent=2)}

# RETRIEVED REFERENCE MATERIAL
{refs_text if refs_text else "No specific references found"}
"""
