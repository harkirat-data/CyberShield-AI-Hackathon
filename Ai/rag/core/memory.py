from __future__ import annotations

import json
import time
from typing import Any, Dict, List, Optional

try:
    import redis
except ImportError:  # pragma: no cover - optional dependency may be missing
    redis = None  # type: ignore[assignment]

try:
    from .config import REDIS_URL, RAG_MEMORY_PREFIX, RAG_MEMORY_WINDOW
except ImportError:  # pragma: no cover - fallback for direct script execution
    from config import REDIS_URL, RAG_MEMORY_PREFIX, RAG_MEMORY_WINDOW


class RedisMemory:
    def __init__(
        self,
        redis_url: str = REDIS_URL,
        prefix: str = RAG_MEMORY_PREFIX,
        window: int = RAG_MEMORY_WINDOW,
    ):
        self.redis_url = redis_url
        self.prefix = prefix
        self.window = window
        self.client = None
        self.backend = "redis"
        self._fallback_store: Dict[str, List[Dict[str, Any]]] = {}

        if redis is None:
            self.backend = "in_memory"
            print("[memory] redis package unavailable; using in-memory fallback")
            return

        try:
            self.client = redis.Redis.from_url(redis_url, decode_responses=True)
            self.client.ping()
            print(f"[memory] connected to redis at {redis_url}")
        except Exception as exc:
            self.client = None
            self.backend = "in_memory"
            print(f"[memory] redis unavailable ({exc}); using in-memory fallback")

    def _key(self, session_id: str) -> str:
        return f"{self.prefix}:{session_id}"

    def add_message(
        self,
        session_id: str,
        role: str,
        content: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        message = {
            "role": role,
            "content": content,
            "metadata": metadata or {},
            "timestamp": int(time.time()),
        }
        if self.client is not None:
            self.client.rpush(self._key(session_id), json.dumps(message))
        else:
            self._fallback_store.setdefault(session_id, []).append(message)
        return message

    def get_history(self, session_id: str, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        max_items = limit or self.window
        if self.client is not None:
            raw_items = self.client.lrange(self._key(session_id), -max_items, -1)
            return [json.loads(item) for item in raw_items]
        return self._fallback_store.get(session_id, [])[-max_items:]

    def clear(self, session_id: str) -> None:
        if self.client is not None:
            self.client.delete(self._key(session_id))
        else:
            self._fallback_store.pop(session_id, None)

    def stats(self, session_id: str) -> Dict[str, Any]:
        if self.client is not None:
            count = self.client.llen(self._key(session_id))
        else:
            count = len(self._fallback_store.get(session_id, []))
        return {
            "backend": self.backend,
            "session_id": session_id,
            "messages": int(count),
            "window": self.window,
        }
