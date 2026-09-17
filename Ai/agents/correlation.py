"""
correlation.py - Find related events for the same indicator (IP/user/host)

For the hackathon: in-memory ring buffer per host.
Production: query Postgres for recent events.
"""
import time
from collections import defaultdict, deque
from typing import Dict, Deque, List
from schema import Event, CorrelationResult


# In-memory correlation store
# Key: (host, indicator_type, indicator_value)
# Value: deque of (timestamp, event)
_EVENT_STORE: Dict[tuple, Deque] = defaultdict(lambda: deque(maxlen=500))
_TIME_WINDOW = 3600  # 1 hour


def add_event(event: Event) -> None:
    """Index an event for later correlation queries."""
    timestamp = event.timestamp or time.strftime("%Y-%m-%dT%H:%M:%SZ")

    keys = []
    ip = event.actor.get("source_ip")
    user = event.actor.get("user")
    if ip:
        keys.append((event.host, "ip", ip))
    if user:
        keys.append((event.host, "user", user))
    keys.append((event.host, "host", event.host))

    for key in keys:
        _EVENT_STORE[key].append((timestamp, event))


def correlate(event: Event, time_window: int = _TIME_WINDOW) -> CorrelationResult:
    """Find events related to this one by IP, user, or host."""
    result = CorrelationResult(time_window_seconds=time_window)
    related: Dict[str, Event] = {}  # dedupe by event_id
    indicators_matched: Dict[str, int] = defaultdict(int)

    ip = event.actor.get("source_ip")
    user = event.actor.get("user")

    # Look up by IP
    if ip:
        for ts, ev in _EVENT_STORE.get((event.host, "ip", ip), []):
            if ev.event_id != event.event_id and ev.event_id not in related:
                related[ev.event_id] = ev
                indicators_matched["source_ip"] += 1

    # Look up by user
    if user:
        for ts, ev in _EVENT_STORE.get((event.host, "user", user), []):
            if ev.event_id != event.event_id and ev.event_id not in related:
                related[ev.event_id] = ev
                indicators_matched["user"] += 1

    # Look up by host (broader)
    for ts, ev in _EVENT_STORE.get((event.host, "host", event.host), []):
        if ev.event_id != event.event_id and ev.event_id not in related:
            related[ev.event_id] = ev
            indicators_matched["host"] += 1

    result.related_events = list(related.values())
    if indicators_matched:
        # Pick the indicator with most matches
        result.primary_indicator = max(indicators_matched, key=lambda k: indicators_matched[k])
        result.correlation_reasons = [
            f"{k}: {v} related events" for k, v in indicators_matched.items()
        ]

    return result


def clear():
    """Reset the store (useful for tests)."""
    _EVENT_STORE.clear()


if __name__ == "__main__":
    # Smoke test
    e1 = Event(event_id="1", timestamp="", host="h1", source="linux_auth",
               event_type="AUTH_FAILURE", severity="high",
               actor={"source_ip": "1.2.3.4", "user": "admin"})
    e2 = Event(event_id="2", timestamp="", host="h1", source="linux_auth",
               event_type="AUTH_FAILURE", severity="high",
               actor={"source_ip": "1.2.3.4", "user": "admin"})
    e3 = Event(event_id="3", timestamp="", host="h1", source="linux_auth",
               event_type="AUTH_SUCCESS", severity="info",
               actor={"source_ip": "1.2.3.4", "user": "admin"})

    add_event(e1)
    add_event(e2)
    add_event(e3)

    r = correlate(e1)
    print(f"Related: {len(r.related_events)}")
    print(f"Reasons: {r.correlation_reasons}")
