"""Run the ARGUS deception grid as a standalone process."""

from __future__ import annotations

import asyncio
import json

from .config import HoneypotSettings
from .runtime import HoneypotRuntime


async def serve() -> None:
    settings = HoneypotSettings.from_env()
    runtime = HoneypotRuntime(settings=settings)
    status = await runtime.start()
    print("ARGUS Gemini Deception Grid")
    print(json.dumps(status, indent=2))
    print("Press Ctrl+C to stop.")
    try:
        await asyncio.Future()
    finally:
        await runtime.stop()


def main() -> None:
    try:
        asyncio.run(serve())
    except KeyboardInterrupt:
        print("\nARGUS deception grid stopped.")


if __name__ == "__main__":
    main()
