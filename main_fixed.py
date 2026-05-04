"""Compatibility shim for older commands.

Use `main:app` as the canonical FastAPI entrypoint.
"""

from main import app

__all__ = ["app"]
