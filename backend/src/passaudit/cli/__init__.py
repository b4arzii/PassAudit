"""PassAudit command-line interface (Typer + Rich).

Independent of FastAPI: it uses only ``passaudit.analysis``. See ``docs/cli.md``.
"""

from passaudit.cli.app import app, main

__all__ = ["app", "main"]
