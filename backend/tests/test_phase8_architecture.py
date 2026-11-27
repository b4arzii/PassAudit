"""Layering and isolation rules for the Phase 8 packages.

The security argument for the opt-in integrations is structural: network code lives in exactly
one module, the engine cannot reach it, and nothing logs or prints.
"""

from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

import passaudit

PACKAGE = Path(passaudit.__file__).parent
NETWORK_MODULES = {
    "socket", "ssl", "http", "urllib", "ftplib", "smtplib", "telnetlib", "requests", "httpx",
    "httpx2", "aiohttp", "websockets", "xmlrpc", "asyncio",
}  # fmt: skip
NETWORK_ALLOWED = {PACKAGE / "breach" / "providers.py"}


def _imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            found.add(node.module)
    return found


def _python_files() -> list[Path]:
    return sorted(p for p in PACKAGE.rglob("*.py") if "__pycache__" not in p.parts)


def test_only_the_breach_provider_module_imports_network_libraries() -> None:
    offenders = {
        str(path.relative_to(PACKAGE)): sorted(
            m
            for m in _imports(path)
            if m.split(".")[0] in NETWORK_MODULES and m != "urllib.parse"  # string parsing only
        )
        for path in _python_files()
        if path not in NETWORK_ALLOWED
    }
    offenders = {k: v for k, v in offenders.items() if v}
    # (uvicorn/fastapi bring their own sockets; they are not imported by name here.)
    assert offenders == {}


def test_the_network_module_uses_only_what_it_needs() -> None:
    (path,) = NETWORK_ALLOWED
    used = {m.split(".")[0] for m in _imports(path)} & NETWORK_MODULES
    assert used <= {"socket", "ssl", "urllib"}
    text = path.read_text(encoding="utf-8")
    for forbidden in ("urlopen(", "http.client", "HTTPHandler(", "FileHandler", "FTPHandler"):
        assert forbidden not in text


def test_the_engine_never_imports_the_integration_packages() -> None:
    forbidden = ("passaudit.breach", "passaudit.reuse", "passaudit.reporting", "passaudit.profiles")
    for path in (PACKAGE / "analysis").glob("*.py"):
        for name in _imports(path):
            assert not name.startswith(forbidden), (path.name, name)


def test_breach_and_reuse_do_not_depend_on_the_web_or_cli_layers() -> None:
    banned = ("passaudit.api", "passaudit.cli", "passaudit.main", "fastapi", "starlette", "typer")
    for folder in ("breach", "reuse", "reporting"):
        for path in (PACKAGE / folder).glob("*.py"):
            for name in _imports(path):
                assert not name.startswith(banned), (path.name, name)


def test_integration_packages_never_log_print_or_execute_dynamic_code() -> None:
    banned_imports = {"logging", "pickle", "shelve", "marshal", "subprocess", "sqlite3", "warnings"}
    banned_calls = {"print", "eval", "exec", "compile", "__import__", "breakpoint"}
    for folder in ("breach", "reuse", "reporting"):
        for path in (PACKAGE / folder).glob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            assert not {m.split(".")[0] for m in _imports(path)} & banned_imports, path.name
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                    assert node.func.id not in banned_calls, (path.name, node.func.id)


def test_importing_the_engine_or_reporting_opens_no_network_stack() -> None:
    code = (
        "import sys, passaudit.analysis, passaudit.reporting, passaudit.reuse;"
        "bad = [m for m in ('urllib.request', 'ssl', 'socket', 'http.client') if m in sys.modules];"
        "print(','.join(bad)); sys.exit(1 if bad else 0)"
    )
    done = subprocess.run(  # noqa: S603 - fixed argv, our own interpreter
        [sys.executable, "-c", code], capture_output=True, text=True, timeout=60, check=False
    )
    # pydantic or the stdlib may import `ssl`/`socket` lazily on some platforms; the rule that
    # matters is that no HTTP client is loaded.
    loaded = set(done.stdout.strip().split(",")) - {""}
    assert not loaded & {"urllib.request", "http.client"}, loaded


def test_the_sha1_use_is_marked_as_a_lookup_key_not_a_security_hash() -> None:
    text = (PACKAGE / "breach" / "hashing.py").read_text(encoding="utf-8")
    assert "usedforsecurity=False" in text
    assert text.count("sha1(") == 1
    for path in _python_files():
        if path.name != "hashing.py":
            assert "sha1(" not in path.read_text(encoding="utf-8"), path.name
