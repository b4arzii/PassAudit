"""Layering rules: the API only *uses* the engine, and the layers stay independent."""

from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

import passaudit
import passaudit.api as api_pkg

PACKAGE = Path(passaudit.__file__).parent
API_FILES = sorted(Path(api_pkg.__file__).parent.glob("*.py"))
ENGINE_INTERNALS = {
    "patterns", "keyboard", "strength", "entropy", "wordlist", "scoring", "recommendations",
    "policy", "personal", "charsets", "text", "analyzer",
}  # fmt: skip


def _imports(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            names.append(node.module)
    return names


def test_api_uses_the_engine_only_through_its_public_surface() -> None:
    """No analysis logic is re-implemented: the API never reaches into engine internals."""
    assert API_FILES
    for path in API_FILES:
        for name in _imports(path):
            if name.startswith("passaudit.analysis."):
                submodule = name.split(".")[2]
                assert submodule not in ENGINE_INTERNALS, f"{path.name} imports {name}"
                assert submodule == "models", f"{path.name} imports {name}"  # constants only


def test_api_contains_no_detection_or_scoring_code() -> None:
    forbidden = {
        "zxcvbn",
        "find_repeats",
        "find_sequences",
        "find_keyboard_runs",
        "WordList",
        "log2",
    }
    for path in API_FILES:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        used = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
        used |= {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
        used |= {part for name in _imports(path) for part in name.split(".")}
        assert not used & forbidden, f"{path.name} uses {used & forbidden}"


def test_api_does_not_depend_on_the_cli() -> None:
    banned = {"typer", "rich", "click", "passaudit.cli"}
    for path in [*API_FILES, PACKAGE / "main.py"]:
        for name in _imports(path):
            assert name.split(".")[0] not in banned, (path.name, name)
            assert not name.startswith("passaudit.cli"), (path.name, name)


def test_engine_and_cli_do_not_depend_on_the_api() -> None:
    for folder in ("analysis", "cli"):
        for path in (PACKAGE / folder).glob("*.py"):
            for name in _imports(path):
                assert not name.startswith("passaudit.api"), (path.name, name)
                assert name not in {"passaudit.main", "fastapi", "starlette", "uvicorn"}, (
                    path.name,
                    name,
                )


def test_only_the_middleware_and_app_factory_use_logging() -> None:
    allowed = {"middleware.py", "main.py"}
    for path in [*API_FILES, PACKAGE / "main.py"]:
        if "logging" in _imports(path):
            assert path.name in allowed, path.name


def test_api_source_has_no_printing_or_dynamic_execution() -> None:
    banned_calls = {"print", "eval", "exec", "compile", "__import__", "breakpoint"}
    banned_imports = {"pickle", "shelve", "subprocess", "socket", "sqlite3", "tempfile", "shutil"}
    for path in [*API_FILES, PACKAGE / "main.py"]:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                assert node.func.id not in banned_calls, (path.name, node.func.id)
        assert not {n.split(".")[0] for n in _imports(path)} & banned_imports, path.name


def test_api_never_reads_request_bodies_in_middleware_code() -> None:
    """Only the request guard wraps ``receive`` (to count bytes); nothing calls ``.body()``."""
    for path in API_FILES:
        text = path.read_text(encoding="utf-8")
        assert ".body()" not in text, path.name
        assert "request.json" not in text, path.name


def test_importing_the_app_does_not_load_the_cli_stack() -> None:
    code = (
        "import sys, passaudit.main;"
        "bad = [m for m in sys.modules if m.split('.')[0] in ('typer','rich','click')"
        " or m.startswith('passaudit.cli')];"
        "print(','.join(sorted(bad))); sys.exit(1 if bad else 0)"
    )
    done = subprocess.run(  # noqa: S603 - fixed argv, our own interpreter
        [sys.executable, "-c", code], capture_output=True, text=True, timeout=60, check=False
    )
    assert done.returncode == 0, f"the API pulled in the CLI stack: {done.stdout}{done.stderr}"
