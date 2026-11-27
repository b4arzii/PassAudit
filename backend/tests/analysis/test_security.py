"""The engine must never persist, print, log, or return passwords - and must stay independent.

These tests turn the rules in docs/security.md into executable checks.
"""

from __future__ import annotations

import ast
import json
import logging
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

import pytest
from pydantic import SecretStr, ValidationError

import passaudit.analysis as analysis_pkg
from passaudit.analysis import (
    AnalysisContext,
    PasswordAnalysis,
    PasswordAnalyzer,
    PasswordPolicy,
    PasswordTooLongError,
    PasswordUsage,
)

from .conftest import CANARY

Analyze = Callable[..., PasswordAnalysis]

PACKAGE_DIR = Path(analysis_pkg.__file__).parent
SOURCE_FILES = sorted(PACKAGE_DIR.glob("*.py"))
PERSONAL = "Zebulon-Quillfeather"

CANARIES = [CANARY, "Hunter2-Tr0ub4dor&3", "dragon-Zq7!xKp#9", "Zebulon-Zq7!xKp#9mWv"]


def _rich_context() -> AnalysisContext:
    return AnalysisContext(
        personal_info=(SecretStr(PERSONAL), SecretStr("zq.quill@example.org")),
        usage=PasswordUsage.PRIVILEGED_ACCOUNT,
        reused_elsewhere=True,
    )


# --------------------------------------------------------- results never contain input


@pytest.mark.parametrize("password", CANARIES)
def test_serialised_result_never_contains_the_password(analyze: Analyze, password: str) -> None:
    result = analyze(password, context=_rich_context(), policy=PasswordPolicy(min_length=40))
    blob = result.model_dump_json() + repr(result) + str(result)
    assert password not in blob


def test_no_fragment_of_a_random_password_appears_in_the_result(analyze: Analyze) -> None:
    result = analyze(CANARY, context=_rich_context())
    blob = result.model_dump_json()
    for width in (5, 6, 8):
        for i in range(len(CANARY) - width + 1):
            assert CANARY[i : i + width] not in blob


def test_personal_info_never_appears_in_the_result(analyze: Analyze) -> None:
    result = analyze(f"{PERSONAL}-9", context=_rich_context())
    blob = (result.model_dump_json() + repr(result)).lower()
    assert PERSONAL.lower() not in blob
    assert "quillfeather" not in blob
    assert "zq.quill" not in blob
    assert any(f.kind.value == "personal_info" for f in result.findings)  # it *was* detected


def test_all_free_text_fields_are_template_strings(analyze: Analyze) -> None:
    result = analyze(f"aaaa-qwer-abcd-dragon-{PERSONAL}", context=_rich_context())
    texts = [f.description for f in result.findings]
    texts += [c.explanation for c in result.risk.components]
    texts += [r.message for r in result.recommendations]
    texts += [v.message for v in result.policy.violations]
    texts += [result.strength.warning, *result.strength.suggestions]
    for text in texts:
        for fragment in ("aaaa-qwer", "abcd-dragon", PERSONAL, "Quillfeather"):
            assert fragment.lower() not in text.lower()


def test_strength_segments_carry_no_text(analyze: Analyze) -> None:
    segment_json = json.dumps(
        [s.model_dump() for s in analyze("correcthorse1999").strength.segments]
    )
    for word in ("correct", "horse", "1999"):
        assert word not in segment_json


# ------------------------------------------------------------ inputs are masked in repr


def test_context_masks_personal_info(analyze: Analyze) -> None:
    ctx = _rich_context()
    blob = repr(ctx) + str(ctx) + ctx.model_dump_json() + repr(ctx.model_dump())
    assert PERSONAL not in blob
    assert "example.org" not in blob


# -------------------------------------------------- errors never echo rejected values


def test_validation_errors_do_not_echo_input_values() -> None:
    secret_items = tuple(SecretStr("S3cretNameValue" * 30) for _ in range(1))
    with pytest.raises(ValidationError) as ctx_err:
        AnalysisContext(personal_info=secret_items)
    assert "S3cretNameValue" not in str(ctx_err.value)

    with pytest.raises(ValidationError) as pol_err:
        PasswordPolicy(min_length="S3cretNameValue")  # type: ignore[arg-type]
    assert "S3cretNameValue" not in str(pol_err.value)

    with pytest.raises(ValidationError) as ctx_err2:
        AnalysisContext(personal_info="S3cretNameValue")  # type: ignore[arg-type]
    assert "S3cretNameValue" not in str(ctx_err2.value)


def test_too_long_error_has_no_password_content() -> None:
    analyzer = PasswordAnalyzer()
    secret = "S3cretValue-" * 200
    with pytest.raises(PasswordTooLongError) as info:
        analyzer.analyze_password(secret)
    assert "S3cretValue" not in str(info.value)
    assert "S3cretValue" not in repr(info.value)
    assert "S3cretValue" not in repr(info.value.args)


# ------------------------------------------------- no logging, printing, or exceptions


def test_analysis_does_not_print_or_log(
    analyze: Analyze, caplog: pytest.LogCaptureFixture, capsys: pytest.CaptureFixture[str]
) -> None:
    caplog.set_level(logging.DEBUG)
    logging.getLogger().setLevel(logging.DEBUG)
    for password in [*CANARIES, "", "password", "x" * 300]:
        analyze(password, context=_rich_context())
    with pytest.raises(PasswordTooLongError):
        PasswordAnalyzer().analyze_password("x" * 5000)
    out = capsys.readouterr()
    assert out.out == ""
    assert out.err == ""
    assert caplog.records == []


def test_source_has_no_logging_printing_or_dynamic_execution() -> None:
    banned_imports = {
        "logging", "pickle", "shelve", "marshal", "sqlite3", "socket", "ssl", "subprocess",
        "urllib", "http", "requests", "httpx", "tempfile", "shutil", "os", "dbm", "csv",
        "warnings", "traceback", "fastapi", "starlette", "uvicorn",
    }  # fmt: skip
    banned_calls = {"print", "eval", "exec", "compile", "__import__", "breakpoint"}
    assert SOURCE_FILES, "no source files found"
    for path in SOURCE_FILES:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = {alias.name.split(".")[0] for alias in node.names}
            elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                names = {node.module.split(".")[0]}
            else:
                names = set()
            assert not names & banned_imports, f"{path.name} imports {names & banned_imports}"
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                assert node.func.id not in banned_calls, f"{path.name} calls {node.func.id}()"


def test_only_the_wordlist_module_touches_the_filesystem() -> None:
    writers = {"write_text", "write_bytes", "unlink", "mkdir", "touch", "rename", "replace"}
    for path in SOURCE_FILES:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute):
                assert node.attr not in writers, f"{path.name} uses .{node.attr}"
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                assert node.func.id != "open", f"{path.name} calls open()"
            if isinstance(node, ast.Attribute) and node.attr == "open":
                assert path.name == "wordlist.py", f"{path.name} opens files"


def test_wordlist_open_is_read_only() -> None:
    source = (PACKAGE_DIR / "wordlist.py").read_text(encoding="utf-8")
    assert ".open(encoding=" in source  # default mode is read-only text
    for mode in ('"w"', "'w'", '"a"', "'a'", '"wb"', '"x"'):
        assert mode not in source


# ------------------------------------------------------------------ no persistence


def test_analysis_leaves_no_state_between_calls(analyzer: PasswordAnalyzer) -> None:
    ctx = AnalysisContext(personal_info=(SecretStr("qzvxjw"),))
    with_ctx = analyzer.analyze_password("qzvxjw", context=ctx)
    plain = analyzer.analyze_password("qzvxjw")
    again = analyzer.analyze_password("qzvxjw")
    assert with_ctx.strength.guesses_log10 < plain.strength.guesses_log10
    assert plain == again  # the personal token did not linger anywhere


def test_analyzer_instances_hold_no_password_derived_attributes() -> None:
    analyzer = PasswordAnalyzer()
    before = {k: id(v) for k, v in vars(analyzer).items()}
    analyzer.analyze_password(CANARY, context=_rich_context())
    assert {k: id(v) for k, v in vars(analyzer).items()} == before
    assert set(vars(analyzer)) == {"config", "wordlist", "dictionaries"}


def test_no_result_caching_on_public_functions() -> None:
    for func in (
        analysis_pkg.analyze_password,
        PasswordAnalyzer.analyze,
        PasswordAnalyzer.analyze_password,
    ):
        assert not hasattr(func, "cache_info"), f"{func.__qualname__} caches results"


# ------------------------------------------------------------------- independence


def test_engine_does_not_import_the_web_application() -> None:
    forbidden = {"fastapi", "starlette", "uvicorn", "passaudit.main", "passaudit.config"}
    for path in SOURCE_FILES:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                assert node.module not in forbidden, f"{path.name} imports {node.module}"
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    assert alias.name not in forbidden, f"{path.name} imports {alias.name}"


def test_importing_the_engine_does_not_load_fastapi_or_the_app() -> None:
    code = (
        "import sys, passaudit.analysis;"
        "bad = [m for m in sys.modules if m.split('.')[0] in ('fastapi','starlette','uvicorn')"
        " or m in ('passaudit.main','passaudit.config')];"
        "print(','.join(bad)); sys.exit(1 if bad else 0)"
    )
    done = subprocess.run(  # noqa: S603 - fixed argv, no user input
        [sys.executable, "-c", code], capture_output=True, text=True, timeout=60, check=False
    )
    assert done.returncode == 0, f"engine pulled in: {done.stdout}{done.stderr}"
