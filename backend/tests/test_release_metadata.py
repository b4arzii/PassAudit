"""Release hygiene: things that rot silently and embarrass a public release.

* the version is the same everywhere it is written;
* the license, changelog and notices exist and agree with the package metadata;
* every ``PASSAUDIT_*`` variable the docs and ``.env.example`` mention is a real setting;
* every relative link in the Markdown documentation points at a file (and heading) that exists;
* the Docker files keep the properties the docs promise.
"""

from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path

import pytest
import yaml

from passaudit import __version__
from passaudit.config import Settings

ROOT = Path(__file__).resolve().parents[2]
MARKDOWN = [
    *ROOT.glob("*.md"),
    *(ROOT / "docs").rglob("*.md"),
    *(ROOT / ".github").rglob("*.md"),
]
# Variables that Compose (not the application) reads, documented in .env.example and docker.md.
COMPOSE_ONLY = {"PASSAUDIT_WEB_PORT", "PASSAUDIT_DATA_DIR"}


def _pyproject() -> dict[str, object]:
    return tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))


# ------------------------------------------------------------------------------ versions


def test_the_version_is_the_same_everywhere() -> None:
    project = _pyproject()["project"]
    assert isinstance(project, dict)
    package = json.loads((ROOT / "frontend" / "package.json").read_text(encoding="utf-8"))
    lock = json.loads((ROOT / "frontend" / "package-lock.json").read_text(encoding="utf-8"))
    assert project["version"] == __version__
    assert package["version"] == __version__
    assert lock["version"] == __version__
    assert lock["packages"][""]["version"] == __version__


def test_the_changelog_has_an_entry_for_the_current_version() -> None:
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    assert f"## [{__version__}]" in changelog
    assert "## [Unreleased]" in changelog


# ------------------------------------------------------------------------------- license


def test_the_license_is_mit_and_declared_consistently() -> None:
    text = (ROOT / "LICENSE").read_text(encoding="utf-8")
    assert text.startswith("MIT License")
    assert "Copyright (c)" in text
    project = _pyproject()["project"]
    assert isinstance(project, dict)
    assert project["license"] == "MIT"
    assert project["license-files"] == ["LICENSE"]
    package = json.loads((ROOT / "frontend" / "package.json").read_text(encoding="utf-8"))
    assert package["license"] == "MIT"


def test_third_party_notices_cover_every_runtime_dependency() -> None:
    notices = (ROOT / "THIRD_PARTY_NOTICES.md").read_text(encoding="utf-8").lower()
    project = _pyproject()["project"]
    assert isinstance(project, dict)
    for requirement in project["dependencies"]:
        name = re.split(r"[<>=!~\[ ]", requirement, maxsplit=1)[0].lower()
        assert name in notices, (
            f"{name} is a runtime dependency missing from THIRD_PARTY_NOTICES.md"
        )
    package = json.loads((ROOT / "frontend" / "package.json").read_text(encoding="utf-8"))
    for name in package["dependencies"]:
        assert name.lower() in notices, f"{name} missing from THIRD_PARTY_NOTICES.md"


def test_font_license_texts_ship_with_the_frontend_build() -> None:
    for name in ("OFL-Inter.txt", "OFL-JetBrains-Mono.txt"):
        text = (ROOT / "frontend" / "public" / "licenses" / name).read_text(encoding="utf-8")
        assert "SIL OPEN FONT LICENSE" in text.upper()


# -------------------------------------------------------------------------- configuration


def _env_names(text: str) -> set[str]:
    return set(re.findall(r"\b(PASSAUDIT_[A-Z0-9_]+)\b", text))


def test_every_documented_environment_variable_is_a_real_setting() -> None:
    fields = {f"PASSAUDIT_{name.upper()}" for name in Settings.model_fields}
    documented = _env_names((ROOT / ".env.example").read_text(encoding="utf-8"))
    for path in [*MARKDOWN, ROOT / "docker-compose.yml", *ROOT.glob("docker-compose.*.yml")]:
        documented |= _env_names(path.read_text(encoding="utf-8"))
    # Prefixes written with a trailing underscore in prose ("PASSAUDIT_") are not variables.
    unknown = {name for name in documented if name not in fields and not name.endswith("_")}
    unknown -= COMPOSE_ONLY
    unknown -= {"PASSAUDIT_FUZZ_ITERATIONS"}  # read by a test, not by the application
    # Short forms such as ``_BREACH_TIMEOUT_SECONDS`` in running text are skipped by the regex.
    assert not unknown, f"documented but not a setting: {sorted(unknown)}"


def test_env_example_covers_every_setting() -> None:
    documented = _env_names((ROOT / ".env.example").read_text(encoding="utf-8"))
    missing = {f"PASSAUDIT_{name.upper()}" for name in Settings.model_fields} - documented
    assert not missing, f".env.example does not mention: {sorted(missing)}"


# ------------------------------------------------------------------------------ doc links

_LINK = re.compile(r"(?<!\!)\[[^\]]*\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")
_IMAGE = re.compile(r"!\[[^\]]*\]\(([^)\s]+)\)")
_HTML_SRC = re.compile(r'<img[^>]+src="([^"]+)"')


def _slug(heading: str) -> str:
    """GitHub's heading anchor: lower-case, drop punctuation, spaces to hyphens."""
    text = re.sub(r"`", "", heading.strip().lower())
    text = re.sub(r"[^\w\- ]", "", text)
    return text.replace(" ", "-")


def _anchors(path: Path) -> set[str]:
    anchors: set[str] = set()
    in_code = False
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("```"):
            in_code = not in_code
        elif not in_code and (match := re.match(r"#{1,6}\s+(.*)", line)):
            anchors.add(_slug(match.group(1)))
    return anchors


def _local_targets(path: Path) -> list[tuple[str, Path, str]]:
    text = path.read_text(encoding="utf-8")
    out: list[tuple[str, Path, str]] = []
    for target in [*_LINK.findall(text), *_IMAGE.findall(text), *_HTML_SRC.findall(text)]:
        if re.match(r"[a-z][a-z0-9+.-]*:", target) or target.startswith("#"):
            if target.startswith("#"):
                out.append((target, path, target[1:]))
            continue
        file_part, _, anchor = target.partition("#")
        out.append((target, (path.parent / file_part).resolve(), anchor))
    return out


@pytest.mark.parametrize("path", MARKDOWN, ids=lambda p: str(p.relative_to(ROOT)))
def test_relative_links_and_anchors_resolve(path: Path) -> None:
    problems: list[str] = []
    for target, file, anchor in _local_targets(path):
        if not file.exists():
            problems.append(f"{target}: no such file")
        elif anchor and file.suffix == ".md" and anchor not in _anchors(file):
            problems.append(f"{target}: no such heading")
    assert not problems, "\n".join(problems)


# ------------------------------------------------------------------------------- docker


def test_compose_keeps_the_promised_isolation() -> None:
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    services = compose["services"]
    assert "ports" not in services["api"], "the unauthenticated API must never publish a port"
    for mapping in services["web"]["ports"]:
        assert str(mapping).startswith("127.0.0.1:"), "the web port must stay on loopback"
    assert compose["networks"]["backend"]["internal"] is True
    assert services["api"]["networks"] == ["backend"]
    assert services["cli"]["network_mode"] == "none"
    for name in ("api", "web", "cli"):
        service = services[name]
        assert service["read_only"] is True
        assert service["cap_drop"] == ["ALL"]
        assert "no-new-privileges:true" in service["security_opt"]
    assert services["api"]["environment"]["PASSAUDIT_EXTERNAL_LOOKUPS_ENABLED"] == "false"


def test_egress_override_is_the_only_thing_that_gives_the_api_a_route_out() -> None:
    egress = yaml.safe_load((ROOT / "docker-compose.egress.yml").read_text(encoding="utf-8"))
    assert egress["services"]["api"]["environment"]["PASSAUDIT_EXTERNAL_LOOKUPS_ENABLED"] == "true"
    assert "egress" in egress["services"]["api"]["networks"]
    data = yaml.safe_load((ROOT / "docker-compose.data.yml").read_text(encoding="utf-8"))
    for service in ("api", "cli"):
        assert all(v["read_only"] is True for v in data["services"][service]["volumes"])


def test_nginx_never_logs_request_lines_or_spools_bodies() -> None:
    conf = (ROOT / "docker" / "nginx.conf").read_text(encoding="utf-8")
    assert re.search(r"^\s*access_log\s+off;", conf, re.MULTILINE)
    assert re.search(r"^\s*error_log\s+/dev/stderr\s+crit;", conf, re.MULTILINE)
    limit = re.search(r"client_max_body_size\s+(\d+)m;", conf)
    buffer = re.search(r"client_body_buffer_size\s+(\d+)m;", conf)
    assert limit
    assert buffer
    assert int(buffer.group(1)) >= int(limit.group(1))


def test_dockerignore_keeps_secrets_and_data_out_of_the_image() -> None:
    ignored = (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()
    for pattern in (".env", ".env.*", "data/", "*.key", ".git/", ".venv/", "node_modules/"):
        assert pattern in ignored


def test_dockerfile_runs_unprivileged_and_installs_from_the_lock() -> None:
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "USER 10001:10001" in dockerfile
    assert "-c backend/requirements.lock.txt" in dockerfile
    assert "npm ci" in dockerfile
    assert "nginx-unprivileged" in dockerfile


def test_ci_never_publishes() -> None:
    for workflow in (ROOT / ".github" / "workflows").glob("*.yml"):
        text = workflow.read_text(encoding="utf-8")
        parsed = yaml.safe_load(text)
        assert parsed["permissions"] == {"contents": "read"}, workflow.name
        for forbidden in ("docker push", "twine upload", "pypi-publish", "gh release create"):
            assert forbidden not in text, f"{workflow.name} must not publish ({forbidden})"
