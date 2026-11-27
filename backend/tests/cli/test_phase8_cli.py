"""Phase 8 on the command line: profiles, dictionaries, opt-in breach checks, reuse, reports."""

from __future__ import annotations

import json
import socket
import urllib.request
from pathlib import Path
from typing import Any

import pytest

from passaudit.breach import sha1_hex
from passaudit.reporting import verify_seal

from .conftest import CANARY, OTHER_STRONG, Cli, everything, parse

PERSONAL = "Zebulon-Quillfeather"


@pytest.fixture
def no_network(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    attempts: list[str] = []

    def guarded(*_a: Any, **_k: Any) -> None:
        attempts.append("network")
        raise AssertionError("a network call was attempted")

    monkeypatch.setattr(urllib.request.OpenerDirector, "open", guarded)
    real_connect = socket.socket.connect

    def connect(self: socket.socket, address: Any) -> None:
        host = address[0] if isinstance(address, tuple) else address
        if host not in {"127.0.0.1", "::1", "localhost"}:
            guarded()
        return real_connect(self, address)

    monkeypatch.setattr(socket.socket, "connect", connect)
    return attempts


def _hash_file(path: Path, passwords: dict[str, int]) -> Path:
    lines = sorted(f"{sha1_hex(p)}:{n}" for p, n in passwords.items())
    path.write_text("\n".join(lines) + "\n", encoding="ascii")
    return path


# --------------------------------------------------------------------------- profiles


def test_profiles_are_listed_as_a_table_and_as_json(cli: Cli) -> None:
    table = cli(["policy", "profiles"])
    assert table.exit_code == 0
    for name in ("default", "nist-inspired", "enterprise", "high-security", "passphrase"):
        assert name in table.stdout
    data = json.loads(cli(["policy", "profiles", "--json"]).stdout)
    assert {p["name"] for p in data["profiles"]} >= {"default", "high-security"}


def test_a_profile_is_applied_and_recorded(cli: Cli) -> None:
    result = cli(
        ["audit", "--stdin", "-f", "json", "--profile", "high-security"], input="Zq7!xKp#9mWv\n"
    )
    report = parse(result)
    assert report["policy"]["min_length"] == 16
    assert report["settings"]["profile"] == "high-security"
    assert report["settings"]["usage"] == "privileged_account"
    assert "min_length" in {v["rule"] for v in report["analysis"]["policy"]["violations"]}
    assert result.exit_code == 1


def test_command_line_overrides_win_over_the_profile(cli: Cli) -> None:
    report = parse(
        cli(
            ["audit", "--stdin", "-f", "json", "--profile", "high-security", "--min-length", "8"],
            input=CANARY + "\n",
        )
    )
    assert report["policy"]["min_length"] == 8


def test_profile_misuse_is_a_usage_error_that_does_not_echo_input(cli: Cli, tmp_path: Path) -> None:
    unknown = cli(["audit", "--stdin", "--profile", CANARY], input=CANARY + "\n")
    assert unknown.exit_code == 2
    assert CANARY not in everything(unknown)
    both = cli(
        ["audit", "--stdin", "--profile", "default", "--policy", str(tmp_path / "p.json")],
        input="x\n",
    )
    assert both.exit_code == 2
    orphan = cli(["audit", "--stdin", "--profiles-file", str(tmp_path / "p.json")], input="x\n")
    assert orphan.exit_code == 2


def test_custom_profiles_files(cli: Cli, tmp_path: Path) -> None:
    file = tmp_path / "profiles.json"
    file.write_text(json.dumps([{"name": "lab", "title": "Lab", "policy": {"min_length": 30}}]))
    listing = cli(["policy", "profiles", "--profiles-file", str(file)])
    assert "lab" in listing.stdout
    assert "custom" in listing.stdout
    shown = json.loads(
        cli(["policy", "show", "--profile", "lab", "--profiles-file", str(file)]).stdout
    )
    assert shown["min_length"] == 30
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps([{"name": "default", "title": "shadow"}]))
    result = cli(["policy", "profiles", "--profiles-file", str(bad)])
    assert result.exit_code == 3
    assert "built-in name" in result.stderr


# ---------------------------------------------------------------------------- dictionary


def test_extra_dictionaries_extend_the_analysis(cli: Cli, tmp_path: Path) -> None:
    words = tmp_path / "company.txt"
    words.write_text("quillfeather\nzebulonic\n")
    password = "Zq7!Quillfeather-Zebulonic!9"
    plain = parse(cli(["audit", "--stdin", "-f", "json"], input=password + "\n"))
    custom = parse(
        cli(["audit", "--stdin", "-f", "json", "--dictionary", str(words)], input=password + "\n")
    )
    assert not [f for f in plain["analysis"]["findings"] if f.get("dictionary")]
    assert [f for f in custom["analysis"]["findings"] if f.get("dictionary") == "words"]
    assert custom["settings"]["extra_dictionaries"] == 1
    missing = cli(["audit", "--stdin", "--dictionary", str(tmp_path / "none.txt")], input="x\n")
    assert missing.exit_code == 3


# ---------------------------------------------------------------------------- breach


def test_nothing_external_happens_unless_asked(cli: Cli, no_network: list[str]) -> None:
    report = parse(cli(["audit", "--stdin", "-f", "json"], input=CANARY + "\n"))
    assert report["external_checks"]["breach_check"] == "off"
    assert report["analysis"]["exposure"] is None
    assert no_network == []


def test_online_breach_check_needs_the_explicit_confirmation(
    cli: Cli, no_network: list[str]
) -> None:
    result = cli(["audit", "--stdin", "--breach", "online"], input=CANARY + "\n")
    assert result.exit_code == 2
    assert "--allow-external" in result.stderr
    assert CANARY not in everything(result)
    assert no_network == []
    bad_url = cli(
        [
            "audit",
            "--stdin",
            "--breach",
            "online",
            "--allow-external",
            "--breach-url",
            "http://x.test/range",
        ],
        input=CANARY + "\n",
    )
    assert bad_url.exit_code == 2
    assert no_network == []


def test_the_online_option_announces_what_it_sends(
    cli: Cli, monkeypatch: pytest.MonkeyPatch
) -> None:
    sent: list[str] = []

    def fake(self: object, request: Any, *a: Any, **k: Any) -> Any:
        sent.append(request.full_url)
        raise OSError("offline")

    monkeypatch.setattr(urllib.request.OpenerDirector, "open", fake)
    result = cli(
        ["audit", "--stdin", "-f", "json", "--breach", "online", "--allow-external"],
        input=CANARY + "\n",
    )
    assert "5-character hash prefixes" in result.stderr
    assert "api.pwnedpasswords.com" in result.stderr
    assert len(sent) == 1
    assert sent[0].rsplit("/", 1)[1] == sha1_hex(CANARY)[:5]  # only the prefix is in the URL
    assert sha1_hex(CANARY) not in " ".join(sent)
    report = parse(result)
    assert report["analysis"]["exposure"]["breach"]["status"] == "unavailable"  # fails open, loudly
    assert report["external_checks"]["breach_service_host"] == "api.pwnedpasswords.com"
    assert CANARY not in everything(result)


def test_local_breach_check_uses_a_file_and_no_network(
    cli: Cli, tmp_path: Path, no_network: list[str]
) -> None:
    corpus = _hash_file(tmp_path / "pwned.txt", {CANARY: 321})
    breached = cli(
        ["audit", "--stdin", "-f", "json", "--breach", "local", "--breach-file", str(corpus)],
        input=CANARY + "\n",
    )
    report = parse(breached)
    assert report["analysis"]["exposure"]["breach"] == {
        "status": "breached",
        "source": "local",
        "count": 321,
    }
    assert report["analysis"]["risk"]["score"] >= 85
    assert breached.exit_code == 1
    clean = parse(
        cli(
            ["audit", "--stdin", "-f", "json", "--breach", "local", "--breach-file", str(corpus)],
            input=OTHER_STRONG + "\n",
        )
    )
    assert clean["analysis"]["exposure"]["breach"]["status"] == "clean"
    assert no_network == []


def test_breach_option_combinations_are_validated(cli: Cli, tmp_path: Path) -> None:
    assert cli(["audit", "--stdin", "--breach", "local"], input="x\n").exit_code == 2
    assert (
        cli(["audit", "--stdin", "--breach-file", str(tmp_path / "f")], input="x\n").exit_code == 2
    )
    unsorted = tmp_path / "unsorted.txt"
    unsorted.write_text("\n".join(f"{n:040X}:1" for n in range(300, 0, -1)) + "\n")
    result = cli(
        ["audit", "--stdin", "--breach", "local", "--breach-file", str(unsorted)], input="x\n"
    )
    assert result.exit_code == 3
    assert "not sorted" in result.stderr
    assert str(tmp_path) not in result.stderr


def test_policy_check_shows_unchecked_breach_rules_honestly(cli: Cli) -> None:
    result = cli(
        ["policy", "check", "--stdin", "--profile", "nist-inspired"], input="Zq7!xKp#9mWv$L2nRb\n"
    )
    assert "NOT CHECKED" in result.stdout
    assert "not checked" in result.stdout
    data = parse(
        cli(
            ["policy", "check", "--stdin", "-f", "json", "--profile", "nist-inspired"],
            input=CANARY + "\n",
        )
    )
    assert (
        next(r for r in data["rules"] if r["rule"] == "block_breached_passwords")["status"]
        == "unchecked"
    )


def test_batch_breach_check_summarises(cli: Cli, tmp_path: Path) -> None:
    corpus = _hash_file(tmp_path / "pwned.txt", {CANARY: 5})
    passwords = tmp_path / "pw.txt"
    passwords.write_text(f"{CANARY}\n{OTHER_STRONG}\n{CANARY}\n", encoding="utf-8")
    result = cli(
        ["batch", str(passwords), "-f", "json", "--breach", "local", "--breach-file", str(corpus)],
    )
    report = parse(result)
    assert report["summary"]["breached"] == 2
    assert [r["breach"] for r in report["results"]] == ["breached", "clean", "breached"]
    text = result.stdout
    assert CANARY not in text
    assert sha1_hex(CANARY)[:5] not in text
    csv_result = cli(
        ["batch", str(passwords), "-f", "csv", "--breach", "local", "--breach-file", str(corpus)]
    )
    assert "breach" in csv_result.stdout.splitlines()[0]
    terminal = cli(["batch", str(passwords), "--breach", "local", "--breach-file", str(corpus)])
    assert "Found in breach data" in terminal.stdout


# ------------------------------------------------------------------------------- reuse


def _build_index(cli: Cli, tmp_path: Path) -> tuple[Path, Path]:
    hr = tmp_path / "hr.txt"
    hr.write_text(f"{CANARY}\nshared-Zq9!pw\n", encoding="utf-8")
    vpn = tmp_path / "vpn.txt"
    vpn.write_text("shared-Zq9!pw\n", encoding="utf-8")
    index, key = tmp_path / "reuse.idx", tmp_path / "reuse.key"
    result = cli(
        [
            "reuse",
            "build",
            "--source",
            f"hr-export={hr}",
            "--source",
            f"vpn={vpn}",
            "--index-out",
            str(index),
            "--key-file",
            str(key),
            "--confirm-authorized",
            "--authorization-ref",
            "TICKET-5",
        ]
    )
    assert result.exit_code == 0, result.stderr
    assert "Protect the key file" in result.stdout
    return index, key


def test_reuse_build_requires_an_authorisation_statement(cli: Cli, tmp_path: Path) -> None:
    data = tmp_path / "d.txt"
    data.write_text("a\n")
    base = [
        "reuse",
        "build",
        "--source",
        f"d={data}",
        "--index-out",
        str(tmp_path / "i"),
        "--key-file",
        str(tmp_path / "k"),
    ]
    for extra in ([], ["--confirm-authorized"], ["--authorization-ref", "T-1"]):
        result = cli([*base, *extra])
        assert result.exit_code == 2
        assert "authorization" in result.stderr
    assert not (tmp_path / "i").exists()
    assert not (tmp_path / "k").exists()  # no key was created either


def test_reuse_index_contains_no_plaintext_and_info_shows_only_names(
    cli: Cli, tmp_path: Path
) -> None:
    index, key = _build_index(cli, tmp_path)
    text = index.read_text(encoding="utf-8")
    assert CANARY not in text
    assert "shared-Zq9!pw" not in text
    info = cli(["reuse", "info", "--index", str(index), "--key-file", str(key), "--json"])
    data = json.loads(info.stdout)
    assert data["authorization_reference"] == "TICKET-5"
    assert data["datasets"] == [
        {"name": "hr-export", "passwords": 2},
        {"name": "vpn", "passwords": 1},
    ]
    assert CANARY not in info.stdout
    again = cli(
        [
            "reuse",
            "build",
            "--source",
            f"x={tmp_path / 'hr.txt'}",
            "--index-out",
            str(index),
            "--key-file",
            str(key),
            "--confirm-authorized",
            "--authorization-ref",
            "T",
        ]
    )
    assert again.exit_code == 4  # never overwrites an index without --force


def test_audit_with_a_reuse_index_reports_dataset_names_and_the_authorisation(
    cli: Cli, tmp_path: Path
) -> None:
    index, key = _build_index(cli, tmp_path)
    base = [
        "audit",
        "--stdin",
        "-f",
        "json",
        "--reuse-index",
        str(index),
        "--reuse-key-file",
        str(key),
    ]
    refused = cli(base, input="shared-Zq9!pw\n")
    assert refused.exit_code == 2  # no --confirm-authorized
    result = cli(
        [*base, "--confirm-authorized", "--authorization-ref", "TICKET-5"], input="shared-Zq9!pw\n"
    )
    report = parse(result)
    assert report["analysis"]["exposure"]["reuse"] == {
        "status": "reused",
        "sources": ["hr-export", "vpn"],
    }
    assert report["external_checks"]["reuse_datasets"] == ["hr-export", "vpn"]
    assert report["external_checks"]["reuse_authorization_reference"] == "TICKET-5"
    assert "shared-Zq9!pw" not in everything(result)
    assert verify_seal(report)


def test_a_wrong_reuse_key_is_rejected(cli: Cli, tmp_path: Path) -> None:
    index, _ = _build_index(cli, tmp_path)
    other = tmp_path / "other.key"
    other.write_text("ab" * 32 + "\n")
    result = cli(
        [
            "audit",
            "--stdin",
            "--reuse-index",
            str(index),
            "--reuse-key-file",
            str(other),
            "--confirm-authorized",
            "--authorization-ref",
            "T",
        ],
        input="x\n",
    )
    assert result.exit_code == 3
    assert "does not match" in result.stderr


def test_batch_reuse_check(cli: Cli, tmp_path: Path) -> None:
    index, key = _build_index(cli, tmp_path)
    passwords = tmp_path / "pw.txt"
    passwords.write_text(f"{CANARY}\n{OTHER_STRONG}\n", encoding="utf-8")
    result = cli(
        [
            "batch",
            str(passwords),
            "-f",
            "json",
            "--reuse-index",
            str(index),
            "--reuse-key-file",
            str(key),
            "--confirm-authorized",
            "--authorization-ref",
            "TICKET-5",
        ]
    )
    report = parse(result)
    assert [r["reuse_datasets"] for r in report["results"]] == [["hr-export"], []]
    assert report["summary"]["reused_in_datasets"] == 1


# ------------------------------------------------------------------------------ reports


def test_reports_are_sealed_and_refuse_to_leak(cli: Cli, tmp_path: Path) -> None:
    result = cli(["audit", "--stdin", "-f", "json", "--details"], input=CANARY + "\n")
    report = parse(result)
    assert verify_seal(report)
    assert report["integrity"]["checksum"]
    assert report["report"]["schema_version"] == "2"

    leaky = tmp_path / "leaky.csv"
    leaky.write_text(f"label,password\n{CANARY},{CANARY}\nok,other-Zq9!pw\n", encoding="utf-8")
    safe = parse(cli(["batch", str(leaky), "-f", "json", "--input-format", "csv"]))
    assert safe["results"][0]["label"] == "[redacted]"  # redacted before the guard even runs
    assert CANARY not in json.dumps(safe)


def test_the_weakest_passwords_still_produce_reports(cli: Cli) -> None:
    for password in ("short", "password", "letmein", "123456"):
        result = cli(["audit", "--stdin", "-f", "json"], input=password + "\n")
        assert result.exit_code in (0, 1), (password, result.stderr)
        assert verify_seal(parse(result))


def test_personal_info_never_reaches_a_sealed_report(cli: Cli, tmp_path: Path) -> None:
    info = tmp_path / "me.txt"
    info.write_text(PERSONAL + "\n", encoding="utf-8")
    result = cli(
        ["audit", "--stdin", "-f", "json", "--details", "--personal-info-file", str(info)],
        input=f"{PERSONAL}-9\n",
    )
    assert PERSONAL.lower() not in result.stdout.lower()
    assert f"{PERSONAL}-9" not in everything(result)
