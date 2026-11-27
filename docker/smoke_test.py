"""Smoke and security checks for the running Docker Compose stack (docs/docker.md).

    docker compose up --build -d --wait
    python docker/smoke_test.py            # the web port defaults to 8080

Standard library only. It checks that the app and the API work through the web container, and
that the container-level security claims hold: the API port is not exposed, the API has no route
to the internet, containers are unprivileged and read-only, and no log contains the password.
Exit status 0 means every check passed.
"""

# A command-line test tool: printing is its output, and it shells out to the docker CLI.
# ruff: noqa: T201, S603, S607

from __future__ import annotations

import http.client
import json
import re
import socket
import subprocess  # nosec B404
import sys
from typing import Any

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
CANARY = "Zx9-SMOKE-canary-pw-5521!"
failures = 0


def check(name: str, ok: bool, detail: object = "") -> None:
    global failures  # noqa: PLW0603
    if not ok:
        failures += 1
    suffix = "" if ok else f"  -> {str(detail)[:300]}"
    print(f"{'PASS' if ok else 'FAIL'}  {name}{suffix}")


def request(
    method: str,
    path: str,
    body: Any = None,
    *,
    host: str | None = None,
    raw_body: bytes | None = None,
) -> tuple[int, dict[str, str], bytes]:
    connection = http.client.HTTPConnection("127.0.0.1", PORT, timeout=30)
    data = raw_body if raw_body is not None else (json.dumps(body).encode() if body else None)
    connection.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
    connection.putheader("Host", host or f"localhost:{PORT}")
    if data is not None:
        connection.putheader("Content-Type", "application/json")
        connection.putheader("Content-Length", str(len(data)))
    connection.endheaders(data)
    response = connection.getresponse()
    headers = {key.lower(): value for key, value in response.getheaders()}
    return response.status, headers, response.read()


def docker(*args: str, stdin: str | None = None) -> tuple[int, str]:
    done = subprocess.run(  # noqa: PLW1510 - the exit status is returned, not raised on
        ["docker", *args], capture_output=True, text=True, input=stdin, timeout=180
    )
    return done.returncode, done.stdout + done.stderr


def web_and_api() -> None:
    status, headers, body = request("GET", "/")
    check("GET / serves the app", status == 200 and b'<div id="root">' in body, status)
    policy = headers.get("content-security-policy", "")
    check(
        "CSP header: connect-src 'self' and frame-ancestors 'none'",
        "connect-src 'self'" in policy and "frame-ancestors 'none'" in policy,
        policy,
    )
    check(
        "security headers on the app",
        headers.get("x-content-type-options") == "nosniff"
        and headers.get("x-frame-options") == "DENY"
        and headers.get("referrer-policy") == "no-referrer",
        headers,
    )
    check("nginx version is hidden", not re.search(r"nginx/\d", headers.get("server", "")))
    status, _, body = request("GET", "/audit")
    check("client-side routes fall back to index.html", status == 200 and b'id="root"' in body)

    status, _, body = request("GET", "/api/v1/health")
    check("API health through the proxy", status == 200 and b'"ok"' in body, (status, body[:80]))
    status, headers, body = request("POST", "/api/v1/audit", {"password": CANARY})
    check(
        "audit through the proxy returns a result without the password",
        status == 200 and b'"risk"' in body and CANARY.encode() not in body,
        (status, body[:80]),
    )
    check("the API's own headers survive the proxy", headers.get("cache-control") == "no-store")
    status, _, body = request(
        "POST", f"/api/v1/audit?password={CANARY}", {"password": "abcdefgh12"}
    )
    check(
        "a query string on POST is refused", status == 400 and CANARY.encode() not in body, status
    )
    status, _, body = request(
        "POST", "/api/v1/audit", {"password": "x", "exposure": {"breach": "online"}}
    )
    check("online lookups are refused by default", status == 403, (status, body[:100]))
    status, _, _ = request("GET", "/api/v1/health", host="evil.example")
    check("a spoofed Host header is refused", status == 400, status)
    items = [{"password": f"{CANARY}{i:03d}"} for i in range(50)]
    padding = b" " * 400_000
    status, _, _ = request(
        "POST", "/api/v1/audit/batch", raw_body=json.dumps({"items": items}).encode() + padding
    )
    check("a large batch body is accepted through the proxy", status == 200, status)
    _, listing = docker(
        "compose", "exec", "-T", "web", "sh", "-c", "ls -A /tmp/client_temp | wc -l"
    )
    check("nginx spooled no request body to disk", listing.strip() == "0", listing)


def isolation() -> None:
    try:
        socket.create_connection(("127.0.0.1", 8000), timeout=3).close()
        check("API port 8000 is not reachable from the host", False, "connected")
    except OSError:
        check("API port 8000 is not reachable from the host", True)
    _, uid = docker("compose", "exec", "-T", "api", "id", "-u")
    check("API runs as an unprivileged user", uid.strip() not in ("", "0"), uid)
    _, uid = docker("compose", "exec", "-T", "web", "id", "-u")
    check("web runs as an unprivileged user", uid.strip() not in ("", "0"), uid)
    _, out = docker("compose", "exec", "-T", "api", "sh", "-c", "touch /should-fail 2>&1; echo $?")
    check("API root filesystem is read-only", "Read-only" in out, out)
    _, out = docker(
        "compose", "exec", "-T", "api", "python", "-c",
        "import urllib.request\n"
        "try:\n urllib.request.urlopen('https://example.com', timeout=4); print('REACHED')\n"
        "except Exception as e: print('blocked', type(e).__name__)",
    )  # fmt: skip
    check("API has no route to the internet by default", "REACHED" not in out, out)
    _, out = docker(
        "compose", "exec", "-T", "api", "sh", "-c", "grep -E '^Cap(Eff|Prm)' /proc/self/status"
    )
    caps = [line.split()[-1] for line in out.splitlines() if line.startswith("Cap")]
    check("API holds no Linux capabilities", bool(caps) and all(set(c) <= {"0"} for c in caps), out)


def cli_and_logs() -> None:
    code, out = docker("compose", "run", "--rm", "-T", "cli", "audit", "--stdin", "-f", "json",
                       stdin=CANARY + "\n")  # fmt: skip
    check(
        "the CLI container audits a password from stdin",
        code in (0, 1) and '"audit"' in out,
        out[:150],
    )
    check("the CLI output does not contain the password", CANARY not in out)
    code, out = docker("compose", "run", "--rm", "cli", "version")
    check("the CLI container reports its version", code == 0 and "PassAudit" in out, out)
    _, logs = docker("compose", "logs", "--no-color")
    check("no container log contains the password", CANARY not in logs)
    _, web_logs = docker("compose", "logs", "--no-color", "web")
    check(
        "nginx logged no request lines",
        "POST /api" not in web_logs and "GET /api" not in web_logs,
        web_logs[-200:],
    )


if __name__ == "__main__":
    web_and_api()
    isolation()
    cli_and_logs()
    print("\nFAILED" if failures else "\nALL PASSED", failures)
    sys.exit(1 if failures else 0)
