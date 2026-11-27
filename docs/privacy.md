# Privacy

PassAudit exists to inspect passwords, so its privacy rules are strict and mostly structural: the
code cannot do the risky thing, rather than promising not to. This page says what happens to a
password, what is stored or logged, and the one optional thing that can leave your machine. The
technical threat model is in [security.md](security.md).

## In short

* A default install **makes no network connection** and sends nothing anywhere. No analytics, no
  telemetry, no update check, no third-party fonts, scripts or images.
* A password is analysed **in memory** and **never stored, logged, cached, or returned**.
* The only outbound call PassAudit can make is an **opt-in** breach check that sends **five
  characters of a hash**, never the password. It needs two separate switches (below).
* Reports contain scores and fixed advice, never passwords or personal details, and a report that
  would contain one is refused.

## Where a password goes

| Step | What happens |
| --- | --- |
| You type it in the web app | It lives in the page's memory only: not in the URL, local storage, session storage, cookies, history, or the console. A hidden password field with autofill off |
| The browser sends it | One `POST` to the same origin (`/api/v1/...`) with a JSON body; never a query string or header; `Referrer-Policy: no-referrer` |
| The API receives it | Analysed in a worker thread, in memory. The request body is not logged, copied or kept. Errors never echo it |
| The result comes back | Positions, scores and fixed-text advice. No part of the password, no hash of it |
| The page afterwards | The password is cleared from the form after a successful audit (an opt-in setting can keep it in memory only) |
| The command line | Read from a hidden prompt, from `--stdin`, or from a file you name: **never from an argument**, which would appear in process lists and shell history |

## What is stored

| Place | Contents |
| --- | --- |
| Browser local storage | UI preferences only: theme, sidebar state, two privacy toggles, and the *policy rules* you set. A test fails if any other key appears. Never a password, a personal detail, or a result |
| Server disk | Nothing. The API has no database and writes no files |
| Server logs | Method, known route, status code, duration, and a random request id. Unknown paths, query strings, headers and bodies are never logged. Unexpected errors log the exception class name only |
| nginx (Docker) | No access log; the error log records critical conditions only; request bodies are kept in memory |
| Reports you export | Scores, finding kinds, rule ids, advice codes, settings, and what external checks ran. See below |
| The reuse index (if you build one) | Keyed HMAC digests and dataset names, in a file you choose, with its key in a separate file. See [security.md](security.md#authorized-reuse-auditing-local-datasets) |

## Reports

JSON and CSV reports are built only from analysis results. They contain **no password, no personal
details, and no password-derived value** (no hash, no fragment). Before a report is written, it is
scanned for every submitted password and personal detail; if one appears, the report is refused.
Labels you give to batch entries are sanitised and replaced if they contain the password they
describe. Each report records which external checks ran. A checksum detects accidental change; it
is not a signature.

## The online breach check

Off by default. To use it, **both** must be true:

1. the operator enabled it on the server (`PASSAUDIT_EXTERNAL_LOOKUPS_ENABLED=true`; in Docker,
   by adding `docker-compose.egress.yml`), **and**
2. the request asked for it (`exposure.breach = "online"` in the API, an unticked-by-default
   option in the web app that is not remembered, or `--breach online --allow-external` on the CLI).

**What is sent:** the first **5 hexadecimal characters** of the password's SHA-1 hash, in the URL
of an HTTPS request to `api.pwnedpasswords.com` (or a mirror you configure), with a generic
`User-Agent`. About a thousand known breached hashes share any such prefix; the service answers
with all of their remaining characters and PassAudit compares them **locally**.

**What is never sent:** the password, the full hash, the rest of the hash, the result, your
identity, cookies, or any header that identifies you. Redirects are never followed.

**What the service can still learn:** that *someone at your IP address* checked *something* at a
given time, and the 20-bit prefix. If the service operator already has a list of candidate
passwords, the prefix lets them test whether a candidate is consistent with your check. For a
password where even that matters, use the **local hash file** instead
(`PASSAUDIT_BREACH_LOCAL_FILE`): it needs no network at all.

**What "not found" means:** the password was not in that data set. It is not a guarantee that the
password is safe, and a failed lookup is reported as "unchecked", never as "clean".

## Personal information

The "personal information" field of an audit (a name, a date of birth, ...) is used to detect a
password that contains it. It is processed exactly like a password: in memory, never stored or
logged, never in a report. It is optional.

## Your responsibilities

* **Only audit passwords you are entitled to examine.** Auditing other people's passwords, or
  building a reuse index from their data, needs the owners' agreement and may be regulated where
  you are (for example by data-protection law). PassAudit makes you state your authorisation for
  reuse auditing and records it, but it **cannot verify it**.
* **Prefer test passwords** when trying the tool out, and prefer a local data set to an online
  lookup for anything sensitive.
* **Keep the service local.** It has no authentication and no TLS; it is built for one person on
  one machine. See [docker.md](docker.md) and [security.md](security.md#known-gaps).

## What PassAudit cannot protect against

Malware or a person with control of your machine (they can read the password before PassAudit
does), browser extensions, screen capture, and the fact that Python and JavaScript cannot wipe
strings from memory (a password remains in memory until garbage-collected; a crash dump or swap
file could contain it). Anyone who can run Docker commands on the host can read container memory.
