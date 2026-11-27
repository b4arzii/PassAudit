"""Terminal output built with Rich.

Design rules: only ASCII glyphs (safe on any console encoding), pass/fail always spelled out
in words (colour is decoration, never the only signal), and every string that did not come
from a fixed template is escaped and made encodable before printing.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from rich import box
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from passaudit.analysis import PasswordAnalysis, PasswordPolicy, Priority, RiskLevel
from passaudit.cli.policy_view import rule_rows

if TYPE_CHECKING:
    from collections.abc import Sequence

    from rich.console import Console

    from passaudit.cli.results import FailOn, PasswordResult, Verdict

LEVEL_STYLE: dict[str, str] = {
    RiskLevel.LOW.value: "green",
    RiskLevel.MODERATE.value: "yellow",
    RiskLevel.HIGH.value: "dark_orange",
    RiskLevel.CRITICAL.value: "bold red",
}
PRIORITY_STYLE: dict[Priority, str] = {
    Priority.HIGH: "bold red",
    Priority.MEDIUM: "yellow",
    Priority.LOW: "cyan",
}
OK_TAG = "[bold green]PASS[/]"
FAIL_TAG = "[bold red]FAIL[/]"
ENTROPY_NOTE = (
    "Entropy and crack-time figures are estimates, not guarantees. A password that has "
    "leaked is weak however strong it looks."
)


def safe_text(console: Console, text: str) -> str:
    """Escape Rich markup and replace characters the console cannot encode."""
    encoding = console.encoding or "utf-8"
    return escape(text.encode(encoding, errors="replace").decode(encoding, errors="replace"))


def risk_bar(score: int, *, width: int = 20) -> str:
    filled = round(width * max(0, min(score, 100)) / 100)
    return escape("[" + "#" * filled + "-" * (width - filled) + "]")


def level_markup(level: str) -> str:
    return f"[{LEVEL_STYLE[level]}]{level.upper()}[/]"


def verdict_markup(verdict: Verdict) -> str:
    if not verdict.failed:
        return OK_TAG
    return f"{FAIL_TAG} ({', '.join(verdict.reasons)})"


def _grid() -> Table:
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold", no_wrap=True)
    grid.add_column()
    return grid


# ------------------------------------------------------------------------------ audit


def _breach_text(status: str, source: str, count: int | None) -> str:
    if status == "breached":
        return f"{FAIL_TAG} found in breach data ({source}; seen {count} times)"
    if status == "clean":
        return f"{OK_TAG} not found in the {source} corpus (not a guarantee)"
    return f"[yellow]unavailable[/] ({source} lookup failed - the password is UNCHECKED)"


def render_audit(
    console: Console,
    analysis: PasswordAnalysis,
    policy: PasswordPolicy,
    verdict: Verdict,
    *,
    usage: str,
    details: bool,
) -> None:
    risk = analysis.risk
    strength = analysis.strength

    overview = _grid()
    overview.add_row(
        "Risk",
        f"{risk.score}/100  {risk_bar(risk.score)}  {level_markup(risk.level.value)}",
    )
    overview.add_row("Strength", f"{strength.score}/4 ({strength.label.value.replace('_', ' ')})")
    length_note = (
        f" (only the first {strength.analyzed_length} were scored for strength)"
        if strength.truncated
        else ""
    )
    overview.add_row("Length", f"{analysis.length} characters{length_note}")
    overview.add_row(
        "Entropy", f"~{analysis.entropy.estimated_bits:.0f} bits (conservative estimate)"
    )
    target = "met" if analysis.meets_usage_target else "[bold red]NOT met[/]"
    overview.add_row("Usage target", f"{target} for {usage.replace('_', ' ')}")
    overview.add_row(
        "Policy",
        OK_TAG
        if analysis.policy.compliant
        else f"{FAIL_TAG} ({len(analysis.policy.violations)} rule(s) violated)",
    )
    exposure = analysis.exposure
    if exposure is not None and exposure.breach is not None:
        overview.add_row(
            "Breach check",
            _breach_text(exposure.breach.status, exposure.breach.source, exposure.breach.count),
        )
    if exposure is not None and exposure.reuse is not None:
        overview.add_row(
            "Reuse check",
            f"{FAIL_TAG} found in: {escape(', '.join(exposure.reuse.sources))}"
            if exposure.reuse.status == "reused"
            else f"{OK_TAG} not in the authorised datasets",
        )
    overview.add_row("Verdict", verdict_markup(verdict))
    console.print(
        Panel(
            overview,
            title="[bold]PassAudit - password audit[/]",
            subtitle="password never displayed or stored",
            box=box.ROUNDED,
            expand=False,
        )
    )

    if strength.warning:
        console.print(f"[yellow]Note:[/] {escape(strength.warning)}")

    if analysis.findings:
        table = Table(title="Findings", box=box.SIMPLE_HEAD, title_justify="left")
        for column in ("Type", "Characters", "Detail"):
            table.add_column(column)
        for finding in analysis.findings:
            first = finding.start + 1
            last = finding.start + finding.length
            table.add_row(
                finding.kind.value.replace("_", " "),
                f"{first}-{last}" if last > first else str(first),
                escape(finding.description),
            )
        console.print(table)

    render_rules(console, rule_rows(policy, analysis), title="Policy")

    if details:
        crack = Table(title="Estimated time to crack", box=box.SIMPLE_HEAD, title_justify="left")
        crack.add_column("Attack scenario")
        crack.add_column("Time")
        times = strength.crack_times
        crack.add_row("Online, throttled (100 guesses/hour)", times.online_throttled)
        crack.add_row("Online, unthrottled (10 guesses/second)", times.online_unthrottled)
        crack.add_row("Offline, slow hash (10^4 guesses/second)", times.offline_slow_hash)
        crack.add_row("Offline, fast hash (10^10 guesses/second)", times.offline_fast_hash)
        console.print(crack)

        breakdown = Table(title="Risk score breakdown", box=box.SIMPLE_HEAD, title_justify="left")
        breakdown.add_column("Factor")
        breakdown.add_column("Points", justify="right")
        breakdown.add_column("Why")
        for component in risk.components:
            cap = f"/{component.max_points}" if component.max_points is not None else ""
            breakdown.add_row(
                component.factor.value.replace("_", " "),
                f"{component.points}{cap}",
                escape(component.explanation),
            )
        console.print(breakdown)

    console.print("[bold]Recommendations[/]")
    for rec in analysis.recommendations:
        style = PRIORITY_STYLE[rec.priority]
        console.print(f"  [{style}]{rec.priority.value.upper():<6}[/] {escape(rec.message)}")
    if details:
        console.print(f"\n[dim]{ENTROPY_NOTE}[/]")


def render_rules(console: Console, rows: list[dict[str, Any]], *, title: str) -> None:
    table = Table(title=title, box=box.SIMPLE_HEAD, title_justify="left")
    table.add_column("Rule")
    table.add_column("Result")
    table.add_column("Detail")
    for row in rows:
        failed = row["status"] == "fail"
        unchecked = row["status"] == "unchecked"
        table.add_row(
            escape(str(row["requirement"])),
            "[yellow]NOT CHECKED[/]" if unchecked else (FAIL_TAG if failed else OK_TAG),
            escape(str(row["message"])) if failed or unchecked else "",
        )
    console.print(table)


# ------------------------------------------------------------------------ policy check


def render_policy_check(
    console: Console,
    rows: list[dict[str, Any]],
    verdict_failed: bool,
    length: int,
) -> None:
    render_rules(console, rows, title=f"Policy check ({length} characters)")
    failed = sum(1 for row in rows if row["status"] == "fail")
    if verdict_failed:
        console.print(f"[bold red]FAIL[/] - {failed} of {len(rows)} rules violated.")
    else:
        unchecked = sum(1 for row in rows if row["status"] == "unchecked")
        if unchecked:
            console.print(
                f"[bold green]PASS[/] - all checked rules satisfied ({unchecked} not checked: "
                "they need an opt-in lookup)."
            )
        else:
            console.print(f"[bold green]PASS[/] - all {len(rows)} rules satisfied.")


# ----------------------------------------------------------------------------- batch


def render_batch(
    console: Console,
    results: Sequence[PasswordResult],
    summary: dict[str, Any],
    *,
    source: str,
    fail_on: FailOn,
    show: int,
) -> None:
    overview = _grid()
    overview.add_row("Source", safe_text(console, source))
    overview.add_row(
        "Passwords", f"{summary['entries']} ({summary['skipped_blank']} blank skipped)"
    )
    overview.add_row("Passed", f"[green]{summary['passed']}[/]")
    overview.add_row("Failed", f"[red]{summary['failed']}[/]" if summary["failed"] else "0")
    if summary["errors"]:
        overview.add_row("Unanalysable", f"[red]{summary['errors']}[/] (too long)")
    overview.add_row("Reused in batch", str(summary["reused_in_batch"]))
    if summary["breach_checked"]:
        overview.add_row("Found in breach data", str(summary["breached"]))
    if summary["reuse_checked"]:
        overview.add_row("Reused in datasets", str(summary["reused_in_datasets"]))
    if summary["average_risk_score"] is not None:
        overview.add_row(
            "Risk (avg / max)", f"{summary['average_risk_score']} / {summary['max_risk_score']}"
        )
    overview.add_row(
        "Fails on",
        f"any policy violation or risk >= {fail_on.value}"
        if fail_on.value != "none"
        else "policy violations only",
    )
    console.print(
        Panel(
            overview,
            title="[bold]PassAudit - batch audit[/]",
            subtitle="passwords never displayed or stored",
            box=box.ROUNDED,
            expand=False,
        )
    )

    levels = Table(title="Risk distribution", box=box.SIMPLE_HEAD, title_justify="left")
    levels.add_column("Level")
    levels.add_column("Count", justify="right")
    levels.add_column("Share")
    analyzed = max(summary["analyzed"], 1)
    for level, count in summary["risk_levels"].items():
        bar = "#" * round(30 * count / analyzed)
        levels.add_row(level_markup(level), str(count), f"[{LEVEL_STYLE[level]}]{bar}[/]")
    console.print(levels)

    ranked = sorted(
        results,
        key=lambda r: (-(r.analysis.risk.score if r.analysis else 101), r.index),
    )[:show]
    table = Table(
        title=f"Highest-risk entries (showing {len(ranked)} of {len(results)})",
        box=box.SIMPLE_HEAD,
        title_justify="left",
    )
    for column, justify in (
        ("#", "right"), ("Line", "right"), ("Label", "left"), ("Len", "right"),
        ("Risk", "left"), ("Strength", "left"), ("Result", "left"), ("Notes", "left"),
    ):  # fmt: skip
        table.add_column(column, justify=justify)  # type: ignore[arg-type]
    for r in ranked:
        notes = []
        if r.reused_in_batch:
            notes.append("reused")
        if r.error:
            notes.append(r.error.replace("_", " "))
        if r.analysis:
            risk = f"{r.analysis.risk.score} {level_markup(r.analysis.risk.level.value)}"
            strength = f"{r.analysis.strength.score}/4"
        else:
            risk = strength = "-"
        table.add_row(
            str(r.index),
            str(r.line) if r.line is not None else "-",
            safe_text(console, r.label) if r.label else "",
            str(r.length),
            risk,
            strength,
            FAIL_TAG if r.verdict.failed else OK_TAG,
            ", ".join(notes),
        )
    console.print(table)
    if summary["failed"]:
        console.print(
            f"[bold red]FAIL[/] - {summary['failed']} of {summary['entries']} passwords failed."
        )
    else:
        console.print(f"[bold green]PASS[/] - all {summary['entries']} passwords passed.")


def render_notice(console: Console, text: str) -> None:
    console.print(Text(text, style="dim"))
