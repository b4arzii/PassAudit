"""Phase 8 command options shared by ``audit``, ``batch`` and ``policy check``.

* **Profiles and dictionaries** - ``--profile`` / ``--profiles-file`` select a named policy;
  ``--dictionary`` adds word lists to the dictionary analysis.
* **Breach checks (opt-in)** - ``--breach local`` searches a sorted hash file (no network);
  ``--breach online`` additionally needs ``--allow-external`` and sends only a 5-character hash
  prefix per distinct password to the range service. Without the flags nothing is looked up.
* **Reuse auditing (opt-in, authorised)** - ``--reuse-index`` needs the key file, the
  ``--confirm-authorized`` flag and an ``--authorization-ref``; the reference lands in reports.

Every failure becomes a ``CliError`` with fixed text: no passwords, hashes, keys or paths.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path  # runtime import: Typer resolves option annotations
from typing import TYPE_CHECKING, Annotated, Any

import typer
from pydantic import ValidationError

from passaudit.analysis import (
    DictionarySet,
    ExposureSignals,
    PasswordPolicy,
    PasswordUsage,
    PolicyProfile,
    ReuseExposure,
    UnknownProfileError,
)
from passaudit.breach import (
    BreachChecker,
    BreachLookupError,
    HibpRangeProvider,
    SortedHashFile,
)
from passaudit.cli.errors import CliError, ExitCode
from passaudit.cli.inputs import load_policy
from passaudit.profiles import ProfileFileError, load_profiles
from passaudit.reporting import describe_external
from passaudit.reuse import (
    ReuseIndex,
    ReuseIndexError,
    SourceInfo,
    read_key_file,
    require_authorization,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence


class BreachMode(StrEnum):
    OFF = "off"
    LOCAL = "local"
    ONLINE = "online"


# ------------------------------------------------------------------ option aliases

ProfileOption = Annotated[
    str | None,
    typer.Option(
        "--profile",
        metavar="NAME",
        help="Use a named policy profile (see 'policy profiles'). Not combinable with --policy.",
        rich_help_panel="Policy",
    ),
]
ProfilesFileOption = Annotated[
    Path | None,
    typer.Option(
        "--profiles-file",
        metavar="FILE",
        help="JSON/TOML file with extra policy profiles to offer next to the built-in ones.",
        rich_help_panel="Policy",
    ),
]
DictionaryOption = Annotated[
    list[Path] | None,
    typer.Option(
        "--dictionary",
        metavar="FILE",
        help="Extra word list (one word per line) for dictionary analysis. Repeatable.",
        rich_help_panel="Context",
    ),
]
BreachOption = Annotated[
    BreachMode,
    typer.Option(
        "--breach",
        case_sensitive=False,
        help="Breach check (opt-in). local = search --breach-file, no network; online = ask a "
        "range service about a 5-character hash prefix (also needs --allow-external).",
        rich_help_panel="Exposure checks",
    ),
]
BreachFileOption = Annotated[
    Path | None,
    typer.Option(
        "--breach-file",
        metavar="FILE",
        help="Sorted 'SHA1[:count]' hash file (Pwned Passwords offline format) for --breach local.",
        rich_help_panel="Exposure checks",
    ),
]
AllowExternalOption = Annotated[
    bool,
    typer.Option(
        "--allow-external",
        help="Confirm that --breach online may contact the range service (a 5-character hash "
        "prefix per distinct password is sent; never a password or a full hash).",
        rich_help_panel="Exposure checks",
    ),
]
BreachUrlOption = Annotated[
    str,
    typer.Option(
        "--breach-url",
        metavar="URL",
        help="Range endpoint for --breach online (https only; a self-hosted mirror is fine).",
        rich_help_panel="Exposure checks",
    ),
]
ReuseIndexOption = Annotated[
    Path | None,
    typer.Option(
        "--reuse-index",
        metavar="FILE",
        help="Authorised reuse index to compare against (see 'reuse build').",
        rich_help_panel="Exposure checks",
    ),
]
ReuseKeyOption = Annotated[
    Path | None,
    typer.Option(
        "--reuse-key-file",
        metavar="FILE",
        help="Key file for --reuse-index.",
        rich_help_panel="Exposure checks",
    ),
]
ConfirmAuthorizedOption = Annotated[
    bool,
    typer.Option(
        "--confirm-authorized",
        help="State that you are authorised to hold and compare the indexed datasets.",
        rich_help_panel="Exposure checks",
    ),
]
AuthorizationRefOption = Annotated[
    str | None,
    typer.Option(
        "--authorization-ref",
        metavar="TEXT",
        help="Reference for the authorisation (ticket, engagement id...). Recorded in reports.",
        rich_help_panel="Exposure checks",
    ),
]


# ------------------------------------------------------------------ profiles


def resolve_profile(
    name: str | None, profiles_file: Path | None, policy_file: Path | None
) -> PolicyProfile | None:
    """The chosen profile, or ``None``. ``--profile`` and ``--policy`` are exclusive."""
    if profiles_file is not None and name is None:
        raise CliError("--profiles-file needs --profile NAME.", ExitCode.USAGE)
    if name is None:
        return None
    if policy_file is not None:
        raise CliError("Use either --profile or --policy, not both.", ExitCode.USAGE)
    try:
        return load_profiles(profiles_file).get(name)
    except UnknownProfileError:
        raise CliError(
            "No policy profile with that name exists. List them with 'policy profiles'.",
            ExitCode.USAGE,
        ) from None
    except ProfileFileError as exc:
        raise CliError(str(exc)) from None


def effective_policy(
    profile: PolicyProfile | None, policy_file: Path | None, overrides: dict[str, Any]
) -> PasswordPolicy:
    """Defaults/file/profile first, then command-line overrides on top."""
    if profile is None:
        return load_policy(policy_file, overrides)
    data = profile.policy.model_dump()
    data.update({key: value for key, value in overrides.items() if value is not None})
    try:
        return PasswordPolicy.model_validate(data)
    except ValidationError:
        raise CliError("The command-line overrides make the profile's policy invalid.") from None


def effective_usage(profile: PolicyProfile | None, usage: PasswordUsage) -> PasswordUsage:
    """A profile's usage applies unless ``--usage`` chose something other than the default."""
    if profile is not None and usage is PasswordUsage.GENERAL:
        return profile.usage
    return usage


def load_dictionaries(paths: Sequence[Path] | None) -> DictionarySet | None:
    if not paths:
        return None
    try:
        return DictionarySet.bundled().with_extra_files(paths)
    except FileNotFoundError:
        raise CliError("A --dictionary file was not found.") from None
    except UnicodeDecodeError:
        raise CliError("A --dictionary file is not valid UTF-8.") from None
    except (OSError, ValueError):
        raise CliError("A --dictionary file could not be read.") from None


# ------------------------------------------------------------------ exposure


@dataclass(slots=True)
class Exposure:
    """The external checks resolved for one run. ``active`` is False when nothing was asked."""

    mode: BreachMode = BreachMode.OFF
    checker: BreachChecker | None = None
    index: ReuseIndex | None = None
    authorization_reference: str | None = None
    online_host: str | None = None

    @property
    def active(self) -> bool:
        return self.mode is not BreachMode.OFF or self.index is not None

    def signals(self, passwords: Sequence[str]) -> list[ExposureSignals | None]:
        """Run the requested lookups for ``passwords`` (parallel result list)."""
        if not self.active:
            return [None] * len(passwords)
        breach = None
        if self.checker is not None and self.mode is not BreachMode.OFF:
            breach = self.checker.check_many(
                list(passwords),
                self.mode.value,  # type: ignore[arg-type]
                max_prefixes=max(len(passwords), 1),
            )
        reuse: list[ReuseExposure] | None = None
        if self.index is not None:
            reuse = []
            for password in passwords:
                sources = self.index.lookup(password)
                reuse.append(
                    ReuseExposure(status="reused" if sources else "clean", sources=sources)
                )
        return [
            ExposureSignals(
                breach=breach[i] if breach is not None else None,
                reuse=reuse[i] if reuse is not None else None,
            )
            for i in range(len(passwords))
        ]

    def sources(self) -> tuple[SourceInfo, ...]:
        return self.index.sources if self.index is not None else ()

    def external_block(self) -> dict[str, Any]:
        """What was consulted, for the report (names and modes only - no data)."""
        return describe_external(
            breach=self.mode.value,
            online_host=self.online_host,
            reuse_datasets=[s.id for s in self.sources()] if self.index is not None else None,
            authorization_reference=self.authorization_reference,
        )


def resolve_exposure(
    *,
    breach: BreachMode,
    breach_file: Path | None,
    allow_external: bool,
    breach_url: str,
    reuse_index: Path | None,
    reuse_key_file: Path | None,
    confirm_authorized: bool,
    authorization_ref: str | None,
    notify: Callable[[str], None],
) -> Exposure:
    """Validate the opt-in options and build the lookups. Nothing is contacted here."""
    exposure = Exposure(mode=breach)
    local = online = None
    if breach is BreachMode.LOCAL:
        if breach_file is None:
            raise CliError("--breach local needs --breach-file FILE.", ExitCode.USAGE)
        try:
            local = SortedHashFile(breach_file)
        except BreachLookupError:
            raise CliError("The --breach-file could not be read.") from None
        if not local.verify_sorted():
            raise CliError("The --breach-file is not sorted by hash.")
    elif breach is BreachMode.ONLINE:
        if not allow_external:
            raise CliError(
                "--breach online contacts an external service (only a 5-character hash prefix "
                "is sent). Add --allow-external to confirm.",
                ExitCode.USAGE,
            )
        try:
            provider = HibpRangeProvider(breach_url)
        except ValueError:
            raise CliError("--breach-url must be an https URL.", ExitCode.USAGE) from None
        online, exposure.online_host = provider, provider.host
        notify(
            f"Online breach check: sending 5-character hash prefixes to {provider.host}. "
            "No password or full hash leaves this machine."
        )
    elif breach_file is not None or allow_external:
        raise CliError(
            "--breach-file / --allow-external need --breach local|online.", ExitCode.USAGE
        )
    if breach is not BreachMode.OFF:
        exposure.checker = BreachChecker(local=local, online=online)

    if reuse_index is not None:
        if reuse_key_file is None:
            raise CliError("--reuse-index needs --reuse-key-file.", ExitCode.USAGE)
        try:
            exposure.authorization_reference = require_authorization(
                confirm_authorized, authorization_ref
            )
            exposure.index = ReuseIndex.load(reuse_index, read_key_file(reuse_key_file))
        except ReuseIndexError as exc:
            code = (
                ExitCode.USAGE if exc.reason == "authorization_required" else ExitCode.INPUT_ERROR
            )
            raise CliError(str(exc), code) from None
    elif reuse_key_file is not None or confirm_authorized or authorization_ref is not None:
        raise CliError(
            "--reuse-key-file, --confirm-authorized and --authorization-ref need --reuse-index.",
            ExitCode.USAGE,
        )
    return exposure
