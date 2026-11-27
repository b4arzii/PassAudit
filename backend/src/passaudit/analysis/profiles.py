"""Configurable policy profiles: named, documented bundles of policy rules.

A *profile* is a name plus a complete :class:`PasswordPolicy` (and the usage it targets), so a
team can say "audit against ``enterprise``" instead of passing a dozen numbers. The built-in
profiles below are starting points - **inspired by** public guidance, not certifications of
compliance with any standard. Operators add their own profiles from a file (loaded by
``passaudit.profiles``; this module does no file I/O).

Rules for custom profiles, enforced here: names are lower-case slugs, a custom profile may not
reuse a built-in name (so ``--profile strict`` always means the same thing), and every policy
is validated by ``PasswordPolicy`` (unknown fields are rejected).
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Annotated

from pydantic import BaseModel, ConfigDict, Field, field_validator

from passaudit.analysis.models import PasswordPolicy, PasswordUsage

if TYPE_CHECKING:
    from collections.abc import Iterable

NAME_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_-]{0,47}$")
MAX_PROFILES = 100


class UnknownProfileError(LookupError):
    """No profile has this name. The message never contains the requested text verbatim."""

    def __init__(self) -> None:
        super().__init__("No policy profile with that name exists.")


class PolicyProfileError(ValueError):
    """A set of profiles is invalid (duplicate names, built-in name reused, too many)."""


class PolicyProfile(BaseModel):
    """A named policy. Frozen; unknown fields are rejected."""

    model_config = ConfigDict(frozen=True, extra="forbid", hide_input_in_errors=True)

    name: str
    title: Annotated[str, Field(min_length=1, max_length=80)]
    description: Annotated[str, Field(max_length=500)] = ""
    policy: PasswordPolicy = Field(default_factory=PasswordPolicy)
    #: What the passwords audited with this profile protect (drives strength targets/advice).
    usage: PasswordUsage = PasswordUsage.GENERAL
    #: Informational pointers (documents the profile was inspired by).
    references: Annotated[
        tuple[Annotated[str, Field(max_length=200)], ...], Field(max_length=5)
    ] = ()
    builtin: bool = False

    @field_validator("name")
    @classmethod
    def _slug(cls, value: str) -> str:
        if not NAME_PATTERN.fullmatch(value):
            raise ValueError("name must be a lower-case slug: letters, digits, '-' or '_'")
        return value


def _builtin(name: str, title: str, description: str, **kwargs: object) -> PolicyProfile:
    policy_fields = kwargs.pop("policy", {})
    usage = kwargs.pop("usage", PasswordUsage.GENERAL)
    references = kwargs.pop("references", ())
    return PolicyProfile.model_validate(
        {
            "name": name,
            "title": title,
            "description": description,
            "policy": PasswordPolicy.model_validate(policy_fields),
            "usage": usage,
            "references": references,
            "builtin": True,
        }
    )


_BUILTIN: tuple[PolicyProfile, ...] = (
    _builtin(
        "default",
        "Default",
        "Sensible length, a common-password blocklist and no forced character mix.",
        policy={},
    ),
    _builtin(
        "nist-inspired",
        "NIST-inspired",
        "Long minimum, generous maximum, no composition rules, blocklists including breach "
        "data (needs the opt-in breach check; otherwise that rule shows as unchecked). "
        "Inspired by NIST SP 800-63B; not a compliance claim.",
        policy={
            "min_length": 15,
            "max_length": 128,
            "min_strength_score": 2,
            "block_breached_passwords": True,
        },
        references=("NIST SP 800-63B, section 5.1.1 (memorized secrets)",),
    ),
    _builtin(
        "enterprise",
        "Enterprise",
        "A typical corporate baseline: 14 characters, mixed case and a digit, no long runs, "
        "a strength floor and a breach check.",
        policy={
            "min_length": 14,
            "min_lowercase": 1,
            "min_uppercase": 1,
            "min_digits": 1,
            "min_unique_characters": 8,
            "max_repeat_run": 3,
            "max_sequence_length": 4,
            "max_keyboard_run": 4,
            "min_strength_score": 3,
            "block_breached_passwords": True,
        },
        usage=PasswordUsage.ONLINE_ACCOUNT,
    ),
    _builtin(
        "high-security",
        "High security",
        "For privileged accounts: 16+ characters, tight pattern limits, no dictionary-built "
        "passwords, a high strength score and a breach check.",
        policy={
            "min_length": 16,
            "min_unique_characters": 10,
            "max_repeat_run": 2,
            "max_sequence_length": 3,
            "max_keyboard_run": 4,
            "min_strength_score": 3,
            "block_dictionary_words": True,
            "block_breached_passwords": True,
        },
        usage=PasswordUsage.PRIVILEGED_ACCOUNT,
    ),
    _builtin(
        "passphrase",
        "Passphrase",
        "For master passwords and encryption keys: 20+ characters, spaces allowed, "
        "strength 3 or better; word-based passphrases are welcome.",
        policy={"min_length": 20, "min_strength_score": 3, "block_breached_passwords": True},
        usage=PasswordUsage.MASTER_PASSWORD,
    ),
    _builtin(
        "legacy-complexity",
        "Legacy complexity",
        "Classic 8-character upper/lower/digit/symbol rules. Common in old systems; not "
        "recommended by current guidance.",
        policy={
            "min_length": 8,
            "min_lowercase": 1,
            "min_uppercase": 1,
            "min_digits": 1,
            "min_symbols": 1,
            "min_strength_score": 0,
        },
    ),
    _builtin(
        "minimal",
        "Minimal",
        "Only blocks very short and very common passwords.",
        policy={"min_length": 8, "min_strength_score": 0, "forbid_personal_info": False},
    ),
)


class ProfileRegistry:
    """An immutable, ordered set of profiles with unique names."""

    def __init__(self, profiles: Iterable[PolicyProfile]) -> None:
        by_name: dict[str, PolicyProfile] = {}
        for profile in profiles:
            if profile.name in by_name:
                raise PolicyProfileError("Two policy profiles share the same name.")
            by_name[profile.name] = profile
        if len(by_name) > MAX_PROFILES:
            raise PolicyProfileError(f"At most {MAX_PROFILES} policy profiles are supported.")
        self._by_name = by_name

    def __len__(self) -> int:
        return len(self._by_name)

    def __contains__(self, name: object) -> bool:
        return isinstance(name, str) and name in self._by_name

    def names(self) -> list[str]:
        return list(self._by_name)

    def all(self) -> list[PolicyProfile]:
        return list(self._by_name.values())

    def get(self, name: str) -> PolicyProfile:
        try:
            return self._by_name[name]
        except KeyError:
            raise UnknownProfileError from None

    def with_custom(self, custom: Iterable[PolicyProfile]) -> ProfileRegistry:
        """This registry plus ``custom`` profiles (which may not reuse a built-in name)."""
        extra = list(custom)
        for profile in extra:
            if profile.name in self._by_name:
                raise PolicyProfileError("A custom policy profile may not reuse a built-in name.")
            if profile.builtin:
                raise PolicyProfileError("A custom policy profile may not be marked built-in.")
        return ProfileRegistry([*self._by_name.values(), *extra])


BUILTIN_PROFILES = ProfileRegistry(_BUILTIN)
