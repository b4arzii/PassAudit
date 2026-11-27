"""The optional integrations an API instance was configured with.

Built once at start-up from :class:`~passaudit.config.Settings` and kept on the service. Every
integration is **off unless the operator configured it**, and start-up fails loudly (with fixed,
path-free messages) if a configured file is unusable - a server that silently skipped a breach
list or reuse index would give a false sense of coverage.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from passaudit.analysis import DictionarySet, ProfileRegistry
from passaudit.breach import BreachChecker, BreachLookupError, HibpRangeProvider, SortedHashFile
from passaudit.profiles import ProfileFileError, load_profiles
from passaudit.reuse import ReuseIndex, ReuseIndexError, read_key_file

if TYPE_CHECKING:
    from passaudit.config import Settings


class IntegrationError(RuntimeError):
    """A configured integration could not be set up. The message is fixed text."""


@dataclass(frozen=True, slots=True)
class Integrations:
    checker: BreachChecker
    reuse_index: ReuseIndex | None
    profiles: ProfileRegistry
    dictionaries: DictionarySet
    online_host: str | None
    reuse_authorization_reference: str | None


def build_integrations(settings: Settings) -> Integrations:
    """Create the integrations the settings ask for (and nothing else)."""
    online = None
    online_host = None
    if settings.external_lookups_enabled:
        provider = HibpRangeProvider(
            settings.breach_api_url, timeout=settings.breach_timeout_seconds
        )
        online, online_host = provider, provider.host

    local = None
    if settings.breach_local_file is not None:
        try:
            local = SortedHashFile(settings.breach_local_file)
        except BreachLookupError:
            raise IntegrationError("The configured local breach file could not be read.") from None
        if not local.verify_sorted():
            raise IntegrationError("The configured local breach file is not sorted by hash.")

    reuse_index = None
    if settings.reuse_index_path is not None and settings.reuse_key_file is not None:
        try:
            key = read_key_file(settings.reuse_key_file)
            reuse_index = ReuseIndex.load(settings.reuse_index_path, key)
        except ReuseIndexError as exc:
            raise IntegrationError(f"The reuse index could not be loaded: {exc}") from None

    try:
        profiles = load_profiles(settings.policy_profiles_path)
    except ProfileFileError as exc:
        raise IntegrationError(f"The policy profiles file is unusable: {exc}") from None

    dictionaries = DictionarySet.bundled()
    if settings.dictionary_paths:
        try:
            dictionaries = dictionaries.with_extra_files(settings.dictionary_paths)
        except (OSError, ValueError, UnicodeDecodeError):
            raise IntegrationError("A configured dictionary file could not be read.") from None

    return Integrations(
        checker=BreachChecker(online=online, local=local),
        reuse_index=reuse_index,
        profiles=profiles,
        dictionaries=dictionaries,
        online_host=online_host,
        reuse_authorization_reference=(
            settings.reuse_authorization_reference.strip()
            if settings.reuse_authorization_reference
            else None
        ),
    )
