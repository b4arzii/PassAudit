"""Authorized password-reuse auditing against local datasets.

An organisation that is *authorised* to hold password data from several systems (for example
during an internal audit, with the owners' agreement) can ask: "which of these passwords are
already used in dataset X?". PassAudit answers that without ever storing plaintext passwords or
unkeyed hashes:

* a dataset is turned into a **reuse index**: every password becomes an HMAC-SHA-256 digest
  under a random 32-byte key kept in a **separate key file**;
* the index file records only the dataset *names* and sizes, a random id, the creation time
  and the authorisation reference - and the digests;
* a lookup recomputes the digest of the password being audited and reports which dataset
  names contain it. Nothing else is learned or stored.

Without the key file the index cannot be searched, and brute-forcing it is no easier than
brute-forcing a random key. With the key, a fast keyed hash can be brute-forced like any fast
hash: **protect the key file like the datasets it indexes** (see ``docs/security.md``).

PassAudit cannot verify that you are authorised. It makes the claim explicit: building and
using an index needs a confirmation flag and an authorisation reference, which are recorded in
the index header and in reports.
"""

from passaudit.reuse.index import (
    ReuseIndex,
    ReuseIndexBuilder,
    ReuseIndexError,
    SourceInfo,
    generate_key,
    read_key_file,
    require_authorization,
    write_key_file,
)

__all__ = [
    "ReuseIndex",
    "ReuseIndexBuilder",
    "ReuseIndexError",
    "SourceInfo",
    "generate_key",
    "read_key_file",
    "require_authorization",
    "write_key_file",
]
