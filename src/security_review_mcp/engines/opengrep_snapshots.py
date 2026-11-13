"""Snapshots of the OpenGrep rules on disk, the copy that OpenGrep reads (``--config``).

The rules live in the database of the Controller server. OpenGrep only reads files: each process
that runs it (the Controller server, a scan engine) writes the rules it was given into a
snapshot, a directory named by the digest of the manifest (rule id → SHA-256), and switches to a
new snapshot when the manifest changes. Only the new and changed rules are fetched; the others
are copied from the current snapshot. The scans running keep the snapshot they started with,
which is deleted once the last of them ends. The directory is a cache: deleting it loses nothing.
"""

import hashlib
import json
import logging
import os
import re
import shutil
import tempfile
import threading
from collections import Counter
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path

from .opengrep import OpenGrepError

logger = logging.getLogger("security_review_mcp.engines")

# A snapshot is named by the digest of its manifest
_SNAPSHOT = re.compile(r"[0-9a-f]{64}")
_TEMPORARY_PREFIX = ".sync-"
# A rule id becomes a file name: never a path (same pattern as opengrep_rule_store.RULE_ID)
_RULE_ID = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9._-]{2,79}")


def rule_digest(content: str) -> str:
    """SHA-256 of an OpenGrep rule file."""
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def manifest_digest(manifest: dict[str, str] | list) -> str:
    """Digest of a whole manifest or rule set: the ``ETag`` of the controller, the name of a
    snapshot."""
    return hashlib.sha256(json.dumps(manifest, sort_keys=True).encode()).hexdigest()


class SnapshotChangedError(OpenGrepError):
    """A rule changed or was deleted while the snapshot was being built (try again)."""


class RuleSnapshots:
    """Snapshots of the OpenGrep rules in ``directory`` (created 0700, its old snapshots
    deleted at the first update)."""

    def __init__(self, directory: Path) -> None:
        self.directory = directory
        # Guards the state below
        self._lock = threading.Lock()
        self._current: Path | None = None
        self._manifest: dict[str, str] = {}
        self._digest: str | None = None
        # Scans running on each snapshot
        self._users: Counter[Path] = Counter()
        self._prepared = False

    @property
    def digest(self) -> str | None:
        """Digest of the manifest of the current snapshot (None: no snapshot yet)."""
        return self._digest if self._current is not None else None

    @property
    def ready(self) -> bool:
        """True once a snapshot exists."""
        return self._current is not None

    def reset(self) -> None:
        """Forget the current manifest: the next update fetches every rule again (the copy may
        be damaged)."""
        with self._lock:
            self._manifest, self._digest = {}, None

    def update(
        self, manifest: dict[str, str], fetch: Callable[[list[str]], dict[str, str]]
    ) -> tuple[int, int]:
        """Switch to the snapshot of ``manifest``, fetching the rules it lacks with ``fetch``
        (rule ids → contents, a missing id meaning a rule deleted meanwhile).

        Returns:
            The number of rules fetched and of rules removed (0, 0 when up to date).

        Raises:
            SnapshotChangedError: If a fetched rule does not match its digest.
            OpenGrepError: If a rule id is not a valid file name.
            OSError: If the snapshot cannot be written.
        """
        if not all(_RULE_ID.fullmatch(rule_id) for rule_id in manifest):
            raise OpenGrepError("Invalid OpenGrep rule identifier")
        digest = manifest_digest(manifest)
        with self._lock:
            if digest == self._digest and self._current is not None:
                return 0, 0
            self._prepare()
            needed = [
                rule_id for rule_id, sha in manifest.items() if self._manifest.get(rule_id) != sha
            ]
            contents = fetch(needed) if needed else {}
            for rule_id in needed:
                if rule_id not in contents or rule_digest(contents[rule_id]) != manifest[rule_id]:
                    raise SnapshotChangedError(
                        "an OpenGrep rule changed during the synchronization"
                    )
            target = self.directory / digest
            if not target.is_dir():
                self._build(target, manifest, contents)
            previous = self._current
            removed = len(self._manifest.keys() - manifest.keys())
            self._current, self._manifest, self._digest = target, manifest, digest
            if previous is not None and previous != target and not self._users[previous]:
                remove(previous)
            return len(needed), removed

    @contextmanager
    def use(self) -> Iterator[Path | None]:
        """Hold the current snapshot (None: none yet) for one scan."""
        with self._lock:
            path = self._current
            if path is not None:
                self._users[path] += 1
        try:
            yield path
        finally:
            if path is not None:
                with self._lock:
                    self._users[path] -= 1
                    if self._users[path] <= 0:
                        del self._users[path]
                        if path != self._current:
                            remove(path)

    def _prepare(self) -> None:
        """Create the directory (0700) and delete the snapshots of a previous run."""
        if self._prepared:
            return
        if self.directory.is_symlink():
            raise OpenGrepError("SECREVIEW_OPENGREP_RULES_DIR must not be a symbolic link")
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        for entry in self.directory.iterdir():
            if (
                entry.is_dir()
                and not entry.is_symlink()
                and (_SNAPSHOT.fullmatch(entry.name) or entry.name.startswith(_TEMPORARY_PREFIX))
            ):
                remove(entry)
        self._prepared = True

    def _build(self, target: Path, manifest: dict[str, str], contents: dict[str, str]) -> None:
        """Write the snapshot ``target``: the fetched rules, the others copied from the current
        snapshot, in a temporary directory renamed at the end."""
        temporary = Path(tempfile.mkdtemp(prefix=_TEMPORARY_PREFIX, dir=self.directory))
        try:
            for rule_id in manifest:
                destination = temporary / f"{rule_id}.yaml"
                if rule_id in contents:
                    with open(destination, "x", encoding="utf-8") as file:
                        file.write(contents[rule_id])
                else:
                    assert self._current is not None
                    shutil.copyfile(self._current / f"{rule_id}.yaml", destination)
                os.chmod(destination, 0o600)
            os.rename(temporary, target)
        except BaseException:
            remove(temporary)
            raise


def remove(path: Path) -> None:
    """Delete a snapshot, logging a failure (a later start deletes it)."""
    try:
        shutil.rmtree(path)
    except OSError as exc:
        logger.warning("Could not delete the OpenGrep rules %s: %s", path.name, type(exc).__name__)
