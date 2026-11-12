"""Rules of a scan engine, copied from the controller and brought up to date before each scan.

A scan engine reads no database: before each scan it reads the rules of the controller through
the REST API, with the access token of its enrollment (see controller_client):

- **internal rules**: ``GET /api/v1/engine/rules`` with the digest of its copy
  (``If-None-Match``); ``304`` when unchanged, otherwise the active rules, validated again here
  (the regexes as for the internal rules) and published to the registry of the engine.
- **OpenGrep rules** (when OpenGrep is enabled): ``GET /api/v1/engine/opengrep-rules`` gives the
  SHA-256 of each rule (``304`` when unchanged). The engine compares them with its copy (the
  diff), downloads the new and changed rules only (``POST``, by batches), checks each against
  its digest, and builds a new snapshot of the rules beside the previous one in
  SECREVIEW_OPENGREP_RULES_DIR: the scans running keep the snapshot they started with, which is
  deleted once the last of them ends.

When the controller does not answer, the engine keeps its copy and does not ask again for
RETRY_DELAY_SECONDS; without any copy yet, it cannot scan (the controller then treats it as
unavailable).
"""

import logging
import os
import re
import shutil
import tempfile
import threading
import time
from collections import Counter
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path

from pydantic import ValidationError

from ..rules import registry, rules_loader
from ..rules.opengrep_rule_store import MAX_RULE_CHARS
from ..rules.scanner import Rule
from .controller_client import ControllerClient, RevokedError
from .opengrep import OpenGrepError
from .protocol import (
    ENGINE_OPENGREP_RULES_PATH,
    ENGINE_RULES_PATH,
    RULE_FETCH_BATCH,
    EngineRuleSet,
    RuleContents,
    RuleFetch,
    RuleManifest,
    manifest_digest,
    rule_digest,
)

logger = logging.getLogger("security_review_mcp.engines")

# After a failed synchronization, the scans use the copy without asking for this long
RETRY_DELAY_SECONDS = 10
# Bound of a rule set or manifest (MAX_ENGINE_RULES entries) and of a batch of OpenGrep rules
# (JSON escapes a character in at most 6 bytes)
MAX_RULE_SET_BYTES = 16 * 1024 * 1024
MAX_MANIFEST_BYTES = 2 * 1024 * 1024
MAX_CONTENTS_BYTES = RULE_FETCH_BATCH * MAX_RULE_CHARS * 6 + 4096
# A snapshot is named by the digest of its manifest
_SNAPSHOT = re.compile(r"[0-9a-f]{64}")
_TEMPORARY_PREFIX = ".sync-"
UNAVAILABLE = "The rules of the Controller server are unavailable"


class RuleSyncError(OpenGrepError):
    """The rules could not be brought up to date (the message names no secret)."""


class RuleCache:
    """Copy of the rules of the controller: the internal rules, published to the registry, and
    snapshots of the OpenGrep rules in ``directory``, one per manifest (None: OpenGrep off)."""

    def __init__(
        self,
        client: ControllerClient,
        directory: Path | None,
        publish: Callable[[list[Rule], list[str]], object] = registry.publish,
    ) -> None:
        self.client = client
        self.directory = directory
        # Where the internal rules go: the registry of the engine
        self.publish = publish
        # One synchronization at a time; guards the state below
        self._lock = threading.Lock()
        self._rules_digest: str | None = None
        self._current: Path | None = None
        self._manifest: dict[str, str] = {}
        self._digest: str | None = None
        # Scans running on each OpenGrep snapshot
        self._users: Counter[Path] = Counter()
        self._prepared = False
        self._retry_at = 0.0

    @contextmanager
    def use(self) -> Iterator[Path | None]:
        """Bring the rules up to date and hold the OpenGrep snapshot (None: OpenGrep off) for
        one scan.

        Raises:
            RuleSyncError: If the engine has no copy of the rules and cannot get one.
        """
        path = self._acquire()
        try:
            yield path
        finally:
            if path is not None:
                with self._lock:
                    self._users[path] -= 1
                    if self._users[path] <= 0:
                        del self._users[path]
                        if path != self._current:
                            _remove(path)

    def refresh(self) -> None:
        """Bring the rules up to date (at the start of the engine).

        Raises:
            RuleSyncError: If the engine has no copy of the rules and cannot get one.
        """
        with self._lock:
            self._refresh()

    def _acquire(self) -> Path | None:
        with self._lock:
            self._refresh()
            if self._current is not None:
                self._users[self._current] += 1
            return self._current

    def _ready(self) -> bool:
        """True once the engine has a copy of every rule set it needs."""
        return self._rules_digest is not None and (
            self.directory is None or self._current is not None
        )

    def _refresh(self) -> None:
        """Synchronize, keeping the current copy when the controller cannot answer."""
        if self.client.revoked:
            raise RuleSyncError("The scan engine was revoked: restart it to enroll again")
        if self._ready() and time.monotonic() < self._retry_at:
            return
        try:
            self._sync_rules()
            if self.directory is not None:
                self._prepare()
                self._sync_opengrep()
        except RevokedError:
            # A revoked engine stops scanning, whatever copy it has
            raise RuleSyncError("The scan engine was revoked: restart it to enroll again") from None
        except (OpenGrepError, OSError) as exc:
            self._retry_at = time.monotonic() + RETRY_DELAY_SECONDS
            reason = str(exc) if isinstance(exc, OpenGrepError) else type(exc).__name__
            if isinstance(exc, OSError):
                # The copy may be damaged: download every OpenGrep rule next time
                self._manifest, self._digest = {}, None
            if not self._ready():
                logger.warning("%s: %s", UNAVAILABLE, reason)
                raise RuleSyncError(UNAVAILABLE) from None
            logger.warning("Keeping the rules of the previous synchronization: %s", reason)

    # ── Internal rules ───────────────────────────────────────────────────────

    def _sync_rules(self) -> None:
        """Publish the active internal rules of the controller when they changed."""
        headers = {"If-None-Match": f'"{self._rules_digest}"'} if self._rules_digest else {}
        raw = self.client.request("GET", ENGINE_RULES_PATH, None, headers, MAX_RULE_SET_BYTES)
        if raw is None:
            return
        try:
            entries = [
                rule.model_dump(mode="json")
                for rule in EngineRuleSet.model_validate_json(raw).rules
            ]
        except ValidationError:
            raise RuleSyncError("the Controller server sent unexpected rules") from None
        rules, errors = [], []
        for entry in entries:
            try:
                rules.append(rules_loader.parse_rule(entry))
            except ValueError as exc:
                errors.append(f"rule {entry['id']}: {exc}")
                logger.warning(
                    "Ignoring the rule %s of the Controller server: %s", entry["id"], exc
                )
        self.publish(rules, errors)
        self._rules_digest = manifest_digest(entries)
        logger.info("Internal rules of the Controller server: %d rule(s)", len(rules))

    # ── OpenGrep rules ───────────────────────────────────────────────────────

    def _prepare(self) -> None:
        """Create the directory (0700) and delete the snapshots of a previous run."""
        if self._prepared:
            return
        assert self.directory is not None
        if self.directory.is_symlink():
            raise RuleSyncError("SECREVIEW_OPENGREP_RULES_DIR must not be a symbolic link")
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        for entry in self.directory.iterdir():
            if (
                entry.is_dir()
                and not entry.is_symlink()
                and (_SNAPSHOT.fullmatch(entry.name) or entry.name.startswith(_TEMPORARY_PREFIX))
            ):
                _remove(entry)
        self._prepared = True

    def _sync_opengrep(self) -> None:
        """Download the OpenGrep rules that differ from the current snapshot and switch to a
        new one."""
        assert self.directory is not None
        manifest = self._fetch_manifest()
        if manifest is None:
            return
        digest = manifest_digest(manifest)
        if digest == self._digest:
            return
        needed = [
            rule_id for rule_id, sha in manifest.items() if self._manifest.get(rule_id) != sha
        ]
        contents: dict[str, str] = {}
        for start in range(0, len(needed), RULE_FETCH_BATCH):
            contents.update(self._fetch_rules(needed[start : start + RULE_FETCH_BATCH]))
        for rule_id in needed:
            if rule_id not in contents or rule_digest(contents[rule_id]) != manifest[rule_id]:
                # Changed or deleted between the two requests: the next scan tries again
                raise RuleSyncError("an OpenGrep rule changed during the synchronization")
        target = self.directory / digest
        if not target.is_dir():
            self._build(target, manifest, contents)
        previous = self._current
        removed = len(self._manifest.keys() - manifest.keys())
        self._current, self._manifest, self._digest = target, manifest, digest
        if previous is not None and previous != target and not self._users[previous]:
            _remove(previous)
        logger.info(
            "OpenGrep rules of the Controller server: %d rule(s), %d downloaded, %d removed",
            len(manifest),
            len(needed),
            removed,
        )

    def _build(self, target: Path, manifest: dict[str, str], contents: dict[str, str]) -> None:
        """Write the snapshot ``target``: the downloaded rules, the others copied from the
        current snapshot, in a temporary directory renamed at the end."""
        assert self.directory is not None
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
            _remove(temporary)
            raise

    def _fetch_manifest(self) -> dict[str, str] | None:
        """The OpenGrep manifest of the controller, None when the snapshot is up to date."""
        headers = {}
        if self._current is not None and self._digest:
            headers["If-None-Match"] = f'"{self._digest}"'
        raw = self.client.request(
            "GET", ENGINE_OPENGREP_RULES_PATH, None, headers, MAX_MANIFEST_BYTES
        )
        if raw is None:
            return None
        try:
            return RuleManifest.model_validate_json(raw).rules
        except ValidationError:
            raise RuleSyncError("the Controller server sent an unexpected answer") from None

    def _fetch_rules(self, ids: list[str]) -> dict[str, str]:
        """Content of the OpenGrep rules ``ids``."""
        body = RuleFetch(ids=ids).model_dump_json().encode()
        headers = {"Content-Type": "application/json"}
        raw = self.client.request(
            "POST", ENGINE_OPENGREP_RULES_PATH, body, headers, MAX_CONTENTS_BYTES
        )
        try:
            rules = RuleContents.model_validate_json(raw or b"").rules
        except ValidationError:
            raise RuleSyncError("the Controller server sent an unexpected answer") from None
        if not rules.keys() <= set(ids):
            raise RuleSyncError("the Controller server sent an unexpected answer")
        return rules


def _remove(path: Path) -> None:
    """Delete a snapshot, logging a failure (a later start deletes it)."""
    try:
        shutil.rmtree(path)
    except OSError as exc:
        logger.warning("Could not delete the OpenGrep rules %s: %s", path.name, type(exc).__name__)
