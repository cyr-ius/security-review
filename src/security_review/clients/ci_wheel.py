"""Wheel of the pipeline client served by the controller (``/api/ci-client/``, see ci_client).

The controller builds in memory the ``security-review-ci`` wheel from its own ``ci_client``
module, which only uses the standard library, at its own version: a developer installs the
client of their controller without PyPI with
``uvx --no-index --find-links <controller>/api/ci-client/ security-review-ci@latest``. The PyPI
distribution of the same module is built by ``scripts/build_ci_client.py``. The archive is
reproducible (fixed timestamps), so its SHA-256, published in the links page, is stable for a
version.
"""

import base64
import hashlib
import html
import io
import zipfile
from dataclasses import dataclass
from functools import cache
from importlib import metadata
from pathlib import Path

from .. import ci_client

PROJECT = "security-review-ci"
MODULE = "security_review_ci"
# Installed distribution whose version and Python requirement the client takes
PACKAGE = "security-review"
DEFAULT_REQUIRES_PYTHON = ">=3.14"
# Timestamp of every member of the archive: the same bytes for the same version
_ZIP_DATE = (2020, 1, 1, 0, 0, 0)


@dataclass(frozen=True)
class Wheel:
    """A built wheel: its file name, its bytes, their SHA-256 and the Python requirement."""

    filename: str
    content: bytes
    sha256: str
    requires_python: str


def _record_hash(data: bytes) -> str:
    """Hash of a RECORD line (PEP 376): urlsafe base64 of the SHA-256, without padding."""
    digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=")
    return f"sha256={digest.decode()}"


@cache
def build_wheel() -> Wheel:
    """Build the ``security-review-ci`` wheel of the installed server (once per process)."""
    try:
        info = metadata.metadata(PACKAGE)
        version = info["Version"]
        requires_python = info.get("Requires-Python") or DEFAULT_REQUIRES_PYTHON
    except metadata.PackageNotFoundError as exc:
        raise RuntimeError(f"The {PACKAGE} distribution is not installed") from exc
    dist_info = f"{MODULE}-{version}.dist-info"
    files = {
        f"{MODULE}.py": Path(ci_client.__file__).read_bytes(),
        f"{dist_info}/METADATA": (
            "Metadata-Version: 2.4\n"
            f"Name: {PROJECT}\n"
            f"Version: {version}\n"
            "Summary: Pipeline and workstation client of the security-review controller\n"
            "License-Expression: Apache-2.0\n"
            f"Requires-Python: {requires_python}\n"
        ).encode(),
        f"{dist_info}/WHEEL": (
            b"Wheel-Version: 1.0\n"
            b"Generator: security-review-controller\n"
            b"Root-Is-Purelib: true\n"
            b"Tag: py3-none-any\n"
        ),
        f"{dist_info}/entry_points.txt": (
            f"[console_scripts]\n{PROJECT} = {MODULE}:main\n"
        ).encode(),
    }
    record = "".join(f"{name},{_record_hash(data)},{len(data)}\n" for name, data in files.items())
    files[f"{dist_info}/RECORD"] = (record + f"{dist_info}/RECORD,,\n").encode()
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, data in files.items():
            member = zipfile.ZipInfo(name, _ZIP_DATE)
            member.compress_type = zipfile.ZIP_DEFLATED
            member.external_attr = 0o644 << 16
            archive.writestr(member, data)
    content = buffer.getvalue()
    return Wheel(
        f"{MODULE}-{version}-py3-none-any.whl",
        content,
        hashlib.sha256(content).hexdigest(),
        requires_python,
    )


def links_page(wheel: Wheel) -> str:
    """HTML page of ``--find-links``: one link to the wheel, with its SHA-256 (checked by uv)
    and its Python requirement."""
    name = html.escape(wheel.filename)
    requires = html.escape(wheel.requires_python)
    return (
        "<!DOCTYPE html>\n"
        f'<html><head><meta charset="utf-8"><title>{PROJECT}</title></head><body>\n'
        f'<a href="{name}#sha256={wheel.sha256}" data-requires-python="{requires}">{name}</a>\n'
        "</body></html>\n"
    )
