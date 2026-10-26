"""Security review server."""

from importlib.metadata import PackageNotFoundError, version

# Single source: the version of pyproject.toml (set with `uv version X.Y.Z`), read from the
# metadata of the installed distribution
try:
    __version__ = version("security-review")
except PackageNotFoundError:  # sources used without being installed
    __version__ = "0.0.0"
