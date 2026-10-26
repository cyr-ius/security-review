"""Write the project of the standalone ``security-review-ci`` distribution.

The pipeline client (``src/security_review_mcp/ci_client.py``) only uses the standard library,
so it is also published alone on PyPI, without the dependencies of the server: a developer
installs it with ``uv tool install security-review-ci`` (uv downloads a Python when none is
installed). The module is copied as ``security_review_ci.py``; the version and the Python
requirement are those of ``pyproject.toml``: both distributions are released from the same tag.

    python scripts/build_ci_client.py build/security-review-ci
    uv build build/security-review-ci --out-dir dist
"""

import shutil
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NAME = "security-review-ci"
MODULE = "security_review_ci"
DOCUMENTATION = (
    "https://cyr-ius.github.io/security-review/review/gate/#pipeline-client-security-review-ci"
)
DESCRIPTION = (
    "Pipeline and workstation client of the security-review-mcp controller: gate, SARIF, "
    "trends, code and dependency scans, read guard of coding agents"
)

PYPROJECT = """\
[build-system]
requires = ["setuptools>=77"]
build-backend = "setuptools.build_meta"

[project]
name = "{name}"
version = "{version}"
description = "{description}"
readme = "README.md"
license = "Apache-2.0"
license-files = ["LICENSE"]
requires-python = "{requires_python}"
dependencies = []

[project.urls]
Documentation = "{documentation}"
Repository = "https://github.com/cyr-ius/security-review"
Issues = "https://github.com/cyr-ius/security-review/issues"

[project.scripts]
{name} = "{module}:main"

[tool.setuptools]
py-modules = ["{module}"]
"""

README = """\
# security-review-ci

Client of the [security-review-mcp]({repository}) controller for pipelines and developer
workstations: deployment gate, SARIF export, trend report, code and dependency scans, through
the REST API with a `ci` token, and an offline read guard for the hooks of coding agents. It
only uses the Python standard library.

```bash
uv tool install {name}       # uv installs a Python when none is available
export SECREVIEW_CONTROLLER_URL=https://secreview.example.com
export SECREVIEW_TOKEN=<ci token>
{name} scan-deps uv.lock --project my-project
```

Documentation: {documentation}
"""


def write_project(dest: Path, root: Path = ROOT) -> Path:
    """Write the project of the distribution in ``dest`` (replaced) and return it."""
    with (root / "pyproject.toml").open("rb") as file:
        server = tomllib.load(file)["project"]
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    values = {
        "name": NAME,
        "module": MODULE,
        "version": server["version"],
        "requires_python": server["requires-python"],
        "description": DESCRIPTION,
        "documentation": DOCUMENTATION,
        "repository": "https://github.com/cyr-ius/security-review",
    }
    (dest / "pyproject.toml").write_text(PYPROJECT.format(**values), encoding="utf-8")
    (dest / "README.md").write_text(README.format(**values), encoding="utf-8")
    shutil.copyfile(root / "LICENSE", dest / "LICENSE")
    shutil.copyfile(root / "src" / "security_review_mcp" / "ci_client.py", dest / f"{MODULE}.py")
    return dest


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(f"usage: {sys.argv[0]} DEST")
    print(write_project(Path(sys.argv[1])))
