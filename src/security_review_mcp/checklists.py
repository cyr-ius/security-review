"""Security review checklists, one per domain (knowledge base used by prompts and tools)."""

from dataclasses import dataclass


@dataclass(frozen=True)
class CheckItem:
    """One verification point of a checklist."""

    id: str
    title: str
    what_to_look_for: str
    cwe: str


def _items(*rows: tuple[str, str, str, str]) -> tuple[CheckItem, ...]:
    """Build a tuple of CheckItem from (id, title, what_to_look_for, cwe) rows."""
    return tuple(CheckItem(*row) for row in rows)


CHECKLISTS: dict[str, tuple[CheckItem, ...]] = {
    "python": _items(
        (
            "PY-01",
            "Injection (SQL / command / template)",
            "String-built SQL, subprocess with shell=True or user input, os.system, "
            "Jinja2 from_string or render of untrusted templates.",
            "CWE-89",
        ),
        (
            "PY-02",
            "Unsafe deserialization",
            "pickle/marshal/shelve on untrusted data, yaml.load without SafeLoader.",
            "CWE-502",
        ),
        (
            "PY-03",
            "Dynamic code execution",
            "eval, exec, compile, __import__ driven by user input.",
            "CWE-95",
        ),
        (
            "PY-04",
            "Path traversal and file handling",
            "open/send_file/extractall with user-controlled paths, tarfile/zipfile without "
            "member validation, insecure temp files (mktemp).",
            "CWE-22",
        ),
        (
            "PY-05",
            "Weak cryptography and randomness",
            "MD5/SHA1 for passwords, ECB mode, hard-coded keys/IV, random instead of secrets "
            "for tokens.",
            "CWE-327",
        ),
        (
            "PY-06",
            "TLS and SSRF",
            "verify=False, disabled hostname checks, requests to user-supplied URLs without an "
            "allow-list.",
            "CWE-295",
        ),
        (
            "PY-07",
            "Secrets and logging",
            "Credentials in code or defaults, secrets/PII in logs or exception messages.",
            "CWE-798",
        ),
        (
            "PY-08",
            "Debug and error exposure",
            "debug=True, stack traces returned to clients, assert used for authorization.",
            "CWE-489",
        ),
    ),
    "java": _items(
        (
            "JV-01",
            "Injection (SQL / JPQL / OS / LDAP / EL)",
            "Concatenated queries instead of PreparedStatement or bound parameters, "
            "Runtime.exec / ProcessBuilder with user input.",
            "CWE-89",
        ),
        (
            "JV-02",
            "Unsafe deserialization",
            "ObjectInputStream on untrusted data, Jackson default typing, XMLDecoder, "
            "XStream without allow-list.",
            "CWE-502",
        ),
        (
            "JV-03",
            "XML external entities (XXE)",
            "DocumentBuilderFactory / SAXParserFactory / XMLInputFactory without "
            "secure-processing and disallow-doctype-decl.",
            "CWE-611",
        ),
        (
            "JV-04",
            "Spring Security configuration",
            "csrf().disable() on session-based apps, permitAll on sensitive routes, missing "
            "method security, wildcard CORS with credentials, actuator endpoints exposed.",
            "CWE-862",
        ),
        (
            "JV-05",
            "Authentication and session",
            "Weak password encoders (NoOp, MD5, SHA-1), JWT without signature/exp/aud checks, "
            "alg=none acceptance.",
            "CWE-287",
        ),
        (
            "JV-06",
            "Weak cryptography",
            "MessageDigest MD5/SHA-1, DES, AES/ECB, static IV, java.util.Random for secrets, "
            "custom TrustManager accepting all certificates.",
            "CWE-327",
        ),
        (
            "JV-07",
            "Path traversal and file upload",
            "new File(userInput), unchecked zip entries (Zip Slip), missing type/size checks.",
            "CWE-22",
        ),
        (
            "JV-08",
            "Secrets and logging",
            "Credentials in application.properties / code, sensitive data in logs, "
            "log injection via unsanitized input.",
            "CWE-798",
        ),
    ),
    "angular": _items(
        (
            "NG-01",
            "Cross-site scripting (XSS)",
            "bypassSecurityTrustHtml/Url/Script/ResourceUrl, [innerHTML] with untrusted data, "
            "direct DOM access (ElementRef.nativeElement, document.write), eval / new Function.",
            "CWE-79",
        ),
        (
            "NG-02",
            "Token and secret storage",
            "JWT or API keys in localStorage/sessionStorage, secrets in environment.ts or "
            "bundled assets.",
            "CWE-922",
        ),
        (
            "NG-03",
            "Route and UI-only authorization",
            "Security enforced only by guards or hidden buttons with no server-side check.",
            "CWE-602",
        ),
        (
            "NG-04",
            "HTTP and CSRF",
            "Missing CSRF/XSRF protection for cookie auth, tokens sent to third-party origins "
            "by interceptors, open redirects from query params.",
            "CWE-352",
        ),
        (
            "NG-05",
            "Dependencies and build",
            "Vulnerable or abandoned npm packages, unpinned versions, source maps in "
            "production, postinstall scripts.",
            "CWE-1104",
        ),
        (
            "NG-06",
            "Content Security Policy and headers",
            "Missing CSP, unsafe-inline/unsafe-eval, missing frame-ancestors, untrusted "
            "third-party scripts without SRI.",
            "CWE-1021",
        ),
    ),
    "api": _items(
        (
            "API-01",
            "Broken object-level authorization (BOLA/IDOR)",
            "Every endpoint taking an id must verify that the caller owns or may access it.",
            "CWE-639",
        ),
        (
            "API-02",
            "Broken authentication",
            "Missing auth on endpoints, weak token validation, no rate limit or lockout on "
            "login, credentials in query strings.",
            "CWE-287",
        ),
        (
            "API-03",
            "Broken function-level authorization",
            "Admin or privileged routes reachable by regular users, role checks missing on "
            "write verbs (PUT/PATCH/DELETE).",
            "CWE-285",
        ),
        (
            "API-04",
            "Mass assignment and excessive data exposure",
            "Binding request bodies directly to entities, responses returning internal fields "
            "(password hashes, internal ids, tokens).",
            "CWE-915",
        ),
        (
            "API-05",
            "Input validation",
            "No schema validation, unbounded page sizes, unbounded payloads, missing content "
            "type checks.",
            "CWE-20",
        ),
        (
            "API-06",
            "Resource consumption",
            "No rate limiting or quotas, expensive queries without limits, unbounded file uploads.",
            "CWE-770",
        ),
        (
            "API-07",
            "Security misconfiguration",
            "Wildcard CORS with credentials, verbose errors, missing security headers, "
            "exposed docs/actuator/debug endpoints in production.",
            "CWE-16",
        ),
        (
            "API-08",
            "SSRF and unsafe consumption of third-party APIs",
            "Fetching user-supplied URLs, trusting upstream data without validation, "
            "following redirects blindly.",
            "CWE-918",
        ),
        (
            "API-09",
            "Inventory and versioning",
            "Old API versions or undocumented endpoints still exposed.",
            "CWE-1059",
        ),
    ),
    "config": _items(
        (
            "CFG-01",
            "Secrets in configuration",
            "Passwords, tokens, private keys in YAML/properties/env files, Dockerfiles, CI "
            "variables printed in logs, committed .env files.",
            "CWE-798",
        ),
        (
            "CFG-02",
            "Container hardening",
            "Running as root (no USER), privileged: true, added capabilities, host "
            "network/PID, mounted docker.sock, :latest tags, ADD from URLs.",
            "CWE-250",
        ),
        (
            "CFG-03",
            "CI/CD pipeline security",
            "Unpinned images/actions/includes, scripts piped from curl to shell, secrets "
            "exposed to untrusted merge requests, runners with excessive privileges.",
            "CWE-829",
        ),
        (
            "CFG-04",
            "Network exposure",
            "0.0.0.0 bindings, 0.0.0.0/0 ingress rules, databases or admin ports exposed, "
            "plain HTTP for sensitive traffic.",
            "CWE-668",
        ),
        (
            "CFG-05",
            "TLS and cryptographic settings",
            "TLS < 1.2, weak ciphers, disabled certificate verification, self-signed "
            "certificates in production.",
            "CWE-326",
        ),
        (
            "CFG-06",
            "Debug and default settings",
            "DEBUG enabled, default credentials, sample accounts, verbose error pages, "
            "directory listing.",
            "CWE-1188",
        ),
        (
            "CFG-07",
            "Logging and audit",
            "No audit trail for authentication and admin actions, sensitive data in logs.",
            "CWE-778",
        ),
        (
            "CFG-08",
            "Permissions and file modes",
            "chmod 777, world-writable volumes, overly broad IAM/RBAC roles or wildcards.",
            "CWE-732",
        ),
    ),
    "cicd": _items(
        (
            "CI-01",
            "Secrets in pipelines",
            "Variables not masked or not protected, secrets printed in logs, tokens in URLs "
            "or command lines, secrets available to merge requests from forks.",
            "CWE-532",
        ),
        (
            "CI-02",
            "Script injection through untrusted values",
            "Branch names, MR titles or parameters interpolated into shell steps "
            "(Jenkins sh with ${params.X}, GitLab script with $CI_COMMIT_BRANCH unquoted).",
            "CWE-78",
        ),
        (
            "CI-03",
            "Supply chain of pipeline code",
            "Remote includes, shared libraries, images and actions not pinned to a version "
            "or digest; scripts downloaded and executed without verification.",
            "CWE-829",
        ),
        (
            "CI-04",
            "Runner and agent isolation",
            "Shared or privileged runners for untrusted code, docker.sock mounts, "
            "docker-in-docker without TLS, persistent workspaces and caches shared between "
            "projects (cache poisoning).",
            "CWE-250",
        ),
        (
            "CI-05",
            "Protected branches and approvals",
            "Deploy jobs reachable from unprotected branches, no approval for production, "
            "pipelines editable by developers who also hold deploy credentials.",
            "CWE-285",
        ),
        (
            "CI-06",
            "Security gates",
            "Security jobs allowed to fail, skipped on some branches, or not blocking the merge.",
            "CWE-693",
        ),
        (
            "CI-07",
            "Artifacts and registries",
            "Artifacts readable by everyone, images pushed without scanning or signing, "
            "mutable tags used for releases.",
            "CWE-494",
        ),
    ),
    "dependencies": _items(
        (
            "SC-01",
            "Known vulnerable versions",
            "Direct and transitive dependencies matching a published advisory; prefer scanning "
            "the lockfile, which lists the exact resolved versions.",
            "CWE-1395",
        ),
        (
            "SC-02",
            "Reproducible resolution",
            "Lockfile committed and used by the build (npm ci, poetry install --no-update, "
            "pinned requirements with hashes); no wildcard, latest or dynamic versions.",
            "CWE-1357",
        ),
        (
            "SC-03",
            "Dependency confusion and registries",
            "Internal packages resolvable from a public registry, extra package indexes, "
            "registries over HTTP, scopes or groups not reserved on public registries.",
            "CWE-829",
        ),
        (
            "SC-04",
            "Untrusted sources",
            "Dependencies installed from VCS branches, URLs, local paths or unreviewed forks.",
            "CWE-829",
        ),
        (
            "SC-05",
            "Install-time code execution",
            "preinstall/postinstall scripts, setup.py doing network calls, build plugins that "
            "download and run code.",
            "CWE-829",
        ),
        (
            "SC-06",
            "Abandoned or typosquatted packages",
            "Unmaintained packages, names close to popular ones, packages with a sudden "
            "ownership change.",
            "CWE-1104",
        ),
    ),
}

DOMAINS: tuple[str, ...] = tuple(CHECKLISTS)


def get_checklist(domain: str) -> tuple[CheckItem, ...]:
    """Return the checklist for a domain.

    Raises:
        ValueError: If the domain is unknown.
    """
    key = domain.strip().lower()
    if key not in CHECKLISTS:
        raise ValueError(f"Unknown domain '{domain}'. Available: {', '.join(DOMAINS)}")
    return CHECKLISTS[key]


def render_checklist_markdown(domain: str) -> str:
    """Render a checklist as Markdown (embedded in prompts and returned by tools)."""
    items = get_checklist(domain)
    lines = [f"### Checklist: {domain.lower()}"]
    for item in items:
        lines.append(f"- **{item.id} - {item.title}** ({item.cwe}): {item.what_to_look_for}")
    return "\n".join(lines)
