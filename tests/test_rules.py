"""Tests for internal rule packs, platform rules, suppression and the registry."""

import pytest

from security_review_mcp import prompts, registry, rule_store
from security_review_mcp.rules_loader import default_content, parse_pack

VALID_PACK = """
disabled_rules = ["PY-008"]

[[rules]]
id = "ACME-001"
title = "Legacy crypto helper"
severity = "high"
cwe = "CWE-327"
languages = ["python"]
pattern = '''LegacyCrypto\\.encrypt\\('''
advice = "Use CryptoService."

[[checklist]]
domain = "company"
id = "ACME-CL-01"
title = "Tenant isolation"
what_to_look_for = "Queries are scoped by tenant."
cwe = "CWE-639"

[[checklist]]
domain = "payments"
id = "ACME-PAY-01"
title = "Idempotency"
what_to_look_for = "Replays are rejected."
"""


def ids(matches: list[dict]) -> set[str]:
    """Return the rule ids of a match list."""
    return {m["rule_id"] for m in matches}


# ── Internal rules (database) ────────────────────────────────────────────────


def test_valid_pack_adds_rules_and_checklists(import_pack):
    import_pack(VALID_PACK)
    matches, _ = registry.scan("x = LegacyCrypto.encrypt(data)", "python")
    assert ids(matches) == {"ACME-001"}
    assert "company" in registry.domains()
    assert "payments" in registry.domains()
    assert "Idempotency" in registry.render_checklist_markdown("payments")
    assert registry.snapshot().errors == ()


def test_pack_can_disable_a_builtin_rule(import_pack):
    import_pack(VALID_PACK)
    matches, _ = registry.scan("v = random.randint(1, 9)", "python")
    assert "PY-008" not in ids(matches)
    assert "PY-008" in registry.snapshot().disabled_rule_ids


def test_custom_rule_replaces_builtin_with_same_id(import_pack):
    import_pack(
        """
[[rules]]
id = "PY-006"
title = "Custom TLS rule"
severity = "critical"
languages = ["python"]
pattern = 'verify\\s*=\\s*False'
"""
    )
    matches, _ = registry.scan("requests.get(u, verify=False)", "python")
    hit = next(m for m in matches if m["rule_id"] == "PY-006")
    assert hit["title"] == "Custom TLS rule"
    assert hit["severity"] == "critical"


def test_company_checklist_is_added_to_review_prompts(import_pack):
    import_pack(VALID_PACK)
    text = prompts.build_security_review_prompt("python", "x = 1", "", "")
    assert "ACME-CL-01" in text
    assert "ACME-CL-01" in prompts.build_api_review_prompt("FastAPI", "", "", "")
    # Other domains, such as an internal one, are named for get_review_checklist, not embedded
    assert "`payments`" in text and "ACME-PAY-01" not in text


def test_without_pack_there_is_no_company_section():
    assert registry.company_checklist_markdown() == ""
    assert "ACME" not in prompts.build_security_review_prompt("java", "", "", "")


@pytest.mark.parametrize(
    "entry, fragment",
    [
        ('id = "bad id"\ntitle = "t"\nseverity = "high"\npattern = "x"', "invalid id"),
        ('id = "A-1"\ntitle = "t"\nseverity = "huge"\npattern = "x"', "invalid severity"),
        ('id = "A-1"\ntitle = "t"\nseverity = "low"\npattern = "("', "invalid regex"),
        ('id = "A-1"\ntitle = "t"\nseverity = "low"\npattern = "(a+)+$"', "backtracking"),
        ('id = "A-1"\ntitle = "t"\nseverity = "low"\npattern = "a*"', "empty string"),
        ('id = "A-1"\ntitle = "t"\nseverity = "low"\npattern = "x"\ncwe = "89"', "invalid cwe"),
        (
            'id = "A-1"\ntitle = "t"\nseverity = "low"\npattern = "x"\nlanguages = ["cobol"]',
            "unknown",
        ),
        ('id = "A-1"\ntitle = "t"\nseverity = "low"', "missing pattern"),
        (f'id = "A-1"\ntitle = "{"t" * 301}"\nseverity = "low"\npattern = "x"', "longer than"),
        (f'id = "A-{"1" * 60}"\ntitle = "t"\nseverity = "low"\npattern = "x"', "invalid id"),
    ],
)
def test_invalid_rules_are_reported(entry, fragment):
    result = parse_pack(f"[[rules]]\n{entry}\n", "bad.toml")
    assert result.rules == []
    assert any(fragment in error and "bad.toml" in error for error in result.errors), result.errors


def test_broken_pack_is_reported():
    result = parse_pack("this is [not valid toml", "broken.toml")
    assert result.errors and "broken.toml" in result.errors[0]
    assert parse_pack('disabled_rules = ["not an id"]', "p.toml").errors


def test_unreadable_database_falls_back_to_the_default_rules(database):
    database.dispose()
    from sqlmodel import SQLModel

    SQLModel.metadata.drop_all(database)
    snapshot = registry.reload()
    assert snapshot.errors and "database error (OperationalError)" in snapshot.errors[0]
    defaults = default_content()
    assert [rule.id for rule in snapshot.rules] == [rule.id for rule in defaults.rules]
    assert set(registry.domains()) == set(defaults.checklist)
    # The scanner never runs without rules: the default file is read directly
    assert any(m["rule_id"] == "PY-001" for m in registry.scan("eval(user_input)", "python")[0])


def test_unseeded_database_falls_back_to_the_default_rules(database):
    from sqlmodel import Session, delete

    from security_review_mcp.storage.models import CustomCheckItem, CustomRule, DefaultSeed

    with Session(database) as session:  # tables created, defaults never seeded
        for model in (CustomRule, CustomCheckItem, DefaultSeed):
            session.exec(delete(model))
        session.commit()
    snapshot = registry.reload()
    assert any("not initialized" in error for error in snapshot.errors)
    assert len(snapshot.rules) == len(default_content().rules)

    rule_store.seed_defaults()  # once seeded, the stored rules are used again
    assert registry.reload().errors == ()


def test_default_rules_file_is_valid_and_complete():
    defaults = default_content()
    ids = [rule.id for rule in defaults.rules]
    assert len(ids) == len(set(ids)) >= 120
    families = {"PY", "JV", "NG", "CFG", "GEN", "GL", "JK", "CI", "SP", "FA", "AI"}
    families |= {"GO", "CS", "RS", "TS"}
    assert {rule_id.split("-")[0] for rule_id in ids} <= families
    # The review prompts rely on these checklist domains
    domains = {"python", "java", "angular", "api", "config", "cicd", "dependencies"}
    domains |= {"go", "csharp", "rust", "node"}
    assert domains <= set(defaults.checklist)


def test_reload_picks_up_changes():
    assert "ACME-001" not in registry.snapshot().custom_rule_ids
    rule_store.import_packs([("company.toml", VALID_PACK)])
    assert "ACME-001" in registry.reload().custom_rule_ids


def test_snapshot_follows_changes_made_by_another_process(monkeypatch):
    assert "ACME-001" not in registry.snapshot().custom_rule_ids
    rule_store.import_packs([("company.toml", VALID_PACK)])  # e.g. the CLI, no reload here
    assert "ACME-001" not in registry.snapshot().custom_rule_ids  # cached
    monkeypatch.setattr(registry, "REFRESH_SECONDS", 0.0)
    assert "ACME-001" in registry.snapshot().custom_rule_ids
    revision = registry.snapshot().revision
    assert registry.snapshot().revision == revision  # unchanged revision: no reload


def test_describe_rules_marks_origin_and_state(import_pack):
    import_pack(VALID_PACK)
    rows = {row["id"]: row for row in registry.describe_rules("python")}
    assert rows["ACME-001"]["origin"] == "custom"
    assert rows["PY-001"]["origin"] == "builtin"
    assert "JV-001" not in rows
    assert "PY-008" not in rows
    every = {row["id"]: row for row in registry.describe_rules("python", include_disabled=True)}
    assert every["PY-008"]["enabled"] is False
    assert every["PY-001"]["enabled"] is True


# ── Platform rules ───────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "language, code, expected",
    [
        ("gitlab-ci", "include:\n  - remote: 'https://example.com/ci.yml'", "GL-001"),
        ("gitlab-ci", '  - echo "token $CI_JOB_TOKEN"', "GL-002"),
        ("gitlab-ci", 'variables:\n  DOCKER_TLS_CERTDIR: ""', "GL-003"),
        ("gitlab-ci", "  allow_failure: true", "GL-004"),
        ("jenkins", 'sh "deploy ${params.TARGET}"', "JK-001"),
        ("jenkins", "@Library('shared-lib') _", "JK-002"),
        ("jenkins", "pipeline { agent any }", "JK-003"),
        ("jenkins", "sh 'curl -k https://nexus/x.sh'", "CI-001"),
        ("config", "management.endpoint.health.show-details=always", "SP-001"),
        ("config", "spring.h2.console.enabled=true", "SP-002"),
        ("java", "http.authorizeRequests().anyRequest().permitAll();", "SP-005"),
        ("java", "public User save(@RequestBody UserEntity user)", "SP-006"),
        ("python", "app.add_middleware(CORSMiddleware, allow_origins=['*'])", "FA-001"),
        ("python", 'jwt.decode(t, options={"verify_signature": False})', "FA-002"),
        ("python", "tar.extractall(path)", "PY-011"),
        ("angular", "win.postMessage(data, '*')", "NG-006"),
    ],
)
def test_platform_rules(language, code, expected):
    matches, _ = registry.scan(code, language)
    assert expected in ids(matches), matches


# Each additional default rule: (language, vulnerable line, safe equivalent, rule id)
ADDITIONAL_RULES = [
    (
        "python",
        'logger.info("login %s", user.password)',
        'logger.info("login %s", user.name)',
        "GEN-005",
    ),
    ("java", 'log.debug("token {}", token);', 'log.debug("user {}", userId);', "GEN-005"),
    ("yaml", "token: " + "ghp_" + "a1" * 18, "token: ${GITHUB_TOKEN}", "GEN-006"),
    (
        "yaml",
        "url: https://deploy:" + "s3cr3t@repo.example.com",
        "url: https://${USER}:${PASS}@repo",
        "GEN-007",
    ),
    (
        "javascript",
        "const t = '" + "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJlMTIz';",
        "const t = getToken();",
        "GEN-008",
    ),
    ("config", "ssl_protocols TLSv1 TLSv1.1 TLSv1.2;", "ssl_protocols TLSv1.2 TLSv1.3;", "GEN-009"),
    (
        "config",
        "url: ldap://dc1.corp.example.com:389",
        "url: ldaps://dc1.corp.example.com:636",
        "GEN-010",
    ),
    (
        "python",
        'REDIS_URL = "redis://:pw@cache.example.com:6379/0"',
        'REDIS_URL = "rediss://:pw@cache.example.com:6380/0"',
        "GEN-010",
    ),
    (
        "config",
        "DATABASE_URL=postgresql://app@db.example.com/app?sslmode=disable",
        "DATABASE_URL=postgresql://app@db.example.com/app?sslmode=verify-full",
        "GEN-011",
    ),
    (
        "java",
        'String url = "jdbc:mysql://db.example.com/app?useSSL=false";',
        'String url = "jdbc:mysql://db.example.com/app?sslMode=VERIFY_IDENTITY";',
        "GEN-011",
    ),
    ("yaml", "  security.protocol: PLAINTEXT", "  security.protocol: SASL_SSL", "GEN-011"),
    ("config", "TLS_REQCERT never", "TLS_REQCERT demand", "GEN-012"),
    (
        "python",
        "conn.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)",
        "conn.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_DEMAND)",
        "GEN-012",
    ),
    (
        "config",
        "jdbc:sqlserver://db.example.com;encrypt=true;trustServerCertificate=true",
        "jdbc:sqlserver://db.example.com;encrypt=true;trustServerCertificate=false",
        "GEN-012",
    ),
    (
        "python",
        "ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_1)",
        "ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)",
        "GEN-009",
    ),
    (
        "python",
        "parser = etree.XMLParser(resolve_entities=True)",
        "parser = etree.XMLParser(resolve_entities=False)",
        "PY-014",
    ),
    (
        "python",
        "return render_template_string(body)",
        'return render_template("page.html", body=body)',
        "PY-015",
    ),
    (
        "python",
        'SECRET_KEY = "django-insecure-abc"',
        'SECRET_KEY = os.environ["SECRET_KEY"]',
        "PY-016",
    ),
    ("python", "ALLOWED_HOSTS = ['*']", "ALLOWED_HOSTS = ['app.example.com']", "PY-017"),
    ("python", "@csrf_exempt", "@csrf_protect", "PY-018"),
    ("python", "return mark_safe(comment)", "return escape(comment)", "PY-019"),
    ("python", "SESSION_COOKIE_SECURE = False", "SESSION_COOKIE_SECURE = True", "PY-020"),
    (
        "python",
        "cipher = AES.new(key, AES.MODE_ECB)",
        "cipher = AES.new(key, AES.MODE_GCM)",
        "PY-021",
    ),
    ("python", "model = torch.load(path)", "model = torch.load(path, weights_only=True)", "PY-022"),
    ("python", "open('/tmp/report.csv', 'w')", "tempfile.NamedTemporaryFile()", "PY-023"),
    ("python", "requests.get(request.args['url'])", "requests.get(API_URL, timeout=5)", "PY-024"),
    ("python", "if token == provided:", "if hmac.compare_digest(token, provided):", "PY-025"),
    ("python", "if signature != expected:", "if digest(a) != digest(b):", "PY-025"),
    (
        "java",
        'ctx.search("ou=users", "(uid=" + user + ")", ctls);',
        'ctx.search("ou=users", "(uid={0})", new Object[]{user}, ctls);',
        "JV-009",
    ),
    ("java", 'new File(request.getParameter("name"))', "new File(BASE_DIR, safeName)", "JV-010"),
    (
        "java",
        'response.sendRedirect(request.getParameter("next"));',
        'response.sendRedirect("/home");',
        "JV-011",
    ),
    ("java", "parser.parseExpression(input).getValue();", "parser.toString();", "JV-012"),
    ("java", "cookie.setHttpOnly(false);", "cookie.setHttpOnly(true);", "JV-013"),
    ("java", "Random r = new Random();", "SecureRandom r = new SecureRandom();", "JV-014"),
    ("java", "e.printStackTrace();", 'log.error("failure", e);', "JV-015"),
    ("java", "XStream xs = new XStream();", "xs.allowTypes(new Class[]{Order.class});", "JV-016"),
    (
        "typescript",
        "window.location.href = this.route.snapshot.queryParams['next'];",
        "this.router.navigate(['/home']);",
        "NG-008",
    ),
    ("javascript", "res.redirect(req.query.next);", "res.redirect('/home');", "NG-008"),
    ("javascript", 'setTimeout("refresh()", 1000);', "setTimeout(refresh, 1000);", "NG-009"),
    ("typescript", "el.insertAdjacentHTML('beforeend', html);", "el.append(text);", "NG-010"),
    (
        "angular",
        "this.sanitizer.sanitize(SecurityContext.NONE, v)",
        "this.sanitizer.sanitize(SecurityContext.HTML, v)",
        "NG-011",
    ),
    ("javascript", "exec(`git log ${branch}`);", "execFile('git', ['log', branch]);", "NG-012"),
    (
        "javascript",
        "spawn(cmd, args, { shell: true });",
        "spawn(cmd, args, { shell: false });",
        "NG-012",
    ),
    ("typescript", "crypto.createHash('md5')", "crypto.createHash('sha256')", "NG-013"),
    (
        "javascript",
        "https.request({ rejectUnauthorized: false })",
        "https.request({ ca: internalCa })",
        "NG-014",
    ),
    (
        "javascript",
        "const claims = jwt.decode(token);",
        "const claims = jwt.verify(token, key, { algorithms: ['RS256'] });",
        "NG-015",
    ),
    (
        "angular",
        "provideHttpClient(withNoXsrfProtection())",
        "provideHttpClient(withXsrfConfiguration({}))",
        "NG-016",
    ),
    (
        "javascript",
        "app.use(cors());",
        "app.use(cors({ origin: ['https://app.example.com'] }));",
        "NG-017",
    ),
    (
        "javascript",
        "db.query(`SELECT * FROM u WHERE id = ${id}`);",
        "db.query('SELECT * FROM u WHERE id = $1', [id]);",
        "NG-018",
    ),
    (
        "javascript",
        "User.find({ $where: filter });",
        "User.find({ name: String(filter) });",
        "NG-019",
    ),
    (
        "javascript",
        "res.sendFile(req.query.file);",
        "res.sendFile(name, { root: PUBLIC_DIR });",
        "NG-020",
    ),
    ("docker", "USER root", "USER 10001", "CFG-010"),
    ("docker", "ADD https://example.com/tool.tgz /opt/", "COPY tool.tgz /opt/", "CFG-011"),
    ("docker", "ENV API_TOKEN=abcd1234efgh", "ENV API_URL=https://api.example.com", "CFG-012"),
    ("yaml", "    hostNetwork: true", "    hostNetwork: false", "CFG-013"),
    ("yaml", "    network_mode: host", "    network_mode: bridge", "CFG-013"),
    ("yaml", "  allowPrivilegeEscalation: true", "  allowPrivilegeEscalation: false", "CFG-014"),
    ("yaml", "    cap_add: [SYS_ADMIN]", "    cap_drop: [ALL]", "CFG-015"),
    ("yaml", "      - /:/host", "      - ./var/lib/secreview:/var/lib/secreview", "CFG-016"),
    ("yaml", '      - "5432:5432"', '      - "127.0.0.1:5432:5432"', "CFG-017"),
    (
        "yaml",
        "      POSTGRES_PASSWORD: postgres",
        "      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}",
        "CFG-018",
    ),
    ("yaml", '    verbs: ["*"]', '    verbs: ["get", "list"]', "CFG-019"),
    ("config", 'acl = "public-read"', 'acl = "private"', "CFG-020"),
    (
        "config",
        "add_header Access-Control-Allow-Origin *;",
        "add_header Access-Control-Allow-Origin https://app.example.com;",
        "CFG-021",
    ),
    ("config", "autoindex on;", "autoindex off;", "CFG-022"),
    ("config", "Options FollowSymLinks Indexes", "Options -Indexes", "CFG-022"),
    ("config", "PermitRootLogin yes", "PermitRootLogin no", "CFG-023"),
    ("yaml", "      ALLOW_EMPTY_PASSWORD: yes", "      ALLOW_EMPTY_PASSWORD: no", "CFG-024"),
    ("config", "SecRuleEngine DetectionOnly", "SecRuleEngine On", "CFG-025"),
    (
        "yaml",
        '    nginx.ingress.kubernetes.io/enable-modsecurity: "false"',
        '    nginx.ingress.kubernetes.io/enable-modsecurity: "true"',
        "CFG-025",
    ),
    (
        "config",
        "SecRequestBodyLimitAction ProcessPartial",
        "SecRequestBodyLimitAction Reject",
        "CFG-026",
    ),
    (
        "config",
        "SecRuleRemoveById 942000-942999",
        'SecRule REQUEST_URI "@beginsWith /notes" "id:1001,pass,ctl:ruleRemoveTargetById=942100"',
        "CFG-027",
    ),
    ("config", 'SecRuleRemoveByTag "attack-sqli"', "SecRuleRemoveById 942100", "CFG-027"),
    ("gitlab-ci", '    - eval "$CI_COMMIT_MESSAGE"', '    - echo "$CI_COMMIT_REF_SLUG"', "GL-006"),
    ("gitlab-ci", '  CI_DEBUG_TRACE: "true"', '  CI_DEBUG_TRACE: "false"', "GL-007"),
    ("gitlab-ci", "    public: true", "    public: false", "GL-008"),
    ("gitlab-ci", '  GIT_SSL_NO_VERIFY: "true"', '  GIT_SSL_NO_VERIFY: "false"', "GL-009"),
    (
        "jenkins",
        'sh "curl -u admin:${API_TOKEN} https://nexus"',
        "sh 'curl -u admin:$API_TOKEN https://nexus'",
        "JK-005",
    ),
    (
        "jenkins",
        "def jobs = Jenkins.instance.getAllItems()",
        "def jobs = currentBuild.number",
        "JK-006",
    ),
    ("gitlab-ci", "    - set -eux", "    - set -eu", "CI-003"),
    ("docker", "RUN npm install && npm run build", "RUN npm ci && npm run build", "CI-004"),
    (
        "config",
        "server.error.include-stacktrace=always",
        "server.error.include-stacktrace=never",
        "SP-007",
    ),
    (
        "config",
        "spring.datasource.password=Sup3rS3cret",
        "spring.datasource.password=${DB_PASSWORD}",
        "SP-008",
    ),
    (
        "java",
        'web.ignoring().requestMatchers("/api/**");',
        "http.authorizeHttpRequests(a -> a.anyRequest().authenticated());",
        "SP-009",
    ),
    (
        "java",
        "http.headers(h -> h.disable());",
        "http.headers(Customizer.withDefaults());",
        "SP-010",
    ),
    ("config", "management.security.enabled=false", "management.security.enabled=true", "SP-011"),
    (
        "config",
        "management.endpoints.web.exposure.include=health,heapdump",
        "management.endpoints.web.exposure.include=health,info",
        "SP-012",
    ),
    (
        "python",
        'app.add_middleware(CORSMiddleware, allow_origin_regex=".*")',
        'allow_origin_regex=r"^https://app\\.example\\.com$"',
        "FA-003",
    ),
    (
        "python",
        'uvicorn.run(app, host="0.0.0.0", reload=True)',
        'uvicorn.run(app, host="0.0.0.0")',
        "FA-004",
    ),
    # Go
    (
        "go",
        'rows, err := db.Query(fmt.Sprintf("SELECT * FROM users WHERE id = %s", id))',
        'rows, err := db.Query("SELECT * FROM users WHERE id = $1", id)',
        "GO-001",
    ),
    (
        "go",
        'err := sqlx.Get(&user, "SELECT * FROM users WHERE name = \'" + name + "\'")',
        'err := sqlx.Get(&user, "SELECT * FROM users WHERE name = ?", name)',
        "GO-001",
    ),
    (
        "go",
        'cmd := exec.Command("sh", "-c", "convert "+name)',
        'cmd := exec.Command("convert", name, out)',
        "GO-002",
    ),
    ("go", "tls.Config{InsecureSkipVerify: true}", "tls.Config{RootCAs: pool}", "GO-003"),
    ("go", "sum := md5.Sum(data)", "sum := sha256.Sum256(data)", "GO-004"),
    ("go", 'import "math/rand"', 'import "crypto/rand"', "GO-005"),
    (
        "go",
        'data := template.HTML(r.FormValue("bio"))',
        "data := template.HTMLEscapeString(bio)",
        "GO-006",
    ),
    (
        "go",
        'f, err := os.Open(filepath.Join(base, r.URL.Query().Get("file")))',
        'f, err := os.Open(filepath.Join(base, "index.html"))',
        "GO-007",
    ),
    (
        "go",
        'resp, err := http.Get(r.URL.Query().Get("url"))',
        "resp, err := http.Get(cfg.WebhookURL)",
        "GO-008",
    ),
    (
        "go",
        'http.Redirect(w, r, r.FormValue("next"), http.StatusFound)',
        'http.Redirect(w, r, "/login", http.StatusFound)',
        "GO-009",
    ),
    (
        "go",
        'log.Fatal(http.ListenAndServe(":8080", mux))',
        "log.Fatal(srv.ListenAndServe())",
        "GO-010",
    ),
    (
        "go",
        "path := filepath.Join(dest, f.Name)",
        "path := filepath.Join(dest, safeName)",
        "GO-011",
    ),
    (
        "go",
        "token, _, err := p.ParseUnverified(raw, claims)",
        "token, err := p.Parse(raw, keyFunc)",
        "GO-012",
    ),
    (
        "go",
        'cors.Options{AllowedOrigins: []string{"*"}}',
        'cors.Options{AllowedOrigins: []string{"https://app.example.com"}}',
        "GO-013",
    ),
    (
        "go",
        'http.Cookie{Name: "sid", HttpOnly: false}',
        'http.Cookie{Name: "sid", HttpOnly: true}',
        "GO-014",
    ),
    ("go", 'import _ "net/http/pprof"', 'import "net/http"', "GO-015"),
    ("go", "MinVersion: tls.VersionTLS10,", "MinVersion: tls.VersionTLS12,", "GO-016"),
    (
        "go",
        'os.WriteFile("token", data, 0666)',
        'os.WriteFile("token", data, 0600)',
        "GO-017",
    ),
    (
        "go",
        "body, err := io.ReadAll(r.Body)",
        "body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))",
        "GO-018",
    ),
    ("go", 'log.Printf("login %s", user.Password)', 'log.Printf("login %s", user.Name)', "GEN-005"),
    # C#
    (
        "csharp",
        'var cmd = new SqlCommand("SELECT * FROM Users WHERE Name = \'" + name + "\'", conn);',
        'var cmd = new SqlCommand("SELECT * FROM Users WHERE Name = @name", conn);',
        "CS-001",
    ),
    (
        "csharp",
        'var users = db.Users.FromSqlRaw($"SELECT * FROM Users WHERE Id = {id}");',
        'var users = db.Users.FromSql($"SELECT * FROM Users WHERE Id = {id}");',
        "CS-001",
    ),
    (
        "csharp",
        'var u = conn.QueryFirstOrDefault<User>($"SELECT * FROM Users WHERE Id = {id}");',
        'var u = conn.QueryFirstOrDefault<User>("SELECT * FROM Users WHERE Id = @id", new { id });',
        "CS-002",
    ),
    (
        "csharp",
        "var formatter = new BinaryFormatter();",
        "var options = new JsonSerializerOptions();",
        "CS-003",
    ),
    (
        "csharp",
        "TypeNameHandling = TypeNameHandling.All",
        "TypeNameHandling = TypeNameHandling.None",
        "CS-003",
    ),
    (
        "csharp",
        'Process.Start("cmd.exe", "/c " + userInput);',
        'Process.Start("convert", args);',
        "CS-004",
    ),
    (
        "csharp",
        "handler.ServerCertificateCustomValidationCallback = (m, c, ch, e) => true;",
        "handler.ServerCertificateCustomValidationCallback = ValidateWithPinnedCa;",
        "CS-005",
    ),
    ("csharp", "using var md5 = MD5.Create();", "using var sha = SHA256.Create();", "CS-006"),
    (
        "csharp",
        "var code = new Random().Next(100000, 999999);",
        "var code = RandomNumberGenerator.GetInt32(100000, 999999);",
        "CS-007",
    ),
    (
        "csharp",
        "settings.DtdProcessing = DtdProcessing.Parse;",
        "settings.DtdProcessing = DtdProcessing.Prohibit;",
        "CS-008",
    ),
    ("csharp", "<div>@Html.Raw(Model.Bio)</div>", "<div>@Model.Bio</div>", "CS-009"),
    (
        "csharp",
        "[IgnoreAntiforgeryToken]",
        "[ValidateAntiForgeryToken]",
        "CS-010",
    ),
    (
        "csharp",
        "policy.AllowAnyOrigin().AllowAnyHeader();",
        'policy.WithOrigins("https://app.example.com").AllowAnyHeader();',
        "CS-011",
    ),
    (
        "csharp",
        "policy.SetIsOriginAllowed(_ => true).AllowCredentials();",
        "policy.SetIsOriginAllowed(IsTrustedOrigin).AllowCredentials();",
        "CS-011",
    ),
    ("csharp", "app.UseDeveloperExceptionPage();", 'app.UseExceptionHandler("/error");', "CS-012"),
    ("csharp", "ValidateLifetime = false,", "ValidateLifetime = true,", "CS-013"),
    (
        "csharp",
        "options.Cookie.SecurePolicy = CookieSecurePolicy.None;",
        "options.Cookie.SecurePolicy = CookieSecurePolicy.Always;",
        "CS-014",
    ),
    (
        "csharp",
        "var path = Path.Combine(_uploads, file.FileName);",
        "var path = Path.Combine(_uploads, Guid.NewGuid().ToString());",
        "CS-015",
    ),
    ("csharp", "return Redirect(returnUrl);", "return LocalRedirect(returnUrl);", "CS-016"),
    (
        "csharp",
        'var body = await client.GetStringAsync(Request.Query["url"]);',
        "var body = await client.GetStringAsync(_options.FeedUrl);",
        "CS-017",
    ),
    (
        "csharp",
        'searcher.Filter = "(&(objectClass=user)(sAMAccountName=" + login + "))";',
        "searcher.Filter = string.Format(UserFilter, LdapEncoder.FilterEncode(login));",
        "CS-018",
    ),
    (
        "csharp",
        "ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls11;",
        "ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;",
        "CS-019",
    ),
    (
        "csharp",
        "xslt.Load(path, XsltSettings.TrustedXslt, resolver);",
        "xslt.Load(path, XsltSettings.Default, null);",
        "CS-020",
    ),
    (
        "csharp",
        '_logger.LogInformation("Login {User} {Password}", user, password);',
        '_logger.LogInformation("Login {User}", user);',
        "GEN-005",
    ),
    # Rust
    (
        "rust",
        "let rows = sqlx::query(&format!(\"SELECT * FROM users WHERE name = '{}'\", name))",
        'let rows = sqlx::query("SELECT * FROM users WHERE name = $1").bind(name)',
        "RS-001",
    ),
    (
        "rust",
        'let out = Command::new("sh").arg("-c").arg(cmd).output()?;',
        'let out = Command::new("convert").arg(input).output()?;',
        "RS-002",
    ),
    (
        "rust",
        "let client = Client::builder().danger_accept_invalid_certs(true).build()?;",
        "let client = Client::builder().add_root_certificate(ca).build()?;",
        "RS-003",
    ),
    ("rust", "let v = unsafe { *ptr };", "let v = *reference;", "RS-004"),
    (
        "rust",
        "let s = std::slice::from_raw_parts(ptr, len);",
        "let s = &buffer[..len];",
        "RS-005",
    ),
    ("rust", "let digest = md5::compute(data);", "let digest = Sha256::digest(data);", "RS-006"),
    (
        "rust",
        "let mut rng = StdRng::seed_from_u64(42);",
        "let mut rng = OsRng;",
        "RS-007",
    ),
    (
        "rust",
        'let file = NamedFile::open(req.match_info().query("path"))?;',
        'let file = NamedFile::open("static/index.html")?;',
        "RS-008",
    ),
    (
        "rust",
        "let cors = CorsLayer::permissive();",
        "let cors = CorsLayer::new().allow_origin(origin);",
        "RS-009",
    ),
    (
        "rust",
        "validation.insecure_disable_signature_validation();",
        'validation.set_audience(&["api"]);',
        "RS-010",
    ),
    (
        "rust",
        'Cookie::build(("sid", id)).http_only(false)',
        'Cookie::build(("sid", id)).http_only(true)',
        "RS-011",
    ),
    (
        "rust",
        'Html(format!("<h1>Hello {}</h1>", name))',
        "Html(template.render()?)",
        "RS-012",
    ),
    (
        "rust",
        "let msg: Message = bincode::deserialize(&bytes)?;",
        "let msg: Message = options.with_limit(1024).deserialize(&bytes)?;",
        "RS-013",
    ),
    (
        "rust",
        "builder.set_min_proto_version(Some(SslVersion::TLS1_1))?;",
        "builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;",
        "RS-014",
    ),
    ("rust", 'info!("login {} {}", user, token);', 'info!("login {}", user);', "GEN-005"),
    # TypeScript / Node.js backend
    (
        "typescript",
        "await prisma.$queryRawUnsafe(`SELECT * FROM users WHERE id = ${id}`);",
        "await prisma.$queryRaw`SELECT * FROM users WHERE id = ${id}`;",
        "TS-001",
    ),
    (
        "typescript",
        "qb.where(`user.name = '${name}'`)",
        'qb.where("user.name = :name", { name })',
        "TS-001",
    ),
    (
        "typescript",
        "const user = await User.findOne(req.body);",
        "const user = await User.findOne({ email: String(req.body.email) });",
        "TS-002",
    ),
    (
        "typescript",
        "await prisma.user.create({ data: req.body });",
        "await prisma.user.create({ data: { email: dto.email } });",
        "TS-003",
    ),
    (
        "javascript",
        "Object.assign(user, req.body);",
        "Object.assign(user, pick(req.body, ['name']));",
        "TS-003",
    ),
    (
        "typescript",
        "const result = vm.runInNewContext(code, sandbox);",
        "const result = await worker.run(code);",
        "TS-004",
    ),
    (
        "javascript",
        "const obj = serialize.unserialize(req.cookies.profile);",
        "const obj = JSON.parse(req.cookies.profile);",
        "TS-005",
    ),
    (
        "typescript",
        "const token = jwt.sign(payload, 'changeme123');",
        "const token = jwt.sign(payload, process.env.JWT_SECRET);",
        "TS-006",
    ),
    (
        "typescript",
        "app.use(session({ cookie: { secure: false } }));",
        "app.use(session({ cookie: { secure: true } }));",
        "TS-007",
    ),
    (
        "typescript",
        "const resp = await axios.get(req.query.url);",
        "const resp = await axios.get(config.feedUrl);",
        "TS-008",
    ),
    (
        "typescript",
        "const re = new RegExp(req.query.q);",
        "const re = new RegExp(escapeRegExp(String(q)));",
        "TS-009",
    ),
    (
        "javascript",
        "res.send(`<p>Hello ${req.query.name}</p>`);",
        "res.json({ name: req.query.name });",
        "TS-010",
    ),
    (
        "typescript",
        "app.useGlobalPipes(new ValidationPipe());",
        "app.useGlobalPipes(new ValidationPipe({ whitelist: true }));",
        "TS-011",
    ),
    (
        "javascript",
        "app.use(express.json({ limit: '500mb' }));",
        "app.use(express.json({ limit: '1mb' }));",
        "TS-012",
    ),
    (
        "javascript",
        "app.set('trust proxy', true);",
        "app.set('trust proxy', 1);",
        "TS-013",
    ),
    (
        "javascript",
        "app.use(express.static('public', { dotfiles: 'allow' }));",
        "app.use(express.static('public', { dotfiles: 'ignore' }));",
        "TS-014",
    ),
    (
        "typescript",
        "if (req.headers.signature === expectedSignature) {",
        "if (crypto.timingSafeEqual(received, expected)) {",
        "TS-015",
    ),
]


@pytest.mark.parametrize("language, vulnerable, safe, rule_id", ADDITIONAL_RULES)
def test_additional_rules(language, vulnerable, safe, rule_id):
    matches, _ = registry.scan(vulnerable, language)
    assert rule_id in ids(matches), matches
    matches, _ = registry.scan(safe, language)
    assert rule_id not in ids(matches), matches


def test_gitlab_ci_inherits_yaml_rules():
    matches, _ = registry.scan("  privileged: true", "gitlab-ci")
    assert "CFG-001" in ids(matches)


def test_language_aliases():
    matches, _ = registry.scan("pipeline { agent any }", "Jenkinsfile")
    assert "JK-003" in ids(matches)
    matches, _ = registry.scan("tls.Config{InsecureSkipVerify: true}", "golang")
    assert "GO-003" in ids(matches)
    matches, _ = registry.scan("var f = new BinaryFormatter();", "C#")
    assert "CS-003" in ids(matches)


# ── Inline suppression ───────────────────────────────────────────────────────


def test_inline_suppression_is_reported_not_hidden():
    code = "subprocess.run(c, shell=True)  # secreview:ignore PY-004 test fixture"
    matches, suppressed = registry.scan(code, "python")
    assert "PY-004" not in ids(matches)
    assert ids(suppressed) == {"PY-004"}
    assert suppressed[0]["line"] == 1


def test_suppression_without_ids_hides_every_rule_on_the_line():
    code = "subprocess.run(c, shell=True); eval(x)  # secreview:ignore"
    matches, suppressed = registry.scan(code, "python")
    assert matches == []
    assert {"PY-001", "PY-004"} <= ids(suppressed)


def test_suppressing_another_rule_does_not_hide_the_match():
    code = "subprocess.run(c, shell=True)  # secreview:ignore PY-001"
    matches, suppressed = registry.scan(code, "python")
    assert "PY-004" in ids(matches)
    assert suppressed == []


def test_very_long_lines_are_truncated_before_matching():
    line = "a" * 5000 + " eval(x)"
    matches, _ = registry.scan(line, "python")
    assert matches == []
