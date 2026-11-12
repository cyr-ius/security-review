# Detection benchmark

How well the scan detects vulnerabilities, measured on the
[OWASP Benchmark](https://owasp.org/www-project-benchmark/), and what this measure does not tell.
It covers a whole-codebase scan on the Controller server with the
[OpenGrep engine](../review/analysis/opengrep.md) enabled (`-opengrep` image), where both engines
run: the built-in pattern rules and the default OpenGrep rules.

## What the scan is

| Engine | Analysis | Role |
|---|---|---|
| [Built-in rules](../review/rules.md) (always enabled) | Line-by-line patterns (regular expressions) | Leads: weak algorithms, risky calls, secrets, configuration. Broad, with false positives |
| [OpenGrep rules](../review/analysis/opengrep.md#default-rules) (`-opengrep` image) | Syntax tree, and data flow for the 60 taint rules | Static analysis (SAST): a value read from the request is followed to a dangerous call, a sanitizer on the way stops it |

The taint analysis follows a value **within a file**: through variables, string building, lists
and dictionaries, and through the functions of the file (`--taint-intrafile`,
`SECREVIEW_OPENGREP_TAINT_INTRAFILE`). It does not follow a value from one file to another
(controller, then service, then data access layer). The AI review, guided by the
[checklists](../review/checklists.md), and a human reviewer cover these flows, the business logic
and the missing checks (authorization, for example).

## Results

Score of the OWASP Benchmark: **true positive rate (TPR) minus false positive rate (FPR)**, per
category, then averaged over the categories. A tool that flags everything, or nothing, scores 0 %.

| Benchmark | Test cases | Built-in rules | OpenGrep rules | Both engines |
|---|---|---|---|---|
| Java 1.2 | 2,740 | 23 % | 59 % | **67 %** (TPR 85 %, FPR 19 %) |
| Python 0.1 | 1,230 | 16 % | 31 % | **45 %** (TPR 77 %, FPR 31 %) |

Measured on 2026-11-12 with OpenGrep 1.31.0 and `--taint-intrafile`, and the rules of commit
`0a0614b1` (147 OpenGrep rules, built-in rules of `default_rules.toml`). Without
`--taint-intrafile`, Java scores 51 % (TPR 84 %, FPR 34 %): following the value into the helper
methods of a test case shows when they return a constant. Python is unchanged.

### With the AI review (estimate)

The scan produces leads that the [AI review](../review/index.md) confirms or dismisses by
reading the code. To estimate the score of this whole chain, 194 flagged test cases (109 Java,
85 Python) were sampled at random and triaged blind by an AI agent (Claude Sonnet), which saw
only the code of the test file and the alerts, never the expected result:

| Benchmark | Real alerts kept | False alerts dismissed | Estimated score (95 % range) |
|---|---|---|---|
| Java 1.2 | 49 / 49 | 60 / 60 | **85 %** (78 to 85 %) |
| Python 0.1 | 48 / 49 | 31 / 36 | **71 %** (60 to 75 %) |

The rates measured on the sample are applied to the true and false positive rates of the
whole benchmark; the range comes from the 95 % confidence intervals of these rates. The review
cannot raise the detection: the estimated score stays below the true positive rate of the rules.

This is an estimate, not a measure of the benchmark:

- the sample is small (60 safe Java cases, 36 safe Python cases);
- the Java cases were triaged on the alerts of the rules before `--taint-intrafile`;
- the agent saw one file at a time and was told that helpers do what their name says, where a
  real review explores the repository;
- the OWASP Benchmark is public: the model may know its idioms, which can flatter the triage;
- the score depends on the model of the host that runs the review.

### Java, per category (both engines)

| Category | CWE | TPR | FPR | Score |
|---|---|---|---|---|
| Command injection | 78 | 63 % | 35 % | 27 % |
| Weak cipher | 327 | 75 % | 0 % | 75 % |
| Weak hash | 328 | 69 % | 0 % | 69 % |
| LDAP injection | 90 | 89 % | 22 % | 67 % |
| Path traversal | 22 | 82 % | 31 % | 51 % |
| Insecure cookie | 614 | 100 % | 0 % | 100 % |
| SQL injection | 89 | 94 % | 26 % | 68 % |
| Trust boundary violation | 501 | 87 % | 47 % | 40 % |
| Weak random | 330 | 100 % | 0 % | 100 % |
| XPath injection | 643 | 93 % | 15 % | 78 % |
| Cross-site scripting | 79 | 89 % | 32 % | 57 % |

### Python, per category (both engines)

| Category | CWE | TPR | FPR | Score |
|---|---|---|---|---|
| Command injection | 78 | 54 % | 100 % | -46 % |
| Code injection | 94 | 100 % | 100 % | 0 % |
| Deserialization | 502 | 100 % | 33 % | 67 % |
| Weak hash | 328 | 100 % | 0 % | 100 % |
| LDAP injection | 90 | 50 % | 0 % | 50 % |
| Path traversal | 22 | 65 % | 43 % | 22 % |
| Open redirect | 601 | 77 % | 43 % | 34 % |
| Insecure cookie | 614 | 100 % | 0 % | 100 % |
| SQL injection | 89 | 60 % | 0 % | 60 % |
| Trust boundary violation | 501 | 50 % | 26 % | 24 % |
| Weak random | 330 | 100 % | 0 % | 100 % |
| XPath injection | 643 | 63 % | 31 % | 32 % |
| Cross-site scripting | 79 | 58 % | 29 % | 29 % |
| XML external entities | 611 | 100 % | 35 % | 65 % |

## Reading the results

- **Most remaining false positives come from conditions and containers.** A test case is safe
  when the value is dropped or replaced along the way (a branch that is never taken, a list
  element that is not the one read back, a value replaced in a dictionary). OpenGrep does not
  evaluate conditions and does not tell the keys of a container apart: such a case is flagged,
  and left to the review. Helper methods that return a constant are no longer flagged, since the
  analysis follows the functions of the file.
- **The two engines complement each other.** The strict OpenGrep rules flag a weak hash or a
  weak random value only for a named secret (password, token, key); the broad built-in rules flag
  every use, which is what the benchmark expects. The gate does not block these medium leads at
  its default threshold.
- **Code injection and command injection in Python** score low. The built-in rules flag every
  `eval` or `exec`, whatever the origin of the value. The command category has only 7 safe cases,
  all flagged because the value is dropped along the way: each false positive weighs heavily.
- **The benchmark is synthetic.** Its test cases are small servlets or Flask routes, each with
  one flow. A score does not predict the results on a real application. The rules are written to
  be generic: no change targets an idiom of the benchmark.

## Precision on real code

Each change to the default rules is also checked on open-source projects that are not tests:
a new alert there must be a real issue, otherwise the rule is corrected. The corpus covers
WebGoat, Spring PetClinic, Django, Flask, Express, OWASP Juice Shop, eShopOnWeb, Gitea and a
Rust (Axum, SQLx) application, plus non-web Python projects (httpie, black, pip, uvicorn), on
which command line arguments and the environment are not sources.

## Method

1. Scan the source of the benchmark with the default OpenGrep rules of the language
   (`opengrep scan --json --taint-intrafile --config src/security_review_mcp/rules/opengrep/<language> <benchmark>`),
   and each test file with the built-in rules (`scanner.scan_content_detailed`).
2. A test case is **flagged** when a finding on its file has the CWE of its category, or a child
   CWE (338 for 330, 95 for 94, 77 for 78, 80 for 79, 326 for 327, 916 for 328).
3. Compare with `expectedresults-<version>.csv` of the benchmark: a flagged real vulnerability is
   a true positive, a flagged safe case a false positive. The score is computed per category,
   then averaged.

This counts a finding by its CWE and its file, as the benchmark's own scorecards do; it does not
check the line.
