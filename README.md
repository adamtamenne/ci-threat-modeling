# CI Threat Modeling

Three tools, one goal: move security review from a quarterly meeting into the PR itself.

1. **Architecture-level threat modeling** ([pytm](https://github.com/izar/pytm)) catches design-level risk when the system's components or data flows change.
2. **Code-level PR diff scanning** (`scan_diff.py`) catches implementation-level risk on every single PR, by reading the actual lines being added.
3. **Workflow hardening scanning** (`scan_workflows.py`) catches CI/CD pipeline misconfigurations: unpinned actions, script injection, excessive permissions, pwn requests, and secret exposure.

All three post their findings as PR comments and run entirely in GitHub Actions, no separate security review step required before merge.

## Tool 1: Architecture Threat Modeling (pytm)

Defines an application's architecture as code: components, data flows, trust boundaries, and data assets. When a PR changes the threat model, the CI pipeline generates a STRIDE threat report and posts a summary as a PR comment. The full report is uploaded as a build artifact.

Security review shifts from a manual gate to an automated part of the development workflow. Engineers see new threats introduced by architecture changes before the PR is merged.

### How It Works

```
threat-model/webapp.py    defines the architecture (components, flows, boundaries)
        |
        v
GitHub Actions workflow    runs pytm on every PR that touches the model
        |
        v
PR comment + artifact      STRIDE threat counts posted to the PR, full report downloadable
```

## Architecture Defined

The model represents a web application with:

| Component | Boundary | Notes |
|-----------|----------|-------|
| End User | Internet | Sends HTTPS requests through load balancer |
| Load Balancer / WAF | DMZ | TLS termination, request filtering |
| Web Application | App Tier | ASP.NET Core, input sanitization, output encoding, access control |
| Authentication Service | App Tier | Issues JWTs, validates credentials |
| Application Database | Data Tier | SQL, encrypted at rest, access controlled |
| Session Cache (Redis) | Data Tier | Session token storage, unencrypted transport (intentional finding) |
| External API | External | Third-party integration over HTTPS |

## STRIDE Categories

| Category | What It Catches |
|----------|----------------|
| **Spoofing** | Can an attacker impersonate a user or component? |
| **Tampering** | Can data be modified in transit or at rest? |
| **Repudiation** | Can actions be performed without accountability? |
| **Information Disclosure** | Can sensitive data leak through unintended channels? |
| **Denial of Service** | Can availability be disrupted? |
| **Elevation of Privilege** | Can an attacker gain unauthorized access? |

## Run Locally

```bash
pip install pytm
cd threat-model
python webapp.py --report report.md
```

The report generates at `threat-model/report.md`.

## Intentional Findings

The model includes a deliberate gap: the Redis session cache transport is unencrypted. pytm flags this as an information disclosure and tampering risk. This demonstrates that the tool catches real architectural weaknesses, not just theoretical ones.

## Why Tool 1 Matters

Most teams do threat modeling in a meeting room once a quarter, if at all. This approach makes it continuous: the model lives in the repo, changes are reviewed in PRs, and threats are generated automatically. When someone adds a new service or data flow, the pipeline tells the team what new risks they just introduced.

---

## Tool 2: PR Diff Security Scanner (scan_diff.py)

---

Reads the actual git diff of a PR and matches added lines against 14 security patterns covering SQL injection, XSS, SSRF, path traversal, command injection, insecure deserialization, missing auth, missing CSRF protection, hardcoded secrets, unencrypted transport, XXE, open redirect, insecure randomness, and sensitive data logging. Every finding is mapped to its STRIDE category, CWE, and a specific remediation, then posted as a PR comment.

Unlike the architecture model, this has no model file to maintain, it scans whatever code actually changed, every time.

### Usage

```bash
python scan_diff.py                              # diff against origin/main
python scan_diff.py --base origin/develop        # custom base branch
python scan_diff.py --summary-out summary.md \
                     --json-out findings.json \
                     --sarif-out findings.sarif   # all three output formats
```

### CI Integration

`.github/workflows/security-review.yml` runs on every PR: scans the diff, posts the findings table as a PR comment, uploads the JSON/SARIF as build artifacts, and uploads the SARIF to GitHub Code Scanning so findings also show up in the Security tab, not just the PR thread.

### Validated Against SonarQube Cloud

Run against the same PR as SonarQube Cloud: this scanner caught 5 findings SonarQube passed clean.

### Tests

`tests/test_scan_diff.py` has 12 tests: 9 confirm each vulnerable pattern fires on a synthetic diff, 3 confirm safe/parameterized equivalents stay silent. Run with:

```bash
python tests/test_scan_diff.py
```

## Why Tool 2 Matters

Architecture threat modeling tells you about risk introduced by *design* changes. It says nothing about the SQL built by string concatenation in a bug fix that never touched the architecture at all, that is most PRs, most of the time. `scan_diff.py` is the net underneath the architecture model, catching implementation-level mistakes the design-level tool was never meant to see.

---

## Tool 3: GitHub Actions Workflow Hardening Scanner (scan_workflows.py)

Parses GitHub Actions workflow YAML files and checks for six categories of security misconfiguration. Each finding is mapped to its CWE with severity and actionable remediation.

| Pattern ID | Category | What It Catches | CWE | Severity |
|------------|----------|----------------|-----|----------|
| WF-SUPPLY-01 | Supply chain | Action pinned to a mutable tag instead of a commit SHA | CWE-829 | High |
| WF-INJECT-01 | Script injection | Attacker-controllable expression (`${{ github.event.* }}`) interpolated into a `run:` block | CWE-78 | Critical |
| WF-PERMS-01 | Excessive permissions | `permissions: write-all` at workflow or job level | CWE-250 | High |
| WF-PRT-01 | Privilege escalation | `pull_request_target` trigger combined with checkout of PR head code | CWE-284 | Critical |
| WF-SECRET-01 | Secret exposure | Secret passed to echo/printf/print in a run block | CWE-532 | High |
| WF-ENV-01 | Secret scope | Secret set as env at workflow or job level, exposed to all steps including third-party actions | CWE-522 | Medium |

### How It Works

The scanner is structure-aware: it parses the YAML rather than running raw regex, so it checks context (which trigger, which permissions scope, which step type) rather than pattern-matching strings.

### Usage

```bash
python scan_workflows.py                               # scan .github/workflows/
python scan_workflows.py --path ci/workflows/           # custom directory
python scan_workflows.py --file workflow.yml             # single file
python scan_workflows.py --summary-out summary.md \
                         --json-out findings.json \
                         --sarif-out findings.sarif      # all three output formats
```

### CI Integration

`.github/workflows/workflow-review.yml` runs on every PR that touches `.github/workflows/**`: scans the workflow files, posts the findings table as a PR comment, uploads JSON/SARIF as build artifacts, and uploads SARIF to GitHub Code Scanning.

### Tests

`tests/test_scan_workflows.py` has 13 tests: 8 confirm each vulnerable pattern fires on synthetic workflow YAML, 5 confirm hardened equivalents stay silent. Run with:

```bash
python tests/test_scan_workflows.py
```

## Why Tool 3 Matters

Tools 1 and 2 secure the application code. Tool 3 secures the pipeline that builds and deploys it. A compromised GitHub Actions workflow can exfiltrate secrets, push malicious code, or pivot into production infrastructure, none of which the application-level scanners would ever see. The workflow hardening scanner closes that gap: it treats CI/CD configuration as an attack surface and reviews it with the same rigor as application code.
