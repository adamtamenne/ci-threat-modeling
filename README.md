# CI Threat Modeling

Automated STRIDE threat modeling in CI/CD using [pytm](https://github.com/izar/pytm).

## What This Does

Defines an application's architecture as code: components, data flows, trust boundaries, and data assets. When a PR changes the threat model, the CI pipeline generates a STRIDE threat report and posts a summary as a PR comment. The full report is uploaded as a build artifact.

Security review shifts from a manual gate to an automated part of the development workflow. Engineers see new threats introduced by architecture changes before the PR is merged.

## How It Works

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

## Why This Matters

Most teams do threat modeling in a meeting room once a quarter, if at all. This approach makes it continuous: the model lives in the repo, changes are reviewed in PRs, and threats are generated automatically. When someone adds a new service or data flow, the pipeline tells the team what new risks they just introduced.
