#!/usr/bin/env python3
"""
Scans GitHub Actions workflow files for security misconfigurations.
Maps each finding to CWE with severity and actionable remediation.
Posts results as a PR comment via CI.

Covers six categories: supply chain (unpinned actions), command injection
(script injection via expressions), excessive permissions, privilege
escalation (pull_request_target), secret exposure in logs, and secret
exposure via broad environment variables.

Usage:
  python scan_workflows.py                           # scan .github/workflows/
  python scan_workflows.py --path ci/workflows/      # custom directory
  python scan_workflows.py --file workflow.yml        # single file
"""

import re
import json
import argparse
import sys
from dataclasses import dataclass, asdict
from pathlib import Path

try:
    import yaml
except ImportError:
    print("pyyaml is required: pip install pyyaml", file=sys.stderr)
    sys.exit(1)

from sarif_output import generate_sarif

# --- Constants ---

# 40 hex character commit SHA
SHA_RE = re.compile(r"^[0-9a-f]{40}$")

# Attacker-controllable expression contexts in GitHub Actions.
# These values can be set by anyone who opens an issue, PR, or comment.
DANGEROUS_CONTEXTS = [
    "github.event.issue.title",
    "github.event.issue.body",
    "github.event.pull_request.title",
    "github.event.pull_request.body",
    "github.event.comment.body",
    "github.event.review.body",
    "github.event.review_comment.body",
    "github.event.commits.*.message",
    "github.event.commits.*.author.name",
    "github.event.commits.*.author.email",
    "github.event.head_commit.message",
    "github.event.head_commit.author.name",
    "github.event.head_commit.author.email",
    "github.head_ref",
    "github.event.workflow_run.head_branch",
    "github.event.workflow_run.head_commit.message",
    "github.event.pull_request.head.ref",
    "github.event.pull_request.head.label",
    "github.event.discussion.title",
    "github.event.discussion.body",
    "github.event.pages.*.page_name",
]

# Build a regex that matches ${{ <dangerous_context> }} in text.
# Wildcard entries (commits.*.message) become [^}]+ so they match
# any array index.
_ctx_patterns = []
for ctx in DANGEROUS_CONTEXTS:
    escaped = re.escape(ctx).replace(r"\.\*\.", r"\.[^}]+\.")
    _ctx_patterns.append(escaped)

DANGEROUS_CONTEXT_RE = re.compile(
    r"\$\{\{\s*(" + "|".join(_ctx_patterns) + r")\s*\}\}"
)

# Secret reference in an expression
SECRET_REF_RE = re.compile(r"\$\{\{\s*secrets\.(\w+)\s*\}\}")

# echo/print of a secret
SECRET_ECHO_RE = re.compile(
    r"(echo|printf|print|cat)\s+.*?\$\{\{\s*secrets\.\w+\s*\}\}",
    re.IGNORECASE,
)

# PR head ref patterns used in checkout
PR_HEAD_PATTERNS = [
    "github.event.pull_request.head.sha",
    "github.event.pull_request.head.ref",
    "refs/pull/",
]


# --- Data classes ---

@dataclass
class Finding:
    pattern_id: str
    name: str
    description: str
    file: str
    line: int
    code: str
    severity: str
    remediation: str
    cwe: str


# --- Helpers ---

def _find_line(text, substring, start=0):
    """Return the 1-based line number where *substring* first appears."""
    pos = text.find(substring, start)
    if pos == -1:
        return 1
    return text[:pos].count("\n") + 1


def _get_all_steps(workflow):
    """Yield (job_name, step_index, step_dict) across every job."""
    jobs = workflow.get("jobs", {})
    if not isinstance(jobs, dict):
        return
    for job_name, job in jobs.items():
        if not isinstance(job, dict):
            continue
        steps = job.get("steps", [])
        if not isinstance(steps, list):
            continue
        for idx, step in enumerate(steps):
            if isinstance(step, dict):
                yield job_name, idx, step


# --- Individual checks ---

def _check_unpinned_actions(workflow, text, filename, findings):
    """WF-SUPPLY-01: action pinned to a mutable tag instead of a SHA."""
    seen = set()
    for _, _, step in _get_all_steps(workflow):
        uses = step.get("uses", "")
        if not uses or "/" not in uses or "@" not in uses:
            continue

        action, ref = uses.rsplit("@", 1)

        if action.startswith("docker://") or action.startswith("./"):
            continue
        if SHA_RE.match(ref):
            continue

        key = (action, ref)
        if key in seen:
            continue
        seen.add(key)

        findings.append(Finding(
            pattern_id="WF-SUPPLY-01",
            name="Unpinned action reference",
            description=(
                f"Action '{action}' is pinned to mutable tag '{ref}'. "
                "A compromised or force-pushed tag can inject malicious code "
                "into the pipeline. Third-party actions should be pinned to "
                "a full commit SHA."
            ),
            file=filename,
            line=_find_line(text, uses),
            code=f"uses: {uses}",
            severity="High",
            remediation=(
                f"Pin to a commit SHA: `uses: {action}@<40-char-sha>`. "
                "Add a comment with the version for readability."
            ),
            cwe="CWE-829",
        ))


def _check_script_injection(workflow, text, filename, findings):
    """WF-INJECT-01: attacker-controllable expression in a run block."""
    seen = set()
    for job_name, _, step in _get_all_steps(workflow):
        run_block = step.get("run", "")
        if not run_block:
            continue

        for m in DANGEROUS_CONTEXT_RE.finditer(run_block):
            expr = m.group(0)
            context = m.group(1)
            key = (job_name, context)
            if key in seen:
                continue
            seen.add(key)

            findings.append(Finding(
                pattern_id="WF-INJECT-01",
                name="Script injection via expression",
                description=(
                    f"The expression `{expr}` in a run block interpolates "
                    "attacker-controllable input directly into a shell command. "
                    f"An attacker can set '{context}' to arbitrary content "
                    "including shell metacharacters."
                ),
                file=filename,
                line=_find_line(text, expr),
                code=expr,
                severity="Critical",
                remediation=(
                    "Pass the value through an environment variable: set it "
                    "in the step's `env:` block and reference $ENV_VAR in the "
                    "script. Environment variables are not interpreted as shell "
                    "syntax."
                ),
                cwe="CWE-78",
            ))


def _check_permissions(workflow, text, filename, findings):
    """WF-PERMS-01: write-all at workflow or job level."""
    # Workflow-level
    perms = workflow.get("permissions", None)
    if isinstance(perms, str) and perms == "write-all":
        findings.append(Finding(
            pattern_id="WF-PERMS-01",
            name="Excessive workflow permissions",
            description=(
                "Workflow grants write-all permissions. Every job and step, "
                "including third-party actions, gets a token that can push "
                "code, manage releases, and modify settings."
            ),
            file=filename,
            line=_find_line(text, "write-all"),
            code="permissions: write-all",
            severity="High",
            remediation=(
                "Declare the minimum permissions each job needs. Set top-level "
                "`permissions: {}` and grant per-job, e.g., "
                "`permissions: { contents: read, pull-requests: write }`."
            ),
            cwe="CWE-250",
        ))

    # Job-level
    jobs = workflow.get("jobs", {})
    if isinstance(jobs, dict):
        for job_name, job in jobs.items():
            if not isinstance(job, dict):
                continue
            job_perms = job.get("permissions", None)
            if isinstance(job_perms, str) and job_perms == "write-all":
                findings.append(Finding(
                    pattern_id="WF-PERMS-01",
                    name="Excessive job permissions",
                    description=(
                        f"Job '{job_name}' grants write-all permissions. Every "
                        "step in this job, including third-party actions, gets "
                        "full write access."
                    ),
                    file=filename,
                    line=_find_line(text, "write-all"),
                    code=f"permissions: write-all  # job: {job_name}",
                    severity="High",
                    remediation=(
                        "Replace with the minimum set this job actually needs, "
                        "e.g., `permissions: { contents: read }`."
                    ),
                    cwe="CWE-250",
                ))


def _check_pr_target(workflow, text, filename, findings):
    """WF-PRT-01: pull_request_target trigger + checkout of PR head code."""
    triggers = workflow.get("on", workflow.get(True, None))
    if triggers is None:
        return

    has_prt = False
    if isinstance(triggers, str):
        has_prt = triggers == "pull_request_target"
    elif isinstance(triggers, list):
        has_prt = "pull_request_target" in triggers
    elif isinstance(triggers, dict):
        has_prt = "pull_request_target" in triggers

    if not has_prt:
        return

    for _, _, step in _get_all_steps(workflow):
        uses = step.get("uses", "")
        if "checkout" not in uses:
            continue

        with_block = step.get("with", {})
        if not isinstance(with_block, dict):
            continue

        ref = str(with_block.get("ref", ""))
        for pattern in PR_HEAD_PATTERNS:
            if pattern in ref:
                findings.append(Finding(
                    pattern_id="WF-PRT-01",
                    name="pull_request_target with PR head checkout",
                    description=(
                        "This workflow uses pull_request_target and checks out "
                        f"the PR author's code (ref: {ref}). The PR author's "
                        "code runs with the base repo's secrets and write "
                        "token, allowing arbitrary code execution in a "
                        "privileged context."
                    ),
                    file=filename,
                    line=_find_line(text, ref),
                    code=f"on: pull_request_target + checkout ref: {ref}",
                    severity="Critical",
                    remediation=(
                        "Use the pull_request trigger instead. If "
                        "pull_request_target is required, never checkout the "
                        "PR head. Build and test in a separate unprivileged "
                        "workflow and pass results via artifacts."
                    ),
                    cwe="CWE-284",
                ))
                return  # one finding per workflow


def _check_secret_logging(text, filename, findings):
    """WF-SECRET-01: secret echoed or printed in a run block."""
    seen = set()
    for m in SECRET_ECHO_RE.finditer(text):
        matched = m.group(0).strip()[:120]
        secret_match = SECRET_REF_RE.search(matched)
        secret_name = secret_match.group(1) if secret_match else "unknown"

        if secret_name in seen:
            continue
        seen.add(secret_name)

        line_num = text[: m.start()].count("\n") + 1
        findings.append(Finding(
            pattern_id="WF-SECRET-01",
            name="Secret written to workflow logs",
            description=(
                f"The secret '{secret_name}' is passed to echo/printf/print. "
                "GitHub masks known secret values, but partial matches, "
                "encoding, or redirection can bypass masking and expose the "
                "value in plaintext logs."
            ),
            file=filename,
            line=line_num,
            code=matched,
            severity="High",
            remediation=(
                "Never echo secrets. To verify a secret is set, check its "
                "length: `if [ -n \"$SECRET\" ]; then echo 'set'; fi`."
            ),
            cwe="CWE-532",
        ))


def _check_env_secrets(workflow, text, filename, findings):
    """WF-ENV-01: secrets set as env at workflow or job level."""
    # Workflow-level env
    env = workflow.get("env", {})
    if isinstance(env, dict):
        for key, value in env.items():
            if isinstance(value, str) and SECRET_REF_RE.search(value):
                findings.append(Finding(
                    pattern_id="WF-ENV-01",
                    name="Secret in workflow-level environment",
                    description=(
                        f"Secret is set as environment variable '{key}' at the "
                        "workflow level. Every step in every job, including "
                        "third-party actions, can read this value."
                    ),
                    file=filename,
                    line=_find_line(text, value),
                    code=f"env: {key}: {value}",
                    severity="Medium",
                    remediation=(
                        "Move the secret to the specific step that needs it. "
                        "Set it in the step's own `env:` block to limit "
                        "exposure to that step alone."
                    ),
                    cwe="CWE-522",
                ))

    # Job-level env
    jobs = workflow.get("jobs", {})
    if isinstance(jobs, dict):
        for job_name, job in jobs.items():
            if not isinstance(job, dict):
                continue
            job_env = job.get("env", {})
            if not isinstance(job_env, dict):
                continue
            for key, value in job_env.items():
                if isinstance(value, str) and SECRET_REF_RE.search(value):
                    findings.append(Finding(
                        pattern_id="WF-ENV-01",
                        name="Secret in job-level environment",
                        description=(
                            f"Secret is set as environment variable '{key}' at "
                            f"the job level in '{job_name}'. Every step in "
                            "this job, including third-party actions, can "
                            "read this value."
                        ),
                        file=filename,
                        line=_find_line(text, value),
                        code=f"env: {key}: {value}  # job: {job_name}",
                        severity="Medium",
                        remediation=(
                            "Move the secret to the specific step that needs "
                            "it. Set it in the step's own `env:` block to "
                            "limit exposure to that step alone."
                        ),
                        cwe="CWE-522",
                    ))


# --- Scanner entry point ---

def scan_workflow_file(filepath):
    """Scan a single workflow YAML file and return a list of Findings."""
    text = Path(filepath).read_text()

    try:
        workflow = yaml.safe_load(text)
    except yaml.YAMLError:
        return []

    if not isinstance(workflow, dict):
        return []

    filename = str(filepath)
    findings = []

    _check_unpinned_actions(workflow, text, filename, findings)
    _check_script_injection(workflow, text, filename, findings)
    _check_permissions(workflow, text, filename, findings)
    _check_pr_target(workflow, text, filename, findings)
    _check_secret_logging(text, filename, findings)
    _check_env_secrets(workflow, text, filename, findings)

    return findings


# --- Output ---

def generate_summary(findings):
    """Build a markdown summary table and details section."""
    lines = []

    if not findings:
        lines.append("## Workflow Security Review\n")
        lines.append("No security misconfigurations detected in workflow files.\n")
        return "\n".join(lines)

    lines.append("## Workflow Security Review\n")
    file_count = len(set(f.file for f in findings))
    lines.append(f"**{len(findings)} finding(s)** in {file_count} workflow file(s).\n")

    lines.append("| Finding | File | Line | Severity | CWE |")
    lines.append("|---------|------|------|----------|-----|")
    for f in findings:
        lines.append(f"| {f.name} | `{f.file}` | {f.line} | {f.severity} | {f.cwe} |")

    lines.append("\n### Details\n")
    for f in findings:
        lines.append(f"**`{f.file}:{f.line}`** ({f.cwe}) {f.name}")
        lines.append(f"  {f.description}")
        lines.append(f"  **Remediation:** {f.remediation}")
        lines.append(f"  ```")
        lines.append(f"  {f.code}")
        lines.append(f"  ```\n")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Scan GitHub Actions workflows for security misconfigurations"
    )
    parser.add_argument(
        "--path", default=".github/workflows",
        help="Directory containing workflow YAML files",
    )
    parser.add_argument("--file", help="Scan a single workflow file")
    parser.add_argument("--json-out", help="Write findings as JSON to this path")
    parser.add_argument(
        "--summary-out", default="workflow-summary.md",
        help="Write markdown summary to this path",
    )
    parser.add_argument("--sarif-out", help="Write findings as SARIF 2.1.0 to this path")
    args = parser.parse_args()

    all_findings = []

    if args.file:
        files = [Path(args.file)]
    else:
        wf_dir = Path(args.path)
        if not wf_dir.is_dir():
            print(f"Workflow directory not found: {args.path}", file=sys.stderr)
            sys.exit(1)
        files = sorted(wf_dir.glob("*.yml")) + sorted(wf_dir.glob("*.yaml"))

    for f in files:
        if f.is_file():
            all_findings.extend(scan_workflow_file(f))

    severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    all_findings.sort(key=lambda f: severity_order.get(f.severity, 99))

    summary = generate_summary(all_findings)
    with open(args.summary_out, "w") as out:
        out.write(summary)

    if args.json_out:
        with open(args.json_out, "w") as out:
            json.dump([asdict(f) for f in all_findings], out, indent=2)

    if args.sarif_out:
        sarif_findings = []
        for f in all_findings:
            sarif_findings.append({
                "pattern_id": f.pattern_id,
                "pattern_name": f.name,
                "description": f.description,
                "file": f.file,
                "line": f.line,
                "severity": f.severity,
                "remediation": f.remediation,
                "cwe": f.cwe,
                "stride": [],
            })
        sarif = generate_sarif(sarif_findings)
        Path(args.sarif_out).write_text(json.dumps(sarif, indent=2))

    print(f"{len(all_findings)} finding(s) in {len(files)} workflow file(s)")
    sys.exit(0)


if __name__ == "__main__":
    main()
