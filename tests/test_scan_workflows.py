"""Tests for scan_workflows.py workflow security checks.

Feeds synthetic workflow YAML through the scanner and validates that
expected patterns fire on insecure configurations and stay silent on
hardened workflows.
"""

import sys
import os
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scan_workflows import scan_workflow_file


# --- Helpers ---

def scan_yaml(content):
    """Write content to a temp file, scan it, return findings."""
    fd, path = tempfile.mkstemp(suffix=".yml")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(content)
        return scan_workflow_file(path)
    finally:
        os.unlink(path)


def find_ids(findings):
    return [f.pattern_id for f in findings]


# --- Vulnerable workflows should trigger ---

def test_unpinned_action():
    findings = scan_yaml("""\
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v3
""")
    assert "WF-SUPPLY-01" in find_ids(findings), f"Expected WF-SUPPLY-01, got {find_ids(findings)}"


def test_script_injection_issue_title():
    findings = scan_yaml("""\
name: Issue Greeting
on: issues
jobs:
  greet:
    runs-on: ubuntu-latest
    steps:
      - run: |
          echo "New issue: ${{ github.event.issue.title }}"
""")
    assert "WF-INJECT-01" in find_ids(findings), f"Expected WF-INJECT-01, got {find_ids(findings)}"


def test_script_injection_pr_body():
    findings = scan_yaml("""\
name: PR Label
on: pull_request
jobs:
  label:
    runs-on: ubuntu-latest
    steps:
      - run: |
          BODY="${{ github.event.pull_request.body }}"
          echo "$BODY" | grep -q "breaking"
""")
    assert "WF-INJECT-01" in find_ids(findings), f"Expected WF-INJECT-01, got {find_ids(findings)}"


def test_excessive_permissions():
    findings = scan_yaml("""\
name: Deploy
on: push
permissions: write-all
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - run: echo "deploying"
""")
    assert "WF-PERMS-01" in find_ids(findings), f"Expected WF-PERMS-01, got {find_ids(findings)}"


def test_pr_target_checkout():
    findings = scan_yaml("""\
name: PR Check
on: pull_request_target
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: npm test
""")
    assert "WF-PRT-01" in find_ids(findings), f"Expected WF-PRT-01, got {find_ids(findings)}"


def test_secret_echo():
    findings = scan_yaml("""\
name: Debug
on: push
jobs:
  debug:
    runs-on: ubuntu-latest
    steps:
      - run: echo ${{ secrets.API_KEY }}
""")
    assert "WF-SECRET-01" in find_ids(findings), f"Expected WF-SECRET-01, got {find_ids(findings)}"


def test_workflow_level_secret_env():
    findings = scan_yaml("""\
name: CI
on: push
env:
  DB_PASSWORD: ${{ secrets.DB_PASSWORD }}
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: ./deploy.sh
""")
    assert "WF-ENV-01" in find_ids(findings), f"Expected WF-ENV-01, got {find_ids(findings)}"


def test_job_level_secret_env():
    findings = scan_yaml("""\
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    env:
      TOKEN: ${{ secrets.DEPLOY_TOKEN }}
    steps:
      - uses: some-org/deploy-action@v2
      - run: ./deploy.sh
""")
    assert "WF-ENV-01" in find_ids(findings), f"Expected WF-ENV-01, got {find_ids(findings)}"


# --- Safe workflows should NOT trigger ---

def test_sha_pinned_action_clean():
    findings = scan_yaml("""\
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
""")
    assert "WF-SUPPLY-01" not in find_ids(findings), "SHA-pinned action should not trigger WF-SUPPLY-01"


def test_safe_expression_in_env_clean():
    findings = scan_yaml("""\
name: CI
on: issues
jobs:
  greet:
    runs-on: ubuntu-latest
    steps:
      - run: echo "Title is $ISSUE_TITLE"
        env:
          ISSUE_TITLE: ${{ github.event.issue.title }}
""")
    assert "WF-INJECT-01" not in find_ids(findings), (
        "Expression in env (not run block) should not trigger WF-INJECT-01"
    )


def test_minimal_permissions_clean():
    findings = scan_yaml("""\
name: CI
on: push
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
""")
    assert "WF-PERMS-01" not in find_ids(findings), "Minimal permissions should not trigger WF-PERMS-01"


def test_pr_target_no_checkout_clean():
    findings = scan_yaml("""\
name: Label
on: pull_request_target
jobs:
  label:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/labeler@v4
""")
    assert "WF-PRT-01" not in find_ids(findings), (
        "pull_request_target without PR head checkout should not trigger WF-PRT-01"
    )


def test_step_level_secret_clean():
    findings = scan_yaml("""\
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: ./deploy.sh
        env:
          DB_PASSWORD: ${{ secrets.DB_PASSWORD }}
""")
    assert "WF-ENV-01" not in find_ids(findings), "Step-level secret env should not trigger WF-ENV-01"


# --- Runner ---

if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed = 0
    failed = 0
    for test in tests:
        try:
            test()
            passed += 1
            print(f"  PASS  {test.__name__}")
        except AssertionError as e:
            failed += 1
            print(f"  FAIL  {test.__name__}: {e}")

    print(f"\n{passed} passed, {failed} failed out of {len(tests)} tests")
    sys.exit(1 if failed else 0)
