"""Tests for scan_diff.py pattern detection.

Feeds synthetic diffs through the scanner and validates that expected
patterns fire on known-vulnerable code and stay silent on safe code.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scan_diff import parse_diff, scan_hunks, PATTERNS


# --- Helpers ---

def make_diff(filename, lines):
    """Build a minimal unified diff with the given added lines."""
    header = f"diff --git a/{filename} b/{filename}\n"
    header += f"--- a/{filename}\n"
    header += f"+++ b/{filename}\n"
    header += f"@@ -0,0 +1,{len(lines)} @@\n"
    body = "\n".join(f"+{line}" for line in lines)
    return header + body


def scan_code(filename, lines):
    """Parse a synthetic diff and return findings."""
    diff = make_diff(filename, lines)
    hunks = parse_diff(diff)
    return scan_hunks(hunks)


def find_ids(findings):
    return [f.pattern_id for f in findings]


# --- Vulnerable code should trigger ---

def test_sqli_string_concat():
    findings = scan_code("Controllers/UserController.cs", [
        'var query = "SELECT * FROM users WHERE id = " + userId;',
    ])
    assert "SQLI-01" in find_ids(findings), f"Expected SQLI-01, got {find_ids(findings)}"


def test_xss_html_raw():
    findings = scan_code("Views/Profile.cshtml", [
        "@Html.Raw(Model.Bio)",
    ])
    assert "XSS-01" in find_ids(findings), f"Expected XSS-01, got {find_ids(findings)}"


def test_command_injection():
    findings = scan_code("Services/BuildService.cs", [
        'Process.Start("cmd", "/c " + userInput);',
    ])
    assert "CMDi-01" in find_ids(findings), f"Expected CMDi-01, got {find_ids(findings)}"


def test_deserialization_typenamehandling():
    findings = scan_code("Config/JsonConfig.cs", [
        "settings.TypeNameHandling = TypeNameHandling.All;",
    ])
    assert "DESER-01" in find_ids(findings), f"Expected DESER-01, got {find_ids(findings)}"


def test_hardcoded_secret():
    findings = scan_code("Services/DbContext.cs", [
        'var password = "SuperSecret123!";',
    ])
    assert "SECRET-01" in find_ids(findings), f"Expected SECRET-01, got {find_ids(findings)}"


def test_xxe_xmlresolver():
    findings = scan_code("Services/XmlParser.cs", [
        "doc.XmlResolver = new XmlUrlResolver();",
    ])
    assert "XXE-01" in find_ids(findings), f"Expected XXE-01, got {find_ids(findings)}"


def test_path_traversal():
    findings = scan_code("Controllers/FileController.cs", [
        'var fullPath = Path.Combine(basePath, req.Query["file"]);',
    ])
    assert "PT-01" in find_ids(findings), f"Expected PT-01, got {find_ids(findings)}"


def test_insecure_random():
    findings = scan_code("Services/TokenService.cs", [
        "var token = new Random().Next().ToString();",
    ])
    assert "RAND-01" in find_ids(findings), f"Expected RAND-01, got {find_ids(findings)}"


def test_open_redirect():
    findings = scan_code("Controllers/AuthController.cs", [
        "return Redirect(returnUrl);",
    ])
    assert "REDIR-01" in find_ids(findings), f"Expected REDIR-01, got {find_ids(findings)}"


# --- Safe code should NOT trigger ---

def test_parameterized_query_clean():
    findings = scan_code("Controllers/UserController.cs", [
        'cmd.Parameters.AddWithValue("@id", userId);',
    ])
    assert "SQLI-01" not in find_ids(findings), "Parameterized query should not trigger SQLI-01"


def test_encoded_output_clean():
    findings = scan_code("Views/Profile.cshtml", [
        "@Model.Bio",
    ])
    assert "XSS-01" not in find_ids(findings), "Auto-encoded Razor output should not trigger XSS-01"


def test_safe_crypto_clean():
    findings = scan_code("Services/HashService.cs", [
        "using var sha256 = SHA256.Create();",
    ])
    crypto_ids = [fid for fid in find_ids(findings) if fid.startswith("CRYPTO")]
    assert len(crypto_ids) == 0, f"SHA256 should not trigger crypto findings, got {crypto_ids}"


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
