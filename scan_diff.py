#!/usr/bin/env python3
"""
Scans the git diff of a PR for security-relevant code patterns.
Maps each finding to STRIDE categories with severity, affected file/line,
and actionable remediation. Posts results as a PR comment via CI.

No model file to maintain. Reads the actual code being changed.

Usage:
  python scan_diff.py                          # diffs against origin/main
  python scan_diff.py --base origin/develop    # custom base branch
  python scan_diff.py --file diff.patch        # read from a patch file
"""

import re
import json
import argparse
import subprocess
import sys
from dataclasses import dataclass, field, asdict

# --- Pattern definitions ---

@dataclass
class Pattern:
    id: str
    name: str
    description: str
    regex: str
    languages: list
    stride: list
    severity: str
    remediation: str
    cwe: str = ""
    # compiled at load time
    _compiled: re.Pattern = field(default=None, repr=False)

    def __post_init__(self):
        self._compiled = re.compile(self.regex, re.IGNORECASE | re.MULTILINE)


PATTERNS = [
    # SQL Injection
    Pattern(
        id="SQLI-01",
        name="SQL query with string concatenation",
        description="User input flows into a SQL query via string concatenation or interpolation instead of parameterized queries.",
        regex=r'''(["'`]SELECT\s.*?\+\s*\w+|["'`]INSERT\s.*?\+\s*\w+|["'`]UPDATE\s.*?\+\s*\w+|["'`]DELETE\s.*?\+\s*\w+|\$".*?SELECT.*?\{|`.*?SELECT.*?\$\{|\.prepare\(\s*`|\.prepare\(\s*['"]\s*\+|FromSqlRaw\s*\(\s*\$|\.ExecuteReader|\.ExecuteNonQuery|\.ExecuteScalar)''',
        languages=["cs", "js", "ts", "py", "go"],
        stride=["Tampering", "Information Disclosure"],
        severity="High",
        remediation="Use parameterized queries, prepared statements, or an ORM with bound parameters.",
        cwe="CWE-89",
    ),
    # XSS
    Pattern(
        id="XSS-01",
        name="Unsanitized output to HTML response",
        description="User-controlled value rendered in HTML without encoding. In .NET, Html.Raw() bypasses Razor auto-encoding.",
        regex=r'''(Html\.Raw\s*\(|@Html\.Raw|res\.send\s*\(\s*[`'"].*?\$\{|res\.write\s*\(.*?req\.|\.innerHTML\s*=|document\.write\s*\()''',
        languages=["cs", "js", "ts", "cshtml"],
        stride=["Tampering"],
        severity="High",
        remediation="Use output encoding. In .NET, let Razor auto-encode (remove Html.Raw). In JS, use textContent instead of innerHTML.",
        cwe="CWE-79",
    ),
    # SSRF
    Pattern(
        id="SSRF-01",
        name="HTTP request with user-controlled URL",
        description="A user-supplied URL is passed to an HTTP client without validation against an allowlist.",
        regex=r'''(HttpClient\s*\(.*?\.Get|HttpClient\s*\(.*?\.Send|HttpClient\s*\(.*?\.Post|GetStringAsync\s*\(|GetAsync\s*\(|fetch\s*\(\s*\w+|requests\.\w+\s*\(\s*\w+|http\.Get\s*\(\s*\w+|urllib\.request\.urlopen\s*\()''',
        languages=["cs", "js", "ts", "py", "go"],
        stride=["Spoofing", "Information Disclosure"],
        severity="High",
        remediation="Validate URLs against an allowlist of permitted domains. Block requests to private IP ranges and cloud metadata endpoints.",
        cwe="CWE-918",
    ),
    # Path Traversal
    Pattern(
        id="PT-01",
        name="File path with user-controlled input",
        description="User input is used to construct a file path without validation that the resolved path stays within the intended directory.",
        regex=r'''(Path\.Combine\s*\(.*?(req|file|param|input|name|path)|path\.join\s*\(.*?(req|file|param|input)|path\.resolve\s*\(.*?(req|file|param)|os\.path\.join\s*\(.*?(request|file|param)|readFileSync\s*\(.*?(req|file|param)|File\.ReadAllBytes\s*\(|File\.ReadAllText\s*\(|StreamReader\s*\(.*?(file|path|input))''',
        languages=["cs", "js", "ts", "py"],
        stride=["Information Disclosure"],
        severity="High",
        remediation="Resolve the full path, then verify it starts with the intended base directory. Reject anything outside.",
        cwe="CWE-22",
    ),
    # Command Injection
    Pattern(
        id="CMDi-01",
        name="Shell command with user input",
        description="User input is concatenated into a shell command without sanitization.",
        regex=r'''(Process\.Start.*?\+.*?\w+|process\.StartInfo\.Arguments.*?\+|exec\s*\(.*?req\.|child_process\.exec\s*\(|subprocess\.call\s*\(.*?shell\s*=\s*True|os\.system\s*\(|Runtime\.getRuntime\(\)\.exec)''',
        languages=["cs", "js", "ts", "py", "java"],
        stride=["Elevation of Privilege"],
        severity="Critical",
        remediation="Use parameterized process execution (e.g., execFile in Node, subprocess.run with list args in Python). Never pass user input through a shell.",
        cwe="CWE-78",
    ),
    # Insecure Deserialization
    Pattern(
        id="DESER-01",
        name="Insecure deserialization configuration",
        description="Deserialization with unrestricted type handling allows an attacker to instantiate arbitrary classes from untrusted input.",
        regex=r'''(TypeNameHandling\s*=\s*TypeNameHandling\.All|TypeNameHandling\.Auto|BinaryFormatter|ObjectInputStream\s*\(|pickle\.loads?\s*\(|yaml\.load\s*\([^)]*Loader\s*=\s*yaml\.FullLoader|eval\s*\(\s*req\.)''',
        languages=["cs", "js", "ts", "py", "java"],
        stride=["Tampering", "Elevation of Privilege"],
        severity="Critical",
        remediation="Never use TypeNameHandling.All with untrusted input. Use a SerializationBinder to allowlist expected types. Avoid BinaryFormatter entirely.",
        cwe="CWE-502",
    ),
    # Missing Auth
    Pattern(
        id="AUTH-01",
        name="Route or endpoint missing authorization",
        description="A controller action or route handler does not enforce authentication or authorization.",
        regex=r'''(\[AllowAnonymous\]|\[HttpPost\][^\[]*?(?!\[Authorize)public|router\.(post|put|delete)\s*\([^)]+(?!requireAuth|isAuthenticated|auth))''',
        languages=["cs", "js", "ts"],
        stride=["Spoofing", "Elevation of Privilege"],
        severity="Medium",
        remediation="Apply [Authorize] attribute to all sensitive endpoints. Use requireAuth middleware on all state-changing routes.",
        cwe="CWE-862",
    ),
    # Missing CSRF
    Pattern(
        id="CSRF-01",
        name="POST handler without anti-forgery protection",
        description="A POST endpoint does not validate an anti-CSRF token.",
        regex=r'''(\[HttpPost\][^\[]*?(?!\[ValidateAntiForgeryToken\]))''',
        languages=["cs"],
        stride=["Tampering"],
        severity="Medium",
        remediation="Add [ValidateAntiForgeryToken] to all POST actions in ASP.NET. Use SameSite cookie attributes as defense in depth.",
        cwe="CWE-352",
    ),
    # Hardcoded Secrets
    Pattern(
        id="SECRET-01",
        name="Hardcoded credential or secret",
        description="A password, connection string, API key, or secret is hardcoded in source code.",
        regex=r'''(password\s*=\s*["'][^"']{4,}|Password\s*=\s*["'][^"']{4,}|connectionString\s*=\s*["']|api[_-]?key\s*=\s*["'][^"']{8,}|secret\s*=\s*["'][^"']{8,}|PRIVATE.KEY|BEGIN RSA)''',
        languages=["cs", "js", "ts", "py", "go", "json", "yaml", "yml"],
        stride=["Information Disclosure"],
        severity="High",
        remediation="Store secrets in a vault (Azure Key Vault, AWS Secrets Manager) or environment variables. Never commit secrets to source.",
        cwe="CWE-798",
    ),
    # Unencrypted Transport
    Pattern(
        id="CRYPTO-01",
        name="Unencrypted connection or disabled TLS verification",
        description="A network connection is made without encryption or with TLS verification disabled.",
        regex=r'''(http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0)|ServerCertificateCustomValidationCallback.*?true|verify\s*=\s*False|rejectUnauthorized\s*:\s*false|InsecureSkipVerify\s*:\s*true|CURLOPT_SSL_VERIFYPEER.*?false)''',
        languages=["cs", "js", "ts", "py", "go"],
        stride=["Information Disclosure", "Tampering"],
        severity="Medium",
        remediation="Use HTTPS for all connections. Do not disable certificate verification in production.",
        cwe="CWE-319",
    ),
    # XXE
    Pattern(
        id="XXE-01",
        name="XML parsing with external entity resolution enabled",
        description="XML parser allows external entity resolution, enabling file reads and SSRF via crafted XML input.",
        regex=r'''(XmlResolver\s*=\s*new\s+XmlUrlResolver|DtdProcessing\s*=\s*DtdProcessing\.Parse|FEATURE.*?external-general-entities.*?true|etree\.parse\s*\(|lxml\.etree\.fromstring)''',
        languages=["cs", "java", "py"],
        stride=["Information Disclosure", "Spoofing"],
        severity="High",
        remediation="Set XmlResolver = null in .NET. Disable DTD processing. Use defusedxml in Python.",
        cwe="CWE-611",
    ),
        # Open Redirect
    Pattern(
        id="REDIR-01",
        name="Open redirect with user-controlled URL",
        description="User input is used in a redirect without validating that the destination is a trusted domain. Attacker crafts a link that redirects the victim to a phishing site.",
        regex=r'''(redirect\s*\(\s*req\.|Redirect\s*\(\s*\w+|res\.redirect\s*\(\s*\w+|location\.href\s*=\s*\w+|window\.location\s*=\s*\w+|header\s*\(\s*['"]Location.*?\+)''',
        languages=["cs", "js", "ts", "py", "go"],
        stride=["Spoofing"],
        severity="Medium",
        remediation="Validate redirect URLs against an allowlist of trusted domains. Use relative paths instead of full URLs. Never pass user input directly to a redirect.",
        cwe="CWE-601",
    ),
    # Insecure Randomness
    Pattern(
        id="RAND-01",
        name="Insecure random number generation",
        description="Using a non-cryptographic random source for security-sensitive values like tokens, session IDs, or secrets. Output is predictable and can be brute-forced.",
        regex=r'''(Math\.random\s*\(|Random\s*\(\)|random\.random\s*\(|random\.randint\s*\(|rand\s*\(\)|mt_rand\s*\()''',
        languages=["cs", "js", "ts", "py", "go", "java", "php"],
        stride=["Spoofing", "Tampering"],
        severity="Medium",
        remediation="Use cryptographically secure alternatives: crypto.randomBytes() in Node, RandomNumberGenerator in .NET, secrets module in Python, crypto/rand in Go.",
        cwe="CWE-330",
    ),
    # Logging Sensitive Data
    Pattern(
        id="LOG-01",
        name="Sensitive data written to logs",
        description="Passwords, tokens, API keys, or other secrets are logged to console or a log file. Logs are often stored in plaintext and accessible to operations staff or attackers who gain read access.",
        regex=r'''(console\.log\s*\(.*?(password|token|secret|apikey|api_key|credential|ssn|credit)|logger?\.\w+\s*\(.*?(password|token|secret|apikey|api_key|credential)|print\s*\(.*?(password|token|secret|api_key|credential)|Log\.\w+\s*\(.*?(password|token|secret|apikey|credential))''',
        languages=["cs", "js", "ts", "py", "go", "java"],
        stride=["Information Disclosure"],
        severity="High",
        remediation="Never log sensitive values. Mask or redact credentials before logging. Use structured logging that excludes sensitive fields by policy.",
        cwe="CWE-532",
    ),
]

# --- Diff parser ---

@dataclass
class DiffHunk:
    file: str
    start_line: int
    added_lines: dict  # line_number -> content


def parse_diff(diff_text):
    """Parse unified diff into file hunks with added lines only."""
    hunks = []
    current_file = None
    current_line = 0

    for line in diff_text.splitlines():
        if line.startswith("+++ b/"):
            current_file = line[6:]
        elif line.startswith("@@ "):
            match = re.search(r'\+(\d+)', line)
            if match:
                current_line = int(match.group(1)) - 1
        elif line.startswith("+") and not line.startswith("+++"):
            current_line += 1
            if current_file:
                if not hunks or hunks[-1].file != current_file:
                    hunks.append(DiffHunk(file=current_file, start_line=current_line, added_lines={}))
                hunks[-1].added_lines[current_line] = line[1:]
        elif not line.startswith("-"):
            current_line += 1

    return hunks


def get_file_extension(filename):
    parts = filename.rsplit(".", 1)
    return parts[1] if len(parts) > 1 else ""


# --- Scanner ---

@dataclass
class Finding:
    pattern_id: str
    name: str
    description: str
    file: str
    line: int
    code: str
    stride: list
    severity: str
    remediation: str
    cwe: str


def scan_hunks(hunks):
    findings = []
    seen = set()

    for hunk in hunks:
        ext = get_file_extension(hunk.file)
        full_added = "\n".join(hunk.added_lines.values())

        for pattern in PATTERNS:
            if ext and ext not in pattern.languages:
                continue

            for line_num, line_content in hunk.added_lines.items():
                if pattern._compiled.search(line_content):
                    key = (pattern.id, hunk.file, line_num)
                    if key not in seen:
                        seen.add(key)
                        findings.append(Finding(
                            pattern_id=pattern.id,
                            name=pattern.name,
                            description=pattern.description,
                            file=hunk.file,
                            line=line_num,
                            code=line_content.strip()[:120],
                            stride=pattern.stride,
                            severity=pattern.severity,
                            remediation=pattern.remediation,
                            cwe=pattern.cwe,
                        ))

    severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    findings.sort(key=lambda f: severity_order.get(f.severity, 99))
    return findings


# --- Output ---

def generate_summary(findings):
    lines = []

    if not findings:
        lines.append("## Security Review: PR Diff\n")
        lines.append("No security-relevant patterns detected in the changed code.\n")
        return "\n".join(lines)

    lines.append("## Security Review: PR Diff\n")
    lines.append(f"**{len(findings)} finding(s)** in {len(set(f.file for f in findings))} file(s) changed.\n")

    lines.append("| Finding | File | Line | STRIDE | Severity |")
    lines.append("|---------|------|------|--------|----------|")
    for f in findings:
        stride_str = ", ".join(f.stride)
        lines.append(f"| {f.name} | `{f.file}` | {f.line} | {stride_str} | {f.severity} |")

    lines.append("\n### Details\n")
    for f in findings:
        lines.append(f"**`{f.file}:{f.line}`** ({f.cwe}) {f.name}")
        lines.append(f"  {f.description}")
        lines.append(f"  **Remediation:** {f.remediation}")
        lines.append(f"  ```")
        lines.append(f"  {f.code}")
        lines.append(f"  ```\n")

    return "\n".join(lines)


def generate_json(findings):
    return json.dumps([asdict(f) for f in findings], indent=2)


def main():
    parser = argparse.ArgumentParser(description="Scan PR diff for security patterns")
    parser.add_argument("--base", default="origin/main", help="Base branch to diff against")
    parser.add_argument("--file", help="Read diff from a patch file instead of git")
    parser.add_argument("--json-out", help="Write findings as JSON to this path")
    parser.add_argument("--summary-out", default="summary.md", help="Write markdown summary to this path")
    args = parser.parse_args()

    if args.file:
        with open(args.file) as f:
            diff_text = f.read()
    else:
        try:
            result = subprocess.run(
                ["git", "diff", args.base + "...HEAD"],
                capture_output=True, text=True, check=True
            )
            diff_text = result.stdout
        except subprocess.CalledProcessError as e:
            print(f"Error running git diff: {e.stderr}", file=sys.stderr)
            sys.exit(1)

    if not diff_text.strip():
        print("No diff found.")
        with open(args.summary_out, "w") as f:
            f.write("## Security Review: PR Diff\n\nNo changes detected.\n")
        sys.exit(0)

    hunks = parse_diff(diff_text)
    findings = scan_hunks(hunks)

    summary = generate_summary(findings)
    with open(args.summary_out, "w") as f:
        f.write(summary)

    if args.json_out:
        with open(args.json_out, "w") as f:
            f.write(generate_json(findings))

    print(f"{len(findings)} finding(s) in {len(hunks)} diff hunk(s)")
    sys.exit(0)


if __name__ == "__main__":
    main()
