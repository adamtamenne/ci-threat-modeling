#!/usr/bin/env python3
"""
Reads pytm JSON output and generates a STRIDE threat summary.
Produces summary.md (PR comment) and report.md (full report artifact).
"""

import json
from collections import Counter

with open("report.json") as f:
    data = json.load(f)

threats = data.get("findings", [])

# Map threats to STRIDE categories based on keywords in threat description/name
stride_keywords = {
    "Spoofing": ["spoof", "impersonat", "authentication abuse", "session sidejack", "hijack", "credential"],
    "Tampering": ["tamper", "manipulat", "injection", "overflow", "format string", "parameter injection", "xml schema poisoning", "double encoding"],
    "Repudiation": ["repudiat", "log", "audit"],
    "Information Disclosure": ["disclos", "excavat", "intercept", "path traversal", "relative path", "sniff"],
    "Denial of Service": ["flood", "denial", "excessive allocation", "xml ping", "resource consumption"],
    "Elevation of Privilege": ["privilege", "escalat", "subvert", "exploit test api"],
}


def classify_stride(threat_id, threat_description):
    desc_lower = (threat_id + " " + threat_description).lower()
    categories = []
    for category, keywords in stride_keywords.items():
        if any(kw in desc_lower for kw in keywords):
            categories.append(category)
    return categories if categories else ["Uncategorized"]


stride_counts = Counter()
categorized_threats = []

for t in threats:
    tid = t.get("threat_id", "")
    tdesc = t.get("description", "")
    tdetails = t.get("details", "")
    target = t.get("target", "")
    severity = t.get("severity", "")
    categories = classify_stride(tid, tdesc + " " + tdetails)
    for cat in categories:
        stride_counts[cat] += 1
    categorized_threats.append({
        "id": tid,
        "description": tdesc,
        "target": target,
        "severity": severity,
        "stride": categories,
    })

# Generate PR comment summary
with open("summary.md", "w") as f:
    f.write("## STRIDE Threat Model Results\n\n")
    f.write(f"**{len(threats)} threats identified** across the application architecture.\n\n")
    f.write("| STRIDE Category | Count |\n")
    f.write("|-----------------|-------|\n")
    for cat in ["Spoofing", "Tampering", "Repudiation", "Information Disclosure", "Denial of Service", "Elevation of Privilege", "Uncategorized"]:
        count = stride_counts.get(cat, 0)
        if count > 0:
            f.write(f"| {cat} | {count} |\n")
    f.write("\nFull report available as a build artifact.\n")

# Generate full report
with open("report.md", "w") as f:
    f.write("# STRIDE Threat Model Report\n\n")
    f.write(f"Total threats: {len(threats)}\n\n")

    for cat in ["Spoofing", "Tampering", "Repudiation", "Information Disclosure", "Denial of Service", "Elevation of Privilege", "Uncategorized"]:
        cat_threats = [t for t in categorized_threats if cat in t["stride"]]
        if not cat_threats:
            continue
        f.write(f"## {cat} ({len(cat_threats)})\n\n")
        f.write("| Threat | Target | Severity |\n")
        f.write("|--------|--------|----------|\n")
        for t in cat_threats:
            desc = t["description"][:80] + "..." if len(t["description"]) > 80 else t["description"]
            f.write(f"| {t['id']}: {desc} | {t['target']} | {t['severity']} |\n")
        f.write("\n")

print(f"Generated summary.md and report.md ({len(threats)} threats)")
