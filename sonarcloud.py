#!/usr/bin/env python3

import json
import os
import sys

LOG_PREFIX = "[trivy][plugins][sonarcube]"
TRIVY_CLOUD_SEVERITY = {
    "UNKNOWN": "INFO",
    "LOW": "MINOR",
    "MEDIUM": "MAJOR",
    "HIGH": "CRITICAL",
    "CRITICAL": "BLOCKER",
}


def load_trivy_report(fname):
    with open(fname) as fobj:
        return json.loads(fobj.read())


def parse_trivy_report(report):
    for result in report.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):
            try:
                vuln["Target"] = result["Target"]
                for key in ("VulnerabilityID", "Severity", "Description"):
                    vuln[key]
            except KeyError:
                continue

            yield vuln


def make_sonar_issues(vulnerabilities, file_path=None):
    return [
        {
            "engineId": "Trivy",
            "ruleId": vuln["VulnerabilityID"],
            "description": vuln["Description"],
            "type": "VULNERABILITY",
            "impacts": [
                {
                    "softwareQuality": "SECURITY",
                    "severity": TRIVY_CLOUD_SEVERITY[vuln["Severity"]],
                },
            ],
            "issues": [
                {
                    "primaryLocation": {
                        "message": vuln["Description"],
                        "filePath": file_path or vuln["Target"]
                    }
                },
            ],
        }
        for vuln in vulnerabilities
    ]


def make_sonar_report(rules):
    return json.dumps({"rules": rules}, indent=2)


def main(args):
    fname = args[1]
    if not os.path.exists(fname):
        sys.exit(f"{LOG_PREFIX} file not found: {fname}")

    arg_filePath = None
    for arg in args[2:]:
        if "filePath" in arg:
            arg_filePath = arg.split("=")[-1].strip()

    report = load_trivy_report(fname)
    vulnerabilities = parse_trivy_report(report)
    rules = make_sonar_issues(vulnerabilities, file_path=arg_filePath)
    report = make_sonar_report(rules)
    print(report)


if __name__ == "__main__":
    main(sys.argv)
