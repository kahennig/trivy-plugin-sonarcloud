import json
import tempfile
import unittest

from sonarcloud import (
    load_trivy_report,
    parse_trivy_report,
    make_sonar_issues,
    make_sonar_report,
)


class TestLoadTrivyReport(unittest.TestCase):
    def test_ok(self):
        _, fname = tempfile.mkstemp()
        with open(fname, "w") as fobj:
            fobj.write('{"a":[]}')

        report = load_trivy_report(fname)
        assert report == {"a": []}


class TestParseTrivyReport(unittest.TestCase):
    def test_ok(self):
        vuln1 = {"field1": "value1"}
        vuln2 = {
            "VulnerabilityID": "vuln1",
            "Severity": "severity1",
            "Description": "desc1",
        }
        vuln3 = {
            "VulnerabilityID": "vuln2",
            "Severity": "severity2",
            "Description": "desc2",
        }
        report = {
            "Results": [
                {
                    "Target": "target1",
                    "Vulnerabilities": [
                        vuln1,
                        vuln2,
                    ],
                },
                {
                    "Target": "target2",
                    "Vulnerabilities": [
                        vuln3,
                    ],
                },
            ],
        }

        vulnerabilities = list(parse_trivy_report(report))
        assert vulnerabilities == [
            {
                "VulnerabilityID": "vuln1",
                "Severity": "severity1",
                "Description": "desc1",
                "Target": "target1",
            },
            {
                "VulnerabilityID": "vuln2",
                "Severity": "severity2",
                "Description": "desc2",
                "Target": "target2",
            },
        ]


class TestMakeSonarIssues(unittest.TestCase):
    def test_file_path_override(self):
        vuln1 = {
            "VulnerabilityID": "vuln1",
            "Severity": "LOW",
            "Description": "desc1",
            "Target": "target1",
        }
        vuln2 = {
            "VulnerabilityID": "vuln2",
            "Severity": "MEDIUM",
            "Description": "desc2",
            "Target": "target2",
        }

        reports = make_sonar_issues([vuln1, vuln2], file_path="path1")
        assert reports == [
            {
                "engineId": "Trivy",
                "ruleId": "vuln1",
                "name": "vuln1",
                "description": "desc1",
                "cleanCodeAttribute": "TRUSTWORTHY",
                "impacts": [
                    {
                        "softwareQuality": "SECURITY",
                        "severity": "MINOR",
                    }
                ],
                "issues": [
                    {
                        "primaryLocation": {
                            "message": "desc1",
                            "filePath": "path1",
                        }
                    }
                ],
            },
            {
                "engineId": "Trivy",
                "ruleId": "vuln2",
                "name": "vuln2",
                "description": "desc2",
                "cleanCodeAttribute": "TRUSTWORTHY",
                "impacts": [
                    {
                        "softwareQuality": "SECURITY",
                        "severity": "MAJOR",
                    }
                ],
                "issues": [
                    {
                        "primaryLocation": {
                            "message": "desc2",
                            "filePath": "path1",
                        }
                    }
                ],
            }
        ]
    

    def test_no_file_path_override(self):
        vuln1 = {
            "VulnerabilityID": "vuln1",
            "Severity": "HIGH",
            "Description": "desc1",
            "Target": "target1",
        }
        vuln2 = {
            "VulnerabilityID": "vuln2",
            "Severity": "CRITICAL",
            "Description": "desc2",
            "Target": "target2",
        }

        reports = make_sonar_issues([vuln1, vuln2])
        assert reports == [
            {
                "engineId": "Trivy",
                "ruleId": "vuln1",
                "name": "vuln1",
                "description": "desc1",
                "cleanCodeAttribute": "TRUSTWORTHY",
                "impacts": [
                    {
                        "softwareQuality": "SECURITY",
                        "severity": "CRITICAL",
                    }
                ],
                "issues": [
                    {
                        "primaryLocation": {
                            "message": "desc1",
                            "filePath": "target1",
                        }
                    }
                ],
            },
            {
                "engineId": "Trivy",
                "ruleId": "vuln2",
                "name": "vuln2",
                "description": "desc2",
                "cleanCodeAttribute": "TRUSTWORTHY",
                "impacts": [
                    {
                        "softwareQuality": "SECURITY",
                        "severity": "BLOCKER",
                    }
                ],
                "issues": [
                    {
                        "primaryLocation": {
                            "message": "desc2",
                            "filePath": "target2",
                        }
                    }
                ],
            }
        ]


class TestMakeSonarReport(unittest.TestCase):
    def test_ok(self):
        rules = [1, True, "three"]
        report = make_sonar_report(rules)
        assert json.loads(report) == {"rules": [1, True, "three"]}


if __name__ == "__main__":
    unittest.main()
