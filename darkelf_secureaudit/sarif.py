"""
sarif.py

SARIF 2.1.0 report generation for Darkelf SecureAudit.
"""

import json

from .rules import (
    SARIF_LEVELS,
    get_rule_id,
)


def write_sarif(findings, output_file):
    """
    Write a SARIF 2.1.0 report.

    Parameters
    ----------
    findings : dict
        Aggregated findings dictionary.

        Project-level findings are expected in the form:

            (line, message, confidence, file_path)

        Older three-item findings are also accepted for compatibility:

            (line, message, confidence)

    output_file : str | Path
        Destination SARIF filename.
    """

    sarif = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Darkelf SecureAudit",
                        "version": "1.0.0",
                        "informationUri": (
                            "https://github.com/Darkelf-Labs/"
                            "Darkelf-Webkit-Audit"
                        ),
                        "rules": [],
                    }
                },
                "results": [],
            }
        ],
    }

    rules = {}
    sarif_results = []

    for severity in ("HIGH", "MEDIUM", "INFO", "GOOD"):
        for finding in findings.get(severity, []):
            #
            # New project-level format:
            #
            #   line, message, confidence, file_path
            #
            # Retain compatibility with older three-field findings.
            #

            if len(finding) >= 4:
                line, message, _, file_path = finding[:4]
            else:
                line, message, _ = finding
                file_path = None

            rule_id = get_rule_id(message)

            if rule_id not in rules:
                rules[rule_id] = {
                    "id": rule_id,
                    "name": message,
                    "shortDescription": {
                        "text": message,
                    },
                }

            result = {
                "ruleId": rule_id,
                "level": SARIF_LEVELS[severity],
                "message": {
                    "text": message,
                },
            }

            #
            # Only provide a physical source location when the scanner
            # actually knows which source file generated the finding.
            #
            # This prevents GitHub from attempting to fingerprint a
            # non-existent placeholder such as "project".
            #

            if file_path:
                result["locations"] = [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": str(file_path).replace("\\", "/"),
                                "uriBaseId": "%SRCROOT%",
                            },
                            "region": {
                                "startLine": max(int(line), 1),
                            },
                        }
                    }
                ]

            sarif_results.append(result)

    sarif["runs"][0]["tool"]["driver"]["rules"] = list(rules.values())
    sarif["runs"][0]["results"] = sarif_results

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(
            sarif,
            f,
            indent=2,
            ensure_ascii=False,
        )