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
                            "https://github.com/Darkelf2024/"
                            "darkelf_secureaudit"
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
        for line, message, _ in findings.get(severity, []):

            rule_id = get_rule_id(message)

            if rule_id not in rules:
                rules[rule_id] = {
                    "id": rule_id,
                    "name": message,
                    "shortDescription": {
                        "text": message,
                    },
                }

            sarif_results.append(
                {
                    "ruleId": rule_id,
                    "level": SARIF_LEVELS[severity],
                    "message": {
                        "text": message,
                    },
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": "project",
                                },
                                "region": {
                                    "startLine": max(line, 1),
                                },
                            }
                        }
                    ],
                }
            )

    sarif["runs"][0]["tool"]["driver"]["rules"] = list(rules.values())
    sarif["runs"][0]["results"] = sarif_results

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(sarif, f, indent=2)
