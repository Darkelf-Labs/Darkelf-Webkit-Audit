
"""
sarif.py

SARIF 2.1.0 report generation for Darkelf SecureAudit.

GitHub Code Scanning should receive actionable security findings,
not informational inventory or positive security detections.
"""

import json

from .rules import SARIF_LEVELS, get_rule_id


def write_sarif(findings, output_file):
    """
    Write a SARIF 2.1.0 report.

    Parameters
    ----------
    findings : dict
        Aggregated findings dictionary.

        Project-level findings are expected as:

            (line, message, confidence, file_path)

        Older three-item findings are accepted for compatibility,
        but cannot be emitted without a source filename.

    output_file : str | Path
        Destination SARIF filename.

    Notes
    -----
    Only HIGH and MEDIUM findings are exported.

    GOOD and INFO findings remain available in console/JSON
    reports but are excluded from GitHub Code Scanning.

    Synthetic findings with invalid line numbers or missing
    source filenames are also excluded.
    """

    sarif = {
        "version": "2.1.0",
        "$schema": (
            "https://json.schemastore.org/sarif-2.1.0.json"
        ),
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

    # Only actionable findings belong in Code Scanning.
    # Positive/informational findings are console inventory.
    for severity in ("HIGH", "MEDIUM"):
        for finding in findings.get(severity, []):

            if len(finding) >= 4:
                line, message, _, file_path = finding[:4]
            else:
                line, message, _ = finding
                file_path = None

            # Never fabricate a source location.
            # Synthetic line 0 must not become line 1.
            if not file_path or int(line) < 1:
                continue

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
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": str(file_path).replace(
                                    "\\", "/"
                                ),
                                "uriBaseId": "%SRCROOT%",
                            },
                            "region": {
                                "startLine": int(line),
                            },
                        }
                    }
                ],
            }

            sarif_results.append(result)

    sarif["runs"][0]["tool"]["driver"]["rules"] = list(
        rules.values()
    )

    sarif["runs"][0]["results"] = sarif_results

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(
            sarif,
            f,
            indent=2,
            ensure_ascii=False,
        )
