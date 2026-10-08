
"""
Regression tests for Darkelf SecureAudit SARIF reporting.

Ensures positive detections, informational entries, and
synthetic locations do not become GitHub Code Scanning alerts.

Real HIGH and MEDIUM findings must remain reportable.
"""

import json

from darkelf_secureaudit.sarif import write_sarif
from darkelf_secureaudit.scanner import scan


def test_delegate_inventory_not_uploaded(tmp_path):
    """
    A normal WKUIDelegate implementation is not a vulnerability.
    """

    lines = [
        "import os\n",
        (
            "def webView_createWebViewWithConfiguration_"
            "forNavigationAction_windowFeatures_"
            "(self, w, c, a, f):\n"
        ),
        "    return None\n",
    ]

    _, found = scan(lines)

    project = {
        category: [
            (
                line,
                message,
                confidence,
                "darkelf_cocoa/darkelf_delegates.py",
            )
            for line, message, confidence in items
        ]
        for category, items in found.items()
    }

    path = tmp_path / "result.sarif"

    write_sarif(project, path)

    results = json.loads(
        path.read_text(encoding="utf-8")
    )["runs"][0]["results"]

    assert results == []


def test_real_findings_preserved(tmp_path):
    """
    Genuine HIGH and MEDIUM findings must remain visible.
    """

    found = {
        "HIGH": [
            (
                42,
                "evaluateJavaScript() uses tainted variable",
                "High",
                "app.py",
            )
        ],
        "MEDIUM": [
            (
                8,
                "Review KVC key: unexpected",
                "Medium",
                "app.py",
            )
        ],
        "INFO": [
            (
                3,
                "Known WebKit KVC: developerExtrasEnabled",
                "Medium",
                "app.py",
            )
        ],
        "GOOD": [
            (
                0,
                "Delegate implements createWebViewWithConfiguration",
                "High",
                "app.py",
            )
        ],
    }

    path = tmp_path / "result.sarif"

    write_sarif(found, path)

    results = json.loads(
        path.read_text(encoding="utf-8")
    )["runs"][0]["results"]

    assert [item["level"] for item in results] == [
        "error",
        "warning",
    ]

    assert [
        item["locations"][0]["physicalLocation"]["region"][
            "startLine"
        ]
        for item in results
    ] == [42, 8]


def test_synthetic_location_skipped(tmp_path):
    """
    Invalid synthetic locations must never be mapped to line 1.
    """

    path = tmp_path / "result.sarif"

    write_sarif(
        {
            "HIGH": [
                (
                    0,
                    "Synthetic",
                    "High",
                    "app.py",
                )
            ]
        },
        path,
    )

    results = json.loads(
        path.read_text(encoding="utf-8")
    )["runs"][0]["results"]

    assert results == []


def test_info_and_good_findings_excluded(tmp_path):
    """
    Positive security inventory must not appear as alerts.
    """

    findings = {
        "HIGH": [],
        "MEDIUM": [],
        "INFO": [
            (
                10,
                "Known WebKit KVC: developerExtrasEnabled",
                "Medium",
                "browser.py",
            )
        ],
        "GOOD": [
            (
                20,
                "Explicit WKProcessPool",
                "High",
                "browser.py",
            )
        ],
    }

    path = tmp_path / "result.sarif"

    write_sarif(findings, path)

    data = json.loads(
        path.read_text(encoding="utf-8")
    )

    assert data["runs"][0]["results"] == []
    assert data["runs"][0]["tool"]["driver"]["rules"] == []
