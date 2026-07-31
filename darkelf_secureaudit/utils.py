"""
utils.py

Shared utility functions for Darkelf SecureAudit.
"""

import os
import re
from pathlib import Path

SKIP_DIRECTORIES = {
    "__pycache__",
    ".git",
    ".github",
    ".venv",
    "venv",
    "env",
    "build",
    "dist",
    ".mypy_cache",
    ".pytest_cache",
    ".tox",
}


def normalize_selector(name: str) -> str:
    """
    Normalize Objective-C selector names so delegate methods
    can be identified regardless of parameter suffixes.

    Example:
        decidePolicyForNavigationAction_decisionHandler_
            ->
        decidePolicyForNavigationAction
    """
    return re.sub(r"_[^_]*Handler_?$", "", name)


def discover_python_files(target):
    """
    Return a sorted list of Python files.

    Parameters
    ----------
    target : str | Path

    Returns
    -------
    list[pathlib.Path]
    """

    target = Path(target)

    if target.is_file():
        return [target]

    files = []

    for root, dirs, names in os.walk(target):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRECTORIES]

        for filename in names:
            if filename.endswith(".py"):
                files.append(Path(root) / filename)

    return sorted(files)


def read_source(path):
    """
    Safely read a Python source file.

    Returns
    -------
    list[str]
    """

    try:
        return path.read_text(
            encoding="utf-8",
            errors="ignore",
        ).splitlines()

    except Exception:
        return []


def join_lines(lines):
    """
    Convert a list of lines into a single string.
    """

    return "\n".join(lines)


def file_score(findings):
    """
    Calculate a security score from findings.

    Starts at 100.

    HIGH   = -10
    MEDIUM = -3
    """

    score = 100

    score -= len(findings["HIGH"]) * 10
    score -= len(findings["MEDIUM"]) * 3

    return max(score, 0)


def project_score(results):
    """
    Average all file scores.
    """

    if not results:
        return 0

    return sum(r["score"] for r in results) // len(results)


def count_high_findings(findings):
    """
    Count HIGH severity findings.
    """

    if not isinstance(findings, dict):
        return 0

    return len(findings.get("HIGH", []))


def empty_findings():
    """
    Create an empty findings dictionary.
    """

    return {
        "GOOD": [],
        "INFO": [],
        "MEDIUM": [],
        "HIGH": [],
    }


def confidence(category):
    """
    Confidence labels used in reports.
    """

    return {
        "GOOD": "High",
        "INFO": "Medium",
        "MEDIUM": "Medium",
        "HIGH": "High",
    }.get(category, "Unknown")
