"""
scanner.py

Main scanning engine for Darkelf SecureAudit.
"""

import re
import traceback
from pathlib import Path

from .ast_scanner import ast_scan
from .rules import (
    DELEGATE_SELECTORS,
    GOOD_RULES,
    SAFE_KVC,
    TAINT_SOURCES,
    UNTRUSTED,
)
from .utils import (
    confidence,
    discover_python_files,
    empty_findings,
    normalize_selector,
)


def scan(lines):
    """
    Scan a single Python source file.

    Parameters
    ----------
    lines : list[str]

    Returns
    -------
    tuple
        (score, findings)
    """

    findings = empty_findings()

    score = 100
    seen = set()

    joined = "\n".join(lines)

    ast_findings = ast_scan(joined)

    tainted = set()
    html_vars = {}

    def add(category, line, message):
        nonlocal score

        key = (category, line, message)

        if key in seen:
            return

        seen.add(key)

        findings[category].append(
            (
                line,
                message,
                confidence(category),
            )
        )

        if category == "HIGH":
            score -= 10

        elif category == "MEDIUM":
            score -= 3

    #
    # Regex scanner
    #

    for line_number, line in enumerate(lines, start=1):
        #
        # Variable tracking
        #

        match = re.match(
            r"\s*([A-Za-z_]\w*)\s*=\s*(.+)",
            line,
        )

        if match:
            variable = match.group(1)
            expression = match.group(2)

            html_vars[variable] = expression

            if any(source in expression for source in TAINT_SOURCES):
                tainted.add(variable)

            for source in list(tainted):
                if source in expression:
                    tainted.add(variable)

        #
        # Positive findings
        #

        for pattern, message in GOOD_RULES:
            if re.search(pattern, line):
                add(
                    "GOOD",
                    line_number,
                    message,
                )

        #
        # KVC inspection
        #

        if "setValue_forKey_" in line:
            match = re.search(
                r'"([^"]+)"',
                line,
            )

            key = match.group(1) if match else "unknown"

            if key in SAFE_KVC:
                add(
                    "INFO",
                    line_number,
                    f"Known WebKit KVC: {key}",
                )

            else:
                add(
                    "MEDIUM",
                    line_number,
                    f"Review KVC key: {key}",
                )

        #
        # loadHTMLString()
        #

        if "loadHTMLString_" in line:
            window = "\n".join(
                lines[max(0, line_number - 41) : min(len(lines), line_number + 5)]
            )

            if any(token in window for token in UNTRUSTED):
                add(
                    "HIGH",
                    line_number,
                    "HTML appears to originate from untrusted source",
                )

        #
        # evaluateJavaScript()
        #

        # Only flag the regex path when a variable already known to be
        # tainted reaches evaluateJavaScript_. AST analysis below handles
        # structured Python expressions more accurately. String
        # concatenation, formatting and f-strings are not vulnerabilities
        # by themselves.
        if "evaluateJavaScript_" in line and any(
            re.search(rf"\\b{re.escape(variable)}\\b", line)
            for variable in tainted
        ):
            add(
                "HIGH",
                line_number,
                "evaluateJavaScript() uses tainted input",
            )

        #
        # Additional detections
        #

        if "userContentController_didReceiveScriptMessage_" in line:
            add(
                "GOOD",
                line_number,
                "WKScriptMessageHandler implemented",
            )

        # WKUserScript, WKWebpagePreferences, enabled JavaScript and local
        # file loading are normal browser primitives. Their mere presence is
        # inventory, not a security finding, so they are intentionally not
        # emitted into SARIF. Risk is reported only when dangerous data flow
        # or configuration is actually detected.

        if "startURLSchemeTask" in line or "webView_startURLSchemeTask_" in line:
            add(
                "GOOD",
                line_number,
                "WKURLSchemeHandler implemented",
            )

        if "allowsContentJavaScript" in line and "False" in line:
            add(
                "GOOD",
                line_number,
                "JavaScript disabled",
            )

    #
    # Delegate detection
    #

    normalized = "\n".join(normalize_selector(line) for line in lines)

    for selector in DELEGATE_SELECTORS:
        if selector in joined or selector in normalized:
            add(
                "GOOD",
                0,
                f"Delegate implements {selector}",
            )

    #
    # Merge AST findings
    #

    for line, severity, message in ast_findings:
        add(
            severity,
            line,
            message,
        )

    return max(score, 0), findings


def scan_project(path):
    """
    Scan a Python file or an entire project directory.

    Returns
    -------
    dict
        {
            "score": int,
            "files": int,
            "findings": {...}
        }

    Project-level findings include the source filename:

        (line, message, confidence, file_path)
    """

    findings = empty_findings()

    total_score = 0
    scanned = 0

    path = Path(path)

    #
    # Preserve the scan target so findings can be mapped back to
    # repository-relative source files for SARIF / GitHub Code Scanning.
    #

    if path.is_file():
        files = [path]
        project_root = path.parent
    else:
        files = discover_python_files(path)
        project_root = path.parent

    for file in files:
        try:
            with file.open("r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()

            score, file_findings = scan(lines)

            total_score += score
            scanned += 1

            #
            # Convert the source path to a POSIX repository-relative path.
            #
            # Example:
            #
            #   darkelf_cocoa/application.py
            #
            # rather than:
            #
            #   /home/runner/work/.../darkelf_cocoa/application.py
            #

            try:
                relative_file = file.relative_to(project_root).as_posix()
            except ValueError:
                relative_file = file.as_posix()

            #
            # Attach the actual source filename to every project finding.
            #

            for severity in findings:
                for line, message, finding_confidence in file_findings[severity]:
                    findings[severity].append(
                        (
                            line,
                            message,
                            finding_confidence,
                            relative_file,
                        )
                    )

        except Exception:
            print("\n" + "=" * 70)
            print(f"ERROR scanning: {file}")
            print("=" * 70)
            traceback.print_exc()
            raise

    average = total_score // scanned if scanned else 0

    return {
        "score": average,
        "files": scanned,
        "findings": findings,
    }
