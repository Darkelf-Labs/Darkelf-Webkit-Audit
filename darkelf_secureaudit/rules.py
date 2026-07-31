"""
rules.py

Rule definitions and constants for Darkelf SecureAudit.
"""

GOOD_RULES = [
    (r"nonPersistentDataStore", "Ephemeral WKWebsiteDataStore"),
    (r"ephemeralSessionConfiguration", "Ephemeral NSURLSession"),
    (r"setNavigationDelegate_", "Navigation delegate configured"),
    (r"setUIDelegate_", "UI delegate configured"),
    (r"setProcessPool_", "Explicit WKProcessPool"),
    (r"WKContentRuleListStore", "Content Rule List"),
    (r"requestMediaCapturePermission", "Media permission delegate"),
    (r"decisionHandler\(0\)", "Media capture denied"),
]


SAFE_KVC = {
    "developerExtrasEnabled",
    "allowFileAccessFromFileURLs",
    "allowUniversalAccessFromFileURLs",
    "javaScriptCanOpenWindowsAutomatically",
    "logsPageMessagesToSystemConsoleEnabled",
}


TRUSTED = (
    "_build_",
    "_render_",
    "HOME_HTML",
    "REPORT_HTML",
    "ABOUT_HTML",
    "CONSOLE_HTML",
)


UNTRUSTED = (
    "requests.",
    "urllib",
    "socket",
    "input(",
    "pasteboard",
    "clipboard",
)


TAINT_SOURCES = {
    "input",
    "requests",
    "urllib",
    "socket",
    "clipboard",
    "pasteboard",
}


RULE_IDS = {
    "Dynamic JavaScript execution": "DEW001",
    "evaluateJavaScript() uses tainted input": "DEW002",
    "evaluateJavaScript() uses tainted variable": "DEW003",
    "Dynamic f-string JavaScript": "DEW004",
    "Concatenated JavaScript": "DEW005",
    "loadHTMLString() uses tainted HTML": "DEW006",
    "loadHTMLString() fed by untrusted HTML": "DEW007",
    "HTML appears to originate from untrusted source": "DEW008",
    "Review KVC key": "DEW009",
    "Known WebKit KVC": "DEW010",
    "Local file loading": "DEW011",
    "WKUserScript detected": "DEW012",
    "WKUserScript created": "DEW013",
    "WKWebpagePreferences configured": "DEW014",
    "JavaScript enabled": "DEW015",
    "JavaScript disabled": "DEW016",
}


SEVERITY_LEVELS = {
    "GOOD": "High",
    "INFO": "Medium",
    "MEDIUM": "Medium",
    "HIGH": "High",
}


SARIF_LEVELS = {
    "GOOD": "none",
    "INFO": "note",
    "MEDIUM": "warning",
    "HIGH": "error",
}


DELEGATE_SELECTORS = (
    "decidePolicyForNavigationAction",
    "requestMediaCapturePermission",
    "createWebViewWithConfiguration",
)


def get_rule_id(message: str) -> str:
    """
    Return the Darkelf rule ID for a finding.
    """

    if message.startswith("Review KVC key:"):
        return RULE_IDS["Review KVC key"]

    if message.startswith("Known WebKit KVC:"):
        return RULE_IDS["Known WebKit KVC"]

    return RULE_IDS.get(message, "DEW999")
