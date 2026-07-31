# 🛡️ Darkelf SecureAudit

**Advanced Security Auditing for WebKit, PyObjC, and Python Applications**

Darkelf SecureAudit is a modular static analysis framework designed to identify security issues in Python applications, with a focus on **WebKit**, **PyObjC**, and desktop browser development.

Unlike traditional Python linters, Darkelf SecureAudit performs framework-aware analysis to detect risky WebKit APIs, JavaScript injection patterns, taint propagation, delegate implementations, and security best practices.

---

## Features

* 🔍 Recursive project scanning
* 🌐 WebKit security analysis
* 🍎 PyObjC-specific checks
* 🧠 AST-based taint analysis
* 🔎 Regex-based security detection
* 📄 SARIF 2.1.0 report generation
* ⚙️ GitHub Code Scanning compatible
* 📦 Modular architecture
* 🐍 Python 3.11+

---

## Current Detection Capabilities

Darkelf SecureAudit can detect:

### JavaScript Security

* Dynamic `evaluateJavaScript()`
* f-string JavaScript injection
* Concatenated JavaScript
* Tainted JavaScript variables

### HTML Injection

* Unsafe `loadHTMLString()`
* Untrusted HTML sources
* HTML taint propagation

### WebKit Features

* WKUserScript creation
* WKScriptMessageHandler implementation
* WKURLSchemeHandler implementation
* WKWebpagePreferences configuration
* JavaScript enable/disable configuration
* Local file loading

### Delegate Analysis

* Navigation delegates
* Media permission delegates
* WebView creation delegates

### Security Best Practices

* Ephemeral `WKWebsiteDataStore`
* Ephemeral `NSURLSession`
* Explicit `WKProcessPool`
* Content Rule Lists
* Safe Key-Value Coding (KVC)

---

# Installation

Clone the repository:

```bash
git clone https://github.com/Darkelf2024/darkelf-webkit-audit.git
cd darkelf-webkit-audit
```

Install:

```bash
pip install .
```

or

```bash
pip install -e .
```

---

# Usage

Scan a single file:

```bash
darkelf-secureaudit browser.py
```

Scan an entire project:

```bash
darkelf-secureaudit /path/to/project
```

Generate JSON:

```bash
darkelf-secureaudit project --json
```

Generate SARIF:

```bash
darkelf-secureaudit project --sarif results.sarif
```

Run as a Python module:

```bash
python -m darkelf_secureaudit project
```

---

# Example Output

```
======================================================================
Darkelf SecureAudit v1.0.0
======================================================================

Files scanned : 18
Project Score : 97/100
HIGH Findings : 1

-------------------------------------------------------
browser.py
-------------------------------------------------------

GOOD
 • Ephemeral WKWebsiteDataStore

GOOD
 • Navigation delegate configured

INFO
 • WKUserScript detected

HIGH
 • Dynamic JavaScript execution

File Score: 90/100
```

---

# Project Structure

```
darkelf_secureaudit/
├── __init__.py
├── __main__.py
├── ast_scanner.py
├── cli.py
├── rules.py
├── sarif.py
├── scanner.py
└── utils.py
```

---

# GitHub Code Scanning

Generate a SARIF report:

```bash
darkelf-secureaudit . --sarif report.sarif
```

Upload the report using GitHub Code Scanning or GitHub Actions.

---

# Exit Codes

| Exit Code | Meaning                                           |
| --------- | ------------------------------------------------- |
| 0         | Scan completed successfully with no HIGH findings |
| 1         | One or more HIGH severity findings detected       |

---

# Supported Platforms

* macOS
* Linux
* Windows

Python 3.11 or newer is recommended.

---

# Roadmap

Planned enhancements include:

* AppKit analysis
* Qt WebEngine analysis
* PySide6 analysis
* Objective-C analysis
* Swift analysis
* HTML report generation
* JSON report enhancements
* Additional taint tracking
* Custom rule support
* Plugin architecture

---

# License

LGPL-3.0-or-later

---

# Contributing

Contributions, bug reports, and feature requests are welcome.

Please open an issue or submit a pull request.

---

# Disclaimer

Darkelf SecureAudit is a static analysis tool. It assists developers in identifying potential security issues but does not guarantee that software is free from vulnerabilities. Manual review, testing, and defense-in-depth practices remain essential.

---

Developed as part of the **Darkelf** open-source security ecosystem.
