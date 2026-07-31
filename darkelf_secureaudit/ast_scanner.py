"""
ast_scanner.py

AST-based security analysis for Darkelf SecureAudit.
"""

import ast

from .rules import TAINT_SOURCES


class WebKitVisitor(ast.NodeVisitor):
    """
    Performs AST-based security analysis for WebKit/PyObjC applications.
    """

    def __init__(self):
        self.assignments = {}
        self.tainted = set()
        self.findings = []

    # ---------------------------------------------------------
    # Helpers
    # ---------------------------------------------------------

    def _mark_tainted(self, variable):
        if variable:
            self.tainted.add(variable)

    def add(self, node, severity, message):
        self.findings.append(
            (
                node.lineno,
                severity,
                message,
            )
        )

    # ---------------------------------------------------------
    # Assignment tracking
    # ---------------------------------------------------------

    def visit_Assign(self, node):

        if len(node.targets) != 1:
            self.generic_visit(node)
            return

        target = node.targets[0]

        if not isinstance(target, ast.Name):
            self.generic_visit(node)
            return

        variable = target.id
        value = node.value

        self.assignments[variable] = value

        #
        # Direct taint source
        #

        if isinstance(value, ast.Call):
            func = value.func

            if (isinstance(func, ast.Name) and func.id in TAINT_SOURCES) or (
                isinstance(func, ast.Attribute) and func.attr in TAINT_SOURCES
            ):
                self._mark_tainted(variable)

        #
        # Propagate taint
        #

        elif isinstance(value, ast.Name) and value.id in self.tainted:
            self._mark_tainted(variable)

        self.generic_visit(node)

    # ---------------------------------------------------------
    # Function calls
    # ---------------------------------------------------------

    def visit_Call(self, node):

        if not isinstance(node.func, ast.Attribute):
            self.generic_visit(node)
            return

        method = node.func.attr

        #
        # evaluateJavaScript_
        #

        if method == "evaluateJavaScript_":
            if node.args:
                arg = node.args[0]

                if isinstance(arg, ast.Name) and arg.id in self.tainted:
                    self.add(
                        node,
                        "HIGH",
                        "evaluateJavaScript() uses tainted variable",
                    )

                elif isinstance(arg, ast.JoinedStr):
                    self.add(
                        node,
                        "HIGH",
                        "Dynamic f-string JavaScript",
                    )

                elif isinstance(arg, ast.BinOp):
                    self.add(
                        node,
                        "HIGH",
                        "Concatenated JavaScript",
                    )

        #
        # loadHTMLString_
        #

        elif method == "loadHTMLString_":
            if node.args:
                arg = node.args[0]

                if isinstance(arg, ast.Name) and arg.id in self.tainted:
                    self.add(
                        node,
                        "HIGH",
                        "loadHTMLString() uses tainted HTML",
                    )

        #
        # WKUserScript
        #

        elif method == "initWithSource_injectionTime_forMainFrameOnly_":
            self.add(
                node,
                "INFO",
                "WKUserScript created",
            )

        self.generic_visit(node)


def ast_scan(source_text):
    """
    Run AST analysis.

    Returns
    -------
    list[(line, severity, message)]
    """

    try:
        tree = ast.parse(source_text)

    except SyntaxError:
        return []

    visitor = WebKitVisitor()
    visitor.visit(tree)

    return visitor.findings
