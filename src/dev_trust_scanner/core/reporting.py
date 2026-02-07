"""Output formatters for scan results."""

import json

from rich.console import Console
from rich.rule import Rule

from .models import ScanResult, Severity


class TextReporter:
    """Human-readable output using rich library."""

    def __init__(self, console: Console | None = None):
        """Initialize text reporter with optional console."""
        self.console = console or Console()

    def report(self, result: ScanResult) -> None:
        """
        Generate and print text report.

        Args:
            result: Scan result to report
        """
        # Header
        self.console.print("🔍 Dev Trust Scanner v0.1.0", style="bold")
        self.console.print(f"Scanning: {result.target_path}")
        self.console.print(f"Plugins: {', '.join(result.plugins_run)}\n")

        # Findings
        if not result.findings:
            self.console.print("✅ No issues found", style="green bold")
        else:
            self.console.print(Rule())

            # Sort by severity (critical first)
            severity_order = {
                Severity.CRITICAL: 0,
                Severity.HIGH: 1,
                Severity.MEDIUM: 2,
                Severity.LOW: 3,
            }
            sorted_findings = sorted(
                result.findings, key=lambda f: severity_order[f.severity]
            )

            for finding in sorted_findings:
                self._print_finding(finding)

            self.console.print(Rule())

        # Summary
        summary = result.summary
        summary_parts = []

        if summary["critical"] > 0:
            summary_parts.append(f"{summary['critical']} critical")
        if summary["high"] > 0:
            summary_parts.append(f"{summary['high']} high")
        if summary["medium"] > 0:
            summary_parts.append(f"{summary['medium']} medium")
        if summary["low"] > 0:
            summary_parts.append(f"{summary['low']} low")

        if summary_parts:
            summary_text = f"Summary: {', '.join(summary_parts)} | {summary['total']} findings in {result.scan_duration_seconds}s"
        else:
            summary_text = f"Summary: 0 findings in {result.scan_duration_seconds}s"

        self.console.print(summary_text)

    def _print_finding(self, finding) -> None:
        """Print single finding with color coding."""
        # Color and icon by severity
        severity_config = {
            Severity.CRITICAL: ("red", "🔴"),
            Severity.HIGH: ("red", "🔴"),
            Severity.MEDIUM: ("yellow", "🟡"),
            Severity.LOW: ("blue", "🔵"),
        }

        color, icon = severity_config[finding.severity]

        # Title line
        self.console.print(
            f"{icon} {finding.severity.value.upper()}: {finding.rule_name} [{finding.rule_id}]",
            style=f"bold {color}",
        )

        # Details
        self.console.print(f"   File: {finding.file_path}", style=color)
        if finding.line_number:
            self.console.print(f"   Line: {finding.line_number}", style=color)

        # Truncate long content
        content = finding.matched_content
        if len(content) > 100:
            content = content[:100] + "..."
        self.console.print(f'   Match: "{content}"', style=color)

        self.console.print(f"   → {finding.recommendation}\n")


class JsonReporter:
    """JSON output for programmatic consumption."""

    def report(self, result: ScanResult) -> str:
        """
        Generate JSON report.

        Args:
            result: Scan result to report

        Returns:
            JSON string
        """
        return result.model_dump_json(indent=2)


class SarifReporter:
    """SARIF 2.1.0 format for CI/CD integration."""

    def report(self, result: ScanResult) -> str:
        """
        Generate SARIF 2.1.0 format report.

        Args:
            result: Scan result to report

        Returns:
            SARIF JSON string
        """
        sarif = {
            "version": "2.1.0",
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Dev Trust Scanner",
                            "version": "0.1.0",
                            "informationUri": "https://github.com/ymlsurgeon/dev-trust-scanner",
                        }
                    },
                    "results": [self._finding_to_sarif(f) for f in result.findings],
                }
            ],
        }

        return json.dumps(sarif, indent=2)

    def _finding_to_sarif(self, finding) -> dict:
        """Convert Finding to SARIF result object."""
        # Map severity to SARIF levels
        severity_map = {
            Severity.CRITICAL: "error",
            Severity.HIGH: "error",
            Severity.MEDIUM: "warning",
            Severity.LOW: "note",
        }

        return {
            "ruleId": finding.rule_id,
            "level": severity_map[finding.severity],
            "message": {"text": finding.description},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": str(finding.file_path)},
                        "region": {"startLine": finding.line_number or 1},
                    }
                }
            ],
        }
