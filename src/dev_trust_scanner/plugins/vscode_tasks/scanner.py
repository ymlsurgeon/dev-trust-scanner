"""Scanner plugin for VS Code tasks.json malicious configurations."""

import json
import logging
import re
from pathlib import Path

import yaml

from ...core.models import Finding, Rule, Severity
from ...core.plugin import BasePlugin
from ...core.static_analysis import (
    calculate_entropy,
    detect_base64,
    detect_obfuscation,
    match_rules,
)

logger = logging.getLogger(__name__)

# Entropy threshold for detecting encoded/obfuscated content
ENTROPY_THRESHOLD = 5.0  # Higher for tasks (often have long paths)


class VsCodeTasksPlugin(BasePlugin):
    """Scanner for malicious VS Code tasks.json configurations."""

    def __init__(self):
        """Initialize plugin and load detection rules."""
        self.rules = self._load_rules()

    def _load_rules(self) -> list[Rule]:
        """Load rules from vscode_rules.yaml."""
        rules_file = Path(__file__).parent / "rules" / "vscode_rules.yaml"

        try:
            with open(rules_file) as f:
                data = yaml.safe_load(f)

            rules = []
            for rule_data in data.get("rules", []):
                # Skip VSC-002 (obfuscation) as it's checked programmatically
                if rule_data["id"] == "VSC-002":
                    continue
                rules.append(Rule(**rule_data))

            logger.info(f"Loaded {len(rules)} VS Code task rules")
            return rules

        except Exception as e:
            logger.error(f"Failed to load vscode rules: {e}")
            return []

    def scan(self, target_path: Path) -> list[Finding]:
        """
        Scan .vscode/tasks.json for malicious configurations.

        Args:
            target_path: Root directory to scan

        Returns:
            List of findings from tasks.json files found
        """
        findings = []

        try:
            # Look for .vscode/tasks.json
            tasks_file = target_path / ".vscode" / "tasks.json"
            if tasks_file.exists():
                # Check file size (10MB limit)
                if tasks_file.stat().st_size > 10 * 1024 * 1024:
                    logger.warning(f"Skipping {tasks_file}: exceeds 10MB")
                    return findings

                findings.extend(self._scan_tasks_file(tasks_file, target_path))

        except Exception as e:
            logger.error(f"Error scanning {target_path}: {e}")

        return findings

    def _strip_json_comments(self, content: str) -> str:
        """
        Remove // and /* */ comments from JSON content (JSONC format).

        VS Code allows comments in tasks.json, but standard JSON parser doesn't.

        Args:
            content: JSONC content

        Returns:
            JSON content with comments removed
        """
        # Remove single-line comments (// ...)
        content = re.sub(r'//.*?$', '', content, flags=re.MULTILINE)

        # Remove multi-line comments (/* ... */)
        content = re.sub(r'/\*.*?\*/', '', content, flags=re.DOTALL)

        return content

    def _scan_tasks_file(self, tasks_path: Path, root: Path) -> list[Finding]:
        """
        Scan a single tasks.json file.

        Args:
            tasks_path: Path to tasks.json
            root: Root directory being scanned

        Returns:
            List of findings from this tasks.json
        """
        findings = []

        # Read and parse JSONC
        try:
            with open(tasks_path, encoding="utf-8", errors="replace") as f:
                raw_content = f.read()

            # Strip comments for parsing
            clean_content = self._strip_json_comments(raw_content)
            data = json.loads(clean_content)

        except json.JSONDecodeError as e:
            logger.warning(f"Malformed JSON in {tasks_path}: {e}")
            return []
        except Exception as e:
            logger.warning(f"Could not read {tasks_path}: {e}")
            return []

        # Get relative path for reporting
        try:
            relative_path = tasks_path.relative_to(root)
        except ValueError:
            relative_path = tasks_path

        # Extract tasks array
        tasks = data.get("tasks", [])
        if not tasks or not isinstance(tasks, list):
            return []

        # Analyze each task
        for task in tasks:
            if not isinstance(task, dict):
                continue

            task_label = task.get("label", "unnamed")

            # Critical check: auto-execution on folder open
            run_options = task.get("runOptions", {})
            if isinstance(run_options, dict):
                run_on = run_options.get("runOn", "default")
                if run_on == "folderOpen":
                    findings.append(
                        Finding(
                            rule_id="VSC-001",
                            rule_name="Auto-executing task on folder open",
                            severity=Severity.CRITICAL,
                            file_path=relative_path,
                            matched_content=f"Task '{task_label}' with runOn: folderOpen",
                            description="CRITICAL: Task runs automatically when folder opens (Contagious Interview attack)",
                            recommendation="Remove auto-execution immediately. This is a known malware technique.",
                            plugin_name=self.get_metadata()["name"],
                        )
                    )

            # Check command content
            command = task.get("command", "")
            if command and isinstance(command, str):
                findings.extend(self._analyze_command(command, task_label, relative_path))

            # Check args array
            args = task.get("args", [])
            if args and isinstance(args, list):
                for arg in args:
                    if isinstance(arg, str):
                        findings.extend(self._analyze_command(arg, task_label, relative_path))

            # Check presentation settings (hidden output)
            presentation = task.get("presentation", {})
            if isinstance(presentation, dict):
                raw_task_str = json.dumps(presentation)
                findings.extend(
                    match_rules(
                        text=raw_task_str,
                        rules=self.rules,
                        file_path=relative_path,
                        plugin_name=self.get_metadata()["name"],
                    )
                )

        return findings

    def _analyze_command(self, command: str, task_label: str, file_path: Path) -> list[Finding]:
        """
        Analyze a task command string for malicious patterns.

        Args:
            command: Command string to analyze
            task_label: Label of the task (for context)
            file_path: Path to tasks.json (for reporting)

        Returns:
            List of findings from this command
        """
        findings = []

        # Apply detection rules
        findings.extend(
            match_rules(
                text=command,
                rules=self.rules,
                file_path=file_path,
                plugin_name=self.get_metadata()["name"],
            )
        )

        # Check for base64
        base64_matches = detect_base64(command, min_length=30)
        if base64_matches:
            findings.append(
                Finding(
                    rule_id="VSC-002",
                    rule_name="Base64 content in task command",
                    severity=Severity.HIGH,
                    file_path=file_path,
                    matched_content=base64_matches[0].matched_text,
                    description=f"Task '{task_label}' command contains base64-encoded content",
                    recommendation="Decode and inspect the base64 content.",
                    plugin_name=self.get_metadata()["name"],
                )
            )

        # Check for obfuscation
        obfuscation_matches = detect_obfuscation(command)
        if obfuscation_matches:
            findings.append(
                Finding(
                    rule_id="VSC-002",
                    rule_name="Obfuscated command in task",
                    severity=Severity.HIGH,
                    file_path=file_path,
                    matched_content=obfuscation_matches[0].matched_text[:200],
                    description=f"Task '{task_label}' contains obfuscated code ({obfuscation_matches[0].pattern_name})",
                    recommendation="Deobfuscate and inspect. Obfuscation is highly suspicious.",
                    plugin_name=self.get_metadata()["name"],
                )
            )

        # Check entropy
        entropy = calculate_entropy(command)
        if entropy > ENTROPY_THRESHOLD:
            findings.append(
                Finding(
                    rule_id="VSC-ENTROPY",
                    rule_name="High entropy in task command",
                    severity=Severity.HIGH,
                    file_path=file_path,
                    matched_content=command[:200],
                    description=f"Task '{task_label}' has high entropy ({entropy}), may contain encoded content",
                    recommendation="Decode and inspect the command.",
                    plugin_name=self.get_metadata()["name"],
                )
            )

        return findings

    def get_metadata(self) -> dict:
        """Return plugin metadata."""
        return {
            "name": "vscode-tasks",
            "version": "0.1.0",
            "author": "Dev Trust Scanner",
            "description": "Detects malicious VS Code tasks.json configurations (Contagious Interview attacks)",
        }

    def get_supported_files(self) -> list[str]:
        """Return supported file patterns."""
        return [".vscode/tasks.json"]
