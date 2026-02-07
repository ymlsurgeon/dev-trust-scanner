"""Scanner plugin for npm lifecycle scripts."""

import json
import logging
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

# Lifecycle scripts that execute automatically (higher risk)
LIFECYCLE_SCRIPTS = {
    "preinstall",
    "install",
    "postinstall",
    "prepublish",
    "prepublishOnly",
    "prepack",
    "postpack",
    "prepare",
}

# Entropy threshold for detecting encoded/obfuscated content
ENTROPY_THRESHOLD = 4.5


class NpmLifecyclePlugin(BasePlugin):
    """Scanner for malicious patterns in npm lifecycle scripts."""

    def __init__(self):
        """Initialize plugin and load detection rules."""
        self.rules = self._load_rules()

    def _load_rules(self) -> list[Rule]:
        """Load rules from npm_rules.yaml."""
        rules_file = Path(__file__).parent / "rules" / "npm_rules.yaml"

        try:
            with open(rules_file) as f:
                data = yaml.safe_load(f)

            rules = []
            for rule_data in data.get("rules", []):
                rules.append(Rule(**rule_data))

            logger.info(f"Loaded {len(rules)} npm rules")
            return rules

        except Exception as e:
            logger.error(f"Failed to load npm rules: {e}")
            return []

    def scan(self, target_path: Path) -> list[Finding]:
        """
        Scan package.json files for malicious lifecycle scripts.

        Args:
            target_path: Root directory to scan

        Returns:
            List of findings from all package.json files found
        """
        findings = []

        try:
            # Find all package.json files (supports monorepos)
            # Skip node_modules per design decision
            for pkg_file in target_path.rglob("package.json"):
                # Skip node_modules directories
                if "node_modules" in pkg_file.parts:
                    continue

                # Check file size (10MB limit per design decision)
                if pkg_file.stat().st_size > 10 * 1024 * 1024:
                    logger.warning(f"Skipping {pkg_file}: exceeds 10MB size limit")
                    continue

                findings.extend(self._scan_package_json(pkg_file, target_path))

        except Exception as e:
            logger.error(f"Error scanning {target_path}: {e}")

        return findings

    def _scan_package_json(self, pkg_path: Path, root: Path) -> list[Finding]:
        """
        Scan a single package.json file.

        Args:
            pkg_path: Path to package.json
            root: Root directory being scanned (for relative paths)

        Returns:
            List of findings from this package.json
        """
        findings = []

        # Parse JSON with error handling
        try:
            with open(pkg_path, encoding="utf-8", errors="replace") as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            logger.warning(f"Malformed JSON in {pkg_path}: {e}")
            return []
        except Exception as e:
            logger.warning(f"Could not read {pkg_path}: {e}")
            return []

        # Extract scripts section
        scripts = data.get("scripts", {})
        if not scripts or not isinstance(scripts, dict):
            return []

        # Analyze each script
        for script_name, script_content in scripts.items():
            if not isinstance(script_content, str):
                continue

            # Get relative path for reporting
            try:
                relative_path = pkg_path.relative_to(root)
            except ValueError:
                relative_path = pkg_path

            # Apply detection rules
            script_findings = match_rules(
                text=script_content,
                rules=self.rules,
                file_path=relative_path,
                plugin_name=self.get_metadata()["name"],
            )

            # Tag lifecycle scripts with higher severity
            if script_name in LIFECYCLE_SCRIPTS:
                for finding in script_findings:
                    # Add context that this is a lifecycle script
                    finding.description = (
                        f"[Lifecycle script: {script_name}] {finding.description}"
                    )

            findings.extend(script_findings)

            # Additional checks for lifecycle scripts
            if script_name in LIFECYCLE_SCRIPTS:
                # High entropy check (encoded/encrypted content)
                entropy = calculate_entropy(script_content)
                if entropy > ENTROPY_THRESHOLD:
                    findings.append(
                        Finding(
                            rule_id="NPM-ENTROPY",
                            rule_name="High entropy in lifecycle script",
                            severity=Severity.HIGH,
                            file_path=relative_path,
                            matched_content=script_content[:200],
                            description=f"Script '{script_name}' has high entropy ({entropy}), may contain encoded/encrypted malware",
                            recommendation="Decode and inspect the script content. High entropy often indicates base64, compression, or encryption.",
                            plugin_name=self.get_metadata()["name"],
                        )
                    )

                # Base64 detection
                base64_matches = detect_base64(script_content, min_length=30)
                if base64_matches:
                    findings.append(
                        Finding(
                            rule_id="NPM-BASE64",
                            rule_name="Base64 content detected in lifecycle script",
                            severity=Severity.HIGH,
                            file_path=relative_path,
                            line_number=base64_matches[0].line_number,
                            matched_content=base64_matches[0].matched_text,
                            description=f"Script '{script_name}' contains base64-encoded content",
                            recommendation="Decode the base64 content and verify it is legitimate.",
                            plugin_name=self.get_metadata()["name"],
                        )
                    )

                # Obfuscation detection
                obfuscation_matches = detect_obfuscation(script_content)
                if obfuscation_matches:
                    findings.append(
                        Finding(
                            rule_id="NPM-OBFUSCATION",
                            rule_name="Code obfuscation in lifecycle script",
                            severity=Severity.HIGH,
                            file_path=relative_path,
                            line_number=obfuscation_matches[0].line_number,
                            matched_content=obfuscation_matches[0].matched_text[:200],
                            description=f"Script '{script_name}' contains obfuscated code ({obfuscation_matches[0].pattern_name})",
                            recommendation="Deobfuscate and inspect. Legitimate packages rarely use obfuscation.",
                            plugin_name=self.get_metadata()["name"],
                        )
                    )

        return findings

    def get_metadata(self) -> dict:
        """Return plugin metadata."""
        return {
            "name": "npm-lifecycle",
            "version": "0.1.0",
            "author": "Dev Trust Scanner",
            "description": "Detects malicious patterns in npm lifecycle scripts (postinstall, preinstall, etc.)",
        }

    def get_supported_files(self) -> list[str]:
        """Return supported file patterns."""
        return ["package.json"]
