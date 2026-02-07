# Dev Trust Scanner

> Open-source security scanner for detecting malicious patterns in developer tooling configurations

[![Python Version](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Overview

**Dev Trust Scanner** is a plugin-based CLI tool that detects malicious patterns in developer tooling configurations. It targets "developer autopilot moments" — attack surfaces where code executes without developer scrutiny.

### Motivation

Recent supply chain attacks exploit developer trust:
- **Shai Hulud** (npm): Worm spreading via postinstall scripts
- **Contagious Interview** (DPRK): VS Code tasks.json weaponization

This tool provides open-source detection for these attack vectors and more.

## Features

- 🔍 **Multi-vector scanning**: npm scripts, VS Code tasks, git hooks (coming soon)
- 🔌 **Plugin architecture**: Easy to extend with new detectors
- 📊 **Multiple output formats**: Text (rich), JSON, SARIF
- 🚫 **Offline-only**: No network calls, no telemetry
- ⚡ **Fast**: Static analysis, no code execution
- 🛡️ **Security-first**: Built with secure coding practices

## Installation

```bash
# Clone repository
git clone https://github.com/yourusername/dev-trust-scanner.git
cd dev-trust-scanner

# Install in editable mode
pip install -e .

# Install with dev dependencies
pip install -e ".[dev]"
```

## Quick Start

```bash
# Scan current directory
dev-trust-scan .

# Scan specific directory
dev-trust-scan /path/to/project

# Scan with specific plugin
dev-trust-scan . --plugin npm-lifecycle

# Output as JSON
dev-trust-scan . --format json

# List available plugins
dev-trust-scan --list-plugins

# Verbose output
dev-trust-scan . -vv
```

## Supported Attack Vectors

### ✅ npm Lifecycle Scripts (implemented)
Detects malicious patterns in `package.json` scripts:
- Eval/exec in lifecycle scripts
- Base64 encoded payloads
- Network calls (curl, wget)
- Environment variable exfiltration
- Suspicious file operations

### ✅ VS Code Tasks (implemented)
Detects Contagious Interview-style attacks in `.vscode/tasks.json`:
- Auto-executing tasks (`runOn: folderOpen`)
- Obfuscated commands
- Suspicious shell patterns
- Hidden task output

### 🔜 Coming Soon
- Git hooks
- GitHub Actions workflows
- Pre-commit configurations

## Architecture

```
dev-trust-scanner/
├── src/dev_trust_scanner/
│   ├── cli.py              # Click-based CLI
│   ├── core/
│   │   ├── models.py       # Pydantic data models
│   │   ├── orchestrator.py # Plugin coordination
│   │   ├── plugin.py       # Base plugin interface
│   │   ├── reporting.py    # Output formatters
│   │   └── static_analysis.py # Shared detection functions
│   └── plugins/
│       ├── npm_lifecycle/
│       └── vscode_tasks/
├── tests/
└── rules/
```

## Exit Codes

- `0`: No findings (clean scan)
- `1`: Findings detected
- `2`: Scan error

Useful for CI/CD pipelines:
```bash
dev-trust-scan . || exit 1
```

## Development

```bash
# Run tests
pytest tests/ -v

# Run tests with coverage
pytest tests/ --cov=dev_trust_scanner --cov-report=html

# Run specific test
pytest tests/test_npm_lifecycle.py -v
```

## Contributing

Contributions welcome! This tool is built to be extensible.

### Adding a New Plugin

1. Create plugin directory: `src/dev_trust_scanner/plugins/my_plugin/`
2. Implement `BasePlugin` interface
3. Create rule definitions in YAML
4. Add tests with malicious samples
5. Register in orchestrator

See `CLAUDE.md` for detailed development workflow.

## Security

This is a **security tool** — we take security seriously:
- ✅ No code execution during scanning (static analysis only)
- ✅ No network calls (offline-only)
- ✅ No telemetry or data collection
- ✅ Minimal dependencies (supply chain security)
- ✅ Input sanitization and error handling

Found a vulnerability? Please report responsibly to [security contact].

## License

MIT License - see [LICENSE](LICENSE) for details.

## Acknowledgments

Inspired by real-world supply chain attacks and the need for open-source security tooling in the developer ecosystem.

## Roadmap

- [x] Project scaffolding
- [ ] Core models and static analysis
- [ ] npm lifecycle plugin
- [ ] VS Code tasks plugin
- [ ] CLI and reporting
- [ ] Integration tests
- [ ] Git hooks plugin
- [ ] GitHub Actions plugin
- [ ] VS Code extension
- [ ] CI/CD GitHub Action

---

**Status**: 🚧 Under active development (MVP in progress)
