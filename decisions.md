# Dev Trust Scanner — Architecture Decisions & Implementation Guide

> **Purpose**: This document is the single source of truth for architectural decisions and implementation instructions. Claude Code should reference this file before writing any code. Update this file as decisions evolve.

This project was born from the claude conversation linked below:
https://claude.ai/share/4cab6c0a-0f09-4240-8863-1b1334239682

---

## Project Overview

**Dev Trust Scanner** is an open-source, plugin-based CLI tool that detects malicious patterns in developer tooling configurations. It targets "developer autopilot moments" — attack surfaces where code executes without developer scrutiny.

**Repository structure target:**

```
dev-trust-scanner/
├── src/
│   └── dev_trust_scanner/
│       ├── __init__.py
│       ├── cli.py                 # Click-based CLI entry point
│       ├── core/
│       │   ├── __init__.py
│       │   ├── orchestrator.py    # Plugin discovery, execution, result aggregation
│       │   ├── models.py          # Pydantic models: Finding, Rule, ScanResult, Severity
│       │   ├── plugin.py          # Abstract base class (ABC) for all plugins
│       │   ├── reporting.py       # Output formatters: JSON, SARIF, text
│       │   └── static_analysis.py # Shared utilities: entropy, base64, regex, AST helpers
│       └── plugins/
│           ├── __init__.py
│           ├── npm_lifecycle/
│           │   ├── __init__.py
│           │   ├── scanner.py     # NpmLifecyclePlugin(BasePlugin)
│           │   └── rules/
│           │       └── npm_rules.yaml
│           └── vscode_tasks/
│               ├── __init__.py
│               ├── scanner.py     # VsCodeTasksPlugin(BasePlugin)
│               └── rules/
│                   └── vscode_rules.yaml
├── tests/
│   ├── conftest.py                # Shared fixtures, sample malicious configs
│   ├── test_orchestrator.py
│   ├── test_static_analysis.py
│   ├── test_npm_lifecycle.py
│   └── test_vscode_tasks.py
├── rules/
│   └── shared/
│       └── ioc_patterns.yaml      # Cross-plugin IOCs (domains, IPs, patterns)
├── docs/
│   └── decisions.md               # THIS FILE
├── pyproject.toml
├── README.md
└── LICENSE                        # MIT
```

---

## Decision Log

### DEC-001: Python Package Layout — `src/` Layout

**Decision**: Use `src/dev_trust_scanner/` layout, not flat layout.

**Rationale**: Prevents accidental imports from the working directory during development. Standard for modern Python packages. Ensures tests import the installed package, not local files.

**Implication**: All imports use `from dev_trust_scanner.core import ...`

---

### DEC-002: Data Models — Pydantic v2

**Decision**: Use Pydantic v2 `BaseModel` for all data structures (`Finding`, `Rule`, `ScanResult`, `Severity`).

**Rationale**: Type validation, JSON serialization for free, clear contracts between plugins and core. Pydantic v2 is significantly faster than v1.

**Models to implement:**

```python
from enum import Enum
from pydantic import BaseModel
from typing import Optional
from pathlib import Path

class Severity(str, Enum):
    CRITICAL = "critical"   # Active exploitation pattern (e.g., known malware signature)
    HIGH = "high"           # Strong malicious indicators (e.g., obfuscated eval + network call)
    MEDIUM = "medium"       # Suspicious patterns (e.g., base64 in lifecycle script)
    LOW = "low"             # Informational (e.g., lifecycle script exists but looks benign)

class Finding(BaseModel):
    rule_id: str                     # e.g., "NPM-001"
    rule_name: str                   # Human-readable name
    severity: Severity
    file_path: Path                  # Relative to scan target
    line_number: Optional[int] = None
    matched_content: str             # The suspicious content found
    description: str                 # What was detected and why it matters
    recommendation: str              # What the developer should do
    plugin_name: str                 # Which plugin produced this finding

class Rule(BaseModel):
    id: str
    name: str
    severity: Severity
    description: str
    pattern: Optional[str] = None         # Regex pattern
    patterns: Optional[list[str]] = None  # Multiple regex patterns (match any)
    keywords: Optional[list[str]] = None  # Simple string matching
    recommendation: str

class ScanResult(BaseModel):
    target_path: Path
    findings: list[Finding]
    plugins_run: list[str]
    scan_duration_seconds: float
    summary: dict                    # e.g., {"critical": 0, "high": 2, "medium": 1, "low": 0}
```

---

### DEC-003: Plugin Interface — ABC with Three Methods

**Decision**: Plugins extend `BasePlugin` ABC with exactly three required methods.

**Rationale**: Minimal contract = easy contribution. Plugins stay independent and testable.

```python
from abc import ABC, abstractmethod
from pathlib import Path

class BasePlugin(ABC):
    @abstractmethod
    def scan(self, target_path: Path) -> list[Finding]:
        """Run all detection logic against the target directory. Return findings."""
        ...

    @abstractmethod
    def get_metadata(self) -> dict:
        """Return plugin metadata: name, version, author, description."""
        ...

    @abstractmethod
    def get_supported_files(self) -> list[str]:
        """Return glob patterns for files this plugin inspects.
        Examples: ['package.json'], ['.vscode/tasks.json']
        """
        ...
```

**Plugin discovery**: Orchestrator imports from `dev_trust_scanner.plugins` using a registry pattern. Each plugin's `__init__.py` exposes a `PLUGIN_CLASS` variable pointing to the scanner class. No magic autodiscovery — explicit is better.

```python
# plugins/npm_lifecycle/__init__.py
from .scanner import NpmLifecyclePlugin
PLUGIN_CLASS = NpmLifecyclePlugin
```

```python
# core/orchestrator.py — plugin registry
PLUGIN_REGISTRY = {
    "npm-lifecycle": "dev_trust_scanner.plugins.npm_lifecycle",
    "vscode-tasks": "dev_trust_scanner.plugins.vscode_tasks",
}
```

---

### DEC-004: Rule Format — YAML with Defined Schema

**Decision**: Rules are YAML files loaded by each plugin at scan time.

**Rationale**: Human-readable, easy to contribute, no code changes needed for new rules. Security teams can write rules without Python knowledge.

**Schema example:**

```yaml
rules:
  - id: "NPM-001"
    name: "Suspicious postinstall script"
    severity: "high"
    description: "postinstall script contains patterns associated with supply chain attacks"
    patterns:
      - "eval\\s*\\("
      - "Function\\s*\\("
      - "child_process"
      - "\\bexec\\b"
    recommendation: "Review the postinstall script manually. Remove if not needed."

  - id: "NPM-002"
    name: "Base64 encoded content in lifecycle script"
    severity: "high"
    description: "Base64 encoding in npm scripts is commonly used to obfuscate malicious payloads"
    patterns:
      - "atob\\s*\\("
      - "Buffer\\.from\\s*\\([^)]+,\\s*['\"]base64['\"]"
      - "[A-Za-z0-9+/]{40,}={0,2}"
    recommendation: "Decode and inspect the base64 content before running."
```

---

### DEC-005: Static Analysis Utilities — Shared Module

**Decision**: Common detection functions live in `core/static_analysis.py`, shared across all plugins.

**Functions to implement:**

| Function | Purpose | Used By |
|---|---|---|
| `detect_base64(text) -> list[Match]` | Find base64-encoded strings above length threshold | npm, vscode |
| `detect_obfuscation(text) -> list[Match]` | Hex escapes, char code building, string concat obfuscation | npm, vscode |
| `calculate_entropy(text) -> float` | Shannon entropy — high entropy = possible encoded/encrypted content | All |
| `check_ioc_patterns(text, iocs) -> list[Match]` | Match against known malicious domains/IPs/URLs | All |
| `detect_suspicious_commands(text) -> list[Match]` | curl\|wget piped to sh, PowerShell download cradles, etc. | All |
| `match_rules(text, rules) -> list[Finding]` | Apply YAML rule patterns against text content | All |

**Match is a simple dataclass:**

```python
@dataclass
class Match:
    pattern_name: str
    matched_text: str
    start_position: int
    end_position: int
    line_number: Optional[int] = None
```

---

### DEC-006: CLI Design — Click with Sensible Defaults

**Decision**: Click framework, subcommand structure, sensible defaults for zero-config scanning.

```
# Scan current directory with all plugins
dev-trust-scan .

# Scan with specific plugin
dev-trust-scan . --plugin npm-lifecycle

# Output formats
dev-trust-scan . --format json
dev-trust-scan . --format sarif
dev-trust-scan . --format text  (default)

# Verbosity
dev-trust-scan . -v        # Show info messages
dev-trust-scan . -vv       # Debug output

# List available plugins
dev-trust-scan --list-plugins
```

**Exit codes**: 0 = no findings, 1 = findings detected, 2 = scan error. This enables CI/CD gating.

---

### DEC-007: Output Formats — Three Tiers

**Decision**: Support JSON, SARIF, and human-readable text output.

**Priority order for MVP**: text first (usable immediately), JSON second (scriptable), SARIF third (CI/CD integration).

**Text output example:**

```
🔍 Dev Trust Scanner v0.1.0
Scanning: /path/to/project
Plugins: npm-lifecycle, vscode-tasks

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🔴 HIGH: Suspicious postinstall script [NPM-001]
   File: package.json (line 12)
   Match: "node -e \"eval(Buffer.from('...', 'base64'))\""
   → Review the postinstall script manually. Remove if not needed.

🟡 MEDIUM: Base64 content in lifecycle script [NPM-002]
   File: package.json (line 14)
   Match: "aG9zdG5hbWU="
   → Decode and inspect the base64 content before running.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Summary: 1 high, 1 medium, 0 low | 2 findings in 0.03s
```

---

### DEC-008: Testing Strategy

**Decision**: pytest with fixture-based test data. Each plugin gets its own malicious sample fixtures.

**Test structure:**

- `conftest.py`: Shared fixtures that create temporary directories with malicious config files
- Each plugin test: Create realistic malicious configs, run scanner, assert expected findings
- Static analysis tests: Unit tests for each utility function

**Sample fixture approach:**

```python
@pytest.fixture
def malicious_package_json(tmp_path):
    pkg = tmp_path / "package.json"
    pkg.write_text(json.dumps({
        "name": "legit-looking-package",
        "scripts": {
            "postinstall": "node -e \"eval(Buffer.from('bWFsaWNpb3Vz','base64').toString())\""
        }
    }))
    return tmp_path
```

**Coverage target for MVP**: Core and static analysis at 80%+. Plugin tests cover each rule firing at least once.

---

### DEC-009: Error Handling Philosophy

**Decision**: Scan should never crash on malformed input. Log warnings, skip unparseable files, continue scanning.

**Rationale**: Real-world projects have broken configs. A scanner that crashes on bad JSON is useless.

**Implementation**: Each plugin wraps its `scan()` in try/except, logs errors, returns partial results. Orchestrator collects errors into the ScanResult for transparency.

---

### DEC-010: Dependency Policy — Minimal

**Decision**: Keep dependencies minimal for security credibility and ease of installation.

**Allowed dependencies:**

- `click` — CLI framework
- `pydantic` — Data validation
- `pyyaml` — Rule loading
- `rich` — Terminal output formatting (text reporter only)

**Dev dependencies:**

- `pytest`
- `pytest-cov`

**No dependencies on**: requests, httpx, or any network library. This is a static analysis tool — it should never phone home.

---

## Implementation Order for Claude Code

**Follow this exact sequence. Do not skip ahead. Commit after each step.**

### Step 1: Project Scaffolding

Create the full directory structure, `pyproject.toml`, empty `__init__.py` files. Ensure `pip install -e .` works.

`pyproject.toml` must include:
- Project name: `dev-trust-scanner`
- Entry point: `dev-trust-scan = dev_trust_scanner.cli:main`
- Python >= 3.11
- Dependencies: click, pydantic, pyyaml, rich
- Dev dependencies in optional group: pytest, pytest-cov

### Step 2: Core Models (`core/models.py`)

Implement `Severity`, `Finding`, `Rule`, `ScanResult`, and `Match` exactly as specified in DEC-002 and DEC-005. Write unit tests to verify serialization.

### Step 3: Static Analysis Utilities (`core/static_analysis.py`)

Implement all functions from DEC-005. Write comprehensive unit tests with known-malicious patterns. Test edge cases: empty strings, binary content, extremely long strings.

### Step 4: Plugin Base Class (`core/plugin.py`)

Implement `BasePlugin` ABC as specified in DEC-003. This should be minimal — just the abstract interface.

### Step 5: npm-lifecycle Plugin (`plugins/npm_lifecycle/`)

Implement `NpmLifecyclePlugin`:
1. Write `npm_rules.yaml` first (minimum 5 rules)
2. Implement `scanner.py` — parse package.json, extract lifecycle scripts, run rules + static analysis
3. Write tests with realistic malicious samples

**Target rules (minimum):**
- NPM-001: Suspicious eval/exec in lifecycle scripts
- NPM-002: Base64 encoded content in scripts
- NPM-003: Network calls in lifecycle scripts (curl, wget, http)
- NPM-004: Environment variable access/exfiltration
- NPM-005: File system operations outside expected paths

### Step 6: vscode-tasks Plugin (`plugins/vscode_tasks/`)

Implement `VsCodeTasksPlugin`:
1. Write `vscode_rules.yaml` first (minimum 4 rules)
2. Implement `scanner.py` — parse tasks.json, check for auto-execution, run rules
3. Write tests with realistic Contagious Interview-style samples

**Target rules (minimum):**
- VSC-001: Auto-executing tasks (runOn: folderOpen)
- VSC-002: Obfuscated commands in tasks
- VSC-003: Shell commands with suspicious patterns
- VSC-004: Hidden task configurations (presentation.reveal: never)

### Step 7: Orchestrator (`core/orchestrator.py`)

Wire up plugin discovery, execution, and result aggregation. Handle plugin failures gracefully per DEC-009.

### Step 8: Reporting (`core/reporting.py`)

Implement text formatter first (with rich), then JSON, then SARIF stub.

### Step 9: CLI (`cli.py`)

Wire everything together with Click. Implement commands from DEC-006. Test manually.

### Step 10: Integration Tests

End-to-end tests: CLI invocation → scan → output verification. Test with both clean and malicious project fixtures.

---

## Coding Standards for Claude Code

- **Type hints everywhere.** No `Any` types unless absolutely unavoidable.
- **Docstrings on all public functions.** Google style.
- **No classes where functions suffice.** Only use classes for plugins and data models.
- **f-strings for formatting.** No `.format()` or `%` formatting.
- **Path objects, not strings.** Use `pathlib.Path` throughout.
- **Plugin LOC limit:** Each plugin scanner.py should be 200-300 lines max. If it's getting longer, refactor shared logic into `static_analysis.py`.
- **Rule IDs are namespaced:** `NPM-XXX` for npm, `VSC-XXX` for vscode, `GH-XXX` for future git hooks.
- **No print statements.** Use `logging` module or `rich.console` for output.
- **Imports:** stdlib first, then third-party, then local. Sorted alphabetically within groups.

---

## Future Decisions (Placeholder)

- DEC-011: Git hooks plugin design (reserved)
- DEC-012: GitHub Actions plugin design (reserved)
- DEC-013: Threat intelligence feed integration (reserved)
- DEC-014: GitHub Action packaging for CI/CD (reserved)
- DEC-015: Plugin contribution guidelines and template (reserved)

---

*Last updated: 2025-02-07*
*Status: MVP scaffolding phase*
