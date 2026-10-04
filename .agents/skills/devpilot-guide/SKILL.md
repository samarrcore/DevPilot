---
name: devpilot-guide
description: Comprehensive guide and development rules for DevPilot, a local-first CLI environment doctor. Use when developing, extending, testing, or auditing DevPilot probes, rules, inferers, models, and CLI commands.
---

# DevPilot Development Guide & System Rules

DevPilot is a local-first, zero-telemetry CLI environment doctor designed to diagnose developer toolchains and workstation configurations before builds, tests, or app execution begin.

---

## 1. Project Philosophy & Non-Goals

DevPilot models environment diagnostics after aviation **preflight checklists**: deterministic, safety-critical, and strictly factual.

### Core Tenets
- **Local-First & Offline:** DevPilot runs entirely on the developer's workstation.
- **Deterministic Observations:** All evaluations stem from verified probe outputs and static manifest parsing.
- **Zero Surprises:** Diagnostics are read-only; no system mutations happen without explicit user review.

### Non-Goals
DevPilot explicitly rejects the following patterns:
- ❌ **No AI Code Generation:** No LLMs or heuristics generating unverified shell commands.
- ❌ **No Cloud Backend or Phoning Home:** No telemetry, analytics, or remote API dependencies.
- ❌ **No User Accounts:** No login, tokens, or subscription state.
- ❌ **No Arbitrary Shell Execution:** Never pipe untrusted strings into shells (`sh`, `bash`, `cmd.exe`, `powershell`).
- ❌ **No Gamified "Health Score":** No arbitrary 82/100 scores; only actionable findings categorized as `Clear`, `Caution`, or `Grounded`.

---

## 2. Flight Metaphor & Diagnostics Taxonomy

DevPilot frames diagnostics using flight readiness terminology.

### Severity Levels
- **`Clear`**: Ready for takeoff. The required tool, runtime, or variable is present, satisfies all version constraints, and is functioning normally.
- **`Caution`**: Advisory. The environment will likely work, but potential instability, deprecated versions, or non-critical mismatches exist.
- **`Grounded`**: Hard blocker. Flight aborted. The current environment state is guaranteed or highly likely to fail builds or runtime operations.

### Categories
- `tooling`: System-level binaries, compilers, and CLI utilities (Node, Java, Gradle, Git, adb).
- `dependencies`: Local project dependencies and package integrity.
- `machine`: Operating system limits, environment variables (e.g. `ANDROID_HOME`), path lengths, and hardware prerequisites.
- `code`: Project configurations and manifest specifications (`package.json`, `.nvmrc`).

### The Factual Reporting Contract
Every diagnostic finding emitted into `model.Finding` must satisfy:
1. **`ID`**: Kebab-case stable identifier (e.g., `node-version-mismatch`, `android-home-missing`).
2. **`Evidence`**: Observable facts collected from probes or manifests (`Key`, `Value`, `Source`).
3. **`Fix`**: Structured `model.Fix` with `Type`, `Title`, `Action` instructions, and `Explanation`.
4. **`Risk`**: Risk tier (`low`, `medium`, `high`) of executing the fix.
5. **`Verify`**: Concrete verification command (e.g. `node -v`, `adb version`) to prove the issue is resolved.

---

## 3. Package Architecture & Layout

```
DevPilot/
├── cmd/
│   └── devpilot/          # CLI entry point, flag parsing, subcommands (preflight, probe, list)
├── internal/
│   ├── probe/             # System inspection probes with execution allowlists
│   ├── infer/             # Static manifest parsers (package.json, .nvmrc, Gradle, etc.)
│   ├── rules/             # Rule evaluation engine, semver comparisons, YAML rule packs
│   ├── model/             # Core data domain (Finding, Evidence, Fix, Report, Severity)
│   ├── report/            # Renderers: Interactive TUI, plain text, and machine-readable JSON
│   └── security/          # Sanitization, path redaction, PII protection, and safety checks
└── testdata/
    └── corpus/            # Golden test fixtures of broken and valid project setups
```

### Component Responsibilities

#### `cmd/devpilot`
- Parses command line flags (e.g., `--target`, `--format=tui|plain|json`, `--verbose`).
- Coordinates execution: `infer` targets $\rightarrow$ `probe` system $\rightarrow$ `rules` evaluate $\rightarrow$ `report` output.
- Exits with status code `0` if all checks are `Clear` or `Caution`, or `1` if any check is `Grounded`.

#### `internal/probe`
- Executes external binaries through the `probe.Execer` interface.
- Safe allowlisting via `AllowedCommands`: maps allowed binary names to exact allowed flags (e.g. `node: ["-v", "--version"]`).
- Implements strict timeout context (default 3 seconds per probe).
- Probes include: Node.js, npm, Java, Gradle, Android SDK, adb, Git, Expo, and Windows Registry / environment readers.

#### `internal/infer`
- Reads repository manifests without executing any repo code or scripts.
- Detects requirements from files like `.nvmrc`, `.node-version`, `package.json` (`engines`, dependencies), `build.gradle`, etc.

#### `internal/rules`
- Compares facts discovered by `probe` against constraints deduced by `infer`.
- Implements semver parsing, range matching (`^`, `~`, `>=`, `<=`, `<`), and compatibility matrices.
- Supports both compiled Go evaluators and declarative YAML rule packs.

#### `internal/model`
- Defines core data transfer structures: `Finding`, `Evidence`, `Fix`, `Report`, `ReportSummary`, `Severity`, `Category`, `RiskLevel`.
- Aggregates report counts through `Report.ComputeSummary()`.

#### `internal/report`
- `plain.go`: Streamed ANSI/plain text output with flight status headers and formatted findings.
- `json.go`: Pure JSON serialization for CI pipelines and tooling integrations.
- TUI renderer: Visual checklist showing statuses in real-time.

#### `internal/security`
- `RedactPath`: Replaces `C:\Users\<username>` or `$HOME` with generic placeholders (`~`, `<user>`) to avoid leaking PII in logs or tickets.
- `RedactString`: General string sanitizer for probe outputs.

#### `testdata/corpus`
- Standalone fixture directories simulating realistic valid and broken toolchains for end-to-end regression testing.

---

## 4. Security Principles & Hard Invariants

All code contributed to DevPilot must obey these invariants:

1. **Read-Only by Default:**
   Probes only observe system state. They never mutate files, delete caches, or install software automatically.

2. **Strict Command Allowlist:**
   - Command execution must pass through `probe.Execer`.
   - The binary name must exist in `AllowedCommands`.
   - The arguments slice must match pre-approved arguments verbatim.
   - Shell invocation (`cmd.exe /c`, `sh -c`, `bash -c`, `powershell`) is strictly forbidden.

3. **Never Output Environment Variable Values:**
   - Probe or report only whether a variable is **set** or **unset** (or points to an existing directory).
   - Never print or serialize sensitive values (e.g., tokens, API keys, passwords, connection strings).

4. **Sanitize Paths and Usernames:**
   - All paths rendered to the user or included in `Finding` outputs must pass through `security.RedactPath()`.
   - Raw usernames must never be displayed in error logs or evidence.

5. **Manifests are Untrusted Input:**
   - Manifest files (`package.json`, `build.gradle`, `.env`) are untrusted files from repositories.
   - Parse them using pure data parsers (`encoding/json`, static line readers).
   - Never run `npm run <script>`, `node -e`, or Gradle build tasks to inspect versions.

6. **Typed Actions, Never Arbitrary Scripts:**
   - `model.Fix` instances contain explicit action metadata and user guidance.
   - Fixes describe what command the developer should run (or an automated safe fixer with confirmation), never unreviewed scripts.

---

## 5. Go Idioms & Quality Standards

- **Co-Located Unit Tests:** Every non-trivial file `foo.go` must have an accompanying `foo_test.go` in the same package.
- **Interfaces for Testability:** Probes must accept `probe.Execer` to enable deterministic unit tests with mock outputs without running real binaries.
- **Errors as Values:** Return errors explicitly; wrap them with context using `fmt.Errorf("description: %w", err)`.
- **Zero Bloat:** Rely primarily on the Go standard library (`os`, `os/exec`, `path/filepath`, `encoding/json`, `context`, `strings`, `time`). Only add third-party dependencies if strictly justified.
- **Reproducible Corpus Tests:** Ensure any new rule or probe behavior is accompanied by a fixture in `testdata/corpus/` and tested via table-driven Go tests.

---

## 6. How-To Developer Workflows

### Adding a New Probe
1. Check if the binary is allowed; if not, add it with approved flags to `probe.AllowedCommands` in `internal/probe/exec.go`.
2. Implement the probe function in `internal/probe/<tool>.go`:
   - Accept `probe.Execer` and `context.Context`.
   - Execute the approved version/status command.
   - Parse and normalize the output (e.g. semver).
   - Sanitize paths or outputs using `security.RedactString()`.
3. Add a unit test in `internal/probe/<tool>_test.go` mocking `Execer`.

### Adding a New Rule Evaluator
1. Identify the manifest requirement in `internal/infer`.
2. Implement evaluation logic in `internal/rules/<tool>_evaluator.go`.
3. Construct `model.Finding` ensuring all fields (`Evidence`, `Fix`, `Risk`, `Verify`, `Severity`) are populated.
4. Add table-driven tests in `internal/rules/<tool>_evaluator_test.go`.
5. Run the test suite:
   ```powershell
   go test ./...
   ```
