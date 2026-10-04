# DevPilot ✈

> **Local-first CLI development environment flight doctor.**

DevPilot is an offline, safety-critical environment doctor designed to diagnose toolchain and workstation misconfigurations before builds, tests, or app execution begin.

Core problem statement: *"Is this failure caused by my code, my dependencies, my tooling, or my machine?"*

First wedge focus: **Windows + Node.js + React Native/Expo + Android SDK/ADB + Java/Gradle**.

---

## Features

- **Preflight Inspection**: Informs developers whether their local workstation is flight-ready before running complex builds.
- **Flight-Themed Taxonomy**:
  - `Clear`: All requirements satisfied; ready for takeoff.
  - `Caution`: Advisory warnings or minor version discrepancies.
  - `Grounded`: Hard blockers that will abort flights/builds.
- **Strict Factual Contract**: Every diagnostic finding includes:
  - **Evidence**: Observable facts collected from allowlisted probes or static manifests.
  - **Fix**: Schema-validated typed action (e.g. `install_tool_version`, `set_env_var`) — never raw arbitrary shell strings.
  - **Risk Level**: Clear risk assessment (`low`, `medium`, `high`).
  - **Verify**: Concrete verification command (e.g. `node -v`).
- **Security-First Architecture**:
  - Read-only by default.
  - Probes run via strict executable and argument allowlists with timeouts and 64KB buffer caps; zero shell invocation (`cmd.exe /c` / `powershell`).
  - Untrusted repo files are parsed statically; never executes package scripts during analysis.
  - Automatic redaction of usernames, user profile paths, hostnames, and secrets in plain and `--json` outputs.

---

## Getting Started

### Prerequisites

- Go 1.22+

### Building from Source

```powershell
# Clone the repository
git clone https://github.com/samarrcore/DevPilot.git
cd DevPilot

# Run tests
go test -v ./...

# Build binary
go build -o devpilot.exe ./cmd/devpilot
```

### Usage

```powershell
# Run preflight inspection on the current directory
.\devpilot.exe preflight

# Inspect a specific target project
.\devpilot.exe preflight --dir path/to/project

# Output machine-readable JSON for CI or automation
.\devpilot.exe preflight --dir path/to/project --json

# Force plain-text output
.\devpilot.exe preflight --plain
```

---

## Project Structure

```
DevPilot/
├── .agents/skills/        # Antigravity project skills & security rules
│   ├── devpilot-guide/    # Development guide and architectural contract
│   └── devpilot-security/ # 10 non-negotiable security rules
├── cmd/devpilot/          # CLI entry point (preflight / doctor, flags)
├── internal/
│   ├── infer/             # Static manifest parsers (package.json, .nvmrc)
│   ├── model/             # Core types (Finding, Evidence, Fix, Report, Severity)
│   ├── probe/             # Allowlisted execution engine and system probes
│   ├── report/            # Plain-text and JSON report renderers
│   ├── rules/             # Rule evaluators and semver engine
│   └── security/          # PII/path sanitization and secret redactor
└── testdata/corpus/       # Reproducible test fixtures (valid & broken environments)
```

---

## Roadmap

- **v0.1 (Current)**: Local CLI preflight on Windows for Node, Java, Android SDK/ADB, Expo, and Gradle. Static repo inference, typed findings, plain & JSON renderers, test corpus.
- **v0.2**: Log triage diagnostic engine (`diagnose`), dry-run fix approval workflow (`fix --dry-run`), capture and verify commands.
- **v1.0**: Teammate diffs (`crew`), GitHub Actions CI integration, macOS/Linux support.

---

## License

MIT
