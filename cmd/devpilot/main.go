package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"devpilot/internal/infer"
	"devpilot/internal/model"
	"devpilot/internal/probe"
	"devpilot/internal/report"
	"devpilot/internal/rules"
	"devpilot/internal/security"
)

const version = "0.1.0-alpha"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(2)
	}

	command := os.Args[1]

	switch command {
	case "preflight", "doctor":
		runPreflight(os.Args[2:])
	case "version", "--version", "-v":
		fmt.Printf("DevPilot v%s\n", version)
		os.Exit(0)
	case "help", "--help", "-h":
		printUsage()
		os.Exit(0)
	default:
		// If user passes flags directly like `devpilot --json` without explicit `preflight` subcommand, default to preflight
		if len(command) > 0 && command[0] == '-' {
			runPreflight(os.Args[1:])
			return
		}
		fmt.Fprintf(os.Stderr, "Unknown command %q. Run 'devpilot help' for available commands.\n", command)
		os.Exit(2)
	}
}

func printUsage() {
	fmt.Print(`DevPilot - Local-first development environment flight doctor

Usage:
  devpilot preflight [flags]    Run environment preflight checks (alias: doctor)
  devpilot version              Show DevPilot version
  devpilot help                 Show this help message

Flags:
  --dir string    Target project directory (default ".")
  --json          Output structured JSON report
  --plain         Output plain text (default in non-TTY or CI)
`)
}

func runPreflight(args []string) {
	fs := flag.NewFlagSet("preflight", flag.ExitOnError)
	dirFlag := fs.String("dir", ".", "Target project directory")
	jsonFlag := fs.Bool("json", false, "Output report as JSON")
	plainFlag := fs.Bool("plain", false, "Output plain text format")

	_ = fs.Parse(args)

	targetDir, err := filepath.Abs(*dirFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error resolving directory: %v\n", err)
		os.Exit(2)
	}

	info, err := os.Stat(targetDir)
	if err != nil || !info.IsDir() {
		fmt.Fprintf(os.Stderr, "Error: directory %q does not exist\n", *dirFlag)
		os.Exit(2)
	}

	// 1. Infer requirements from target project repo
	expected, err := infer.Infer(targetDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to read project manifests: %v\n", err)
	}

	// 2. Safe allowlisted probe
	execer := probe.NewOSExecer()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// 2. Safe allowlisted probes
	nodeActual := probe.ProbeNode(ctx, execer)
	npmActual := probe.ProbeNpm(ctx, execer)
	gitActual := probe.ProbeGit(ctx, execer)
	javaActual := probe.ProbeJava(ctx, execer)
	adbActual := probe.ProbeAdb(ctx, execer)
	androidSdkActual := probe.ProbeAndroidSDK()
	winEnvActual := probe.ReadWindowsEnvironment()

	// 3. Rule evaluation
	var findings []model.Finding

	// Tooling rules
	findings = append(findings, rules.EvaluateNode(nodeActual, expected))
	findings = append(findings, rules.EvaluateNpm(npmActual))
	findings = append(findings, rules.EvaluateGit(gitActual))
	findings = append(findings, rules.EvaluateJava(javaActual, winEnvActual))
	findings = append(findings, rules.EvaluateAndroid(androidSdkActual, adbActual)...)

	// Machine / Windows environment rules
	findings = append(findings, rules.EvaluateWindowsEnvironment(winEnvActual)...)

	// 4. Construct final report with redacted target path
	rep := &model.Report{
		Timestamp: time.Now(),
		TargetDir: security.RedactPath(targetDir),
		Findings:  findings,
	}
	rep.ComputeSummary()

	// 5. Render report
	if *jsonFlag {
		if err := report.RenderJSON(os.Stdout, rep); err != nil {
			fmt.Fprintf(os.Stderr, "Error rendering JSON: %v\n", err)
			os.Exit(2)
		}
	} else {
		// In M1, default is plain output (--plain or standard)
		_ = plainFlag
		if err := report.RenderPlain(os.Stdout, rep); err != nil {
			fmt.Fprintf(os.Stderr, "Error rendering report: %v\n", err)
			os.Exit(2)
		}
	}

	// Exit code: 1 if Grounded blockers found, 0 otherwise
	if rep.Summary.Grounded > 0 {
		os.Exit(1)
	}
	os.Exit(0)
}
