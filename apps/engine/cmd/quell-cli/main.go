package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/quell-dev/quell/apps/engine/internal/ast"
	"github.com/quell-dev/quell/apps/engine/internal/patcher"
	"github.com/quell-dev/quell/apps/engine/internal/scanner"
	"github.com/quell-dev/quell/apps/engine/internal/triage"
)

// ScanReport represents the aggregated result of a Quell scan.
type ScanReport struct {
	Timestamp      string                 `json:"timestamp"`
	TargetDir      string                 `json:"target_dir"`
	TotalSuspects  int                    `json:"total_suspects"`
	ConfirmedVulns int                    `json:"confirmed_vulns"`
	FalsePositives int                    `json:"false_positives"`
	Items          []ReportItem           `json:"items"`
}

type ReportItem struct {
	Finding     scanner.Finding       `json:"finding"`
	ASTContext  *ast.ASTContext       `json:"ast_context"`
	Triage      *triage.TriageResult  `json:"triage"`
	UnifiedDiff string                `json:"unified_diff,omitempty"`
}

func printBanner() {
	fmt.Println("\033[1;36m")
	fmt.Println("  ██████╗ ██╗   ██╗███████╗██╗     ██╗     ")
	fmt.Println(" ██╔═══██╗██║   ██║██╔════╝██║     ██║     ")
	fmt.Println(" ██║   ██║██║   ██║█████╗  ██║     ██║     ")
	fmt.Println(" ██║▄▄ ██║██║   ██║██╔══╝  ██║     ██║     ")
	fmt.Println(" ╚██████╔╝╚██████╔╝███████╗███████╗███████╗")
	fmt.Println("  ╚══▀▀═╝  ╚═════╝ ╚══════╝╚══════╝╚══════╝")
	fmt.Println("   Autonomous AI Security Engineer SaaS    ")
	fmt.Println("\033[0m")
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]
	switch command {
	case "scan":
		runScanCommand(os.Args[2:])
	case "version":
		fmt.Println("Quell Core Engine v0.1.0-alpha (Go 1.22+)")
	default:
		fmt.Printf("Unknown command: %s\n", command)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	printBanner()
	fmt.Println("Usage:")
	fmt.Println("  quell-cli scan <target_directory> [flags]")
	fmt.Println("\nFlags:")
	fmt.Println("  --config <file>     Path to custom Semgrep ruleset (defaults to embedded Quell rules)")
	fmt.Println("  --auto              Use Semgrep community auto rules")
	fmt.Println("  --model <name>      LLM model (defaults to gpt-4o-mini or $OPENAI_MODEL)")
	fmt.Println("  --json              Output full result in JSON format")
	fmt.Println("  --write             Apply generated patches directly to source files")
	fmt.Println("  --output-diff <file> Save unified diff to specified file")
}

func runScanCommand(args []string) {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	configFile := fs.String("config", "", "Path to custom Semgrep ruleset")
	autoConfig := fs.Bool("auto", false, "Use Semgrep community auto rules")
	model := fs.String("model", "", "LLM model name")
	jsonOutput := fs.Bool("json", false, "Output results in JSON format")
	writePatches := fs.Bool("write", false, "Write patches directly to files")
	outputDiffPath := fs.String("output-diff", "", "Save unified diff to file")

	// Separate positional args from flags to allow flags anywhere in args
	var flagArgs []string
	var posArgs []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if strings.HasPrefix(arg, "-") {
			flagArgs = append(flagArgs, arg)
			// If flag takes value and value is in next arg
			if (arg == "--config" || arg == "-config" || arg == "--model" || arg == "-model" || arg == "--output-diff" || arg == "-output-diff") && i+1 < len(args) {
				i++
				flagArgs = append(flagArgs, args[i])
			}
		} else {
			posArgs = append(posArgs, arg)
		}
	}

	if err := fs.Parse(flagArgs); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing flags: %v\n", err)
		os.Exit(1)
	}

	if len(posArgs) < 1 {
		fmt.Fprintln(os.Stderr, "Error: missing target directory argument.")
		fmt.Fprintln(os.Stderr, "Usage: quell-cli scan <target_dir> [flags]")
		os.Exit(1)
	}

	targetDir := posArgs[0]
	absTargetDir, err := filepath.Abs(targetDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid target directory: %v\n", err)
		os.Exit(1)
	}

	if !*jsonOutput {
		printBanner()
		fmt.Printf("🎯 Target Directory: \033[1;37m%s\033[0m\n", absTargetDir)
	}

	ctx := context.Background()

	// 1. Static Scan (Semgrep)
	if !*jsonOutput {
		fmt.Println("\n\033[1;34m[1/4] Running Deterministic Static Analysis (Semgrep)...\033[0m")
	}

	scanOpts := scanner.ScanOptions{
		TargetDir:  targetDir,
		ConfigFile: *configFile,
		AutoConfig: *autoConfig,
	}

	startTime := time.Now()
	findings, err := scanner.RunScan(ctx, scanOpts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ Scan error: %v\n", err)
		os.Exit(1)
	}

	if !*jsonOutput {
		fmt.Printf("      Found \033[1;33m%d\033[0m suspect candidate(s) in %v.\n", len(findings), time.Since(startTime).Round(time.Millisecond))
	}

	if len(findings) == 0 {
		if !*jsonOutput {
			fmt.Println("\n\033[1;32m✅ Zero security vulnerabilities found. Codebase is clean!\033[0m")
		} else {
			report := ScanReport{
				Timestamp: time.Now().UTC().Format(time.RFC3339),
				TargetDir: absTargetDir,
			}
			json.NewEncoder(os.Stdout).Encode(report)
		}
		return
	}

	// Initialize AST Chunker and Triage Agent
	chunker := ast.NewChunker()
	agent := triage.NewAgent(triage.Config{
		Model: *model,
	})

	report := ScanReport{
		Timestamp:     time.Now().UTC().Format(time.RFC3339),
		TargetDir:     absTargetDir,
		TotalSuspects: len(findings),
	}

	var combinedDiffs strings.Builder

	// 2. Loop through findings: AST Chunker -> LLM Triage -> Patch Diff
	for i, f := range findings {
		if !*jsonOutput {
			fmt.Printf("\n\033[1;34m[2/4] AST Context Extraction (%d/%d): \033[0m\033[1;37m%s:%d\033[0m\n", i+1, len(findings), f.FilePath, f.StartLine)
		}

		astCtx, err := chunker.ExtractContext(f.FilePath, f.StartLine, f.EndLine, absTargetDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "⚠️  AST extraction warning: %v\n", err)
			astCtx = &ast.ASTContext{
				TargetFile:        f.FilePath,
				EnclosingFunction: "unknown",
				FunctionSource:    f.Lines,
			}
		}

		if !*jsonOutput {
			fmt.Printf("      Enclosing Function: \033[36m%s\033[0m (lines %d-%d)\n", astCtx.EnclosingFunction, astCtx.FunctionStartLine, astCtx.FunctionEndLine)
			if astCtx.RouteDefinition != "" {
				fmt.Printf("      Cross-file Route:   \033[35m%s\033[0m\n", astCtx.RouteDefinition)
			}
			if len(astCtx.MiddlewareContext) > 0 {
				for mwKey := range astCtx.MiddlewareContext {
					fmt.Printf("      Attached Middleware: \033[32m%s\033[0m\n", mwKey)
				}
			}
		}

		// 3. Triage
		if !*jsonOutput {
			fmt.Printf("\033[1;34m[3/4] Contextual AI Triage...\033[0m\n")
		}

		triageRes, err := agent.Triage(ctx, f, astCtx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "❌ Triage error: %v\n", err)
			continue
		}

		item := ReportItem{
			Finding:    f,
			ASTContext: astCtx,
			Triage:     triageRes,
		}

		if triageRes.IsExploitable {
			report.ConfirmedVulns++

			if !*jsonOutput {
				fmt.Printf("      Status: \033[1;31m[EXPLOITABLE - %s]\033[0m (Confidence: %.0f%%)\n", triageRes.Severity, triageRes.Confidence*100)
				fmt.Printf("      Vuln Type: \033[1;37m%s\033[0m\n", triageRes.VulnerabilityType)
				fmt.Printf("      Reason:    %s\n", triageRes.TriageReason)
				fmt.Printf("      Attack:    \033[33m%s\033[0m\n", triageRes.AttackVector)
				fmt.Printf("      Fix Plan:  \033[32m%s\033[0m\n", triageRes.RemediationSummary)
			}

			// 4. Generate Unified Patch Diff
			if !*jsonOutput {
				fmt.Printf("\033[1;34m[4/4] Generating Automated Auto-Fix Git Diff...\033[0m\n")
			}

			patchOut, err := patcher.GenerateDiff(f.FilePath, astCtx.FullFileSource, triageRes.OriginalCodeBlock, triageRes.PatchedCodeBlock)
			if err != nil {
				fmt.Fprintf(os.Stderr, "⚠️  Diff generation warning: %v\n", err)
			} else if patchOut.UnifiedDiff != "" {
				item.UnifiedDiff = patchOut.UnifiedDiff
				combinedDiffs.WriteString(patchOut.UnifiedDiff)
				combinedDiffs.WriteString("\n")

				if !*jsonOutput {
					fmt.Println("\n" + patcher.ColorizeDiff(patchOut.UnifiedDiff))
				}

				if *writePatches {
					targetFileAbs := filepath.Join(absTargetDir, filepath.Base(f.FilePath))
					if err := patcher.WritePatchToFile(targetFileAbs, patchOut.NewFileContent); err != nil {
						fmt.Fprintf(os.Stderr, "❌ Failed to write patch to %s: %v\n", targetFileAbs, err)
					} else {
						fmt.Printf("      \033[1;32m✓ Successfully applied patch to %s\033[0m\n", targetFileAbs)
					}
				}
			}
		} else {
			report.FalsePositives++
			if !*jsonOutput {
				fmt.Printf("      Status: \033[1;32m[FALSE POSITIVE SUPPRESSED]\033[0m (Confidence: %.0f%%)\n", triageRes.Confidence*100)
				fmt.Printf("      Reason: %s\n", triageRes.TriageReason)
			}
		}

		report.Items = append(report.Items, item)
	}

	// Save diff to file if requested
	if *outputDiffPath != "" && combinedDiffs.Len() > 0 {
		if err := os.WriteFile(*outputDiffPath, []byte(combinedDiffs.String()), 0644); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to write diff file: %v\n", err)
		} else if !*jsonOutput {
			fmt.Printf("\n📁 Unified Diff written to: \033[1;37m%s\033[0m\n", *outputDiffPath)
		}
	}

	// Summary
	if !*jsonOutput {
		fmt.Println("\n\033[1;37m═══════════════════════════════════════════════════════════\033[0m")
		fmt.Println("\033[1;36m                 QUELL SCAN SCORECARD                      \033[0m")
		fmt.Println("\033[1;37m═══════════════════════════════════════════════════════════\033[0m")
		fmt.Printf("  Total Suspects Scanned:     \033[1;33m%d\033[0m\n", report.TotalSuspects)
		fmt.Printf("  Confirmed Real Vulns:       \033[1;31m%d\033[0m\n", report.ConfirmedVulns)
		fmt.Printf("  False Positives Eliminated: \033[1;32m%d\033[0m\n", report.FalsePositives)
		fmt.Printf("  Ready-to-Merge PR Patches:  \033[1;35m%d\033[0m\n", report.ConfirmedVulns)
		fmt.Println("\033[1;37m═══════════════════════════════════════════════════════════\033[0m")
	} else {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(report)
	}
}
