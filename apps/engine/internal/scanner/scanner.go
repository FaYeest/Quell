package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

// Finding represents a single security finding normalized from Semgrep output.
type Finding struct {
	RuleID      string                 `json:"rule_id"`
	FilePath    string                 `json:"file_path"`
	StartLine   int                    `json:"start_line"`
	StartCol    int                    `json:"start_col"`
	EndLine     int                    `json:"end_line"`
	EndCol      int                    `json:"end_col"`
	Message     string                 `json:"message"`
	Severity    string                 `json:"severity"`
	Lines       string                 `json:"lines"`
	CWE         string                 `json:"cwe,omitempty"`
	OWASP       string                 `json:"owasp,omitempty"`
	VulnType    string                 `json:"vuln_type,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// SemgrepRawResult models Semgrep's JSON output structure.
type SemgrepRawResult struct {
	Results []struct {
		CheckID string `json:"check_id"`
		Path    string `json:"path"`
		Start   struct {
			Line int `json:"line"`
			Col  int `json:"col"`
		} `json:"start"`
		End struct {
			Line int `json:"line"`
			Col  int `json:"col"`
		} `json:"end"`
		Extra struct {
			Message  string                 `json:"message"`
			Severity string                 `json:"severity"`
			Lines    string                 `json:"lines"`
			Metadata map[string]interface{} `json:"metadata"`
		} `json:"extra"`
	} `json:"results"`
	Errors []struct {
		Message string `json:"message"`
	} `json:"errors"`
}

// ScanOptions configures the static analysis execution.
type ScanOptions struct {
	TargetDir  string
	ConfigFile string
	AutoConfig bool
}

// LocateSemgrep attempts to find the semgrep executable in PATH or known python script folders.
func LocateSemgrep() (string, error) {
	// 1. Try standard LookPath
	path, err := exec.LookPath("semgrep")
	if err == nil {
		return path, nil
	}

	// 2. On Windows, check common Python Scripts folders
	if runtime.GOOS == "windows" {
		userHome, _ := os.UserHomeDir()
		candidates := []string{
			filepath.Join(userHome, "AppData", "Local", "Programs", "Python", "Python314", "Scripts", "semgrep.exe"),
			filepath.Join(userHome, "AppData", "Local", "Programs", "Python", "Python313", "Scripts", "semgrep.exe"),
			filepath.Join(userHome, "AppData", "Local", "Programs", "Python", "Python312", "Scripts", "semgrep.exe"),
			filepath.Join(userHome, "AppData", "Local", "Programs", "Python", "Python311", "Scripts", "semgrep.exe"),
			filepath.Join(userHome, "AppData", "Roaming", "Python", "Scripts", "semgrep.exe"),
			"C:\\Python314\\Scripts\\semgrep.exe",
			"C:\\Python313\\Scripts\\semgrep.exe",
			"C:\\Python312\\Scripts\\semgrep.exe",
			"C:\\Python311\\Scripts\\semgrep.exe",
		}

		for _, candidate := range candidates {
			if _, err := os.Stat(candidate); err == nil {
				return candidate, nil
			}
		}
	}

	return "", fmt.Errorf("semgrep executable not found. Please install semgrep (e.g. 'pip install semgrep')")
}

// RunScan executes Semgrep deterministically on targetDir and returns parsed Findings.
func RunScan(ctx context.Context, opts ScanOptions) ([]Finding, error) {
	semgrepBin, err := LocateSemgrep()
	if err != nil {
		return nil, err
	}

	var tempRuleFile string
	configArg := opts.ConfigFile

	if opts.AutoConfig {
		configArg = "auto"
	} else if configArg == "" {
		// Use embedded default Quell rules
		tmp, err := os.CreateTemp("", "quell_rules_*.yml")
		if err != nil {
			return nil, fmt.Errorf("failed to create temp rule file: %w", err)
		}
		tempRuleFile = tmp.Name()
		defer os.Remove(tempRuleFile)

		if _, err := tmp.WriteString(DefaultQuellRulesYAML); err != nil {
			tmp.Close()
			return nil, fmt.Errorf("failed to write temp rule file: %w", err)
		}
		tmp.Close()
		configArg = tempRuleFile
	}

	args := []string{
		"scan",
		"--json",
		"--quiet",
		fmt.Sprintf("--config=%s", configArg),
		opts.TargetDir,
	}

	cmd := exec.CommandContext(ctx, semgrepBin, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	runErr := cmd.Run()
	// Semgrep exits with 0 or 1 on findings; error is only fatal if stdout has no JSON
	outBytes := stdout.Bytes()
	if len(outBytes) == 0 && runErr != nil {
		return nil, fmt.Errorf("semgrep execution failed: %v, stderr: %s", runErr, stderr.String())
	}

	// Parse JSON
	var raw SemgrepRawResult
	if err := json.Unmarshal(outBytes, &raw); err != nil {
		// Sometimes stdout might contain leading non-json warning logs; find first '{'
		firstBrace := bytes.IndexByte(outBytes, '{')
		if firstBrace >= 0 {
			if err2 := json.Unmarshal(outBytes[firstBrace:], &raw); err2 == nil {
				goto PARSED
			}
		}
		return nil, fmt.Errorf("failed to parse semgrep json output: %w. Raw output: %s", err, string(outBytes))
	}

PARSED:
	var findings []Finding
	for _, res := range raw.Results {
		normalizedPath := filepath.ToSlash(res.Path)
		f := Finding{
			RuleID:    res.CheckID,
			FilePath:  normalizedPath,
			StartLine: res.Start.Line,
			StartCol:  res.Start.Col,
			EndLine:   res.End.Line,
			EndCol:    res.End.Col,
			Message:   res.Extra.Message,
			Severity:  res.Extra.Severity,
			Lines:     res.Extra.Lines,
			Metadata:  res.Extra.Metadata,
		}

		if res.Extra.Metadata != nil {
			if cwe, ok := res.Extra.Metadata["cwe"].(string); ok {
				f.CWE = cwe
			} else if cwes, ok := res.Extra.Metadata["cwe"].([]interface{}); ok && len(cwes) > 0 {
				f.CWE = fmt.Sprint(cwes[0])
			}

			if owasp, ok := res.Extra.Metadata["owasp"].(string); ok {
				f.OWASP = owasp
			} else if owasps, ok := res.Extra.Metadata["owasp"].([]interface{}); ok && len(owasps) > 0 {
				f.OWASP = fmt.Sprint(owasps[0])
			}

			if vt, ok := res.Extra.Metadata["vulnerability_type"].(string); ok {
				f.VulnType = vt
			}
		}

		findings = append(findings, f)
	}

	return findings, nil
}
