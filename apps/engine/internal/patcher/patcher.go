package patcher

import (
	"fmt"
	"os"
	"strings"

	"github.com/hexops/gotextdiff"
	"github.com/hexops/gotextdiff/myers"
	"github.com/hexops/gotextdiff/span"
)

// PatchOutput contains the result of patch application and the unified diff.
type PatchOutput struct {
	FilePath       string `json:"file_path"`
	NewFileContent string `json:"new_file_content"`
	UnifiedDiff    string `json:"unified_diff"`
}

// GenerateDiff computes the new file content and a standard Git Unified Diff.
func GenerateDiff(filePath, originalFileContent, originalBlock, patchedBlock string) (*PatchOutput, error) {
	if originalBlock == "" || patchedBlock == "" {
		return nil, fmt.Errorf("originalBlock and patchedBlock cannot be empty")
	}

	if originalBlock == patchedBlock {
		return &PatchOutput{
			FilePath:       filePath,
			NewFileContent: originalFileContent,
			UnifiedDiff:    "",
		}, nil
	}

	// Replace originalBlock with patchedBlock
	var newContent string
	if strings.Contains(originalFileContent, originalBlock) {
		newContent = strings.Replace(originalFileContent, originalBlock, patchedBlock, 1)
	} else {
		// Try normalized whitespace replacement if exact match fails
		normOrigBlock := strings.TrimSpace(originalBlock)
		if strings.Contains(originalFileContent, normOrigBlock) {
			newContent = strings.Replace(originalFileContent, normOrigBlock, strings.TrimSpace(patchedBlock), 1)
		} else {
			return nil, fmt.Errorf("original code block not found in file %s", filePath)
		}
	}

	// Generate Git Unified Diff
	uri := span.URIFromPath(filePath)
	edits := myers.ComputeEdits(uri, originalFileContent, newContent)
	diff := fmt.Sprint(gotextdiff.ToUnified("a/"+filePath, "b/"+filePath, originalFileContent, edits))

	return &PatchOutput{
		FilePath:       filePath,
		NewFileContent: newContent,
		UnifiedDiff:    diff,
	}, nil
}

// WritePatchToFile saves the patched content directly to disk.
func WritePatchToFile(filePath string, newContent string) error {
	return os.WriteFile(filePath, []byte(newContent), 0644)
}

// ColorizeDiff adds ANSI colors to a unified diff for terminal display.
func ColorizeDiff(diff string) string {
	lines := strings.Split(diff, "\n")
	var colored []string

	for _, line := range lines {
		if strings.HasPrefix(line, "---") || strings.HasPrefix(line, "+++") {
			colored = append(colored, "\033[1;35m"+line+"\033[0m") // Magenta
		} else if strings.HasPrefix(line, "@@") {
			colored = append(colored, "\033[36m"+line+"\033[0m") // Cyan
		} else if strings.HasPrefix(line, "+") {
			colored = append(colored, "\033[32m"+line+"\033[0m") // Green
		} else if strings.HasPrefix(line, "-") {
			colored = append(colored, "\033[31m"+line+"\033[0m") // Red
		} else {
			colored = append(colored, line)
		}
	}

	return strings.Join(colored, "\n")
}
