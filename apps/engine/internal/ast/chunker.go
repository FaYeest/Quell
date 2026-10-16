package ast

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/golang"
	"github.com/smacker/go-tree-sitter/javascript"
	"github.com/smacker/go-tree-sitter/python"
	"github.com/smacker/go-tree-sitter/typescript/typescript"
)

// ASTContext holds the extracted code block and cross-file dependencies.
type ASTContext struct {
	TargetFile         string            `json:"target_file"`
	EnclosingFunction  string            `json:"enclosing_function"`
	FunctionStartLine  int               `json:"function_start_line"`
	FunctionEndLine    int               `json:"function_end_line"`
	FunctionSource     string            `json:"function_source"`
	FullFileSource     string            `json:"-"`
	Imports            []string          `json:"imports"`
	RouteDefinition    string            `json:"route_definition,omitempty"`
	MiddlewareContext  map[string]string `json:"middleware_context,omitempty"` // file/func name -> source
}

// Chunker encapsulates Tree-sitter parsing logic.
type Chunker struct{}

// NewChunker creates a new Chunker instance.
func NewChunker() *Chunker {
	return &Chunker{}
}

// getLanguageForFile determines Tree-sitter language based on file extension.
func getLanguageForFile(ext string) *sitter.Language {
	switch strings.ToLower(ext) {
	case ".js", ".jsx", ".mjs", ".cjs":
		return javascript.GetLanguage()
	case ".ts", ".tsx":
		return typescript.GetLanguage()
	case ".py":
		return python.GetLanguage()
	case ".go":
		return golang.GetLanguage()
	default:
		return javascript.GetLanguage()
	}
}

// ExtractContext extracts enclosing function and cross-file context for a finding.
func (c *Chunker) ExtractContext(filePath string, startLine, endLine int, repoRoot string) (*ASTContext, error) {
	absPath := filePath
	if !filepath.IsAbs(absPath) {
		absPath = filepath.Join(repoRoot, filePath)
	}

	contentBytes, err := os.ReadFile(absPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %w", absPath, err)
	}
	contentStr := strings.ReplaceAll(string(contentBytes), "\r\n", "\n")
	contentBytes = []byte(contentStr)
	lines := strings.Split(contentStr, "\n")

	parser := sitter.NewParser()
	lang := getLanguageForFile(filepath.Ext(absPath))
	parser.SetLanguage(lang)

	ctx := context.Background()
	tree, err := parser.ParseCtx(ctx, nil, contentBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse AST for %s: %w", absPath, err)
	}

	root := tree.RootNode()

	// 0-indexed points for Tree-sitter
	pointStart := sitter.Point{Row: uint32(startLine - 1), Column: 0}
	pointEnd := sitter.Point{Row: uint32(endLine - 1), Column: 1000}

	enclosingNode := findEnclosingFunction(root, pointStart, pointEnd)

	var funcName string
	var fStartLine, fEndLine int
	var funcSource string

	if enclosingNode != nil {
		fStartLine = int(enclosingNode.StartPoint().Row) + 1
		fEndLine = int(enclosingNode.EndPoint().Row) + 1
		funcName = extractNodeName(enclosingNode, contentBytes)
		funcSource = enclosingNode.Content(contentBytes)
	} else {
		// Fallback: take 15 lines before and after if no specific AST function found
		fStartLine = max(1, startLine-10)
		fEndLine = min(len(lines), endLine+10)
		funcName = "anonymous_block"
		funcSource = strings.Join(lines[fStartLine-1:fEndLine], "\n")
	}

	astCtx := &ASTContext{
		TargetFile:        filepath.ToSlash(filePath),
		EnclosingFunction: funcName,
		FunctionStartLine: fStartLine,
		FunctionEndLine:   fEndLine,
		FunctionSource:    funcSource,
		FullFileSource:    contentStr,
		Imports:           extractImports(root, contentBytes),
		MiddlewareContext: make(map[string]string),
	}

	// Cross-file trace: find routes and middleware in repo
	c.enrichCrossFileContext(astCtx, repoRoot, absPath)

	return astCtx, nil
}

// findEnclosingFunction walks the AST to find the tightest enclosing function/method node.
func findEnclosingFunction(root *sitter.Node, pStart, pEnd sitter.Point) *sitter.Node {
	var best *sitter.Node

	var walk func(n *sitter.Node)
	walk = func(n *sitter.Node) {
		if n == nil {
			return
		}

		nStart := n.StartPoint()
		nEnd := n.EndPoint()

		// Check if node contains the target line range
		if (nStart.Row <= pStart.Row) && (nEnd.Row >= pEnd.Row) {
			t := n.Type()
			if isFunctionNodeType(t) {
				best = n
			}

			// Explore children for a tighter match
			count := int(n.ChildCount())
			for i := 0; i < count; i++ {
				walk(n.Child(i))
			}
		}
	}

	walk(root)
	return best
}

func isFunctionNodeType(t string) bool {
	switch t {
	case "function_declaration",
		"function_expression",
		"arrow_function",
		"method_definition",
		"generator_function_declaration",
		"function_definition",
		"async_function_definition",
		"method_declaration":
		return true
	default:
		return false
	}
}

func extractNodeName(n *sitter.Node, src []byte) string {
	if n == nil {
		return "unknown"
	}

	// Try common identifier field names
	if id := n.ChildByFieldName("name"); id != nil {
		return id.Content(src)
	}

	// For arrow functions in assignments: const foo = () => {}
	parent := n.Parent()
	if parent != nil {
		if id := parent.ChildByFieldName("name"); id != nil {
			return id.Content(src)
		}
		if parent.Type() == "variable_declarator" && parent.ChildCount() > 0 {
			return parent.Child(0).Content(src)
		}
		if parent.Type() == "pair" && parent.ChildCount() > 0 {
			// e.g. { getUserProfile: async () => {} }
			return parent.Child(0).Content(src)
		}
	}

	return "handler"
}

// extractImports extracts import and require paths.
func extractImports(root *sitter.Node, src []byte) []string {
	var imports []string
	if root == nil {
		return imports
	}

	var walk func(n *sitter.Node)
	walk = func(n *sitter.Node) {
		if n == nil {
			return
		}

		t := n.Type()
		if t == "import_statement" || t == "import_declaration" {
			imports = append(imports, n.Content(src))
		} else if t == "call_expression" {
			if fn := n.ChildByFieldName("function"); fn != nil && fn.Content(src) == "require" {
				imports = append(imports, n.Content(src))
			}
		}

		count := int(n.ChildCount())
		for i := 0; i < count; i++ {
			walk(n.Child(i))
		}
	}

	walk(root)
	return imports
}

// enrichCrossFileContext resolves callers (routes) and referenced middlewares.
func (c *Chunker) enrichCrossFileContext(ctx *ASTContext, repoRoot, currentFile string) {
	if ctx.EnclosingFunction == "" {
		return
	}

	funcName := ctx.EnclosingFunction

	// Look for route bindings in .js / .ts files in repo
	err := filepath.Walk(repoRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		ext := filepath.Ext(path)
		if ext != ".js" && ext != ".ts" {
			return nil
		}

		content, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		contentStr := string(content)

		// Check if this file references the function (e.g. userController.getUserProfile or getUserProfile)
		if strings.Contains(contentStr, funcName) {
			lines := strings.Split(contentStr, "\n")
			for _, line := range lines {
				trimmed := strings.TrimSpace(line)
				if (strings.Contains(trimmed, "app.") || strings.Contains(trimmed, "router.")) && strings.Contains(trimmed, funcName) {
					ctx.RouteDefinition = fmt.Sprintf("%s: %s", filepath.ToSlash(filepath.Clean(path)), trimmed)

					// Check if a middleware is mentioned (e.g., authenticateToken)
					re := regexp.MustCompile(`[a-zA-Z0-9_]*auth[a-zA-Z0-9_]*|[a-zA-Z0-9_]*token[a-zA-Z0-9_]*`)
					matches := re.FindAllString(trimmed, -1)
					for _, m := range matches {
						if m != funcName {
							c.findAndAttachMiddleware(ctx, repoRoot, m)
						}
					}
				}
			}
		}
		return nil
	})

	if err != nil {
		// Log or suppress walk error
		return
	}
}

// findAndAttachMiddleware finds the definition of a middleware in the repository.
func (c *Chunker) findAndAttachMiddleware(ctx *ASTContext, repoRoot, mwName string) {
	_ = filepath.Walk(repoRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		ext := filepath.Ext(path)
		if ext != ".js" && ext != ".ts" {
			return nil
		}

		content, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		contentStr := string(content)

		if strings.Contains(contentStr, "function "+mwName) || strings.Contains(contentStr, mwName+" =") {
			// Extract a snippet of the middleware
			lines := strings.Split(contentStr, "\n")
			var snippet []string
			recording := false
			braceCount := 0

			for _, l := range lines {
				if !recording && strings.Contains(l, mwName) {
					recording = true
				}
				if recording {
					snippet = append(snippet, l)
					braceCount += strings.Count(l, "{") - strings.Count(l, "}")
					if braceCount <= 0 && len(snippet) > 1 {
						break
					}
				}
			}

			if len(snippet) > 0 {
				ctx.MiddlewareContext[fmt.Sprintf("%s#%s", filepath.ToSlash(filepath.Clean(path)), mwName)] = strings.Join(snippet, "\n")
			}
		}
		return nil
	})
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
