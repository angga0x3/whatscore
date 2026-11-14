// Package architecture enforces the import rules from
// docs/architecture/technical-specification.md §3.1 mechanically, so a PR
// that crosses a layer boundary fails CI instead of relying on review
// alone. It parses imports with go/parser and never builds or executes the
// packages under test.
package architecture

import (
	"fmt"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const modulePath = "github.com/angga0x3/whatscore"

// importRule rejects imports that match isViolation, reporting the reason.
type importRule struct {
	name        string
	dir         string
	isViolation func(importPath string) string
}

// TestLayerImportRules walks the production and test sources under each
// rule's directory and fails with file:line for every violation.
func TestLayerImportRules(t *testing.T) {
	root := repositoryRoot(t)

	rules := []importRule{
		{
			name: "protocol does not import application or infrastructure layers",
			dir:  "protocol",
			isViolation: func(importPath string) string {
				for _, layer := range []string{"core", "server", "storage", "config"} {
					if isWithin(importPath, modulePath+"/"+layer) {
						return "protocol must stay below " + layer
					}
				}
				return ""
			},
		},
		{
			name: "protocol imports only approved third-party modules",
			dir:  "protocol",
			isViolation: func(importPath string) string {
				if isWithin(importPath, modulePath) {
					return "" // other protocol/* packages
				}
				first := strings.SplitN(importPath, "/", 2)[0]
				if !strings.Contains(first, ".") {
					return "" // standard library
				}
				for _, allowed := range []string{
					"golang.org/x/crypto",
					"github.com/gorilla/websocket",
					"google.golang.org/protobuf",
				} {
					if isWithin(importPath, allowed) {
						return ""
					}
				}
				return "third-party module is not in the §5.1 allowlist"
			},
		},
		{
			name: "server does not import the protocol engine",
			dir:  "server",
			isViolation: func(importPath string) string {
				if isWithin(importPath, modulePath+"/protocol") {
					return "server must reach the engine through the application core"
				}
				return ""
			},
		},
	}

	for _, rule := range rules {
		rule := rule
		t.Run(rule.name, func(t *testing.T) {
			violations, err := scanImports(filepath.Join(root, rule.dir), rule.isViolation)
			if err != nil {
				t.Fatalf("scan %s: %v", rule.dir, err)
			}
			for _, v := range violations {
				t.Errorf("%s", v)
			}
			if len(violations) > 0 {
				t.Fatalf("%d import-rule violation(s); see docs/architecture/technical-specification.md §3.1", len(violations))
			}
		})
	}
}

// scanImports parses every .go file under dir (including tests) and returns
// one message per violating import.
func scanImports(dir string, isViolation func(string) string) ([]string, error) {
	fset := token.NewFileSet()
	var violations []string

	err := filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if entry.Name() == "vendor" || entry.Name() == "testdata" || entry.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}

		file, parseErr := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if parseErr != nil {
			return fmt.Errorf("parse %s: %w", path, parseErr)
		}
		for _, spec := range file.Imports {
			importPath, unquoteErr := strconv.Unquote(spec.Path.Value)
			if unquoteErr != nil {
				return fmt.Errorf("%s: unquote import %s: %w", path, spec.Path.Value, unquoteErr)
			}
			if reason := isViolation(importPath); reason != "" {
				pos := fset.Position(spec.Pos())
				violations = append(violations, fmt.Sprintf("%s:%d: imports %q: %s",
					pos.Filename, pos.Line, importPath, reason))
			}
		}
		return nil
	})
	return violations, err
}

// isWithin reports whether importPath equals prefix or is a subpackage of it.
func isWithin(importPath, prefix string) bool {
	return importPath == prefix || strings.HasPrefix(importPath, prefix+"/")
}

// repositoryRoot returns the module root (two levels above tests/architecture)
// and verifies go.mod is there, so the test fails loudly if it is ever moved.
func repositoryRoot(t *testing.T) string {
	t.Helper()
	root, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	root = filepath.Clean(filepath.Join(root, "..", ".."))
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("repository root %s has no go.mod: %v", root, err)
	}
	return root
}
