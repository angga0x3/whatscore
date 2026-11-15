// Command tokendict validates a candidate WhatsApp token table without
// embedding one. It prints counts and provenance only: token values never
// reach stdout, stderr, or an error string, so a run cannot copy a
// proprietary table into a terminal, CI log, or issue comment.
//
// Usage:
//
//	tokendict -in table.json [-check]
//
// Default: validate and print a JSON summary of counts and provenance.
// -check: validate only, silent on success, for scripts and CI gates. Both
// modes exit 1 with a typed error on an invalid table.
//
// The policy this enforces is docs/protocol/tokens.md; the licensing question
// behind it is technical-specification §10.2.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/angga0x3/whatscore/internal/tokendict"
)

// summary is the only thing this command prints about a table: shapes and
// attribution, never entries.
type summary struct {
	Source        string `json:"source"`
	ObservedDate  string `json:"observed_date"`
	License       string `json:"license"`
	SingleEntries int    `json:"single_entries"`
	SingleTokens  int    `json:"single_tokens"`
	DoubleRows    int    `json:"double_rows"`
	DoubleTokens  int    `json:"double_tokens"`
	TotalTokens   int    `json:"total_tokens"`
}

func main() {
	in := flag.String("in", "", "path to the candidate token table (JSON)")
	check := flag.Bool("check", false, "validate only; print nothing on success")
	flag.Usage = func() {
		_, _ = fmt.Fprintf(flag.CommandLine.Output(), "usage: %s -in table.json [-check]\n", os.Args[0])
		_, _ = fmt.Fprintln(flag.CommandLine.Output(), "\nPrints counts and provenance only; never token values.")
		_, _ = fmt.Fprintln(flag.CommandLine.Output(), "Policy: docs/protocol/tokens.md. Licensing: spec §10.2.")
		flag.PrintDefaults()
	}
	flag.Parse()

	if *in == "" {
		flag.Usage()
		os.Exit(2)
	}
	if err := run(*in, os.Stdout, *check); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(path string, out io.Writer, checkOnly bool) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("tokendict: open %s: %w", path, err)
	}
	defer func() { _ = file.Close() }()

	table, err := tokendict.LoadAndValidate(file)
	if err != nil {
		return fmt.Errorf("tokendict: rejected: %w", err)
	}
	if checkOnly {
		return nil
	}
	return json.NewEncoder(out).Encode(buildSummary(table))
}

func buildSummary(table tokendict.Table) summary {
	singleTokens := 0
	// Index 0 is reserved; count only slots a codec can actually use.
	for i := 1; i < len(table.Single); i++ {
		if table.Single[i] != "" {
			singleTokens++
		}
	}
	doubleTokens := 0
	for _, row := range table.Double {
		for _, token := range row {
			if token != "" {
				doubleTokens++
			}
		}
	}
	prov := table.Provenance()
	return summary{
		Source:        prov.Source,
		ObservedDate:  prov.ObservedDate,
		License:       prov.License,
		SingleEntries: len(table.Single),
		SingleTokens:  singleTokens,
		DoubleRows:    len(table.Double),
		DoubleTokens:  doubleTokens,
		TotalTokens:   singleTokens + doubleTokens,
	}
}
