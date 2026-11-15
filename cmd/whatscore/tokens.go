package main

import (
	"errors"
	"fmt"
	"log/slog"

	"github.com/angga0x3/whatscore/config"
	"github.com/angga0x3/whatscore/internal/tokendict"
	"github.com/angga0x3/whatscore/protocol/binary"
)

// ErrInvalidTokenTable is returned when an operator-supplied table is rejected.
var ErrInvalidTokenTable = errors.New("cmd/whatscore: invalid token dictionary")

// loadTokenDictionary builds the codec dictionary from the configured table.
//
// ADR 0002: the table is operator data, never repository data. No path means an
// empty dictionary, which is correct for every code path that does not encode
// WhatsApp string tokens (tests, fixtures, early bootstrap). A configured path
// must pass tokendict validation, so a table without provenance or with
// structural damage fails at startup instead of producing garbled stanzas.
func loadTokenDictionary(cfg *config.Config, logger *slog.Logger) (*binary.Dictionary, error) {
	if cfg == nil {
		return nil, fmt.Errorf("%w: nil config", ErrInvalidTokenTable)
	}
	path := cfg.Engine.TokenDictionaryPath
	if path == "" {
		if logger != nil {
			logger.Info("no token dictionary configured; the binary codec runs with an empty table",
				"env", "WHATSAPP_TOKEN_DICTIONARY", "adr", "docs/architecture/decisions/0002-token-table.md")
		}
		return binary.NewDictionary(), nil
	}

	table, err := tokendict.LoadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidTokenTable, err)
	}
	dictionary, err := tokendict.Build(table)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidTokenTable, err)
	}
	if logger != nil {
		provenance := table.Provenance()
		logger.Info("loaded token dictionary",
			"path", path,
			"source", provenance.Source,
			"observed_date", provenance.ObservedDate,
			"license", provenance.License,
			"single", len(table.Single)-1,
			"double", len(table.Double),
		)
	}
	return dictionary, nil
}
