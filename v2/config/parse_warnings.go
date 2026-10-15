package config

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// parse_warnings.go — request-scoped aggregation of non-fatal import warnings.
//
// filterValidLeavesJSON (soft parse) and MigrateLegacyJSON (1.4→1.5 rewrite)
// used to only fmt.Printf drops/rewrites to the core stdout, so the Flutter UI
// never learned that part of a subscription was silently discarded. The gRPC
// Parse handler now attaches a ParseWarningsCollector to the request context
// (WithParseWarnings) and returns the summary in ParseResponse.Message (a
// field that is empty on OK otherwise), so the UI can show a snackbar like
// "3 nodes skipped on import (unknown type "trojan-go") · 2 nodes migrated".
//
// All helpers treat a missing collector as a no-op, so call sites that never
// attach one (Start path, CLI, tests) behave exactly as before.

// LeafDrop is one config leaf dropped by the soft parse, with the reason the
// engine/registry rejected it.
type LeafDrop struct {
	Kind   string // "outbound" | "group" | "endpoint" | "inbound"
	Type   string
	Tag    string
	Reason string
}

// String renders the drop for logs and the UI sample list:
// outbound "fr-1" (trojan-go): unknown type
func (d LeafDrop) String() string {
	tag := d.Tag
	if tag == "" {
		tag = "?"
	}
	if d.Type == "" {
		return fmt.Sprintf("%s %q: %s", d.Kind, tag, d.Reason)
	}
	return fmt.Sprintf("%s %q (%s): %s", d.Kind, tag, d.Type, d.Reason)
}

// ParseWarningsSummary is the JSON payload carried in ParseResponse.Message on
// OK responses when the import dropped or migrated leaves. Field names are
// part of the Dart contract (profile_parse_warnings.dart).
type ParseWarningsSummary struct {
	Dropped  int `json:"dropped"`
	Migrated int `json:"migrated"`
	// TopDrop is the reason of the first dropped leaf (single line, capped) —
	// the UI shows it as the headline cause.
	TopDrop        string   `json:"topDrop,omitempty"`
	DropSamples    []string `json:"dropSamples,omitempty"`
	MigrateSamples []string `json:"migrateSamples,omitempty"`
}

// parseWarningsMessageKey wraps the summary so Dart can tell a warnings payload
// apart from a plain (error) message: {"parseWarnings": {...}}.
const parseWarningsMessageKey = "parseWarnings"

// parseWarningsSampleCap bounds the per-kind sample lists so Message stays
// small for pathological subscriptions.
const parseWarningsSampleCap = 3

// parseWarningsReasonCap keeps one-line reasons snackbar-safe.
const parseWarningsReasonCap = 200

// ParseWarningsCollector accumulates drops and migrations for one Parse call.
// Not goroutine-safe by design: Parse handles one config per call; attach one
// collector per request context.
type ParseWarningsCollector struct {
	drops      []LeafDrop
	migrations []string
}

type parseWarningsCtxKey struct{}

// WithParseWarnings attaches a fresh collector to ctx and returns both.
func WithParseWarnings(ctx context.Context) (context.Context, *ParseWarningsCollector) {
	c := &ParseWarningsCollector{}
	return context.WithValue(ctx, parseWarningsCtxKey{}, c), c
}

// parseWarningsFrom returns the collector attached to ctx, or nil.
func parseWarningsFrom(ctx context.Context) *ParseWarningsCollector {
	if ctx == nil {
		return nil
	}
	c, _ := ctx.Value(parseWarningsCtxKey{}).(*ParseWarningsCollector)
	return c
}

func (c *ParseWarningsCollector) addDrop(kind, typ, tag string, reason interface{}) {
	if c == nil {
		return
	}
	c.drops = append(c.drops, LeafDrop{
		Kind:   kind,
		Type:   typ,
		Tag:    tag,
		Reason: sanitizeParseWarningReason(fmt.Sprint(reason)),
	})
}

func (c *ParseWarningsCollector) addMigration(msg string) {
	if c == nil {
		return
	}
	c.migrations = append(c.migrations, sanitizeParseWarningReason(msg))
}

// MessageJSON serializes the collected warnings for ParseResponse.Message.
// Returns "" when nothing was dropped or migrated.
func (c *ParseWarningsCollector) MessageJSON() string {
	if c == nil || (len(c.drops) == 0 && len(c.migrations) == 0) {
		return ""
	}
	summary := ParseWarningsSummary{
		Dropped:  len(c.drops),
		Migrated: len(c.migrations),
	}
	for i, d := range c.drops {
		if i == 0 {
			summary.TopDrop = d.Reason
		}
		if i < parseWarningsSampleCap {
			summary.DropSamples = append(summary.DropSamples, d.String())
		}
	}
	for i, m := range c.migrations {
		if i < parseWarningsSampleCap {
			summary.MigrateSamples = append(summary.MigrateSamples, m)
		}
	}
	raw, err := json.Marshal(map[string]ParseWarningsSummary{parseWarningsMessageKey: summary})
	if err != nil {
		return ""
	}
	return string(raw)
}

// sanitizeParseWarningReason flattens multi-line engine errors (CheckConfig
// failures can span lines) to one line and caps the length for snackbars.
func sanitizeParseWarningReason(reason string) string {
	line, _, _ := strings.Cut(reason, "\n")
	line = strings.TrimSpace(line)
	runes := []rune(line)
	if len(runes) > parseWarningsReasonCap {
		line = string(runes[:parseWarningsReasonCap-1]) + "…"
	}
	return line
}
