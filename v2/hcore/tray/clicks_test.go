package tray

import "testing"

// TestSetupClickHandlersAcceptsHandler is a smoke test: the tray primary click
// must register a single-click handler (no double-click gating that closes UI).
func TestSetupClickHandlersAcceptsHandler(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("setupClickHandlers panicked: %v", r)
		}
	}()
	setupClickHandlers(func() {})
}