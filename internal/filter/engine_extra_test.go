package filter

import (
	"testing"
)

func TestEngine_AllPassMode(t *testing.T) {
	engine := NewEngine("all", []string{"test.com"}, []string{})
	if engine.ShouldBlock("test.com") {
		t.Error("expected test.com to be allowed in all-pass mode")
	}
	if engine.ShouldBlock("bad.com") {
		t.Error("expected bad.com to be allowed in all-pass mode")
	}
}

func TestEngine_UpdateRules(t *testing.T) {
	engine := NewEngine("whitelist", []string{"allowed.com"}, []string{})
	
	if !engine.ShouldBlock("blocked.com") {
		t.Error("expected blocked.com to be blocked initially")
	}

	// Update to blacklist
	engine.UpdateRules("blacklist", []string{"blocked.com"}, []string{})

	if engine.ShouldBlock("allowed.com") {
		t.Error("expected allowed.com to be allowed after updating to blacklist")
	}
	if !engine.ShouldBlock("blocked.com") {
		t.Error("expected blocked.com to be blocked after updating to blacklist")
	}
}
