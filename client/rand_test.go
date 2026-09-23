package main

import (
	"strings"
	"testing"
)

func TestRogerRandUsesFullLongKey(t *testing.T) {
	prefix := strings.Repeat("a", 28)
	extra := "roger/" + version

	first := newRogerRand(prefix + "111").randValue(extra)
	second := newRogerRand(prefix + "222").randValue(extra)

	if first == second {
		t.Fatalf("long keys that differ after byte 28 generated the same value")
	}
}

func TestRogerRandShortKeyIsDeterministic(t *testing.T) {
	extra := "roger/" + version

	first := newRogerRand("short-key").randValue(extra)
	second := newRogerRand("short-key").randValue(extra)

	if first != second {
		t.Fatalf("short key hash path is not deterministic")
	}
}
