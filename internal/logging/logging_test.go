package logging

import "testing"

func TestInitSetsLogger(t *testing.T) {
	Init("debug")
	if Logger == nil {
		t.Fatalf("expected logger to be initialized")
	}
}

func TestParseLevel(t *testing.T) {
	if lvl := parseLevel("debug"); lvl != -4 {
		t.Fatalf("expected debug level, got %v", lvl)
	}
	if lvl := parseLevel("warn"); lvl != 4 {
		t.Fatalf("expected warn level, got %v", lvl)
	}
	if lvl := parseLevel("error"); lvl != 8 {
		t.Fatalf("expected error level, got %v", lvl)
	}
	if lvl := parseLevel("unknown"); lvl != 0 {
		t.Fatalf("expected info level fallback, got %v", lvl)
	}
}
