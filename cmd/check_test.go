package cmd

import (
	"testing"
)

func TestPerIdentityFilename_Basic(t *testing.T) {
	got := perIdentityFilename("report.csv", "Test User", 0)
	want := "report-000-Test-User.csv"
	if got != want {
		t.Errorf("perIdentityFilename basic: got %q, want %q", got, want)
	}
}

func TestPerIdentityFilename_IndexPreventsCollision(t *testing.T) {
	a := perIdentityFilename("report.csv", "Same Name", 0)
	b := perIdentityFilename("report.csv", "Same Name", 1)
	if a == b {
		t.Errorf("two identities with same display name should produce different filenames, both got %q", a)
	}
}

func TestPerIdentityFilename_SpecialCharsSanitized(t *testing.T) {
	got := perIdentityFilename("out.json", "user@domain.com (SPN)", 2)
	// @ . ( ) and space should all become -
	if got != "out-002-user-domain-com--SPN-.json" {
		t.Errorf("special chars not sanitized correctly: got %q", got)
	}
}

func TestPerIdentityFilename_LongNameTruncated(t *testing.T) {
	longName := ""
	for i := 0; i < 100; i++ {
		longName += "a"
	}
	got := perIdentityFilename("base.html", longName, 5)
	// safeName should be truncated to 80 chars
	expected := "base-005-" + longName[:80] + ".html"
	if got != expected {
		t.Errorf("long name not truncated: got %q (len=%d), want %q", got, len(got), expected)
	}
}

func TestPerIdentityFilename_NoExtension(t *testing.T) {
	got := perIdentityFilename("output", "TestUser", 0)
	want := "output-000-TestUser"
	if got != want {
		t.Errorf("no extension: got %q, want %q", got, want)
	}
}

func TestPerIdentityFilename_IndexFormatting(t *testing.T) {
	tests := []struct {
		index int
		want  string
	}{
		{0, "r-000-u.csv"},
		{1, "r-001-u.csv"},
		{10, "r-010-u.csv"},
		{999, "r-999-u.csv"},
	}
	for _, tt := range tests {
		got := perIdentityFilename("r.csv", "u", tt.index)
		if got != tt.want {
			t.Errorf("index %d: got %q, want %q", tt.index, got, tt.want)
		}
	}
}
