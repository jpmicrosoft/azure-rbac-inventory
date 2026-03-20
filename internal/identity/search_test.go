package identity

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// IsPattern tests
// ---------------------------------------------------------------------------

func TestIsPattern(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"UUID returns false", "550e8400-e29b-41d4-a716-446655440000", false},
		{"wildcard suffix returns true", "spn-*", true},
		{"plain name returns true (not UUID)", "myapp", true},
		{"empty returns true (not UUID)", "", true},
		{"UUID with wildcard returns true", "550e8400-*", true},
		{"question mark returns true", "my?app", true},
		{"uppercase UUID returns false", "550E8400-E29B-41D4-A716-446655440000", false},
		{"all zeros UUID returns false", "00000000-0000-0000-0000-000000000000", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsPattern(tt.input)
			if got != tt.want {
				t.Errorf("IsPattern(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// ParsePattern tests
// ---------------------------------------------------------------------------

func TestParsePattern(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		wantTerm     string
		wantPrefix   bool
		wantContains bool
		wantExact    bool
	}{
		{
			name:       "prefix pattern",
			input:      "prefix*",
			wantTerm:   "prefix",
			wantPrefix: true,
		},
		{
			name:         "suffix pattern becomes contains",
			input:        "*suffix",
			wantTerm:     "suffix",
			wantContains: true,
		},
		{
			name:         "contains pattern",
			input:        "*mid*",
			wantTerm:     "mid",
			wantContains: true,
		},
		{
			name:      "exact name (no wildcards)",
			input:     "exact",
			wantTerm:  "exact",
			wantExact: true,
		},
		{
			name:  "empty input returns all false",
			input: "",
		},
		{
			name:       "question mark in prefix stripped",
			input:      "app?name*",
			wantTerm:   "appname",
			wantPrefix: true,
		},
		{
			name:         "multiple wildcards with text",
			input:        "*foo*bar*",
			wantTerm:     "foo bar",
			wantContains: true,
		},
		{
			name:       "double trailing wildcard",
			input:      "test**",
			wantTerm:   "test",
			wantPrefix: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			term, isPrefix, isContains, isExact := ParsePattern(tt.input)
			if term != tt.wantTerm {
				t.Errorf("ParsePattern(%q) term = %q, want %q", tt.input, term, tt.wantTerm)
			}
			if isPrefix != tt.wantPrefix {
				t.Errorf("ParsePattern(%q) isPrefix = %v, want %v", tt.input, isPrefix, tt.wantPrefix)
			}
			if isContains != tt.wantContains {
				t.Errorf("ParsePattern(%q) isContains = %v, want %v", tt.input, isContains, tt.wantContains)
			}
			if isExact != tt.wantExact {
				t.Errorf("ParsePattern(%q) isExact = %v, want %v", tt.input, isExact, tt.wantExact)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// escapeOData tests
// ---------------------------------------------------------------------------

func TestEscapeOData(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"no quotes", "no quotes"},
		{"O'Brien", "O''Brien"},
		{"it's a test's data", "it''s a test''s data"},
		{"", ""},
	}
	for _, tt := range tests {
		got := escapeOData(tt.input)
		if got != tt.want {
			t.Errorf("escapeOData(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// Search tests — using the mockGraphRequester from resolver_test.go
// ---------------------------------------------------------------------------

func TestSearch_ServicePrincipals(t *testing.T) {
	mock := &mockGraphRequester{
		doRequestFunc: func(ctx context.Context, path string, query url.Values) ([]byte, error) {
			if strings.Contains(path, "/servicePrincipals") {
				return []byte(`{
					"value": [
						{
							"@odata.type": "#microsoft.graph.servicePrincipal",
							"id": "spn-1",
							"displayName": "My Test SPN",
							"appId": "app-123",
							"servicePrincipalType": "Application"
						}
					]
				}`), nil
			}
			return nil, fmt.Errorf("unexpected path: %s", path)
		},
	}

	resolver := NewResolver(mock)
	results, err := resolver.Search(context.Background(), "My Test*", "spn", 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	r := results[0]
	if r.Identity.DisplayName != "My Test SPN" {
		t.Errorf("DisplayName = %q, want %q", r.Identity.DisplayName, "My Test SPN")
	}
	if r.Source != "servicePrincipal" {
		t.Errorf("Source = %q, want %q", r.Source, "servicePrincipal")
	}
	if r.Identity.Type != TypeServicePrincipal {
		t.Errorf("Type = %q, want %q", r.Identity.Type, TypeServicePrincipal)
	}
	if r.Identity.AppID != "app-123" {
		t.Errorf("AppID = %q, want %q", r.Identity.AppID, "app-123")
	}
}

func TestSearch_TypeFiltering(t *testing.T) {
	tests := []struct {
		name          string
		identityType  string
		expectedPaths []string
	}{
		{"spn only searches servicePrincipals", "spn", []string{"/servicePrincipals"}},
		{"user only searches users", "user", []string{"/users"}},
		{"group only searches groups", "group", []string{"/groups"}},
		{"app only searches applications", "app", []string{"/applications"}},
		{"all searches all four endpoints", "all",
			[]string{"/servicePrincipals", "/users", "/groups", "/applications"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var calledPaths []string
			mock := &mockGraphRequester{
				doRequestFunc: func(ctx context.Context, path string, query url.Values) ([]byte, error) {
					calledPaths = append(calledPaths, path)
					return []byte(`{"value": []}`), nil
				},
			}

			resolver := NewResolver(mock)
			_, err := resolver.Search(context.Background(), "testname", tt.identityType, 10)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if len(calledPaths) != len(tt.expectedPaths) {
				t.Fatalf("expected %d API calls, got %d: %v",
					len(tt.expectedPaths), len(calledPaths), calledPaths)
			}

			for _, expected := range tt.expectedPaths {
				found := false
				for _, called := range calledPaths {
					if strings.Contains(called, expected) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected path containing %q to be called, got: %v",
						expected, calledPaths)
				}
			}
		})
	}
}

func TestSearch_UnsupportedType(t *testing.T) {
	mock := &mockGraphRequester{}
	resolver := NewResolver(mock)
	_, err := resolver.Search(context.Background(), "test", "bogus", 10)
	if err == nil {
		t.Fatal("expected error for unsupported identity type, got nil")
	}
	if !strings.Contains(err.Error(), "unsupported identity type") {
		t.Errorf("error = %v, want it to mention unsupported identity type", err)
	}
}

func TestSearch_EmptyPattern(t *testing.T) {
	mock := &mockGraphRequester{}
	resolver := NewResolver(mock)
	_, err := resolver.Search(context.Background(), "", "spn", 10)
	if err == nil {
		t.Fatal("expected error for empty pattern, got nil")
	}
}

func TestSearch_MaxResults(t *testing.T) {
	mock := &mockGraphRequester{
		doRequestFunc: func(ctx context.Context, path string, query url.Values) ([]byte, error) {
			return []byte(`{
				"value": [
					{"id": "1", "displayName": "Alpha"},
					{"id": "2", "displayName": "Bravo"},
					{"id": "3", "displayName": "Charlie"},
					{"id": "4", "displayName": "Delta"},
					{"id": "5", "displayName": "Echo"}
				]
			}`), nil
		},
	}

	resolver := NewResolver(mock)
	results, err := resolver.Search(context.Background(), "test*", "spn", 3)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 3 {
		t.Errorf("expected max 3 results, got %d", len(results))
	}
}

func TestSearch_Deduplication(t *testing.T) {
	mock := &mockGraphRequester{
		doRequestFunc: func(ctx context.Context, path string, query url.Values) ([]byte, error) {
			// Every endpoint returns the same identity.
			return []byte(`{
				"value": [
					{"id": "duplicate-id", "displayName": "Shared Name"}
				]
			}`), nil
		},
	}

	resolver := NewResolver(mock)
	results, err := resolver.Search(context.Background(), "Shared", "all", 100)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Errorf("expected 1 deduplicated result, got %d", len(results))
	}
}

func TestSearch_EmptyResults(t *testing.T) {
	mock := &mockGraphRequester{
		doRequestFunc: func(ctx context.Context, path string, query url.Values) ([]byte, error) {
			return []byte(`{"value": []}`), nil
		},
	}

	resolver := NewResolver(mock)
	results, err := resolver.Search(context.Background(), "nonexistent", "spn", 10)
	if err != nil {
		t.Fatalf("expected no error for empty results, got: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("expected 0 results, got %d", len(results))
	}
}

func TestSearch_ODataEscaping(t *testing.T) {
	var capturedQuery url.Values
	mock := &mockGraphRequester{
		doRequestFunc: func(ctx context.Context, path string, query url.Values) ([]byte, error) {
			capturedQuery = query
			return []byte(`{"value": []}`), nil
		},
	}

	resolver := NewResolver(mock)
	// "O'Brien" is an exact match (no wildcards) → uses $filter with eq
	_, err := resolver.Search(context.Background(), "O'Brien", "spn", 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	filter := capturedQuery.Get("$filter")
	if !strings.Contains(filter, "O''Brien") {
		t.Errorf("expected escaped single quote in filter, got: %s", filter)
	}
}

func TestSearch_ContainsPattern_UsesHeaders(t *testing.T) {
	var capturedHeaders map[string]string
	mock := &mockGraphRequester{
		doRequestWithHeadersFunc: func(ctx context.Context, path string, query url.Values, headers map[string]string) ([]byte, error) {
			capturedHeaders = headers
			return []byte(`{"value": []}`), nil
		},
	}

	resolver := NewResolver(mock)
	// "*test*" is a contains pattern → uses $search + ConsistencyLevel header
	_, err := resolver.Search(context.Background(), "*test*", "spn", 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if capturedHeaders == nil {
		t.Fatal("expected DoRequestWithHeaders to be called for contains pattern")
	}
	if capturedHeaders["ConsistencyLevel"] != "eventual" {
		t.Errorf("ConsistencyLevel = %q, want %q",
			capturedHeaders["ConsistencyLevel"], "eventual")
	}
}

func TestSearch_ResultsSortedByDisplayName(t *testing.T) {
	mock := &mockGraphRequester{
		doRequestFunc: func(ctx context.Context, path string, query url.Values) ([]byte, error) {
			return []byte(`{
				"value": [
					{"id": "3", "displayName": "Zulu"},
					{"id": "1", "displayName": "Alpha"},
					{"id": "2", "displayName": "Mike"}
				]
			}`), nil
		},
	}

	resolver := NewResolver(mock)
	results, err := resolver.Search(context.Background(), "test*", "spn", 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}
	if results[0].Identity.DisplayName != "Alpha" {
		t.Errorf("first result = %q, want %q", results[0].Identity.DisplayName, "Alpha")
	}
	if results[1].Identity.DisplayName != "Mike" {
		t.Errorf("second result = %q, want %q", results[1].Identity.DisplayName, "Mike")
	}
	if results[2].Identity.DisplayName != "Zulu" {
		t.Errorf("third result = %q, want %q", results[2].Identity.DisplayName, "Zulu")
	}
}
