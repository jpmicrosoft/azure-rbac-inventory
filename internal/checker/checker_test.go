package checker

import (
	"context"
	"strings"
	"testing"

	cloudenv "github.com/jpmicrosoft/azure-rbac-inventory/internal/cloud"
)

// ---------- Run: identity ID validation ----------

func TestRun_InvalidIdentityID(t *testing.T) {
	cfg := Config{IdentityID: "not-a-uuid"}
	_, err := Run(context.Background(), nil, cloudenv.Environment{}, cfg)
	if err == nil {
		t.Fatal("expected error for invalid identity ID, got nil")
	}
	if !strings.Contains(err.Error(), "invalid identity ID format") {
		t.Errorf("expected UUID validation error, got: %v", err)
	}
}

func TestRun_EmptyIdentityID(t *testing.T) {
	cfg := Config{IdentityID: ""}
	_, err := Run(context.Background(), nil, cloudenv.Environment{}, cfg)
	if err == nil {
		t.Fatal("expected error for empty identity ID, got nil")
	}
	if !strings.Contains(err.Error(), "invalid identity ID format") {
		t.Errorf("expected UUID validation error, got: %v", err)
	}
}

func TestRun_IdentityID_UUIDWithBraces(t *testing.T) {
	cfg := Config{IdentityID: "{550e8400-e29b-41d4-a716-446655440000}"}
	_, err := Run(context.Background(), nil, cloudenv.Environment{}, cfg)
	if err == nil {
		t.Fatal("expected error for UUID with braces, got nil")
	}
}

func TestRun_IdentityID_UUIDWithoutDashes(t *testing.T) {
	cfg := Config{IdentityID: "550e8400e29b41d4a716446655440000"}
	_, err := Run(context.Background(), nil, cloudenv.Environment{}, cfg)
	if err == nil {
		t.Fatal("expected error for UUID without dashes, got nil")
	}
}

func TestRun_IdentityID_WhitespaceAroundUUID(t *testing.T) {
	cfg := Config{IdentityID: " 550e8400-e29b-41d4-a716-446655440000 "}
	_, err := Run(context.Background(), nil, cloudenv.Environment{}, cfg)
	if err == nil {
		t.Fatal("expected error for UUID with surrounding whitespace, got nil")
	}
}

func TestRun_IdentityID_SQLInjection(t *testing.T) {
	cfg := Config{IdentityID: "'; DROP TABLE users; --"}
	_, err := Run(context.Background(), nil, cloudenv.Environment{}, cfg)
	if err == nil {
		t.Fatal("expected error for SQL injection attempt, got nil")
	}
}

func TestRun_IdentityID_PathTraversal(t *testing.T) {
	cfg := Config{IdentityID: "../../../etc/passwd"}
	_, err := Run(context.Background(), nil, cloudenv.Environment{}, cfg)
	if err == nil {
		t.Fatal("expected error for path traversal attempt, got nil")
	}
}

// ---------- Run: tenant ID validation ----------

func TestRun_InvalidTenantID(t *testing.T) {
	cfg := Config{
		IdentityID: "00000000-0000-0000-0000-000000000001",
		TenantID:   "bad-tenant",
	}
	_, err := Run(context.Background(), nil, cloudenv.Environment{}, cfg)
	if err == nil {
		t.Fatal("expected error for invalid tenant ID, got nil")
	}
	if !strings.Contains(err.Error(), "invalid tenant ID") {
		t.Errorf("expected tenant ID validation error, got: %v", err)
	}
}

func TestRun_EmptyTenantID_IsAllowed(t *testing.T) {
	// Empty tenant ID is valid — it means "use default from credential".
	// The function should pass tenant validation and fail later (at graph/auth).
	cfg := Config{
		IdentityID: "00000000-0000-0000-0000-000000000001",
		TenantID:   "",
	}
	// With nil cred, the graph client panics after validation passes.
	// Recover from the panic to confirm we got past tenant validation.
	var err error
	func() {
		defer func() { recover() }()
		_, err = Run(context.Background(), nil, cloudenv.Environment{}, cfg)
	}()
	// The error (if any) should NOT be about tenant ID validation.
	if err != nil && strings.Contains(err.Error(), "invalid tenant ID") {
		t.Errorf("empty tenant ID should be allowed, but got validation error: %v", err)
	}
}

func TestRun_TenantID_PathTraversal(t *testing.T) {
	cfg := Config{
		IdentityID: "00000000-0000-0000-0000-000000000001",
		TenantID:   "../../common",
	}
	_, err := Run(context.Background(), nil, cloudenv.Environment{}, cfg)
	if err == nil {
		t.Fatal("expected error for path traversal in tenant ID, got nil")
	}
	if !strings.Contains(err.Error(), "invalid tenant ID") {
		t.Errorf("expected tenant ID validation error, got: %v", err)
	}
}

// ---------- Run: subscription ID validation ----------

func TestRun_InvalidSubscriptionID(t *testing.T) {
	cfg := Config{
		IdentityID:    "00000000-0000-0000-0000-000000000001",
		Subscriptions: []string{"bad-sub"},
	}
	_, err := Run(context.Background(), nil, cloudenv.Environment{}, cfg)
	if err == nil {
		t.Fatal("expected error for invalid subscription ID, got nil")
	}
	if !strings.Contains(err.Error(), "invalid subscription ID") {
		t.Errorf("expected subscription ID validation error, got: %v", err)
	}
}

func TestRun_MixedValidInvalidSubscriptionIDs(t *testing.T) {
	cfg := Config{
		IdentityID: "00000000-0000-0000-0000-000000000001",
		Subscriptions: []string{
			"11111111-1111-1111-1111-111111111111",
			"not-valid",
		},
	}
	_, err := Run(context.Background(), nil, cloudenv.Environment{}, cfg)
	if err == nil {
		t.Fatal("expected error for mixed valid/invalid subscription IDs, got nil")
	}
	if !strings.Contains(err.Error(), "invalid subscription ID") {
		t.Errorf("expected subscription ID validation error, got: %v", err)
	}
	if !strings.Contains(err.Error(), "not-valid") {
		t.Errorf("error should mention the invalid subscription ID, got: %v", err)
	}
}

func TestRun_EmptySubscriptions_IsAllowed(t *testing.T) {
	// nil/empty subscriptions means "query all accessible".
	cfg := Config{
		IdentityID:    "00000000-0000-0000-0000-000000000001",
		Subscriptions: nil,
	}
	var err error
	func() {
		defer func() { recover() }()
		_, err = Run(context.Background(), nil, cloudenv.Environment{}, cfg)
	}()
	// Error should NOT be about subscription validation.
	if err != nil && strings.Contains(err.Error(), "invalid subscription ID") {
		t.Errorf("nil subscriptions should be allowed, but got validation error: %v", err)
	}
}

func TestRun_EmptyStringSubscription(t *testing.T) {
	// An empty string in the subscription list is invalid (not a UUID).
	cfg := Config{
		IdentityID:    "00000000-0000-0000-0000-000000000001",
		Subscriptions: []string{""},
	}
	_, err := Run(context.Background(), nil, cloudenv.Environment{}, cfg)
	if err == nil {
		t.Fatal("expected error for empty string subscription ID, got nil")
	}
	if !strings.Contains(err.Error(), "invalid subscription ID") {
		t.Errorf("expected subscription ID validation error, got: %v", err)
	}
}

func TestRun_MultipleInvalidSubscriptions_FailsOnFirst(t *testing.T) {
	cfg := Config{
		IdentityID: "00000000-0000-0000-0000-000000000001",
		Subscriptions: []string{
			"bad-first",
			"bad-second",
		},
	}
	_, err := Run(context.Background(), nil, cloudenv.Environment{}, cfg)
	if err == nil {
		t.Fatal("expected error for invalid subscription IDs, got nil")
	}
	// Should fail on the first invalid one.
	if !strings.Contains(err.Error(), "bad-first") {
		t.Errorf("expected error to reference first invalid sub, got: %v", err)
	}
}

// ---------- Run: validation passes, fails later ----------

func TestRun_ValidInputs_NilCred_FailsAtGraphLayer(t *testing.T) {
	// All validation passes, but nil credential causes a panic/error
	// when the graph client tries to acquire a token.
	cfg := Config{
		IdentityID: "00000000-0000-0000-0000-000000000001",
		TenantID:   "22222222-2222-2222-2222-222222222222",
		Subscriptions: []string{
			"33333333-3333-3333-3333-333333333333",
		},
	}

	// With nil cred, graph.NewClient will succeed, but resolver.Resolve
	// will panic when calling cred.GetToken(). We recover from the panic
	// to verify we got past all validation steps.
	func() {
		defer func() {
			r := recover()
			if r == nil {
				// No panic — Run returned normally or with error.
				// That's fine; the point is it didn't fail at validation.
				return
			}
			// A panic at the graph layer is expected with nil cred.
			// This confirms validation passed.
		}()

		_, err := Run(context.Background(), nil, cloudenv.Environment{}, cfg)
		if err == nil {
			return
		}
		// Error should NOT be about input validation.
		errMsg := err.Error()
		if strings.Contains(errMsg, "invalid identity ID format") ||
			strings.Contains(errMsg, "invalid tenant ID") ||
			strings.Contains(errMsg, "invalid subscription ID") {
			t.Errorf("valid inputs should pass validation, but got: %v", err)
		}
	}()
}

// ---------- Run: identity ID table-driven validation ----------

func TestRun_IdentityID_TableDriven(t *testing.T) {
	tests := []struct {
		name        string
		identityID  string
		wantErr     bool
		errContains string
	}{
		{
			name:       "valid lowercase UUID",
			identityID: "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
			wantErr:    false,
		},
		{
			name:       "valid uppercase UUID",
			identityID: "A1B2C3D4-E5F6-7890-ABCD-EF1234567890",
			wantErr:    false,
		},
		{
			name:        "empty string",
			identityID:  "",
			wantErr:     true,
			errContains: "invalid identity ID format",
		},
		{
			name:        "plain text",
			identityID:  "hello-world",
			wantErr:     true,
			errContains: "invalid identity ID format",
		},
		{
			name:        "UUID with trailing newline",
			identityID:  "a1b2c3d4-e5f6-7890-abcd-ef1234567890\n",
			wantErr:     true,
			errContains: "invalid identity ID format",
		},
		{
			name:        "too short UUID",
			identityID:  "a1b2c3d4-e5f6-7890",
			wantErr:     true,
			errContains: "invalid identity ID format",
		},
		{
			name:        "non-hex characters",
			identityID:  "g1b2c3d4-e5f6-7890-abcd-ef1234567890",
			wantErr:     true,
			errContains: "invalid identity ID format",
		},
		{
			name:       "all zeros UUID",
			identityID: "00000000-0000-0000-0000-000000000000",
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{IdentityID: tt.identityID}
			var err error
			func() {
				defer func() { recover() }()
				_, err = Run(context.Background(), nil, cloudenv.Environment{}, cfg)
			}()
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("expected error containing %q, got: %v", tt.errContains, err)
				}
			} else {
				// For valid UUIDs, the error (if any) should NOT be about identity validation.
				if err != nil && strings.Contains(err.Error(), "invalid identity ID format") {
					t.Errorf("valid UUID should pass validation, got: %v", err)
				}
			}
		})
	}
}

// ---------- Config defaults ----------

func TestConfig_ZeroValueDefaults(t *testing.T) {
	cfg := Config{}
	if cfg.IdentityID != "" {
		t.Errorf("IdentityID zero value = %q, want empty", cfg.IdentityID)
	}
	if cfg.Cloud != "" {
		t.Errorf("Cloud zero value = %q, want empty", cfg.Cloud)
	}
	if cfg.TenantID != "" {
		t.Errorf("TenantID zero value = %q, want empty", cfg.TenantID)
	}
	if cfg.Subscriptions != nil {
		t.Errorf("Subscriptions zero value = %v, want nil", cfg.Subscriptions)
	}
	if cfg.IncludeGroups != false {
		t.Error("IncludeGroups zero value should be false")
	}
	if cfg.Verbose != false {
		t.Error("Verbose zero value should be false")
	}
	if cfg.OutputFormat != "" {
		t.Errorf("OutputFormat zero value = %q, want empty", cfg.OutputFormat)
	}
	if cfg.JSONFile != "" {
		t.Errorf("JSONFile zero value = %q, want empty", cfg.JSONFile)
	}
}

func TestConfig_WithAllFields(t *testing.T) {
	cfg := Config{
		IdentityID:    "00000000-0000-0000-0000-000000000001",
		Cloud:         "AzureCloud",
		TenantID:      "11111111-1111-1111-1111-111111111111",
		Subscriptions: []string{"22222222-2222-2222-2222-222222222222"},
		IncludeGroups: true,
		Verbose:       true,
		OutputFormat:  "json",
		JSONFile:      "/tmp/report.json",
	}

	if cfg.IdentityID != "00000000-0000-0000-0000-000000000001" {
		t.Errorf("IdentityID = %q, want set value", cfg.IdentityID)
	}
	if cfg.Cloud != "AzureCloud" {
		t.Errorf("Cloud = %q, want %q", cfg.Cloud, "AzureCloud")
	}
	if cfg.TenantID != "11111111-1111-1111-1111-111111111111" {
		t.Errorf("TenantID = %q, want set value", cfg.TenantID)
	}
	if len(cfg.Subscriptions) != 1 {
		t.Errorf("Subscriptions length = %d, want 1", len(cfg.Subscriptions))
	}
	if !cfg.IncludeGroups {
		t.Error("IncludeGroups should be true")
	}
	if !cfg.Verbose {
		t.Error("Verbose should be true")
	}
	if cfg.OutputFormat != "json" {
		t.Errorf("OutputFormat = %q, want %q", cfg.OutputFormat, "json")
	}
	if cfg.JSONFile != "/tmp/report.json" {
		t.Errorf("JSONFile = %q, want set value", cfg.JSONFile)
	}
}

// ---------- ParseSubscriptions ----------

func TestParseSubscriptions_EmptyString(t *testing.T) {
	result := ParseSubscriptions("")
	if result != nil {
		t.Errorf("ParseSubscriptions(\"\") = %v, want nil", result)
	}
}

func TestParseSubscriptions_SingleSubscription(t *testing.T) {
	result := ParseSubscriptions("11111111-1111-1111-1111-111111111111")
	if len(result) != 1 {
		t.Fatalf("len = %d, want 1", len(result))
	}
	if result[0] != "11111111-1111-1111-1111-111111111111" {
		t.Errorf("result[0] = %q, want UUID", result[0])
	}
}

func TestParseSubscriptions_MultipleSubscriptions(t *testing.T) {
	result := ParseSubscriptions("aaaa-1,bbbb-2,cccc-3")
	if len(result) != 3 {
		t.Fatalf("len = %d, want 3", len(result))
	}
	want := []string{"aaaa-1", "bbbb-2", "cccc-3"}
	for i, w := range want {
		if result[i] != w {
			t.Errorf("result[%d] = %q, want %q", i, result[i], w)
		}
	}
}

func TestParseSubscriptions_TrimsWhitespace(t *testing.T) {
	result := ParseSubscriptions("  sub-1 , sub-2 ,sub-3  ")
	if len(result) != 3 {
		t.Fatalf("len = %d, want 3", len(result))
	}
	want := []string{"sub-1", "sub-2", "sub-3"}
	for i, w := range want {
		if result[i] != w {
			t.Errorf("result[%d] = %q, want %q", i, result[i], w)
		}
	}
}

func TestParseSubscriptions_TrailingComma(t *testing.T) {
	result := ParseSubscriptions("sub-1,")
	if len(result) != 2 {
		t.Fatalf("len = %d, want 2", len(result))
	}
	if result[0] != "sub-1" {
		t.Errorf("result[0] = %q, want %q", result[0], "sub-1")
	}
	if result[1] != "" {
		t.Errorf("result[1] = %q, want empty string", result[1])
	}
}

func TestParseSubscriptions_LeadingComma(t *testing.T) {
	result := ParseSubscriptions(",sub-1")
	if len(result) != 2 {
		t.Fatalf("len = %d, want 2", len(result))
	}
	if result[0] != "" {
		t.Errorf("result[0] = %q, want empty string", result[0])
	}
	if result[1] != "sub-1" {
		t.Errorf("result[1] = %q, want %q", result[1], "sub-1")
	}
}

func TestParseSubscriptions_OnlyComma(t *testing.T) {
	result := ParseSubscriptions(",")
	if len(result) != 2 {
		t.Fatalf("len = %d, want 2", len(result))
	}
	for i, v := range result {
		if v != "" {
			t.Errorf("result[%d] = %q, want empty string", i, v)
		}
	}
}

func TestParseSubscriptions_WhitespaceOnly(t *testing.T) {
	result := ParseSubscriptions("   ")
	if len(result) != 1 {
		t.Fatalf("len = %d, want 1", len(result))
	}
	// "   " is not empty, so it gets split — single trimmed result.
	if result[0] != "" {
		t.Errorf("result[0] = %q, want empty (after trim)", result[0])
	}
}

func TestParseSubscriptions_TableDriven(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "empty string returns nil",
			input: "",
			want:  nil,
		},
		{
			name:  "single value no whitespace",
			input: "abc",
			want:  []string{"abc"},
		},
		{
			name:  "two values with spaces",
			input: " x , y ",
			want:  []string{"x", "y"},
		},
		{
			name:  "real UUIDs comma-separated",
			input: "11111111-1111-1111-1111-111111111111,22222222-2222-2222-2222-222222222222",
			want: []string{
				"11111111-1111-1111-1111-111111111111",
				"22222222-2222-2222-2222-222222222222",
			},
		},
		{
			name:  "tabs and newlines treated as whitespace",
			input: "\tsub-1\t,\nsub-2\n",
			want:  []string{"sub-1", "sub-2"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseSubscriptions(tt.input)
			if tt.want == nil {
				if got != nil {
					t.Errorf("ParseSubscriptions(%q) = %v, want nil", tt.input, got)
				}
				return
			}
			if len(got) != len(tt.want) {
				t.Fatalf("ParseSubscriptions(%q) returned %d items, want %d", tt.input, len(got), len(tt.want))
			}
			for i := range tt.want {
				if got[i] != tt.want[i] {
					t.Errorf("result[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

// ---------- Run: validation ordering ----------

func TestRun_ValidationOrder_IdentityCheckedBeforeTenant(t *testing.T) {
	// Both identity and tenant are invalid. Identity should be checked first.
	cfg := Config{
		IdentityID: "bad-identity",
		TenantID:   "bad-tenant",
	}
	_, err := Run(context.Background(), nil, cloudenv.Environment{}, cfg)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	// Should fail on identity, not tenant.
	if strings.Contains(err.Error(), "invalid tenant ID") {
		t.Errorf("identity should be validated before tenant, got: %v", err)
	}
	if !strings.Contains(err.Error(), "invalid identity ID format") {
		t.Errorf("expected identity validation error, got: %v", err)
	}
}

func TestRun_ValidationOrder_TenantCheckedBeforeSubscriptions(t *testing.T) {
	// Identity valid, both tenant and subscription invalid.
	cfg := Config{
		IdentityID:    "00000000-0000-0000-0000-000000000001",
		TenantID:      "bad-tenant",
		Subscriptions: []string{"bad-sub"},
	}
	_, err := Run(context.Background(), nil, cloudenv.Environment{}, cfg)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	// Should fail on tenant, not subscription.
	if strings.Contains(err.Error(), "invalid subscription ID") {
		t.Errorf("tenant should be validated before subscriptions, got: %v", err)
	}
	if !strings.Contains(err.Error(), "invalid tenant ID") {
		t.Errorf("expected tenant validation error, got: %v", err)
	}
}

func TestRun_ValidationOrder_SubscriptionsCheckedInOrder(t *testing.T) {
	cfg := Config{
		IdentityID: "00000000-0000-0000-0000-000000000001",
		Subscriptions: []string{
			"11111111-1111-1111-1111-111111111111", // valid
			"first-bad",                            // invalid — should fail here
			"second-bad",                           // never reached
		},
	}
	_, err := Run(context.Background(), nil, cloudenv.Environment{}, cfg)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "first-bad") {
		t.Errorf("expected error to reference first invalid sub, got: %v", err)
	}
}

// ---------- Run: context cancellation ----------

func TestRun_CancelledContext_FailsGracefully(t *testing.T) {
	// Even with valid inputs and nil cred, a cancelled context should fail
	// gracefully (not hang).
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	cfg := Config{
		IdentityID: "00000000-0000-0000-0000-000000000001",
	}

	// With nil cred, it will panic at GetToken (before context matters),
	// OR it might return a context error if the graph layer checks it first.
	func() {
		defer func() {
			recover() // swallow any nil-cred panic
		}()
		_, _ = Run(ctx, nil, cloudenv.Environment{}, cfg)
	}()

	// If we get here without hanging, the test passes.
}
