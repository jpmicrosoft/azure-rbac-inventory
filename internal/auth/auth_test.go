package auth

import (
	"strings"
	"testing"

	cloudenv "github.com/jpmicrosoft/azure-rbac-inventory/internal/cloud"
)

func TestGetCredential_InvalidMethod(t *testing.T) {
	env, _ := cloudenv.GetEnvironment("AzureCloud")
	_, err := GetCredential(env, "", "bogus")
	if err == nil {
		t.Fatal("expected error for invalid auth method, got nil")
	}
	if !strings.Contains(err.Error(), "unknown auth method") {
		t.Errorf("error should mention unknown auth method, got: %v", err)
	}
	if !strings.Contains(err.Error(), "interactive") {
		t.Errorf("error should list valid methods, got: %v", err)
	}
}

func TestGetCredential_ValidMethods(t *testing.T) {
	env, _ := cloudenv.GetEnvironment("AzureCloud")

	// These should not return an error (credential creation succeeds even
	// without Azure connectivity — authentication happens at GetToken time).
	// Note: "environment" requires env vars to be set, so it's tested separately.
	for _, method := range []string{"interactive", "device-code", "managed-identity", "azurecli", ""} {
		cred, err := GetCredential(env, "", method)
		if err != nil {
			t.Errorf("GetCredential(%q) returned unexpected error: %v", method, err)
		}
		if cred == nil {
			t.Errorf("GetCredential(%q) returned nil credential", method)
		}
	}
}

func TestGetCredential_Environment(t *testing.T) {
	// NewEnvironmentCredential requires AZURE_CLIENT_ID + AZURE_TENANT_ID + a secret.
	// When env vars are missing, it returns an error — verify we get a clear error.
	env, _ := cloudenv.GetEnvironment("AzureCloud")
	_, err := GetCredential(env, "", "environment")
	if err == nil {
		// If it succeeds, env vars were already set — that's fine too
		return
	}
	// Error should mention missing environment variables
	if !strings.Contains(err.Error(), "environment") && !strings.Contains(err.Error(), "AZURE_") {
		t.Errorf("expected error about missing env vars, got: %v", err)
	}
}

func TestGetCredential_WithTenantID(t *testing.T) {
	env, _ := cloudenv.GetEnvironment("AzureCloud")
	cred, err := GetCredential(env, "00000000-0000-0000-0000-000000000001", "interactive")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cred == nil {
		t.Fatal("expected non-nil credential")
	}
}

func TestGetCredential_AzureCLIWithTenant(t *testing.T) {
	env, _ := cloudenv.GetEnvironment("AzureCloud")
	cred, err := GetCredential(env, "00000000-0000-0000-0000-000000000001", "azurecli")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cred == nil {
		t.Fatal("expected non-nil credential")
	}
}

func TestValidAuthMethods_Contents(t *testing.T) {
	expected := map[string]bool{
		"interactive":      false,
		"device-code":      false,
		"environment":      false,
		"managed-identity": false,
		"azurecli":         false,
	}
	for _, m := range ValidAuthMethods {
		if _, ok := expected[m]; !ok {
			t.Errorf("unexpected auth method in ValidAuthMethods: %q", m)
		}
		expected[m] = true
	}
	for method, found := range expected {
		if !found {
			t.Errorf("missing expected auth method %q in ValidAuthMethods", method)
		}
	}
}

func TestIsNonInteractive(t *testing.T) {
	tests := []struct {
		method string
		want   bool
	}{
		{"interactive", false},
		{"device-code", false},
		{"", false},
		{"environment", true},
		{"managed-identity", true},
		{"azurecli", true},
	}
	for _, tt := range tests {
		got := IsNonInteractive(tt.method)
		if got != tt.want {
			t.Errorf("IsNonInteractive(%q) = %v, want %v", tt.method, got, tt.want)
		}
	}
}

func TestNeedsPreAuth(t *testing.T) {
	tests := []struct {
		method string
		want   bool
	}{
		{"interactive", true},
		{"device-code", true},
		{"", true},
		{"azurecli", true},
		{"environment", false},
		{"managed-identity", false},
	}
	for _, tt := range tests {
		got := NeedsPreAuth(tt.method)
		if got != tt.want {
			t.Errorf("NeedsPreAuth(%q) = %v, want %v", tt.method, got, tt.want)
		}
	}
}
