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
	// without Azure connectivity — authentication happens at GetToken time)
	for _, method := range []string{"interactive", "device-code", ""} {
		cred, err := GetCredential(env, "", method)
		if err != nil {
			t.Errorf("GetCredential(%q) returned unexpected error: %v", method, err)
		}
		if cred == nil {
			t.Errorf("GetCredential(%q) returned nil credential", method)
		}
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

func TestValidAuthMethods_Contents(t *testing.T) {
	expected := map[string]bool{
		"interactive": false,
		"device-code": false,
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
