package rbac

import (
	"testing"

	cloudenv "github.com/jpmicrosoft/azure-rbac-inventory/internal/cloud"
)

func TestClassifyScope(t *testing.T) {
	tests := []struct {
		name  string
		scope string
		want  string
	}{
		{
			name:  "subscription scope",
			scope: "/subscriptions/abc-123",
			want:  "Subscription",
		},
		{
			name:  "resource group scope",
			scope: "/subscriptions/abc/resourceGroups/myRG",
			want:  "Resource Group",
		},
		{
			name:  "resource scope with provider",
			scope: "/subscriptions/abc/resourceGroups/myRG/providers/Microsoft.Compute/virtualMachines/vm1",
			want:  "Resource",
		},
		{
			name:  "management group scope",
			scope: "/managementGroups/myMG",
			want:  "Management Group",
		},
		{
			name:  "root scope",
			scope: "/",
			want:  "Other",
		},
		{
			name:  "empty string",
			scope: "",
			want:  "Other",
		},
		{
			name:  "nested resource scope",
			scope: "/subscriptions/abc/resourceGroups/myRG/providers/Microsoft.Network/virtualNetworks/vnet1/subnets/subnet1",
			want:  "Resource",
		},
		{
			name:  "subscription with trailing slash",
			scope: "/subscriptions/abc-123/",
			want:  "Subscription",
		},
		{
			name:  "management group with long name",
			scope: "/managementGroups/my-long-management-group-name-123",
			want:  "Management Group",
		},
		{
			name:  "resource group with trailing slash (trailing slash stripped)",
			scope: "/subscriptions/abc/resourceGroups/myRG/",
			want:  "Resource Group",
		},
		{
			name:  "case-sensitive managementGroups",
			scope: "/MANAGEMENTGROUPS/myMG",
			want:  "Other",
		},
		{
			name:  "management group inside subscription path",
			scope: "/subscriptions/abc/managementGroups/mg1",
			want:  "Management Group",
		},
		{
			name:  "single slash",
			scope: "/",
			want:  "Other",
		},
		{
			name:  "deeply nested resource",
			scope: "/subscriptions/abc/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet/subnets/sub/ipConfigurations/ip",
			want:  "Resource",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyScope(tt.scope)
			if got != tt.want {
				t.Errorf("classifyScope(%q) = %q, want %q", tt.scope, got, tt.want)
			}
		})
	}
}

func TestSafeDeref(t *testing.T) {
	t.Run("nil pointer returns empty string", func(t *testing.T) {
		got := safeDeref(nil)
		if got != "" {
			t.Errorf("safeDeref(nil) = %q, want %q", got, "")
		}
	})

	t.Run("non-nil pointer returns value", func(t *testing.T) {
		val := "hello"
		got := safeDeref(&val)
		if got != "hello" {
			t.Errorf("safeDeref(&%q) = %q, want %q", val, got, "hello")
		}
	})

	t.Run("empty string pointer returns empty string", func(t *testing.T) {
		val := ""
		got := safeDeref(&val)
		if got != "" {
			t.Errorf("safeDeref(&%q) = %q, want %q", val, got, "")
		}
	})

	t.Run("string with spaces", func(t *testing.T) {
		val := "  spaces  "
		got := safeDeref(&val)
		if got != "  spaces  " {
			t.Errorf("safeDeref(&%q) = %q, want %q", val, got, "  spaces  ")
		}
	})
}

func TestNewChecker(t *testing.T) {
	env := cloudenv.Environment{Name: "AzureCloud"}
	checker := NewChecker(nil, env)
	if checker == nil {
		t.Fatal("NewChecker returned nil")
	}
}

func TestMaxConcurrentSubscriptions(t *testing.T) {
	// Verify the concurrency limit constant has a sane value.
	if maxConcurrentSubscriptions <= 0 {
		t.Errorf("maxConcurrentSubscriptions = %d, want > 0", maxConcurrentSubscriptions)
	}
	if maxConcurrentSubscriptions > 50 {
		t.Errorf("maxConcurrentSubscriptions = %d, seems unreasonably high (>50)", maxConcurrentSubscriptions)
	}
}

// ---------------------------------------------------------------------------
// Security regression: ARM filter escaping
// ---------------------------------------------------------------------------

func TestEscapeARMFilter(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"normal-uuid", "normal-uuid"},
		{"id-with-'quote", "id-with-''quote"},
		{"multiple'quotes'here", "multiple''quotes''here"},
		{"", ""},
	}
	for _, tt := range tests {
		got := escapeARMFilter(tt.input)
		if got != tt.want {
			t.Errorf("escapeARMFilter(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
