package cloud

import (
	"testing"
)

func TestGetEnvironment_AzureCloud(t *testing.T) {
	env, ok := GetEnvironment("AzureCloud")
	if !ok {
		t.Fatal("expected ok=true for AzureCloud")
	}

	if env.Name != "AzureCloud" {
		t.Errorf("Name = %q, want %q", env.Name, "AzureCloud")
	}
	if env.ARMEndpoint != "https://management.azure.com" {
		t.Errorf("ARMEndpoint = %q, want %q", env.ARMEndpoint, "https://management.azure.com")
	}
	if env.ARMScope != "https://management.azure.com/.default" {
		t.Errorf("ARMScope = %q, want %q", env.ARMScope, "https://management.azure.com/.default")
	}
	if env.GraphEndpoint != "https://graph.microsoft.com" {
		t.Errorf("GraphEndpoint = %q, want %q", env.GraphEndpoint, "https://graph.microsoft.com")
	}
	if env.GraphScope != "https://graph.microsoft.com/.default" {
		t.Errorf("GraphScope = %q, want %q", env.GraphScope, "https://graph.microsoft.com/.default")
	}
	if env.LoginEndpoint != "https://login.microsoftonline.com" {
		t.Errorf("LoginEndpoint = %q, want %q", env.LoginEndpoint, "https://login.microsoftonline.com")
	}
}

func TestGetEnvironment_AzureUSGovernment(t *testing.T) {
	env, ok := GetEnvironment("AzureUSGovernment")
	if !ok {
		t.Fatal("expected ok=true for AzureUSGovernment")
	}

	if env.Name != "AzureUSGovernment" {
		t.Errorf("Name = %q, want %q", env.Name, "AzureUSGovernment")
	}
	if env.ARMEndpoint != "https://management.usgovcloudapi.net" {
		t.Errorf("ARMEndpoint = %q, want %q", env.ARMEndpoint, "https://management.usgovcloudapi.net")
	}
	if env.ARMScope != "https://management.usgovcloudapi.net/.default" {
		t.Errorf("ARMScope = %q, want %q", env.ARMScope, "https://management.usgovcloudapi.net/.default")
	}
	if env.GraphEndpoint != "https://graph.microsoft.us" {
		t.Errorf("GraphEndpoint = %q, want %q", env.GraphEndpoint, "https://graph.microsoft.us")
	}
	if env.GraphScope != "https://graph.microsoft.us/.default" {
		t.Errorf("GraphScope = %q, want %q", env.GraphScope, "https://graph.microsoft.us/.default")
	}
	if env.LoginEndpoint != "https://login.microsoftonline.us" {
		t.Errorf("LoginEndpoint = %q, want %q", env.LoginEndpoint, "https://login.microsoftonline.us")
	}
}

func TestGetEnvironment_AzureChinaCloud(t *testing.T) {
	env, ok := GetEnvironment("AzureChinaCloud")
	if !ok {
		t.Fatal("expected ok=true for AzureChinaCloud")
	}

	if env.Name != "AzureChinaCloud" {
		t.Errorf("Name = %q, want %q", env.Name, "AzureChinaCloud")
	}
	if env.ARMEndpoint != "https://management.chinacloudapi.cn" {
		t.Errorf("ARMEndpoint = %q, want %q", env.ARMEndpoint, "https://management.chinacloudapi.cn")
	}
	if env.ARMScope != "https://management.chinacloudapi.cn/.default" {
		t.Errorf("ARMScope = %q, want %q", env.ARMScope, "https://management.chinacloudapi.cn/.default")
	}
	if env.GraphEndpoint != "https://microsoftgraph.chinacloudapi.cn" {
		t.Errorf("GraphEndpoint = %q, want %q", env.GraphEndpoint, "https://microsoftgraph.chinacloudapi.cn")
	}
	if env.GraphScope != "https://microsoftgraph.chinacloudapi.cn/.default" {
		t.Errorf("GraphScope = %q, want %q", env.GraphScope, "https://microsoftgraph.chinacloudapi.cn/.default")
	}
	if env.LoginEndpoint != "https://login.chinacloudapi.cn" {
		t.Errorf("LoginEndpoint = %q, want %q", env.LoginEndpoint, "https://login.chinacloudapi.cn")
	}
}

func TestGetEnvironment_InvalidName(t *testing.T) {
	env, ok := GetEnvironment("SomeNonExistentCloud")
	if ok {
		t.Fatal("expected ok=false for invalid cloud name")
	}
	if env.Name != "" {
		t.Errorf("expected zero-value Environment, got %+v", env)
	}
}

func TestGetEnvironment_CaseInsensitive(t *testing.T) {
	// The function should match cloud names case-insensitively.
	caseVariants := []struct {
		input    string
		wantName string
	}{
		{"azurecloud", "AzureCloud"},
		{"AZURECLOUD", "AzureCloud"},
		{"azureCloud", "AzureCloud"},
		{"azureusgovernment", "AzureUSGovernment"},
		{"azurechinacloud", "AzureChinaCloud"},
	}

	for _, tc := range caseVariants {
		t.Run(tc.input, func(t *testing.T) {
			env, ok := GetEnvironment(tc.input)
			if !ok {
				t.Errorf("GetEnvironment(%q) returned ok=false, want true (case-insensitive)", tc.input)
			}
			if env.Name != tc.wantName {
				t.Errorf("GetEnvironment(%q).Name = %q, want %q", tc.input, env.Name, tc.wantName)
			}
		})
	}
}

func TestGetEnvironment_EmptyString(t *testing.T) {
	_, ok := GetEnvironment("")
	if ok {
		t.Error("expected ok=false for empty string")
	}
}

func TestValidCloudNames_MatchGetEnvironment(t *testing.T) {
	// Every name in ValidCloudNames should resolve successfully.
	for _, name := range ValidCloudNames {
		t.Run(name, func(t *testing.T) {
			env, ok := GetEnvironment(name)
			if !ok {
				t.Errorf("ValidCloudNames contains %q but GetEnvironment returned ok=false", name)
			}
			if env.Name != name {
				t.Errorf("env.Name = %q, want %q", env.Name, name)
			}
		})
	}
}

func TestGetEnvironment_CloudConfigSet(t *testing.T) {
	// Verify each environment has a non-zero CloudConfig with the correct authority host.
	tests := []struct {
		name         string
		wantAuthHost string
	}{
		{"AzureCloud", "https://login.microsoftonline.com/"},
		{"AzureUSGovernment", "https://login.microsoftonline.us/"},
		{"AzureChinaCloud", "https://login.chinacloudapi.cn/"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env, ok := GetEnvironment(tt.name)
			if !ok {
				t.Fatalf("GetEnvironment(%q) returned ok=false", tt.name)
			}
			if env.CloudConfig.ActiveDirectoryAuthorityHost != tt.wantAuthHost {
				t.Errorf("CloudConfig.ActiveDirectoryAuthorityHost = %q, want %q",
					env.CloudConfig.ActiveDirectoryAuthorityHost, tt.wantAuthHost)
			}
		})
	}
}
