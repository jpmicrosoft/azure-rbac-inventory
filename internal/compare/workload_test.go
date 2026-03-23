package compare

import (
	"testing"
)

func TestExtractWorkloadName(t *testing.T) {
	tests := []struct {
		name     string
		spnName  string
		subNames []string
		want     string
	}{
		{
			name:     "wkld pattern validated",
			spnName:  "spn-platform-wkld-contoso",
			subNames: []string{"azg-sub-contoso-hub-01"},
			want:     "contoso",
		},
		{
			name:     "wkld pattern case insensitive",
			spnName:  "spn-platform-WKLD-Fabrikam",
			subNames: []string{"azg-sub-FABRIKAM-prod-01"},
			want:     "fabrikam",
		},
		{
			name:     "wkld pattern mid-string token",
			spnName:  "spn-platform-wkld-myapp-extra",
			subNames: []string{"azg-sub-myapp-hub-01"},
			want:     "myapp",
		},
		{
			name:     "wkld pattern not validated falls to common segment",
			spnName:  "spn-contoso-wkld-nomatch",
			subNames: []string{"azg-sub-contoso-hub-01"},
			want:     "contoso",
		},
		{
			name:     "common segment fallback",
			spnName:  "spn-platform-sentinel",
			subNames: []string{"azg-sub-sentinel-prod-01"},
			want:     "sentinel",
		},
		{
			name:     "common segment longest wins",
			spnName:  "spn-platform-sentinel-longworkload",
			subNames: []string{"azg-sub-longworkload-prod-01"},
			want:     "longworkload",
		},
		{
			name:     "noise segments filtered",
			spnName:  "spn-azg-prod-hub-myworkload",
			subNames: []string{"azg-sub-myworkload-prod-01"},
			want:     "myworkload",
		},
		{
			name:     "no match returns empty",
			spnName:  "spn-platform-wkld-nomatch",
			subNames: []string{"azg-sub-unrelated-hub-01"},
			want:     "",
		},
		{
			name:     "empty spn name",
			spnName:  "",
			subNames: []string{"azg-sub-contoso-hub-01"},
			want:     "",
		},
		{
			name:     "empty sub names",
			spnName:  "spn-platform-wkld-contoso",
			subNames: []string{},
			want:     "",
		},
		{
			name:     "nil sub names",
			spnName:  "spn-platform-wkld-contoso",
			subNames: nil,
			want:     "",
		},
		{
			name:     "single segment spn name",
			spnName:  "contoso",
			subNames: []string{"azg-sub-contoso-hub-01"},
			want:     "contoso",
		},
		{
			name:     "all digits segment filtered",
			spnName:  "spn-12345-myapp",
			subNames: []string{"azg-sub-myapp-prod-01"},
			want:     "myapp",
		},
		{
			name:     "short segments filtered",
			spnName:  "ab-cd-myworkload",
			subNames: []string{"azg-sub-myworkload-prod-01"},
			want:     "myworkload",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractWorkloadName(tt.spnName, tt.subNames)
			if got != tt.want {
				t.Errorf("ExtractWorkloadName(%q, %v) = %q, want %q",
					tt.spnName, tt.subNames, got, tt.want)
			}
		})
	}
}

func TestNormalizeScope(t *testing.T) {
	subNames := map[string]string{
		"aaa-111": "azg-sub-contoso-hub-01",
		"bbb-222": "azg-sub-fabrikam-prod-01",
		"ccc-333": "azg-sub-neworkload-dev-01",
	}

	tests := []struct {
		name         string
		scope        string
		workloadName string
		subNames     map[string]string
		want         string
	}{
		{
			name:         "subscription only scope",
			scope:        "/subscriptions/aaa-111",
			workloadName: "contoso",
			subNames:     subNames,
			want:         "azg-sub-{workload}-hub-01",
		},
		{
			name:         "subscription and resource group",
			scope:        "/subscriptions/aaa-111/resourceGroups/rg-contoso-prod",
			workloadName: "contoso",
			subNames:     subNames,
			want:         "azg-sub-{workload}-hub-01/rg-{workload}-prod",
		},
		{
			name:         "subscription RG and resource",
			scope:        "/subscriptions/aaa-111/resourceGroups/rg-contoso-prod/providers/Microsoft.Network/virtualNetworks/vnet-contoso-hub",
			workloadName: "contoso",
			subNames:     subNames,
			want:         "azg-sub-{workload}-hub-01/rg-{workload}-prod/Microsoft.Network/virtualNetworks/vnet-{workload}-hub",
		},
		{
			name:         "management group scope returned as-is",
			scope:        "/providers/Microsoft.Management/managementGroups/mg-root",
			workloadName: "contoso",
			subNames:     subNames,
			want:         "/providers/Microsoft.Management/managementGroups/mg-root",
		},
		{
			name:         "scope without workload token",
			scope:        "/subscriptions/ccc-333/resourceGroups/rg-shared-services",
			workloadName: "contoso",
			subNames:     subNames,
			want:         "azg-sub-neworkload-dev-01/rg-shared-services",
		},
		{
			name:         "case insensitive replacement",
			scope:        "/subscriptions/aaa-111/resourceGroups/rg-CONTOSO-prod",
			workloadName: "contoso",
			subNames:     subNames,
			want:         "azg-sub-{workload}-hub-01/rg-{workload}-prod",
		},
		{
			name:         "different workload fabrikam",
			scope:        "/subscriptions/bbb-222/resourceGroups/rg-fabrikam-prod",
			workloadName: "fabrikam",
			subNames:     subNames,
			want:         "azg-sub-{workload}-prod-01/rg-{workload}-prod",
		},
		{
			name:         "unknown subscription GUID",
			scope:        "/subscriptions/zzz-999/resourceGroups/rg-test",
			workloadName: "test",
			subNames:     subNames,
			want:         "/rg-{workload}",
		},
		{
			name:         "empty workload name no replacement",
			scope:        "/subscriptions/aaa-111/resourceGroups/rg-contoso-prod",
			workloadName: "",
			subNames:     subNames,
			want:         "azg-sub-contoso-hub-01/rg-contoso-prod",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NormalizeScope(tt.scope, tt.workloadName, tt.subNames)
			if got != tt.want {
				t.Errorf("NormalizeScope(%q, %q, ...) = %q, want %q",
					tt.scope, tt.workloadName, got, tt.want)
			}
		})
	}
}

func TestWorkloadScopeKey(t *testing.T) {
	tests := []struct {
		role  string
		scope string
		want  string
	}{
		{"Reader", "azg-sub-{workload}-hub-01/rg-{workload}-prod", "Reader|azg-sub-{workload}-hub-01/rg-{workload}-prod"},
		{"Contributor", "azg-sub-{workload}-hub-01", "Contributor|azg-sub-{workload}-hub-01"},
		{"", "", "|"},
	}

	for _, tt := range tests {
		t.Run(tt.role+"_"+tt.scope, func(t *testing.T) {
			got := WorkloadScopeKey(tt.role, tt.scope)
			if got != tt.want {
				t.Errorf("WorkloadScopeKey(%q, %q) = %q, want %q",
					tt.role, tt.scope, got, tt.want)
			}
		})
	}
}
