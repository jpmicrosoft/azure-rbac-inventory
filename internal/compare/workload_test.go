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
			spnName:  "spn-fedrampmod-wkld-axonius",
			subNames: []string{"azg-sub-axonius-hub-01"},
			want:     "axonius",
		},
		{
			name:     "wkld pattern case insensitive",
			spnName:  "spn-fedrampmod-WKLD-Adh",
			subNames: []string{"azg-sub-ADH-prod-01"},
			want:     "adh",
		},
		{
			name:     "wkld pattern mid-string token",
			spnName:  "spn-fedrampmod-wkld-myapp-extra",
			subNames: []string{"azg-sub-myapp-hub-01"},
			want:     "myapp",
		},
		{
			name:     "wkld pattern not validated falls to common segment",
			spnName:  "spn-axonius-wkld-nomatch",
			subNames: []string{"azg-sub-axonius-hub-01"},
			want:     "axonius",
		},
		{
			name:     "common segment fallback",
			spnName:  "spn-fedrampmod-sentinel",
			subNames: []string{"azg-sub-sentinel-prod-01"},
			want:     "sentinel",
		},
		{
			name:     "common segment longest wins",
			spnName:  "spn-fedrampmod-sentinel-longworkload",
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
			spnName:  "spn-fedrampmod-wkld-nomatch",
			subNames: []string{"azg-sub-unrelated-hub-01"},
			want:     "",
		},
		{
			name:     "empty spn name",
			spnName:  "",
			subNames: []string{"azg-sub-axonius-hub-01"},
			want:     "",
		},
		{
			name:     "empty sub names",
			spnName:  "spn-fedrampmod-wkld-axonius",
			subNames: []string{},
			want:     "",
		},
		{
			name:     "nil sub names",
			spnName:  "spn-fedrampmod-wkld-axonius",
			subNames: nil,
			want:     "",
		},
		{
			name:     "single segment spn name",
			spnName:  "axonius",
			subNames: []string{"azg-sub-axonius-hub-01"},
			want:     "axonius",
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
		"aaa-111": "azg-sub-axonius-hub-01",
		"bbb-222": "azg-sub-adh-prod-01",
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
			workloadName: "axonius",
			subNames:     subNames,
			want:         "azg-sub-{workload}-hub-01",
		},
		{
			name:         "subscription and resource group",
			scope:        "/subscriptions/aaa-111/resourceGroups/rg-axonius-prod",
			workloadName: "axonius",
			subNames:     subNames,
			want:         "azg-sub-{workload}-hub-01/rg-{workload}-prod",
		},
		{
			name:         "subscription RG and resource",
			scope:        "/subscriptions/aaa-111/resourceGroups/rg-axonius-prod/providers/Microsoft.Network/virtualNetworks/vnet-axonius-hub",
			workloadName: "axonius",
			subNames:     subNames,
			want:         "azg-sub-{workload}-hub-01/rg-{workload}-prod/Microsoft.Network/virtualNetworks/vnet-{workload}-hub",
		},
		{
			name:         "management group scope returned as-is",
			scope:        "/providers/Microsoft.Management/managementGroups/mg-root",
			workloadName: "axonius",
			subNames:     subNames,
			want:         "/providers/Microsoft.Management/managementGroups/mg-root",
		},
		{
			name:         "scope without workload token",
			scope:        "/subscriptions/ccc-333/resourceGroups/rg-shared-services",
			workloadName: "axonius",
			subNames:     subNames,
			want:         "azg-sub-neworkload-dev-01/rg-shared-services",
		},
		{
			name:         "case insensitive replacement",
			scope:        "/subscriptions/aaa-111/resourceGroups/rg-AXONIUS-prod",
			workloadName: "axonius",
			subNames:     subNames,
			want:         "azg-sub-{workload}-hub-01/rg-{workload}-prod",
		},
		{
			name:         "different workload adh",
			scope:        "/subscriptions/bbb-222/resourceGroups/rg-adh-prod",
			workloadName: "adh",
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
			scope:        "/subscriptions/aaa-111/resourceGroups/rg-axonius-prod",
			workloadName: "",
			subNames:     subNames,
			want:         "azg-sub-axonius-hub-01/rg-axonius-prod",
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
