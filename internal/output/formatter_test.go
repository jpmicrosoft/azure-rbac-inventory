package output

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jpmicrosoft/azure-rbac-inventory/internal/graph"
	"github.com/jpmicrosoft/azure-rbac-inventory/internal/identity"
	"github.com/jpmicrosoft/azure-rbac-inventory/internal/rbac"
	"github.com/jpmicrosoft/azure-rbac-inventory/internal/report"
)

// captureStdout redirects os.Stdout to a pipe, runs fn, and returns whatever
// fn printed. Not safe for parallel tests that also redirect stdout.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}
	os.Stdout = w

	outC := make(chan string)
	go func() {
		var buf bytes.Buffer
		io.Copy(&buf, r)
		outC <- buf.String()
	}()

	fn()

	w.Close()
	os.Stdout = old
	return <-outC
}

func TestTruncateScope(t *testing.T) {
	tests := []struct {
		name   string
		scope  string
		maxLen int
		want   string
	}{
		{
			name:   "shorter than max returns unchanged",
			scope:  "/subscriptions/abc",
			maxLen: 50,
			want:   "/subscriptions/abc",
		},
		{
			name:   "exactly at max returns unchanged",
			scope:  "abcde",
			maxLen: 5,
			want:   "abcde",
		},
		{
			name:   "over max gets truncated with ellipsis prefix",
			scope:  "abcdefghij",
			maxLen: 7,
			want:   "...ghij",
		},
		{
			name:   "edge case maxLen equals 3 gets bumped to 4",
			scope:  "abcdef",
			maxLen: 3,
			want:   "...f",
		},
		{
			name:   "long scope gets truncated",
			scope:  "/subscriptions/abc-123/resourceGroups/myRG/providers/Microsoft.Compute/virtualMachines/vm1",
			maxLen: 30,
			want:   "...Compute/virtualMachines/vm1",
		},
		{
			name:   "empty string returns empty",
			scope:  "",
			maxLen: 10,
			want:   "",
		},
		{
			name:   "single char under max",
			scope:  "x",
			maxLen: 10,
			want:   "x",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := truncateScope(tt.scope, tt.maxLen)
			if got != tt.want {
				t.Errorf("truncateScope(%q, %d) = %q, want %q", tt.scope, tt.maxLen, got, tt.want)
			}
		})
	}
}

func TestExportJSON(t *testing.T) {
	t.Run("writes valid JSON with expected fields", func(t *testing.T) {
		dir := t.TempDir()
		filePath := filepath.Join(dir, "report.json")

		rpt := &report.Report{
			Identity: &identity.Identity{
				ObjectID:    "00000000-0000-0000-0000-000000000001",
				DisplayName: "Test User",
				Type:        identity.TypeUser,
			},
			Cloud: "AzureCloud",
		}

		err := ExportJSON(rpt, filePath)
		if err != nil {
			t.Fatalf("ExportJSON returned error: %v", err)
		}

		data, err := os.ReadFile(filePath)
		if err != nil {
			t.Fatalf("failed to read exported file: %v", err)
		}

		// Verify it's valid JSON
		var parsed map[string]interface{}
		if err := json.Unmarshal(data, &parsed); err != nil {
			t.Fatalf("exported file is not valid JSON: %v", err)
		}

		// Verify expected top-level fields
		expectedFields := []string{"identity", "cloud", "rbacAssignments", "directoryRoles",
			"accessPackageAssignments", "accessPackageRequests", "groupMemberships"}
		for _, field := range expectedFields {
			if _, ok := parsed[field]; !ok {
				t.Errorf("expected field %q not found in exported JSON", field)
			}
		}

		// Verify identity values
		ident, ok := parsed["identity"].(map[string]interface{})
		if !ok {
			t.Fatal("identity field is not a JSON object")
		}
		if ident["objectId"] != "00000000-0000-0000-0000-000000000001" {
			t.Errorf("objectId = %v, want %q", ident["objectId"], "00000000-0000-0000-0000-000000000001")
		}
		if ident["displayName"] != "Test User" {
			t.Errorf("displayName = %v, want %q", ident["displayName"], "Test User")
		}

		// Verify cloud value
		if parsed["cloud"] != "AzureCloud" {
			t.Errorf("cloud = %v, want %q", parsed["cloud"], "AzureCloud")
		}
	})

	t.Run("file has correct permissions", func(t *testing.T) {
		dir := t.TempDir()
		filePath := filepath.Join(dir, "report.json")

		rpt := &report.Report{
			Identity: &identity.Identity{
				ObjectID:    "00000000-0000-0000-0000-000000000002",
				DisplayName: "Perm Test",
				Type:        identity.TypeServicePrincipal,
			},
			Cloud: "AzureUSGovernment",
		}

		err := ExportJSON(rpt, filePath)
		if err != nil {
			t.Fatalf("ExportJSON returned error: %v", err)
		}

		info, err := os.Stat(filePath)
		if err != nil {
			t.Fatalf("failed to stat file: %v", err)
		}
		if info.Size() == 0 {
			t.Error("exported file is empty")
		}
	})

	t.Run("error on invalid path", func(t *testing.T) {
		rpt := &report.Report{
			Identity: &identity.Identity{
				ObjectID:    "00000000-0000-0000-0000-000000000003",
				DisplayName: "Bad Path",
				Type:        identity.TypeUser,
			},
			Cloud: "AzureCloud",
		}

		err := ExportJSON(rpt, filepath.Join("nonexistent", "dir", "deep", "report.json"))
		if err == nil {
			t.Error("expected error when writing to invalid path, got nil")
		}
	})
}

// ---------- PrintTable tests (stdout capture) ----------

func TestPrintTable_CompleteReport(t *testing.T) {
	rpt := &report.Report{
		Identity: &identity.Identity{
			ObjectID:    "00000000-0000-0000-0000-000000000001",
			DisplayName: "Test User",
			Type:        identity.TypeUser,
		},
		Cloud: "AzureCloud",
		RBACAssignments: []rbac.RoleAssignment{
			{
				RoleName:       "Reader",
				Scope:          "/subscriptions/abc-123",
				ScopeType:      "Subscription",
				AssignmentType: "Direct",
				PrincipalType:  "User",
			},
		},
		DirectoryRoles: []graph.DirectoryRole{
			{
				RoleName: "Global Administrator",
				Status:   "Active",
			},
		},
		AccessPackages: []graph.AccessPackageAssignment{
			{
				PackageName:    "Dev Tools",
				CatalogName:    "IT",
				Status:         "Delivered",
				ExpirationDate: "2025-12-31",
			},
		},
		AccessRequests: []graph.AccessPackageRequest{
			{
				PackageName: "Admin Portal",
				RequestType: "userAdd",
				Status:      "Pending",
				CreatedDate: "2025-01-15",
			},
		},
		GroupMemberships: []graph.GroupMembership{
			{
				GroupName:  "Engineering",
				GroupType:  "Security",
				Membership: "Direct",
			},
		},
	}

	out := captureStdout(t, func() {
		PrintTable(rpt)
	})

	// Header
	if !strings.Contains(out, "Azure RBAC Inventory") {
		t.Error("output should contain 'Azure RBAC Inventory' header")
	}
	if !strings.Contains(out, "Test User") {
		t.Error("output should contain identity display name")
	}
	if !strings.Contains(out, "AzureCloud") {
		t.Error("output should contain cloud name")
	}

	// RBAC section
	if !strings.Contains(out, "[RBAC] Azure Role Assignments (1)") {
		t.Error("output should contain RBAC assignment count")
	}
	if !strings.Contains(out, "Reader") {
		t.Error("output should contain role name")
	}

	// Directory roles section
	if !strings.Contains(out, "[ROLES] Entra ID Directory Roles (1)") {
		t.Error("output should contain directory role count")
	}
	if !strings.Contains(out, "Global Administrator") {
		t.Error("output should contain directory role name")
	}

	// Access packages section
	if !strings.Contains(out, "[PACKAGES] Access Package Assignments (1)") {
		t.Error("output should contain access package count")
	}
	if !strings.Contains(out, "Dev Tools") {
		t.Error("output should contain package name")
	}

	// Access requests section
	if !strings.Contains(out, "[REQUESTS] Access Package Requests (1)") {
		t.Error("output should contain request count")
	}
	if !strings.Contains(out, "Admin Portal") {
		t.Error("output should contain request package name")
	}

	// Group memberships section
	if !strings.Contains(out, "[GROUPS] Group Memberships (1)") {
		t.Error("output should contain group membership count")
	}
	if !strings.Contains(out, "Engineering") {
		t.Error("output should contain group name")
	}
}

func TestPrintTable_EmptySections(t *testing.T) {
	rpt := &report.Report{
		Identity: &identity.Identity{
			ObjectID:             "00000000-0000-0000-0000-000000000002",
			DisplayName:          "Empty SPN",
			Type:                 identity.TypeServicePrincipal,
			AppID:                "app-id-123",
			ServicePrincipalType: "Application",
		},
		Cloud: "AzureUSGovernment",
	}

	out := captureStdout(t, func() {
		PrintTable(rpt)
	})

	// Empty state messages
	if !strings.Contains(out, "None found.") {
		t.Error("output should contain 'None found.' for empty sections")
	}

	// Header contains SPN-specific fields
	if !strings.Contains(out, "app-id-123") {
		t.Error("output should contain App ID for service principal")
	}
	if !strings.Contains(out, "Application") {
		t.Error("output should contain SPN Type for service principal")
	}
}

func TestPrintJSON_ValidOutput(t *testing.T) {
	rpt := &report.Report{
		Identity: &identity.Identity{
			ObjectID:    "00000000-0000-0000-0000-000000000001",
			DisplayName: "JSON User",
			Type:        identity.TypeUser,
		},
		Cloud: "AzureCloud",
	}

	var jsonErr error
	out := captureStdout(t, func() {
		jsonErr = PrintJSON(rpt)
	})

	if jsonErr != nil {
		t.Fatalf("PrintJSON returned error: %v", jsonErr)
	}

	// Verify it's valid JSON
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("PrintJSON output is not valid JSON: %v\nOutput: %s", err, out)
	}

	// Verify expected fields
	if parsed["cloud"] != "AzureCloud" {
		t.Errorf("cloud = %v, want %q", parsed["cloud"], "AzureCloud")
	}

	ident, ok := parsed["identity"].(map[string]interface{})
	if !ok {
		t.Fatal("identity field is not a JSON object")
	}
	if ident["displayName"] != "JSON User" {
		t.Errorf("displayName = %v, want %q", ident["displayName"], "JSON User")
	}
}

func TestPrintTable_AccessPackageEmptyExpiration(t *testing.T) {
	rpt := &report.Report{
		Identity: &identity.Identity{
			ObjectID:    "00000000-0000-0000-0000-000000000001",
			DisplayName: "Test",
			Type:        identity.TypeUser,
		},
		Cloud: "AzureCloud",
		AccessPackages: []graph.AccessPackageAssignment{
			{
				PackageName:    "Permanent",
				CatalogName:    "Cat",
				Status:         "Delivered",
				ExpirationDate: "", // empty → shows em-dash
			},
		},
	}

	out := captureStdout(t, func() {
		PrintTable(rpt)
	})

	// Empty expiration should render as dash
	if !strings.Contains(out, "-") {
		t.Error("empty expiration should display as dash")
	}
}

func TestTruncateScope_MaxLenLessThan4_GuardedToMinimum(t *testing.T) {
	// maxLen < 4 is guarded — gets bumped to 4, no panic.
	got := truncateScope("abcdef", 2)
	if got != "...f" {
		t.Errorf("truncateScope(\"abcdef\", 2) = %q, want %q (guarded to minLen 4)", got, "...f")
	}
}

func TestPrintTable_MultipleRBACAssignments(t *testing.T) {
	rpt := &report.Report{
		Identity: &identity.Identity{
			ObjectID:    "00000000-0000-0000-0000-000000000001",
			DisplayName: "Multi User",
			Type:        identity.TypeUser,
		},
		Cloud: "AzureCloud",
		RBACAssignments: []rbac.RoleAssignment{
			{RoleName: "Reader", Scope: "/subscriptions/sub1", ScopeType: "Subscription", AssignmentType: "Direct", PrincipalType: "User"},
			{RoleName: "Contributor", Scope: "/subscriptions/sub2/resourceGroups/rg1", ScopeType: "Resource Group", AssignmentType: "Direct", PrincipalType: "User"},
			{RoleName: "Owner", Scope: "/subscriptions/sub3/resourceGroups/rg2/providers/Microsoft.Compute/virtualMachines/vm1", ScopeType: "Resource", AssignmentType: "Via Group (Admins)", PrincipalType: "Group"},
		},
	}

	out := captureStdout(t, func() {
		PrintTable(rpt)
	})

	if !strings.Contains(out, "(3)") {
		t.Error("output should show count of 3")
	}
	if !strings.Contains(out, "Reader") {
		t.Error("output should contain Reader role")
	}
	if !strings.Contains(out, "Contributor") {
		t.Error("output should contain Contributor role")
	}
	if !strings.Contains(out, "Owner") {
		t.Error("output should contain Owner role")
	}
	if !strings.Contains(out, "Via Group (Admins)") {
		t.Error("output should contain group-inherited assignment type")
	}
	// Verify grouped output shows subscription/RG/resource group headers
	if !strings.Contains(out, "Subscription: sub1") {
		t.Error("output should show subscription group header")
	}
	if !strings.Contains(out, "Resource Group: rg1") {
		t.Error("output should show resource group header")
	}
	if !strings.Contains(out, "Virtual Machines") {
		t.Error("output should show friendly resource type group header")
	}
}

// ---------------------------------------------------------------------------
// extractResourceInfo tests
// ---------------------------------------------------------------------------

func TestExtractResourceInfo(t *testing.T) {
	tests := []struct {
		name             string
		scope            string
		scopeType        string
		wantGroupName    string
		wantResourceName string
	}{
		{
			name:             "management group scope",
			scope:            "/providers/Microsoft.Management/managementGroups/mgname",
			scopeType:        "Management Group",
			wantGroupName:    "Management Group: mgname",
			wantResourceName: "",
		},
		{
			name:             "subscription scope",
			scope:            "/subscriptions/subid",
			scopeType:        "Subscription",
			wantGroupName:    "Subscription: subid",
			wantResourceName: "",
		},
		{
			name:             "resource group scope",
			scope:            "/subscriptions/sub1/resourceGroups/rgname",
			scopeType:        "Resource Group",
			wantGroupName:    "Resource Group: rgname",
			wantResourceName: "",
		},
		{
			name:             "key vault resource",
			scope:            "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.KeyVault/vaults/myvault",
			scopeType:        "Resource",
			wantGroupName:    "Key Vaults",
			wantResourceName: "myvault",
		},
		{
			name:             "private DNS zone resource",
			scope:            "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Network/privateDnsZones/privatelink.vault.usgovcloudapi.net",
			scopeType:        "Resource",
			wantGroupName:    "Private DNS Zones",
			wantResourceName: "privatelink.vault.usgovcloudapi.net",
		},
		{
			name:             "storage container nested resource",
			scope:            "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/mystorage/blobServices/default/containers/containername",
			scopeType:        "Resource",
			wantGroupName:    "Storage Containers",
			wantResourceName: "containername",
		},
		{
			name:             "unknown resource type gets capitalized",
			scope:            "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Custom/customThings/myresource",
			scopeType:        "Resource",
			wantGroupName:    "CustomThings",
			wantResourceName: "myresource",
		},
		{
			name:             "trailing slash handling on subscription",
			scope:            "/subscriptions/sub1/",
			scopeType:        "Subscription",
			wantGroupName:    "Subscription: sub1",
			wantResourceName: "",
		},
		{
			name:             "trailing slash handling on management group",
			scope:            "/providers/Microsoft.Management/managementGroups/mg1/",
			scopeType:        "Management Group",
			wantGroupName:    "Management Group: mg1",
			wantResourceName: "",
		},
		{
			name:             "empty scope falls to Other",
			scope:            "",
			scopeType:        "",
			wantGroupName:    "Other",
			wantResourceName: "",
		},
		{
			name:             "root scope falls to Other",
			scope:            "/",
			scopeType:        "",
			wantGroupName:    "Other",
			wantResourceName: "",
		},
		{
			name:             "management group without match returns label only",
			scope:            "/some/unrecognized/path",
			scopeType:        "Management Group",
			wantGroupName:    "Management Group",
			wantResourceName: "",
		},
		{
			name:             "resource scope with no providers segment",
			scope:            "/subscriptions/sub1/resourceGroups/rg1",
			scopeType:        "Resource",
			wantGroupName:    "Resource",
			wantResourceName: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			groupName, resourceName := extractResourceInfo(tt.scope, tt.scopeType)
			if groupName != tt.wantGroupName {
				t.Errorf("extractResourceInfo(%q, %q) groupName = %q, want %q",
					tt.scope, tt.scopeType, groupName, tt.wantGroupName)
			}
			if resourceName != tt.wantResourceName {
				t.Errorf("extractResourceInfo(%q, %q) resourceName = %q, want %q",
					tt.scope, tt.scopeType, resourceName, tt.wantResourceName)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// friendlyResourceType tests
// ---------------------------------------------------------------------------

func TestFriendlyResourceType(t *testing.T) {
	tests := []struct {
		name    string
		rawType string
		want    string
	}{
		{"known: vaults", "vaults", "Key Vaults"},
		{"known: privateDnsZones", "privateDnsZones", "Private DNS Zones"},
		{"known: storageAccounts", "storageAccounts", "Storage Accounts"},
		{"known: virtualMachines", "virtualMachines", "Virtual Machines"},
		{"known: containers", "containers", "Storage Containers"},
		{"known: managedClusters", "managedClusters", "AKS Clusters"},
		{"unknown gets capitalized", "customWidgets", "CustomWidgets"},
		{"single char capitalized", "x", "X"},
		{"empty string", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := friendlyResourceType(tt.rawType)
			if got != tt.want {
				t.Errorf("friendlyResourceType(%q) = %q, want %q", tt.rawType, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// printRBACAssignments grouped output tests
// ---------------------------------------------------------------------------

func TestPrintRBACAssignments_Grouped(t *testing.T) {
	assignments := []rbac.RoleAssignment{
		{
			RoleName:       "Key Vault Reader",
			Scope:          "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.KeyVault/vaults/myvault",
			ScopeType:      "Resource",
			AssignmentType: "Direct",
			PrincipalType:  "ServicePrincipal",
		},
		{
			RoleName:       "Reader",
			Scope:          "/subscriptions/sub1",
			ScopeType:      "Subscription",
			AssignmentType: "Direct",
			PrincipalType:  "ServicePrincipal",
		},
		{
			RoleName:       "Contributor",
			Scope:          "/subscriptions/sub1/resourceGroups/rg1",
			ScopeType:      "Resource Group",
			AssignmentType: "Direct",
			PrincipalType:  "ServicePrincipal",
		},
		{
			RoleName:       "MG Reader",
			Scope:          "/providers/Microsoft.Management/managementGroups/mymg",
			ScopeType:      "Management Group",
			AssignmentType: "Direct",
			PrincipalType:  "ServicePrincipal",
		},
	}

	out := captureStdout(t, func() {
		printRBACAssignments(assignments)
	})

	// Verify ► group headers appear
	if !strings.Contains(out, "►") {
		t.Error("output should contain ► group headers")
	}

	// Verify groups are sorted: MG < Subscription < Resource Group < Resource
	mgIdx := strings.Index(out, "Management Group: mymg")
	subIdx := strings.Index(out, "Subscription: sub1")
	rgIdx := strings.Index(out, "Resource Group: rg1")
	kvIdx := strings.Index(out, "Key Vaults")

	if mgIdx < 0 || subIdx < 0 || rgIdx < 0 || kvIdx < 0 {
		t.Fatalf("missing expected group headers in output:\n%s", out)
	}
	if mgIdx >= subIdx {
		t.Error("Management Group should appear before Subscription")
	}
	if subIdx >= rgIdx {
		t.Error("Subscription should appear before Resource Group")
	}
	if rgIdx >= kvIdx {
		t.Error("Resource Group should appear before Key Vaults (Resources)")
	}

	// Verify resource-level items show → for resource name
	if !strings.Contains(out, "→") {
		t.Error("output should contain → for resource-level items")
	}
	if !strings.Contains(out, "myvault") {
		t.Error("output should contain resource name 'myvault'")
	}

	// Verify scope-level items show [Direct]
	if !strings.Contains(out, "[Direct]") {
		t.Error("output should contain [Direct] for scope-level items")
	}

	// Verify total count in header
	if !strings.Contains(out, "(4)") {
		t.Error("output should contain total assignment count (4)")
	}
}

func TestPrintRBACAssignments_EmptyList(t *testing.T) {
	out := captureStdout(t, func() {
		printRBACAssignments(nil)
	})

	if !strings.Contains(out, "None found.") {
		t.Error("empty assignments should show 'None found.'")
	}
	if !strings.Contains(out, "(0)") {
		t.Error("empty assignments should show count (0)")
	}
}

func TestPrintRBACAssignments_MultipleResourcesInSameGroup(t *testing.T) {
	assignments := []rbac.RoleAssignment{
		{
			RoleName:       "Key Vault Reader",
			Scope:          "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.KeyVault/vaults/vault1",
			ScopeType:      "Resource",
			AssignmentType: "Direct",
		},
		{
			RoleName:       "Key Vault Secrets User",
			Scope:          "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.KeyVault/vaults/vault2",
			ScopeType:      "Resource",
			AssignmentType: "Direct",
		},
	}

	out := captureStdout(t, func() {
		printRBACAssignments(assignments)
	})

	// Both should be under "Key Vaults" group
	if !strings.Contains(out, "Key Vaults") {
		t.Error("expected Key Vaults group header")
	}
	if !strings.Contains(out, "vault1") {
		t.Error("expected vault1 resource name")
	}
	if !strings.Contains(out, "vault2") {
		t.Error("expected vault2 resource name")
	}
	// The group should show count (2)
	if !strings.Contains(out, "(2)") {
		t.Error("Key Vaults group should show count (2)")
	}
}

func TestFriendlyScope(t *testing.T) {
	tests := []struct {
		name      string
		scope     string
		scopeType string
		want      string
	}{
		{"management group", "/providers/Microsoft.Management/managementGroups/my-mg", "Management Group", "MG: my-mg"},
		{"subscription", "/subscriptions/abc-123", "Subscription", "Sub: abc-123"},
		{"resource group", "/subscriptions/abc/resourceGroups/my-rg", "Resource Group", "RG: my-rg"},
		{"resource", "/subscriptions/abc/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm1", "Resource", "virtualMachines/vm1"},
		{"trailing slash", "/providers/Microsoft.Management/managementGroups/mg1/", "Management Group", "MG: mg1"},
		{"unknown falls back to truncate", "/some/unknown/path", "Other", "/some/unknown/path"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := friendlyScope(tt.scope, tt.scopeType)
			if got != tt.want {
				t.Errorf("friendlyScope(%q, %q) = %q, want %q", tt.scope, tt.scopeType, got, tt.want)
			}
		})
	}
}
