package compare

import (
	"fmt"
	"testing"

	"github.com/jpmicrosoft/azure-rbac-inventory/internal/graph"
	"github.com/jpmicrosoft/azure-rbac-inventory/internal/identity"
	"github.com/jpmicrosoft/azure-rbac-inventory/internal/rbac"
	reportpkg "github.com/jpmicrosoft/azure-rbac-inventory/internal/report"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

func makeIdentity(name, objID string) *identity.Identity {
	return &identity.Identity{
		ObjectID:    objID,
		DisplayName: name,
		Type:        identity.TypeServicePrincipal,
	}
}

func makeReport(name, objID string, rbacCount, roleCount, groupCount, pkgCount int) *reportpkg.Report {
	r := &reportpkg.Report{
		Identity: makeIdentity(name, objID),
		Cloud:    "AzureCloud",
	}
	for i := 0; i < rbacCount; i++ {
		r.RBACAssignments = append(r.RBACAssignments, makeRBACAssignment(
			fmt.Sprintf("Role-%d", i), "Subscription"))
	}
	for i := 0; i < roleCount; i++ {
		r.DirectoryRoles = append(r.DirectoryRoles, makeDirectoryRole(
			fmt.Sprintf("DirRole-%d", i)))
	}
	for i := 0; i < groupCount; i++ {
		r.GroupMemberships = append(r.GroupMemberships, makeGroup(
			fmt.Sprintf("Group-%d", i)))
	}
	for i := 0; i < pkgCount; i++ {
		r.AccessPackages = append(r.AccessPackages, makePackage(
			fmt.Sprintf("Pkg-%d", i), "Catalog-0"))
	}
	return r
}

func makeRBACAssignment(roleName, scopeType string) rbac.RoleAssignment {
	return rbac.RoleAssignment{
		RoleName:       roleName,
		ScopeType:      scopeType,
		Scope:          "/subscriptions/test-sub",
		AssignmentType: "Direct",
		PrincipalType:  "ServicePrincipal",
	}
}

func makeDirectoryRole(name string) graph.DirectoryRole {
	return graph.DirectoryRole{RoleName: name, RoleID: "role-" + name, Status: "Active"}
}

func makeGroup(name string) graph.GroupMembership {
	return graph.GroupMembership{GroupName: name, GroupType: "Security", Membership: "Direct"}
}

func makePackage(name, catalog string) graph.AccessPackageAssignment {
	return graph.AccessPackageAssignment{PackageName: name, CatalogName: catalog, Status: "Delivered"}
}

func emptyReport(name, objID string) *reportpkg.Report {
	return &reportpkg.Report{
		Identity: makeIdentity(name, objID),
		Cloud:    "AzureCloud",
	}
}

// ---------------------------------------------------------------------------
// CompareReports tests
// ---------------------------------------------------------------------------

func TestCompareReports_BothEmpty(t *testing.T) {
	a := emptyReport("A", "aaa-111")
	b := emptyReport("B", "bbb-222")

	result := CompareReports(a, b)

	assertLen(t, "RBAC.Shared", result.RBAC.Shared, 0)
	assertLen(t, "RBAC.OnlyA", result.RBAC.OnlyA, 0)
	assertLen(t, "RBAC.OnlyB", result.RBAC.OnlyB, 0)
	assertLen(t, "DirectoryRoles.Shared", result.DirectoryRoles.Shared, 0)
	assertLen(t, "Groups.Shared", result.Groups.Shared, 0)
	assertLen(t, "AccessPackages.Shared", result.AccessPackages.Shared, 0)

	if result.MatchPercent != 100.0 {
		t.Errorf("expected MatchPercent=100, got %.2f", result.MatchPercent)
	}
}

func TestCompareReports_Identical(t *testing.T) {
	a := makeReport("A", "aaa-111", 3, 2, 2, 1)
	b := makeReport("B", "bbb-222", 3, 2, 2, 1)

	result := CompareReports(a, b)

	assertLen(t, "RBAC.Shared", result.RBAC.Shared, 3)
	assertLen(t, "RBAC.OnlyA", result.RBAC.OnlyA, 0)
	assertLen(t, "RBAC.OnlyB", result.RBAC.OnlyB, 0)
	assertLen(t, "DirectoryRoles.Shared", result.DirectoryRoles.Shared, 2)
	assertLen(t, "DirectoryRoles.OnlyA", result.DirectoryRoles.OnlyA, 0)
	assertLen(t, "Groups.Shared", result.Groups.Shared, 2)
	assertLen(t, "AccessPackages.Shared", result.AccessPackages.Shared, 1)

	if result.MatchPercent != 100.0 {
		t.Errorf("expected MatchPercent=100, got %.2f", result.MatchPercent)
	}
}

func TestCompareReports_CompletelyDifferent(t *testing.T) {
	a := &reportpkg.Report{
		Identity: makeIdentity("A", "aaa"),
		Cloud:    "AzureCloud",
		RBACAssignments: []rbac.RoleAssignment{
			makeRBACAssignment("Reader", "Subscription"),
			makeRBACAssignment("Contributor", "ResourceGroup"),
			makeRBACAssignment("Owner", "Subscription"),
		},
	}
	b := &reportpkg.Report{
		Identity: makeIdentity("B", "bbb"),
		Cloud:    "AzureCloud",
		RBACAssignments: []rbac.RoleAssignment{
			makeRBACAssignment("StorageBlobReader", "Subscription"),
			makeRBACAssignment("NetworkContributor", "Subscription"),
		},
	}

	result := CompareReports(a, b)

	assertLen(t, "RBAC.OnlyA", result.RBAC.OnlyA, 3)
	assertLen(t, "RBAC.OnlyB", result.RBAC.OnlyB, 2)
	assertLen(t, "RBAC.Shared", result.RBAC.Shared, 0)

	if result.MatchPercent != 0.0 {
		t.Errorf("expected MatchPercent=0, got %.2f", result.MatchPercent)
	}
}

func TestCompareReports_PartialOverlap(t *testing.T) {
	a := &reportpkg.Report{
		Identity: makeIdentity("A", "aaa"),
		Cloud:    "AzureCloud",
		RBACAssignments: []rbac.RoleAssignment{
			makeRBACAssignment("Reader", "Subscription"),
			makeRBACAssignment("Contributor", "Subscription"),
			makeRBACAssignment("Owner", "Subscription"),
		},
		DirectoryRoles: []graph.DirectoryRole{
			makeDirectoryRole("GlobalAdmin"),
			makeDirectoryRole("UserAdmin"),
		},
		GroupMemberships: []graph.GroupMembership{
			makeGroup("DevTeam"),
		},
	}
	b := &reportpkg.Report{
		Identity: makeIdentity("B", "bbb"),
		Cloud:    "AzureCloud",
		RBACAssignments: []rbac.RoleAssignment{
			makeRBACAssignment("Reader", "Subscription"),
			makeRBACAssignment("Contributor", "Subscription"),
		},
		DirectoryRoles: []graph.DirectoryRole{
			makeDirectoryRole("GlobalAdmin"),
			makeDirectoryRole("AppAdmin"),
		},
		GroupMemberships: []graph.GroupMembership{
			makeGroup("DevTeam"),
			makeGroup("OpsTeam"),
		},
	}

	result := CompareReports(a, b)

	assertLen(t, "RBAC.Shared", result.RBAC.Shared, 2)
	assertLen(t, "RBAC.OnlyA", result.RBAC.OnlyA, 1)
	assertLen(t, "RBAC.OnlyB", result.RBAC.OnlyB, 0)
	assertLen(t, "DirectoryRoles.Shared", result.DirectoryRoles.Shared, 1)
	assertLen(t, "DirectoryRoles.OnlyA", result.DirectoryRoles.OnlyA, 1)
	assertLen(t, "DirectoryRoles.OnlyB", result.DirectoryRoles.OnlyB, 1)
	assertLen(t, "Groups.Shared", result.Groups.Shared, 1)
	assertLen(t, "Groups.OnlyA", result.Groups.OnlyA, 0)
	assertLen(t, "Groups.OnlyB", result.Groups.OnlyB, 1)

	// totalA=6, totalB=6, shared=4 → 4/6*100 = 66.67
	wantPct := float64(4) / float64(6) * 100.0
	if !floatClose(result.MatchPercent, wantPct) {
		t.Errorf("expected MatchPercent≈%.2f, got %.2f", wantPct, result.MatchPercent)
	}
}

func TestCompareReports_RBACKeyByScopeType(t *testing.T) {
	// Same role name but different scopes → should now be OnlyA/OnlyB (scope-aware).
	a := &reportpkg.Report{
		Identity: makeIdentity("A", "aaa"),
		Cloud:    "AzureCloud",
		RBACAssignments: []rbac.RoleAssignment{
			{RoleName: "Contributor", ScopeType: "Subscription", Scope: "/subscriptions/sub-AAA"},
		},
	}
	b := &reportpkg.Report{
		Identity: makeIdentity("B", "bbb"),
		Cloud:    "AzureCloud",
		RBACAssignments: []rbac.RoleAssignment{
			{RoleName: "Contributor", ScopeType: "Subscription", Scope: "/subscriptions/sub-BBB"},
		},
	}

	result := CompareReports(a, b)

	assertLen(t, "RBAC.Shared", result.RBAC.Shared, 0)
	assertLen(t, "RBAC.OnlyA", result.RBAC.OnlyA, 1)
	assertLen(t, "RBAC.OnlyB", result.RBAC.OnlyB, 1)
}

func TestCompareReports_RBACKeyByScopeSameScope(t *testing.T) {
	// Same role name + same scope → should be Shared.
	a := &reportpkg.Report{
		Identity: makeIdentity("A", "aaa"),
		Cloud:    "AzureCloud",
		RBACAssignments: []rbac.RoleAssignment{
			{RoleName: "Contributor", ScopeType: "Subscription", Scope: "/subscriptions/sub-SAME"},
		},
	}
	b := &reportpkg.Report{
		Identity: makeIdentity("B", "bbb"),
		Cloud:    "AzureCloud",
		RBACAssignments: []rbac.RoleAssignment{
			{RoleName: "Contributor", ScopeType: "Subscription", Scope: "/subscriptions/sub-SAME"},
		},
	}

	result := CompareReports(a, b)

	assertLen(t, "RBAC.Shared", result.RBAC.Shared, 1)
	assertLen(t, "RBAC.OnlyA", result.RBAC.OnlyA, 0)
	assertLen(t, "RBAC.OnlyB", result.RBAC.OnlyB, 0)
}

func TestCompareReports_DuplicateRBACKeys(t *testing.T) {
	a := &reportpkg.Report{
		Identity: makeIdentity("A", "aaa"),
		Cloud:    "AzureCloud",
		RBACAssignments: []rbac.RoleAssignment{
			makeRBACAssignment("Contributor", "Subscription"),
			makeRBACAssignment("Contributor", "Subscription"),
			makeRBACAssignment("Contributor", "Subscription"),
		},
	}
	b := &reportpkg.Report{
		Identity: makeIdentity("B", "bbb"),
		Cloud:    "AzureCloud",
		RBACAssignments: []rbac.RoleAssignment{
			makeRBACAssignment("Contributor", "Subscription"),
			makeRBACAssignment("Contributor", "Subscription"),
		},
	}

	result := CompareReports(a, b)

	assertLen(t, "RBAC.Shared", result.RBAC.Shared, 2)
	assertLen(t, "RBAC.OnlyA", result.RBAC.OnlyA, 1)
	assertLen(t, "RBAC.OnlyB", result.RBAC.OnlyB, 0)
}

func TestCompareReports_DirectoryRoles(t *testing.T) {
	a := &reportpkg.Report{
		Identity: makeIdentity("A", "aaa"),
		Cloud:    "AzureCloud",
		DirectoryRoles: []graph.DirectoryRole{
			makeDirectoryRole("GlobalAdmin"),
			makeDirectoryRole("UserAdmin"),
		},
	}
	b := &reportpkg.Report{
		Identity: makeIdentity("B", "bbb"),
		Cloud:    "AzureCloud",
		DirectoryRoles: []graph.DirectoryRole{
			makeDirectoryRole("GlobalAdmin"),
			makeDirectoryRole("AppAdmin"),
		},
	}

	result := CompareReports(a, b)

	assertLen(t, "DirectoryRoles.OnlyA", result.DirectoryRoles.OnlyA, 1)
	assertLen(t, "DirectoryRoles.OnlyB", result.DirectoryRoles.OnlyB, 1)
	assertLen(t, "DirectoryRoles.Shared", result.DirectoryRoles.Shared, 1)

	if result.DirectoryRoles.OnlyA[0].RoleName != "UserAdmin" {
		t.Errorf("expected OnlyA role=UserAdmin, got %s", result.DirectoryRoles.OnlyA[0].RoleName)
	}
	if result.DirectoryRoles.OnlyB[0].RoleName != "AppAdmin" {
		t.Errorf("expected OnlyB role=AppAdmin, got %s", result.DirectoryRoles.OnlyB[0].RoleName)
	}
}

func TestCompareReports_Groups(t *testing.T) {
	a := &reportpkg.Report{
		Identity: makeIdentity("A", "aaa"),
		Cloud:    "AzureCloud",
		GroupMemberships: []graph.GroupMembership{
			makeGroup("TeamAlpha"),
			makeGroup("SharedGroup"),
		},
	}
	b := &reportpkg.Report{
		Identity: makeIdentity("B", "bbb"),
		Cloud:    "AzureCloud",
		GroupMemberships: []graph.GroupMembership{
			makeGroup("SharedGroup"),
			makeGroup("TeamBeta"),
		},
	}

	result := CompareReports(a, b)

	assertLen(t, "Groups.OnlyA", result.Groups.OnlyA, 1)
	assertLen(t, "Groups.OnlyB", result.Groups.OnlyB, 1)
	assertLen(t, "Groups.Shared", result.Groups.Shared, 1)

	if result.Groups.OnlyA[0].GroupName != "TeamAlpha" {
		t.Errorf("expected OnlyA group=TeamAlpha, got %s", result.Groups.OnlyA[0].GroupName)
	}
}

func TestCompareReports_AccessPackages(t *testing.T) {
	a := &reportpkg.Report{
		Identity: makeIdentity("A", "aaa"),
		Cloud:    "AzureCloud",
		AccessPackages: []graph.AccessPackageAssignment{
			makePackage("PkgShared", "CatalogX"),
			makePackage("PkgOnlyA", "CatalogX"),
			// Same name, different catalog → different key.
			makePackage("PkgShared", "CatalogY"),
		},
	}
	b := &reportpkg.Report{
		Identity: makeIdentity("B", "bbb"),
		Cloud:    "AzureCloud",
		AccessPackages: []graph.AccessPackageAssignment{
			makePackage("PkgShared", "CatalogX"),
			makePackage("PkgOnlyB", "CatalogX"),
		},
	}

	result := CompareReports(a, b)

	assertLen(t, "AccessPackages.Shared", result.AccessPackages.Shared, 1)
	assertLen(t, "AccessPackages.OnlyA", result.AccessPackages.OnlyA, 2)
	assertLen(t, "AccessPackages.OnlyB", result.AccessPackages.OnlyB, 1)
}

func TestCompareReports_MatchPercent_AllCategories(t *testing.T) {
	a := &reportpkg.Report{
		Identity: makeIdentity("A", "aaa"),
		Cloud:    "AzureCloud",
		RBACAssignments: []rbac.RoleAssignment{
			makeRBACAssignment("Reader", "Subscription"),
			makeRBACAssignment("Writer", "Subscription"),
		},
		DirectoryRoles: []graph.DirectoryRole{
			makeDirectoryRole("GlobalAdmin"),
		},
		GroupMemberships: []graph.GroupMembership{
			makeGroup("G1"),
			makeGroup("G2"),
		},
		AccessPackages: []graph.AccessPackageAssignment{
			makePackage("P1", "C1"),
		},
	}
	// totalA = 2+1+2+1 = 6
	b := &reportpkg.Report{
		Identity: makeIdentity("B", "bbb"),
		Cloud:    "AzureCloud",
		RBACAssignments: []rbac.RoleAssignment{
			makeRBACAssignment("Reader", "Subscription"),
			makeRBACAssignment("Owner", "Subscription"),
			makeRBACAssignment("NetAdmin", "ResourceGroup"),
		},
		DirectoryRoles: []graph.DirectoryRole{
			makeDirectoryRole("GlobalAdmin"),
			makeDirectoryRole("AppAdmin"),
		},
		GroupMemberships: []graph.GroupMembership{
			makeGroup("G1"),
			makeGroup("G3"),
		},
		AccessPackages: []graph.AccessPackageAssignment{
			makePackage("P1", "C1"),
			makePackage("P2", "C1"),
		},
	}
	// totalB = 3+2+2+2 = 9

	result := CompareReports(a, b)

	// Shared: RBAC=1(Reader), Roles=1(GlobalAdmin), Groups=1(G1), Packages=1(P1) = 4
	// max(6,9) = 9
	wantPct := float64(4) / float64(9) * 100.0
	if !floatClose(result.MatchPercent, wantPct) {
		t.Errorf("expected MatchPercent≈%.2f, got %.2f", wantPct, result.MatchPercent)
	}
}

func TestCompareReports_OneEmpty(t *testing.T) {
	a := makeReport("A", "aaa", 2, 1, 1, 1)
	b := emptyReport("B", "bbb")

	result := CompareReports(a, b)

	assertLen(t, "RBAC.OnlyA", result.RBAC.OnlyA, 2)
	assertLen(t, "RBAC.Shared", result.RBAC.Shared, 0)
	assertLen(t, "RBAC.OnlyB", result.RBAC.OnlyB, 0)
	assertLen(t, "DirectoryRoles.OnlyA", result.DirectoryRoles.OnlyA, 1)
	assertLen(t, "Groups.OnlyA", result.Groups.OnlyA, 1)
	assertLen(t, "AccessPackages.OnlyA", result.AccessPackages.OnlyA, 1)

	if result.MatchPercent != 0.0 {
		t.Errorf("expected MatchPercent=0, got %.2f", result.MatchPercent)
	}
}

// ---------------------------------------------------------------------------
// ModelCompare tests
// ---------------------------------------------------------------------------

func TestModelCompare_NoTargets(t *testing.T) {
	model := makeReport("Model", "mmm", 2, 1, 0, 0)
	mcr := ModelCompare(model, nil)

	if len(mcr.Results) != 0 {
		t.Fatalf("expected 0 results, got %d", len(mcr.Results))
	}
	if mcr.Model.DisplayName != "Model" {
		t.Errorf("expected Model identity, got %s", mcr.Model.DisplayName)
	}
}

func TestModelCompare_SingleTarget(t *testing.T) {
	model := &reportpkg.Report{
		Identity: makeIdentity("Model", "mmm"),
		Cloud:    "AzureCloud",
		RBACAssignments: []rbac.RoleAssignment{
			makeRBACAssignment("Reader", "Subscription"),
			makeRBACAssignment("Contributor", "Subscription"),
		},
	}
	target := &reportpkg.Report{
		Identity: makeIdentity("Target", "ttt"),
		Cloud:    "AzureCloud",
		RBACAssignments: []rbac.RoleAssignment{
			makeRBACAssignment("Reader", "Subscription"),
			makeRBACAssignment("Owner", "Subscription"),
		},
	}

	mcr := ModelCompare(model, []*reportpkg.Report{target})

	if len(mcr.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(mcr.Results))
	}
	r := mcr.Results[0]
	if r.MissingRBAC != 1 { // Contributor in model, not target
		t.Errorf("expected MissingRBAC=1, got %d", r.MissingRBAC)
	}
	if r.ExtraRBAC != 1 { // Owner in target, not model
		t.Errorf("expected ExtraRBAC=1, got %d", r.ExtraRBAC)
	}
	if r.MatchPercent != 50.0 {
		t.Errorf("expected MatchPercent=50, got %.2f", r.MatchPercent)
	}
}

func TestModelCompare_MultipleTargets(t *testing.T) {
	model := &reportpkg.Report{
		Identity: makeIdentity("Model", "mmm"),
		Cloud:    "AzureCloud",
		RBACAssignments: []rbac.RoleAssignment{
			makeRBACAssignment("Reader", "Subscription"),
			makeRBACAssignment("Contributor", "Subscription"),
		},
	}
	// Target with 100% match.
	t1 := &reportpkg.Report{
		Identity: makeIdentity("Perfect", "t1"),
		Cloud:    "AzureCloud",
		RBACAssignments: []rbac.RoleAssignment{
			makeRBACAssignment("Reader", "Subscription"),
			makeRBACAssignment("Contributor", "Subscription"),
		},
	}
	// Target with 50% match (1 shared, 1 extra).
	t2 := &reportpkg.Report{
		Identity: makeIdentity("Partial", "t2"),
		Cloud:    "AzureCloud",
		RBACAssignments: []rbac.RoleAssignment{
			makeRBACAssignment("Reader", "Subscription"),
			makeRBACAssignment("Owner", "Subscription"),
		},
	}
	// Target with 0% match (completely different).
	t3 := &reportpkg.Report{
		Identity: makeIdentity("None", "t3"),
		Cloud:    "AzureCloud",
		RBACAssignments: []rbac.RoleAssignment{
			makeRBACAssignment("Owner", "Subscription"),
			makeRBACAssignment("NetAdmin", "Subscription"),
		},
	}

	mcr := ModelCompare(model, []*reportpkg.Report{t3, t1, t2})

	if len(mcr.Results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(mcr.Results))
	}

	// Sorted by MatchPercent descending.
	if mcr.Results[0].Target.DisplayName != "Perfect" {
		t.Errorf("expected first result=Perfect, got %s", mcr.Results[0].Target.DisplayName)
	}
	if mcr.Results[1].Target.DisplayName != "Partial" {
		t.Errorf("expected second result=Partial, got %s", mcr.Results[1].Target.DisplayName)
	}
	if mcr.Results[2].Target.DisplayName != "None" {
		t.Errorf("expected third result=None, got %s", mcr.Results[2].Target.DisplayName)
	}

	if mcr.Results[0].MatchPercent != 100.0 {
		t.Errorf("expected Perfect MatchPercent=100, got %.2f", mcr.Results[0].MatchPercent)
	}
	if mcr.Results[1].MatchPercent != 50.0 {
		t.Errorf("expected Partial MatchPercent=50, got %.2f", mcr.Results[1].MatchPercent)
	}
	if mcr.Results[2].MatchPercent != 0.0 {
		t.Errorf("expected None MatchPercent=0, got %.2f", mcr.Results[2].MatchPercent)
	}
}

func TestModelCompare_PerfectMatch(t *testing.T) {
	model := makeReport("Model", "mmm", 3, 2, 1, 1)
	target := makeReport("Target", "ttt", 3, 2, 1, 1)

	mcr := ModelCompare(model, []*reportpkg.Report{target})

	r := mcr.Results[0]
	if r.MatchPercent != 100.0 {
		t.Errorf("expected MatchPercent=100, got %.2f", r.MatchPercent)
	}
	if r.MissingRBAC != 0 {
		t.Errorf("expected MissingRBAC=0, got %d", r.MissingRBAC)
	}
	if r.ExtraRBAC != 0 {
		t.Errorf("expected ExtraRBAC=0, got %d", r.ExtraRBAC)
	}
	if r.MissingRoles != 0 {
		t.Errorf("expected MissingRoles=0, got %d", r.MissingRoles)
	}
	if r.ExtraRoles != 0 {
		t.Errorf("expected ExtraRoles=0, got %d", r.ExtraRoles)
	}
	if r.MissingGroups != 0 {
		t.Errorf("expected MissingGroups=0, got %d", r.MissingGroups)
	}
	if r.ExtraGroups != 0 {
		t.Errorf("expected ExtraGroups=0, got %d", r.ExtraGroups)
	}
}

// ---------------------------------------------------------------------------
// Helper function key tests
// ---------------------------------------------------------------------------

func TestRBACKey(t *testing.T) {
	a := rbac.RoleAssignment{RoleName: "Reader", ScopeType: "Subscription", Scope: "/subscriptions/abc"}
	got := rbacKey(a)
	want := "Reader|/subscriptions/abc"
	if got != want {
		t.Errorf("rbacKey() = %q, want %q", got, want)
	}
}

func TestModelRBACKey(t *testing.T) {
	a := rbac.RoleAssignment{RoleName: "Reader", ScopeType: "Subscription", Scope: "/subscriptions/abc"}
	got := modelRBACKey(a)
	want := "Reader|Subscription"
	if got != want {
		t.Errorf("modelRBACKey() = %q, want %q", got, want)
	}
}

func TestModelCompare_StructuralMatchDifferentScopes(t *testing.T) {
	// Same role + scope type but different subscription paths → should be Shared in model compare.
	model := &reportpkg.Report{
		Identity: makeIdentity("Model", "mmm"),
		Cloud:    "AzureCloud",
		RBACAssignments: []rbac.RoleAssignment{
			{RoleName: "Reader", ScopeType: "Subscription", Scope: "/subscriptions/sub-AAA"},
			{RoleName: "Contributor", ScopeType: "ResourceGroup", Scope: "/subscriptions/sub-AAA/resourceGroups/rg-model"},
		},
	}
	target := &reportpkg.Report{
		Identity: makeIdentity("Target", "ttt"),
		Cloud:    "AzureCloud",
		RBACAssignments: []rbac.RoleAssignment{
			{RoleName: "Reader", ScopeType: "Subscription", Scope: "/subscriptions/sub-BBB"},
			{RoleName: "Contributor", ScopeType: "ResourceGroup", Scope: "/subscriptions/sub-BBB/resourceGroups/rg-target"},
		},
	}

	mcr := ModelCompare(model, []*reportpkg.Report{target})

	r := mcr.Results[0]
	if r.MatchPercent != 100.0 {
		t.Errorf("expected 100%% match (structural), got %.2f%%", r.MatchPercent)
	}
	if r.MissingRBAC != 0 {
		t.Errorf("expected MissingRBAC=0, got %d", r.MissingRBAC)
	}
	if r.ExtraRBAC != 0 {
		t.Errorf("expected ExtraRBAC=0, got %d", r.ExtraRBAC)
	}
}

func TestRoleKey(t *testing.T) {
	r := graph.DirectoryRole{RoleName: "GlobalAdmin"}
	got := roleKey(r)
	if got != "GlobalAdmin" {
		t.Errorf("roleKey() = %q, want %q", got, "GlobalAdmin")
	}
}

func TestGroupKey(t *testing.T) {
	g := graph.GroupMembership{GroupName: "DevTeam"}
	got := groupKey(g)
	if got != "DevTeam" {
		t.Errorf("groupKey() = %q, want %q", got, "DevTeam")
	}
}

func TestPackageKey(t *testing.T) {
	p := graph.AccessPackageAssignment{PackageName: "MyPkg", CatalogName: "MyCatalog"}
	got := packageKey(p)
	want := "MyPkg|MyCatalog"
	if got != want {
		t.Errorf("packageKey() = %q, want %q", got, want)
	}
}

// ---------------------------------------------------------------------------
// Assertion helpers
// ---------------------------------------------------------------------------

func assertLen[T any](t *testing.T, label string, slice []T, want int) {
	t.Helper()
	if len(slice) != want {
		t.Errorf("%s: len=%d, want %d", label, len(slice), want)
	}
}

func floatClose(a, b float64) bool {
	const epsilon = 0.01
	diff := a - b
	if diff < 0 {
		diff = -diff
	}
	return diff < epsilon
}

// ---------------------------------------------------------------------------
// WorkloadModelCompare tests
// ---------------------------------------------------------------------------

func makeWorkloadReport(spnName string, subNames map[string]string, assignments []rbac.RoleAssignment) *reportpkg.Report {
	return &reportpkg.Report{
		Identity: &identity.Identity{
			DisplayName: spnName,
			ObjectID:    "test-oid-" + spnName,
			Type:        identity.TypeServicePrincipal,
		},
		Cloud:             "AzureUSGovernment",
		SubscriptionNames: subNames,
		RBACAssignments:   assignments,
	}
}

func TestWorkloadModelCompare_BasicMatch(t *testing.T) {
	golden := makeWorkloadReport("spn-platform-wkld-contoso",
		map[string]string{
			"aaa-1111": "azg-sub-contoso-hub-01",
			"aaa-2222": "azg-sub-contoso-spoke-01",
		},
		[]rbac.RoleAssignment{
			{RoleName: "Reader", Scope: "/subscriptions/aaa-1111", ScopeType: "Subscription"},
			{RoleName: "Contributor", Scope: "/subscriptions/aaa-2222", ScopeType: "Subscription"},
		},
	)

	target := makeWorkloadReport("spn-platform-wkld-litware",
		map[string]string{
			"bbb-1111": "azg-sub-litware-hub-01",
			"bbb-2222": "azg-sub-litware-spoke-01",
		},
		[]rbac.RoleAssignment{
			{RoleName: "Reader", Scope: "/subscriptions/bbb-1111", ScopeType: "Subscription"},
			{RoleName: "Contributor", Scope: "/subscriptions/bbb-2222", ScopeType: "Subscription"},
		},
	)

	result := WorkloadModelCompare(golden, []*reportpkg.Report{target}, "", nil)

	if len(result.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(result.Results))
	}
	r := result.Results[0]
	if !floatClose(r.MatchPercent, 100.0) {
		t.Errorf("expected MatchPercent≈100, got %.2f", r.MatchPercent)
	}
	if r.MissingRBAC != 0 {
		t.Errorf("expected MissingRBAC=0, got %d", r.MissingRBAC)
	}
	if r.ExtraRBAC != 0 {
		t.Errorf("expected ExtraRBAC=0, got %d", r.ExtraRBAC)
	}
}

func TestWorkloadModelCompare_Drift(t *testing.T) {
	golden := makeWorkloadReport("spn-platform-wkld-contoso",
		map[string]string{
			"aaa-1111": "azg-sub-contoso-hub-01",
			"aaa-2222": "azg-sub-contoso-spoke-01",
		},
		[]rbac.RoleAssignment{
			{RoleName: "Reader", Scope: "/subscriptions/aaa-1111", ScopeType: "Subscription"},
			{RoleName: "Contributor", Scope: "/subscriptions/aaa-2222", ScopeType: "Subscription"},
			{RoleName: "Key Vault Admin", Scope: "/subscriptions/aaa-1111", ScopeType: "Subscription"},
		},
	)

	target := makeWorkloadReport("spn-platform-wkld-fabrikam",
		map[string]string{
			"bbb-1111": "azg-sub-fabrikam-prod-01",
			"bbb-2222": "azg-sub-fabrikam-spoke-01",
		},
		[]rbac.RoleAssignment{
			{RoleName: "Reader", Scope: "/subscriptions/bbb-1111", ScopeType: "Subscription"},
			{RoleName: "Contributor", Scope: "/subscriptions/bbb-2222", ScopeType: "Subscription"},
		},
	)

	result := WorkloadModelCompare(golden, []*reportpkg.Report{target}, "", nil)

	if len(result.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(result.Results))
	}
	r := result.Results[0]

	// With env normalization, hub and prod both become {env}, so both
	// subscriptions normalize to azg-sub-{workload}-{env}-{n}.
	// Golden keys: Reader|..{env}.., Contributor|..{env}.., Key Vault Admin|..{env}..
	// Target keys: Reader|..{env}.., Contributor|..{env}..
	// Shared: Reader + Contributor (2), Missing: Key Vault Admin (1), Extra: 0
	if r.MissingRBAC != 1 {
		t.Errorf("expected MissingRBAC=1, got %d", r.MissingRBAC)
	}
	if r.ExtraRBAC != 0 {
		t.Errorf("expected ExtraRBAC=0, got %d", r.ExtraRBAC)
	}

	// shared=2, max(golden=3, target=2)=3 → 2/3 ≈ 66.67%
	wantPct := float64(2) / float64(3) * 100.0
	if !floatClose(r.MatchPercent, wantPct) {
		t.Errorf("expected MatchPercent≈%.2f, got %.2f", wantPct, r.MatchPercent)
	}
}

func TestWorkloadModelCompare_ExplicitWorkloadKey(t *testing.T) {
	golden := makeWorkloadReport("spn-platform-wkld-contoso",
		map[string]string{
			"aaa-1111": "azg-sub-contoso-hub-01",
			"aaa-2222": "azg-sub-contoso-spoke-01",
		},
		[]rbac.RoleAssignment{
			{RoleName: "Reader", Scope: "/subscriptions/aaa-1111", ScopeType: "Subscription"},
			{RoleName: "Contributor", Scope: "/subscriptions/aaa-2222", ScopeType: "Subscription"},
		},
	)

	target := makeWorkloadReport("spn-platform-wkld-litware",
		map[string]string{
			"bbb-1111": "azg-sub-litware-hub-01",
			"bbb-2222": "azg-sub-litware-spoke-01",
		},
		[]rbac.RoleAssignment{
			{RoleName: "Reader", Scope: "/subscriptions/bbb-1111", ScopeType: "Subscription"},
			{RoleName: "Contributor", Scope: "/subscriptions/bbb-2222", ScopeType: "Subscription"},
		},
	)

	result := WorkloadModelCompare(golden, []*reportpkg.Report{target}, "contoso", nil)

	// Explicit workload key should be stored in result.
	if result.GoldenWorkload != "contoso" {
		t.Errorf("expected GoldenWorkload=%q, got %q", "contoso", result.GoldenWorkload)
	}
	if len(result.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(result.Results))
	}
	if !floatClose(result.Results[0].MatchPercent, 100.0) {
		t.Errorf("expected MatchPercent≈100, got %.2f", result.Results[0].MatchPercent)
	}
}

func TestWorkloadModelCompare_FallbackNoWorkload(t *testing.T) {
	golden := makeWorkloadReport("generic-service-principal",
		map[string]string{
			"aaa-1111": "azg-sub-platform-hub-01",
		},
		[]rbac.RoleAssignment{
			{RoleName: "Reader", Scope: "/subscriptions/aaa-1111", ScopeType: "Subscription"},
		},
	)

	target := makeWorkloadReport("another-service-principal",
		map[string]string{
			"bbb-1111": "azg-sub-platform-hub-01",
		},
		[]rbac.RoleAssignment{
			{RoleName: "Reader", Scope: "/subscriptions/bbb-1111", ScopeType: "Subscription"},
		},
	)

	// No discernible workload name — should fall back gracefully.
	result := WorkloadModelCompare(golden, []*reportpkg.Report{target}, "", nil)

	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if len(result.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(result.Results))
	}
	// Sanity: MatchPercent is in [0, 100].
	pct := result.Results[0].MatchPercent
	if pct < 0.0 || pct > 100.0 {
		t.Errorf("MatchPercent out of range: %.2f", pct)
	}
}

func TestWorkloadModelCompare_MultipleTargets(t *testing.T) {
	golden := makeWorkloadReport("spn-platform-wkld-contoso",
		map[string]string{
			"aaa-1111": "azg-sub-contoso-hub-01",
			"aaa-2222": "azg-sub-contoso-spoke-01",
		},
		[]rbac.RoleAssignment{
			{RoleName: "Reader", Scope: "/subscriptions/aaa-1111", ScopeType: "Subscription"},
			{RoleName: "Contributor", Scope: "/subscriptions/aaa-2222", ScopeType: "Subscription"},
			{RoleName: "Key Vault Admin", Scope: "/subscriptions/aaa-1111", ScopeType: "Subscription"},
		},
	)

	// Target 1: 100% match (same structure, different workload name).
	t1 := makeWorkloadReport("spn-platform-wkld-litware",
		map[string]string{
			"bbb-1111": "azg-sub-litware-hub-01",
			"bbb-2222": "azg-sub-litware-spoke-01",
		},
		[]rbac.RoleAssignment{
			{RoleName: "Reader", Scope: "/subscriptions/bbb-1111", ScopeType: "Subscription"},
			{RoleName: "Contributor", Scope: "/subscriptions/bbb-2222", ScopeType: "Subscription"},
			{RoleName: "Key Vault Admin", Scope: "/subscriptions/bbb-1111", ScopeType: "Subscription"},
		},
	)

	// Target 2: partial match (hub vs prod suffix drift).
	t2 := makeWorkloadReport("spn-platform-wkld-fabrikam",
		map[string]string{
			"ccc-1111": "azg-sub-fabrikam-prod-01",
			"ccc-2222": "azg-sub-fabrikam-spoke-01",
		},
		[]rbac.RoleAssignment{
			{RoleName: "Reader", Scope: "/subscriptions/ccc-1111", ScopeType: "Subscription"},
			{RoleName: "Contributor", Scope: "/subscriptions/ccc-2222", ScopeType: "Subscription"},
		},
	)

	// Target 3: 0 matching RBAC (completely different roles).
	t3 := makeWorkloadReport("spn-platform-wkld-northwind",
		map[string]string{
			"ddd-1111": "azg-sub-northwind-hub-01",
			"ddd-2222": "azg-sub-northwind-spoke-01",
		},
		[]rbac.RoleAssignment{
			{RoleName: "Owner", Scope: "/subscriptions/ddd-1111", ScopeType: "Subscription"},
			{RoleName: "Network Contributor", Scope: "/subscriptions/ddd-2222", ScopeType: "Subscription"},
		},
	)

	result := WorkloadModelCompare(golden, []*reportpkg.Report{t1, t2, t3}, "", nil)

	if len(result.Results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(result.Results))
	}

	// Results must be sorted by MatchPercent descending.
	if result.Results[0].Target.DisplayName != "spn-platform-wkld-litware" {
		t.Errorf("expected first=litware, got %s", result.Results[0].Target.DisplayName)
	}
	if result.Results[1].Target.DisplayName != "spn-platform-wkld-fabrikam" {
		t.Errorf("expected second=fabrikam, got %s", result.Results[1].Target.DisplayName)
	}
	if result.Results[2].Target.DisplayName != "spn-platform-wkld-northwind" {
		t.Errorf("expected third=northwind, got %s", result.Results[2].Target.DisplayName)
	}

	if !floatClose(result.Results[0].MatchPercent, 100.0) {
		t.Errorf("expected litware MatchPercent≈100, got %.2f", result.Results[0].MatchPercent)
	}

	// fabrikam: with env normalization, hub/spoke/prod all become {env},
	// so Reader + Contributor match (shared=2), only Key Vault Admin missing.
	// 2/3 ≈ 66.67%
	wantPartialPct := float64(2) / float64(3) * 100.0
	if !floatClose(result.Results[1].MatchPercent, wantPartialPct) {
		t.Errorf("expected fabrikam MatchPercent≈%.2f, got %.2f", wantPartialPct, result.Results[1].MatchPercent)
	}

	if !floatClose(result.Results[2].MatchPercent, 0.0) {
		t.Errorf("expected northwind MatchPercent≈0, got %.2f", result.Results[2].MatchPercent)
	}
}

func TestWorkloadModelCompare_CommonScopes(t *testing.T) {
	commonSubID := "ccc-3333"
	commonSubName := "azg-sub-shared-services-01"

	golden := makeWorkloadReport("spn-platform-wkld-contoso",
		map[string]string{
			"aaa-1111":  "azg-sub-contoso-hub-01",
			commonSubID: commonSubName,
		},
		[]rbac.RoleAssignment{
			{RoleName: "Reader", Scope: "/subscriptions/aaa-1111", ScopeType: "Subscription"},
			{RoleName: "Reader", Scope: "/subscriptions/" + commonSubID, ScopeType: "Subscription"},
		},
	)

	target := makeWorkloadReport("spn-platform-wkld-litware",
		map[string]string{
			"bbb-1111":  "azg-sub-litware-hub-01",
			commonSubID: commonSubName,
		},
		[]rbac.RoleAssignment{
			{RoleName: "Reader", Scope: "/subscriptions/bbb-1111", ScopeType: "Subscription"},
			{RoleName: "Reader", Scope: "/subscriptions/" + commonSubID, ScopeType: "Subscription"},
		},
	)

	result := WorkloadModelCompare(golden, []*reportpkg.Report{target}, "", nil)

	if len(result.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(result.Results))
	}
	r := result.Results[0]

	// Workload-specific sub normalizes: Reader|azg-sub-{workload}-{env}-{n} → match.
	// Common sub has no workload name: Reader|azg-sub-shared-services-{n} → exact match.
	if !floatClose(r.MatchPercent, 100.0) {
		t.Errorf("expected MatchPercent≈100, got %.2f", r.MatchPercent)
	}
	if r.MissingRBAC != 0 {
		t.Errorf("expected MissingRBAC=0, got %d", r.MissingRBAC)
	}
	if r.ExtraRBAC != 0 {
		t.Errorf("expected ExtraRBAC=0, got %d", r.ExtraRBAC)
	}
}
