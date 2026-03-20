package report

import (
	"testing"

	"github.com/jpmicrosoft/azure-rbac-inventory/internal/graph"
	"github.com/jpmicrosoft/azure-rbac-inventory/internal/identity"
	"github.com/jpmicrosoft/azure-rbac-inventory/internal/rbac"
)

func TestNewMultiReport_EmptySlice(t *testing.T) {
	mr := NewMultiReport(nil)
	if mr == nil {
		t.Fatal("NewMultiReport(nil) returned nil")
	}
	if len(mr.Reports) != 0 {
		t.Errorf("Reports length = %d, want 0", len(mr.Reports))
	}
	if mr.TotalRBAC != 0 || mr.TotalDirRoles != 0 || mr.TotalPackages != 0 || mr.TotalGroups != 0 || mr.TotalWarnings != 0 {
		t.Errorf("all totals should be 0 for empty slice, got RBAC=%d DirRoles=%d Packages=%d Groups=%d Warnings=%d",
			mr.TotalRBAC, mr.TotalDirRoles, mr.TotalPackages, mr.TotalGroups, mr.TotalWarnings)
	}
}

func TestNewMultiReport_SingleReport(t *testing.T) {
	rpt := &Report{
		Identity: &identity.Identity{
			ObjectID:    "00000000-0000-0000-0000-000000000001",
			DisplayName: "Test",
			Type:        identity.TypeUser,
		},
		Cloud: "AzureCloud",
		RBACAssignments: []rbac.RoleAssignment{
			{RoleName: "Reader"},
			{RoleName: "Contributor"},
		},
		DirectoryRoles: []graph.DirectoryRole{
			{RoleName: "Global Reader"},
		},
		AccessPackages: []graph.AccessPackageAssignment{
			{PackageName: "Dev Access"},
			{PackageName: "Prod Access"},
			{PackageName: "Test Access"},
		},
		GroupMemberships: []graph.GroupMembership{
			{GroupName: "Engineering"},
		},
		Warnings: []string{"warning1", "warning2"},
	}

	mr := NewMultiReport([]*Report{rpt})

	if len(mr.Reports) != 1 {
		t.Fatalf("Reports length = %d, want 1", len(mr.Reports))
	}
	if mr.TotalRBAC != 2 {
		t.Errorf("TotalRBAC = %d, want 2", mr.TotalRBAC)
	}
	if mr.TotalDirRoles != 1 {
		t.Errorf("TotalDirRoles = %d, want 1", mr.TotalDirRoles)
	}
	if mr.TotalPackages != 3 {
		t.Errorf("TotalPackages = %d, want 3", mr.TotalPackages)
	}
	if mr.TotalGroups != 1 {
		t.Errorf("TotalGroups = %d, want 1", mr.TotalGroups)
	}
	if mr.TotalWarnings != 2 {
		t.Errorf("TotalWarnings = %d, want 2", mr.TotalWarnings)
	}
}

func TestNewMultiReport_MultipleReports(t *testing.T) {
	rpt1 := &Report{
		Identity: &identity.Identity{ObjectID: "id-1", DisplayName: "First", Type: identity.TypeUser},
		RBACAssignments: []rbac.RoleAssignment{
			{RoleName: "Reader"},
		},
		DirectoryRoles: []graph.DirectoryRole{
			{RoleName: "Admin"},
		},
		GroupMemberships: []graph.GroupMembership{
			{GroupName: "Group1"},
			{GroupName: "Group2"},
		},
		Warnings: []string{"warn1"},
	}

	rpt2 := &Report{
		Identity: &identity.Identity{ObjectID: "id-2", DisplayName: "Second", Type: identity.TypeServicePrincipal},
		RBACAssignments: []rbac.RoleAssignment{
			{RoleName: "Contributor"},
			{RoleName: "Owner"},
			{RoleName: "Reader"},
		},
		AccessPackages: []graph.AccessPackageAssignment{
			{PackageName: "Access1"},
		},
	}

	mr := NewMultiReport([]*Report{rpt1, rpt2})

	if len(mr.Reports) != 2 {
		t.Fatalf("Reports length = %d, want 2", len(mr.Reports))
	}
	if mr.TotalRBAC != 4 {
		t.Errorf("TotalRBAC = %d, want 4 (1 + 3)", mr.TotalRBAC)
	}
	if mr.TotalDirRoles != 1 {
		t.Errorf("TotalDirRoles = %d, want 1", mr.TotalDirRoles)
	}
	if mr.TotalPackages != 1 {
		t.Errorf("TotalPackages = %d, want 1", mr.TotalPackages)
	}
	if mr.TotalGroups != 2 {
		t.Errorf("TotalGroups = %d, want 2", mr.TotalGroups)
	}
	if mr.TotalWarnings != 1 {
		t.Errorf("TotalWarnings = %d, want 1", mr.TotalWarnings)
	}
}

func TestNewMultiReport_AllEmptyReports(t *testing.T) {
	rpt1 := &Report{
		Identity: &identity.Identity{ObjectID: "id-1", DisplayName: "Empty1", Type: identity.TypeUser},
	}
	rpt2 := &Report{
		Identity: &identity.Identity{ObjectID: "id-2", DisplayName: "Empty2", Type: identity.TypeGroup},
	}

	mr := NewMultiReport([]*Report{rpt1, rpt2})

	if len(mr.Reports) != 2 {
		t.Fatalf("Reports length = %d, want 2", len(mr.Reports))
	}
	if mr.TotalRBAC != 0 || mr.TotalDirRoles != 0 || mr.TotalPackages != 0 || mr.TotalGroups != 0 || mr.TotalWarnings != 0 {
		t.Error("all totals should be 0 for reports with no data")
	}
}

func TestReport_ZeroValue(t *testing.T) {
	rpt := &Report{}
	if rpt.Identity != nil {
		t.Error("zero-value report should have nil Identity")
	}
	if rpt.Cloud != "" {
		t.Error("zero-value report should have empty Cloud")
	}
	if rpt.RBACAssignments != nil {
		t.Error("zero-value report should have nil RBACAssignments")
	}
	if rpt.Warnings != nil {
		t.Error("zero-value report should have nil Warnings")
	}
}
