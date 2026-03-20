package report

import (
	"testing"

	"github.com/jpmicrosoft/azure-rbac-inventory/internal/identity"
	"github.com/jpmicrosoft/azure-rbac-inventory/internal/rbac"
)

func TestMergeRelatedReports_EmptyInput(t *testing.T) {
	t.Run("nil input", func(t *testing.T) {
		got := MergeRelatedReports(nil)
		if len(got) != 0 {
			t.Errorf("MergeRelatedReports(nil) returned %d reports, want 0", len(got))
		}
	})

	t.Run("empty slice", func(t *testing.T) {
		got := MergeRelatedReports([]*Report{})
		if len(got) != 0 {
			t.Errorf("MergeRelatedReports([]) returned %d reports, want 0", len(got))
		}
	})
}

func TestMergeRelatedReports_NoMerge(t *testing.T) {
	rpt1 := &Report{
		Identity: &identity.Identity{
			ObjectID:    "oid-1",
			AppID:       "app-1",
			DisplayName: "Alpha",
			Type:        identity.TypeServicePrincipal,
		},
		Cloud: "AzureCloud",
		RBACAssignments: []rbac.RoleAssignment{
			{RoleName: "Reader", Scope: "/subscriptions/sub1"},
		},
	}
	rpt2 := &Report{
		Identity: &identity.Identity{
			ObjectID:    "oid-2",
			AppID:       "app-2",
			DisplayName: "Bravo",
			Type:        identity.TypeUser,
		},
		Cloud: "AzureCloud",
		RBACAssignments: []rbac.RoleAssignment{
			{RoleName: "Contributor", Scope: "/subscriptions/sub2"},
		},
	}

	got := MergeRelatedReports([]*Report{rpt1, rpt2})

	if len(got) != 2 {
		t.Fatalf("expected 2 reports, got %d", len(got))
	}
	if got[0].Identity.DisplayName != "Alpha" {
		t.Errorf("first report name = %q, want Alpha", got[0].Identity.DisplayName)
	}
	if got[1].Identity.DisplayName != "Bravo" {
		t.Errorf("second report name = %q, want Bravo", got[1].Identity.DisplayName)
	}
	for _, r := range got {
		if r.Identity.IsMerged {
			t.Errorf("report %q should not be marked as merged", r.Identity.DisplayName)
		}
	}
}

func TestMergeRelatedReports_MergeSameAppID(t *testing.T) {
	spn := &Report{
		Identity: &identity.Identity{
			ObjectID:    "oid-spn",
			AppID:       "shared-app-id",
			DisplayName: "MyApp",
			Type:        identity.TypeServicePrincipal,
		},
		Cloud: "AzureCloud",
		RBACAssignments: []rbac.RoleAssignment{
			{RoleName: "Reader", Scope: "/subscriptions/sub1"},
			{RoleName: "Contributor", Scope: "/subscriptions/sub2"},
		},
	}
	app := &Report{
		Identity: &identity.Identity{
			ObjectID:    "oid-app",
			AppID:       "shared-app-id",
			DisplayName: "MyApp",
			Type:        identity.TypeApplication,
		},
		Cloud: "AzureCloud",
		RBACAssignments: []rbac.RoleAssignment{
			{RoleName: "Owner", Scope: "/subscriptions/sub3"},
		},
	}

	got := MergeRelatedReports([]*Report{spn, app})

	if len(got) != 1 {
		t.Fatalf("expected 1 merged report, got %d", len(got))
	}

	merged := got[0]
	if !merged.Identity.IsMerged {
		t.Error("merged report should have IsMerged=true")
	}
	if merged.Identity.Type != identity.TypeServicePrincipal {
		t.Errorf("merged identity type = %q, want ServicePrincipal", merged.Identity.Type)
	}
	if merged.Identity.AppID != "shared-app-id" {
		t.Errorf("merged AppID = %q, want shared-app-id", merged.Identity.AppID)
	}
	if len(merged.RBACAssignments) != 3 {
		t.Errorf("expected 3 RBAC assignments, got %d", len(merged.RBACAssignments))
	}
}

func TestMergeRelatedReports_SameNameDifferentAppID(t *testing.T) {
	rpt1 := &Report{
		Identity: &identity.Identity{
			ObjectID:    "oid-1",
			AppID:       "app-id-a",
			DisplayName: "SameName",
			Type:        identity.TypeServicePrincipal,
		},
		Cloud: "AzureCloud",
	}
	rpt2 := &Report{
		Identity: &identity.Identity{
			ObjectID:    "oid-2",
			AppID:       "app-id-b",
			DisplayName: "SameName",
			Type:        identity.TypeApplication,
		},
		Cloud: "AzureCloud",
	}

	got := MergeRelatedReports([]*Report{rpt1, rpt2})

	if len(got) != 2 {
		t.Fatalf("expected 2 reports (different AppIDs), got %d", len(got))
	}
	for _, r := range got {
		if r.Identity.IsMerged {
			t.Errorf("report %q should not be merged (different AppIDs)", r.Identity.DisplayName)
		}
	}
}

func TestMergeRelatedReports_DeduplicatesRBAC(t *testing.T) {
	rpt1 := &Report{
		Identity: &identity.Identity{
			ObjectID:    "oid-1",
			AppID:       "shared-app",
			DisplayName: "DupApp",
			Type:        identity.TypeServicePrincipal,
		},
		Cloud: "AzureCloud",
		RBACAssignments: []rbac.RoleAssignment{
			{RoleName: "Reader", Scope: "/subscriptions/sub1"},
			{RoleName: "Contributor", Scope: "/subscriptions/sub2"},
		},
	}
	rpt2 := &Report{
		Identity: &identity.Identity{
			ObjectID:    "oid-2",
			AppID:       "shared-app",
			DisplayName: "DupApp",
			Type:        identity.TypeApplication,
		},
		Cloud: "AzureCloud",
		RBACAssignments: []rbac.RoleAssignment{
			{RoleName: "Reader", Scope: "/subscriptions/sub1"}, // duplicate
			{RoleName: "Owner", Scope: "/subscriptions/sub3"},  // unique
		},
	}

	got := MergeRelatedReports([]*Report{rpt1, rpt2})

	if len(got) != 1 {
		t.Fatalf("expected 1 merged report, got %d", len(got))
	}

	merged := got[0]
	if len(merged.RBACAssignments) != 3 {
		t.Errorf("expected 3 deduplicated RBAC assignments, got %d", len(merged.RBACAssignments))
		for i, a := range merged.RBACAssignments {
			t.Logf("  [%d] %s @ %s", i, a.RoleName, a.Scope)
		}
	}

	// Verify the specific roles are present.
	roles := map[string]bool{}
	for _, a := range merged.RBACAssignments {
		roles[a.RoleName+"|"+a.Scope] = true
	}
	expected := []string{
		"Reader|/subscriptions/sub1",
		"Contributor|/subscriptions/sub2",
		"Owner|/subscriptions/sub3",
	}
	for _, e := range expected {
		if !roles[e] {
			t.Errorf("missing expected RBAC assignment: %s", e)
		}
	}
}
