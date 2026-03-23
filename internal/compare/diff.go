package compare

import (
	"sort"

	"github.com/jpmicrosoft/azure-rbac-inventory/internal/graph"
	"github.com/jpmicrosoft/azure-rbac-inventory/internal/identity"
	"github.com/jpmicrosoft/azure-rbac-inventory/internal/rbac"
	reportpkg "github.com/jpmicrosoft/azure-rbac-inventory/internal/report"
)

// DiffCategory represents a category of comparison items.
type DiffCategory string

const (
	CategoryRBAC           DiffCategory = "RBAC"
	CategoryDirectoryRoles DiffCategory = "DirectoryRoles"
	CategoryGroups         DiffCategory = "Groups"
	CategoryAccessPackages DiffCategory = "AccessPackages"
)

// RBACDiff holds RBAC role assignments split into only-A, only-B, shared.
type RBACDiff struct {
	OnlyA  []rbac.RoleAssignment
	OnlyB  []rbac.RoleAssignment
	Shared []rbac.RoleAssignment
}

// RoleDiff holds directory roles split into only-A, only-B, shared.
type RoleDiff struct {
	OnlyA  []graph.DirectoryRole
	OnlyB  []graph.DirectoryRole
	Shared []graph.DirectoryRole
}

// GroupDiff holds group memberships split into only-A, only-B, shared.
type GroupDiff struct {
	OnlyA  []graph.GroupMembership
	OnlyB  []graph.GroupMembership
	Shared []graph.GroupMembership
}

// PackageDiff holds access package assignments split into only-A, only-B, shared.
type PackageDiff struct {
	OnlyA  []graph.AccessPackageAssignment
	OnlyB  []graph.AccessPackageAssignment
	Shared []graph.AccessPackageAssignment
}

// ComparisonResult holds the full comparison between two identities.
type ComparisonResult struct {
	IdentityA      *identity.Identity
	IdentityB      *identity.Identity
	Cloud          string
	RBAC           RBACDiff
	DirectoryRoles RoleDiff
	Groups         GroupDiff
	AccessPackages PackageDiff
	WarningsA      []string
	WarningsB      []string
	MatchPercent   float64
}

// ModelTargetResult holds the comparison of one target against the model.
type ModelTargetResult struct {
	Target        *identity.Identity
	Comparison    *ComparisonResult
	MatchPercent  float64
	MissingRBAC   int // in model but not target
	ExtraRBAC     int // in target but not model
	MissingRoles  int
	ExtraRoles    int
	MissingGroups int
	ExtraGroups   int
}

// ModelComparisonResult holds the full 1:N model comparison.
type ModelComparisonResult struct {
	Model   *identity.Identity
	Cloud   string
	Results []ModelTargetResult
}

// rbacKey returns the comparison key for an RBAC assignment.
// Uses the full Scope path (not just ScopeType) so that assignments at
// different scopes (e.g. two different subscriptions) are not conflated.
func rbacKey(a rbac.RoleAssignment) string {
	return a.RoleName + "|" + a.Scope
}

// roleKey returns the comparison key for a directory role.
func roleKey(r graph.DirectoryRole) string {
	return r.RoleName
}

// groupKey returns the comparison key for a group membership.
func groupKey(g graph.GroupMembership) string {
	return g.GroupName
}

// packageKey returns the comparison key for an access package.
func packageKey(p graph.AccessPackageAssignment) string {
	return p.PackageName + "|" + p.CatalogName
}

// CompareReports compares two reports and returns a ComparisonResult.
func CompareReports(a, b *reportpkg.Report) *ComparisonResult {
	result := &ComparisonResult{
		IdentityA: a.Identity,
		IdentityB: b.Identity,
		Cloud:     a.Cloud,
		WarningsA: a.Warnings,
		WarningsB: b.Warnings,
	}

	// --- RBAC comparison (counting approach for duplicate keys) ---
	result.RBAC = diffRBAC(a.RBACAssignments, b.RBACAssignments)

	// --- Directory Roles comparison (simple set diff by RoleName) ---
	result.DirectoryRoles = diffRoles(a.DirectoryRoles, b.DirectoryRoles)

	// --- Groups comparison (simple set diff by GroupName) ---
	result.Groups = diffGroups(a.GroupMemberships, b.GroupMemberships)

	// --- Access Packages comparison (simple set diff by PackageName|CatalogName) ---
	result.AccessPackages = diffPackages(a.AccessPackages, b.AccessPackages)

	// --- Match percentage ---
	sharedTotal := len(result.RBAC.Shared) + len(result.DirectoryRoles.Shared) +
		len(result.Groups.Shared) + len(result.AccessPackages.Shared)

	totalA := len(a.RBACAssignments) + len(a.DirectoryRoles) +
		len(a.GroupMemberships) + len(a.AccessPackages)
	totalB := len(b.RBACAssignments) + len(b.DirectoryRoles) +
		len(b.GroupMemberships) + len(b.AccessPackages)

	maxTotal := totalA
	if totalB > maxTotal {
		maxTotal = totalB
	}

	if maxTotal == 0 {
		result.MatchPercent = 100.0
	} else {
		result.MatchPercent = float64(sharedTotal) / float64(maxTotal) * 100.0
	}

	return result
}

// diffRBAC compares RBAC assignments using a counting approach for duplicate keys.
func diffRBAC(aList, bList []rbac.RoleAssignment) RBACDiff {
	type entry struct {
		items []rbac.RoleAssignment
		count int
	}

	// Build ordered counts for A.
	aKeys := make(map[string]*entry)
	for _, item := range aList {
		k := rbacKey(item)
		if e, ok := aKeys[k]; ok {
			e.items = append(e.items, item)
			e.count++
		} else {
			aKeys[k] = &entry{items: []rbac.RoleAssignment{item}, count: 1}
		}
	}

	// Build ordered counts for B.
	bKeys := make(map[string]*entry)
	for _, item := range bList {
		k := rbacKey(item)
		if e, ok := bKeys[k]; ok {
			e.items = append(e.items, item)
			e.count++
		} else {
			bKeys[k] = &entry{items: []rbac.RoleAssignment{item}, count: 1}
		}
	}

	var diff RBACDiff

	// Walk A keys.
	for k, ae := range aKeys {
		if be, ok := bKeys[k]; ok {
			shared := ae.count
			if be.count < shared {
				shared = be.count
			}
			// Shared: take 'shared' items from A side.
			for i := 0; i < shared; i++ {
				diff.Shared = append(diff.Shared, ae.items[i])
			}
			// Excess in A → OnlyA.
			for i := shared; i < ae.count; i++ {
				diff.OnlyA = append(diff.OnlyA, ae.items[i])
			}
		} else {
			diff.OnlyA = append(diff.OnlyA, ae.items...)
		}
	}

	// Walk B keys for items not shared (excess in B).
	for k, be := range bKeys {
		if ae, ok := aKeys[k]; ok {
			shared := ae.count
			if be.count < shared {
				shared = be.count
			}
			for i := shared; i < be.count; i++ {
				diff.OnlyB = append(diff.OnlyB, be.items[i])
			}
		} else {
			diff.OnlyB = append(diff.OnlyB, be.items...)
		}
	}

	return diff
}

// diffRoles compares directory roles using a simple set diff by RoleName.
func diffRoles(aList, bList []graph.DirectoryRole) RoleDiff {
	bSet := make(map[string]bool, len(bList))
	for _, r := range bList {
		bSet[roleKey(r)] = true
	}

	aSet := make(map[string]bool, len(aList))
	for _, r := range aList {
		aSet[roleKey(r)] = true
	}

	var diff RoleDiff
	for _, r := range aList {
		if bSet[roleKey(r)] {
			diff.Shared = append(diff.Shared, r)
		} else {
			diff.OnlyA = append(diff.OnlyA, r)
		}
	}
	for _, r := range bList {
		if !aSet[roleKey(r)] {
			diff.OnlyB = append(diff.OnlyB, r)
		}
	}
	return diff
}

// diffGroups compares group memberships using a simple set diff by GroupName.
func diffGroups(aList, bList []graph.GroupMembership) GroupDiff {
	bSet := make(map[string]bool, len(bList))
	for _, g := range bList {
		bSet[groupKey(g)] = true
	}

	aSet := make(map[string]bool, len(aList))
	for _, g := range aList {
		aSet[groupKey(g)] = true
	}

	var diff GroupDiff
	for _, g := range aList {
		if bSet[groupKey(g)] {
			diff.Shared = append(diff.Shared, g)
		} else {
			diff.OnlyA = append(diff.OnlyA, g)
		}
	}
	for _, g := range bList {
		if !aSet[groupKey(g)] {
			diff.OnlyB = append(diff.OnlyB, g)
		}
	}
	return diff
}

// diffPackages compares access package assignments using a simple set diff.
func diffPackages(aList, bList []graph.AccessPackageAssignment) PackageDiff {
	bSet := make(map[string]bool, len(bList))
	for _, p := range bList {
		bSet[packageKey(p)] = true
	}

	aSet := make(map[string]bool, len(aList))
	for _, p := range aList {
		aSet[packageKey(p)] = true
	}

	var diff PackageDiff
	for _, p := range aList {
		if bSet[packageKey(p)] {
			diff.Shared = append(diff.Shared, p)
		} else {
			diff.OnlyA = append(diff.OnlyA, p)
		}
	}
	for _, p := range bList {
		if !aSet[packageKey(p)] {
			diff.OnlyB = append(diff.OnlyB, p)
		}
	}
	return diff
}

// ModelCompare compares a model report against multiple target reports.
func ModelCompare(model *reportpkg.Report, targets []*reportpkg.Report) *ModelComparisonResult {
	mcr := &ModelComparisonResult{
		Model:   model.Identity,
		Cloud:   model.Cloud,
		Results: make([]ModelTargetResult, 0, len(targets)),
	}

	for _, target := range targets {
		comp := CompareReports(model, target)
		mtr := ModelTargetResult{
			Target:        target.Identity,
			Comparison:    comp,
			MatchPercent:  comp.MatchPercent,
			MissingRBAC:   len(comp.RBAC.OnlyA),
			ExtraRBAC:     len(comp.RBAC.OnlyB),
			MissingRoles:  len(comp.DirectoryRoles.OnlyA),
			ExtraRoles:    len(comp.DirectoryRoles.OnlyB),
			MissingGroups: len(comp.Groups.OnlyA),
			ExtraGroups:   len(comp.Groups.OnlyB),
		}
		mcr.Results = append(mcr.Results, mtr)
	}

	// Sort by MatchPercent descending (best matches first).
	sort.Slice(mcr.Results, func(i, j int) bool {
		return mcr.Results[i].MatchPercent > mcr.Results[j].MatchPercent
	})

	return mcr
}
