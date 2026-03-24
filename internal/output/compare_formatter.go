package output

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/jpmicrosoft/azure-rbac-inventory/internal/compare"
	"github.com/jpmicrosoft/azure-rbac-inventory/internal/graph"
	"github.com/jpmicrosoft/azure-rbac-inventory/internal/rbac"
)

// PrintCompare renders a 1:1 comparison result as formatted console tables.
func PrintCompare(result *compare.ComparisonResult) {
	printCompareHeader(result)
	printRBACDiff(result)
	printRoleDiff(result)
	printGroupDiff(result)
	printPackageDiff(result)
}

func printCompareHeader(result *compare.ComparisonResult) {
	fmt.Println()
	fmt.Println("  ======================================================")
	fmt.Println("   Azure RBAC Inventory - Comparison Report")
	fmt.Println("  ======================================================")
	fmt.Println()
	fmt.Printf("    Identity A:  %s (%s)\n", result.IdentityA.DisplayName, string(result.IdentityA.Type))
	fmt.Printf("    Identity B:  %s (%s)\n", result.IdentityB.DisplayName, string(result.IdentityB.Type))
	fmt.Printf("    Cloud:       %s\n", result.Cloud)
	fmt.Printf("    Match:       %.1f%%\n", result.MatchPercent)
	fmt.Println()
}

// rbacLabel formats an RBAC assignment for display: "RoleName (ScopeType) — Scope".
func rbacLabel(a rbac.RoleAssignment) string {
	return fmt.Sprintf("%s (%s) — %s", a.RoleName, a.ScopeType, a.Scope)
}

// rbacLabelShort formats an RBAC assignment without scope path for compact display.
func rbacLabelShort(a rbac.RoleAssignment) string {
	return fmt.Sprintf("%s (%s)", a.RoleName, a.ScopeType)
}

// rbacSharedLabel formats a shared RBAC item, appending [xN] when count > 1.
func rbacSharedLabel(label string, count int) string {
	if count > 1 {
		return fmt.Sprintf("%s [x%d]", label, count)
	}
	return label
}

// scopeDiffSegments compares two ARM scope paths segment-by-segment and returns
// the model and target paths with differing segments wrapped in brackets for
// terminal display.
func scopeDiffSegments(modelScope, targetScope string) (string, string) {
	mParts := strings.Split(modelScope, "/")
	tParts := strings.Split(targetScope, "/")

	mOut := make([]string, len(mParts))
	tOut := make([]string, len(tParts))

	minLen := len(mParts)
	if len(tParts) < minLen {
		minLen = len(tParts)
	}

	for i := 0; i < minLen; i++ {
		if strings.EqualFold(mParts[i], tParts[i]) {
			mOut[i] = mParts[i]
			tOut[i] = tParts[i]
		} else {
			mOut[i] = "[" + mParts[i] + "]"
			tOut[i] = "[" + tParts[i] + "]"
		}
	}
	for i := minLen; i < len(mParts); i++ {
		mOut[i] = "[" + mParts[i] + "]"
	}
	for i := minLen; i < len(tParts); i++ {
		tOut[i] = "[" + tParts[i] + "]"
	}
	return strings.Join(mOut, "/"), strings.Join(tOut, "/")
}

func printRBACDiff(result *compare.ComparisonResult) {
	diff := result.RBAC
	fmt.Println("  [RBAC] Role Assignment Differences")
	fmt.Println("  " + strings.Repeat("-", 54))

	if len(diff.OnlyA) == 0 && len(diff.OnlyB) == 0 && len(diff.Shared) == 0 && len(diff.Inferred) == 0 {
		fmt.Println("    No assignments found.")
		fmt.Println()
		return
	}

	if len(diff.OnlyA) == 0 && len(diff.OnlyB) == 0 {
		fmt.Printf("    No differences found.\n")
		fmt.Printf("    Shared (%d)\n", len(diff.Shared))
		if len(diff.Inferred) > 0 {
			fmt.Printf("    Inferred Matches (%d)\n", len(diff.Inferred))
		}
		fmt.Println()
		return
	}

	// Only in A
	fmt.Printf("    Only in A (%d):\n", len(diff.OnlyA))
	if len(diff.OnlyA) == 0 {
		fmt.Println("      None.")
	} else {
		for _, a := range diff.OnlyA {
			fmt.Printf("      ✗ %s\n", rbacLabel(a))
		}
	}
	fmt.Println()

	// Only in B
	fmt.Printf("    Only in B (%d):\n", len(diff.OnlyB))
	if len(diff.OnlyB) == 0 {
		fmt.Println("      None.")
	} else {
		for _, a := range diff.OnlyB {
			fmt.Printf("      ✗ %s\n", rbacLabel(a))
		}
	}
	fmt.Println()

	// Shared – collapse duplicates by RoleName|ScopeType and show count
	fmt.Printf("    Shared (%d):\n", len(diff.Shared))
	if len(diff.Shared) == 0 {
		fmt.Println("      None.")
	} else {
		type sharedEntry struct {
			label string
			count int
		}
		seen := map[string]*sharedEntry{}
		order := []string{}
		for _, a := range diff.Shared {
			lbl := rbacLabelShort(a)
			if e, ok := seen[lbl]; ok {
				e.count++
			} else {
				seen[lbl] = &sharedEntry{label: lbl, count: 1}
				order = append(order, lbl)
			}
		}
		sort.Strings(order)
		for _, lbl := range order {
			e := seen[lbl]
			fmt.Printf("      ✓ %s\n", rbacSharedLabel(e.label, e.count))
		}
	}
	fmt.Println()

	// Inferred Matches – show paired model/target scopes with diff highlighting
	if len(diff.Inferred) > 0 {
		fmt.Printf("    Inferred Matches (%d):\n", len(diff.Inferred))
		for _, im := range diff.Inferred {
			fmt.Printf("      ≈ %s (%s)\n", im.Model.RoleName, im.Model.ScopeType)
			mScope, tScope := scopeDiffSegments(im.Model.Scope, im.Target.Scope)
			fmt.Printf("          Model:  %s\n", mScope)
			fmt.Printf("          Target: %s\n", tScope)
		}
		fmt.Println()
	}
}

func printRoleDiff(result *compare.ComparisonResult) {
	diff := result.DirectoryRoles
	fmt.Println("  [ROLES] Directory Role Differences")
	fmt.Println("  " + strings.Repeat("-", 54))

	if len(diff.OnlyA) == 0 && len(diff.OnlyB) == 0 && len(diff.Shared) == 0 {
		fmt.Println("    No assignments found.")
		fmt.Println()
		return
	}

	if len(diff.OnlyA) == 0 && len(diff.OnlyB) == 0 {
		fmt.Printf("    No differences found.\n")
		fmt.Printf("    Shared (%d)\n", len(diff.Shared))
		fmt.Println()
		return
	}

	fmt.Printf("    Only in A (%d):\n", len(diff.OnlyA))
	if len(diff.OnlyA) == 0 {
		fmt.Println("      None.")
	} else {
		for _, r := range diff.OnlyA {
			fmt.Printf("      ✗ %s\n", r.RoleName)
		}
	}

	fmt.Printf("    Only in B (%d):\n", len(diff.OnlyB))
	if len(diff.OnlyB) == 0 {
		fmt.Println("      None.")
	} else {
		for _, r := range diff.OnlyB {
			fmt.Printf("      ✗ %s\n", r.RoleName)
		}
	}

	fmt.Printf("    Shared (%d):\n", len(diff.Shared))
	if len(diff.Shared) == 0 {
		fmt.Println("      None.")
	} else {
		for _, r := range diff.Shared {
			fmt.Printf("      ✓ %s\n", r.RoleName)
		}
	}
	fmt.Println()
}

func printGroupDiff(result *compare.ComparisonResult) {
	diff := result.Groups
	fmt.Println("  [GROUPS] Group Membership Differences")
	fmt.Println("  " + strings.Repeat("-", 54))

	if len(diff.OnlyA) == 0 && len(diff.OnlyB) == 0 && len(diff.Shared) == 0 {
		fmt.Println("    No assignments found.")
		fmt.Println()
		return
	}

	if len(diff.OnlyA) == 0 && len(diff.OnlyB) == 0 {
		fmt.Printf("    No differences found.\n")
		fmt.Printf("    Shared (%d)\n", len(diff.Shared))
		fmt.Println()
		return
	}

	fmt.Printf("    Only in A (%d):\n", len(diff.OnlyA))
	if len(diff.OnlyA) == 0 {
		fmt.Println("      None.")
	} else {
		for _, g := range diff.OnlyA {
			fmt.Printf("      ✗ %s (%s)\n", g.GroupName, g.GroupType)
		}
	}

	fmt.Printf("    Only in B (%d):\n", len(diff.OnlyB))
	if len(diff.OnlyB) == 0 {
		fmt.Println("      None.")
	} else {
		for _, g := range diff.OnlyB {
			fmt.Printf("      ✗ %s (%s)\n", g.GroupName, g.GroupType)
		}
	}

	fmt.Printf("    Shared (%d):\n", len(diff.Shared))
	if len(diff.Shared) == 0 {
		fmt.Println("      None.")
	} else {
		for _, g := range diff.Shared {
			fmt.Printf("      ✓ %s (%s)\n", g.GroupName, g.GroupType)
		}
	}
	fmt.Println()
}

func printPackageDiff(result *compare.ComparisonResult) {
	diff := result.AccessPackages
	fmt.Println("  [PACKAGES] Access Package Differences")
	fmt.Println("  " + strings.Repeat("-", 54))

	if len(diff.OnlyA) == 0 && len(diff.OnlyB) == 0 && len(diff.Shared) == 0 {
		fmt.Println("    No assignments found.")
		fmt.Println()
		return
	}

	if len(diff.OnlyA) == 0 && len(diff.OnlyB) == 0 {
		fmt.Printf("    No differences found.\n")
		fmt.Printf("    Shared (%d)\n", len(diff.Shared))
		fmt.Println()
		return
	}

	fmt.Printf("    Only in A (%d):\n", len(diff.OnlyA))
	if len(diff.OnlyA) == 0 {
		fmt.Println("      None.")
	} else {
		for _, p := range diff.OnlyA {
			fmt.Printf("      ✗ %s (%s)\n", p.PackageName, p.CatalogName)
		}
	}

	fmt.Printf("    Only in B (%d):\n", len(diff.OnlyB))
	if len(diff.OnlyB) == 0 {
		fmt.Println("      None.")
	} else {
		for _, p := range diff.OnlyB {
			fmt.Printf("      ✗ %s (%s)\n", p.PackageName, p.CatalogName)
		}
	}

	fmt.Printf("    Shared (%d):\n", len(diff.Shared))
	if len(diff.Shared) == 0 {
		fmt.Println("      None.")
	} else {
		for _, p := range diff.Shared {
			fmt.Printf("      ✓ %s (%s)\n", p.PackageName, p.CatalogName)
		}
	}
	fmt.Println()
}

// PrintModelCompare renders a 1:N model comparison as a summary table with
// detail sections for targets that have drift.
func PrintModelCompare(result *compare.ModelComparisonResult) {
	printModelHeader(result)
	printModelSummary(result)
	printModelDetails(result)
}

func printModelHeader(result *compare.ModelComparisonResult) {
	fmt.Println()
	fmt.Println("  ======================================================")
	fmt.Println("   Azure RBAC Inventory - Model Comparison Report")
	fmt.Println("  ======================================================")
	fmt.Println()
	fmt.Printf("    Model:  %s (%s)\n", result.Model.DisplayName, string(result.Model.Type))
	fmt.Printf("    Cloud:  %s\n", result.Cloud)
	if result.GoldenWorkload != "" {
		fmt.Printf("    Workload: %s (auto-detected)\n", result.GoldenWorkload)
	}
	fmt.Println()

	if len(result.ModelRBAC) > 0 {
		fmt.Printf("  [MODEL RBAC] %s Assignments (%d)\n", result.Model.DisplayName, len(result.ModelRBAC))
		fmt.Println("  " + strings.Repeat("-", 54))
		for _, a := range result.ModelRBAC {
			fmt.Printf("      • %s\n", rbacLabel(a))
		}
		fmt.Println()
	}
}

// missingExtraSummary formats a combined count label like "3 RBAC" or "3 RBAC, 1 Role".
func missingExtraSummary(rbacCount, roleCount, groupCount int) string {
	if rbacCount == 0 && roleCount == 0 && groupCount == 0 {
		return "0"
	}
	parts := []string{}
	if rbacCount > 0 {
		parts = append(parts, fmt.Sprintf("%d RBAC", rbacCount))
	}
	if roleCount > 0 {
		parts = append(parts, fmt.Sprintf("%d Role", roleCount))
	}
	if groupCount > 0 {
		parts = append(parts, fmt.Sprintf("%d Grp", groupCount))
	}
	return strings.Join(parts, ", ")
}

func printModelSummary(result *compare.ModelComparisonResult) {
	fmt.Printf("  [SUMMARY] Comparison against model (%d targets)\n", len(result.Results))
	fmt.Println("  " + strings.Repeat("-", 54))

	w := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
	fmt.Fprintln(w, "    IDENTITY\tWORKLOAD\tMATCH\tMISSING\tEXTRA\tSTATUS")
	fmt.Fprintln(w, "    "+strings.Repeat("-", 27)+"\t"+strings.Repeat("-", 12)+"\t"+strings.Repeat("-", 7)+"\t"+strings.Repeat("-", 8)+"\t"+strings.Repeat("-", 8)+"\t"+strings.Repeat("-", 10))

	for _, r := range result.Results {
		missTotal := r.MissingRBAC + r.MissingRoles + r.MissingGroups
		extraTotal := r.ExtraRBAC + r.ExtraRoles + r.ExtraGroups
		status := "Match"
		if missTotal > 0 || extraTotal > 0 {
			status = "Drift"
		}
		missing := missingExtraSummary(r.MissingRBAC, r.MissingRoles, r.MissingGroups)
		extra := missingExtraSummary(r.ExtraRBAC, r.ExtraRoles, r.ExtraGroups)
		workload := r.WorkloadName
		if workload == "" {
			workload = "-"
		}
		fmt.Fprintf(w, "    %s\t%s\t%.1f%%\t%s\t%s\t%s\n",
			r.Target.DisplayName, workload, r.MatchPercent, missing, extra, status)
	}
	_ = w.Flush()
	fmt.Println()
}

// modelDriftItem is a single missing or extra item for a detail section.
type modelDriftItem struct {
	category string // "RBAC", "Role", "Group"
	label    string
}

func printModelDetails(result *compare.ModelComparisonResult) {
	for _, r := range result.Results {
		missTotal := r.MissingRBAC + r.MissingRoles + r.MissingGroups
		extraTotal := r.ExtraRBAC + r.ExtraRoles + r.ExtraGroups
		if missTotal == 0 && extraTotal == 0 {
			continue // skip 100% matches
		}

		if r.WorkloadName != "" {
			fmt.Printf("  [DETAIL] %s (workload: %s) — %.1f%% match\n", r.Target.DisplayName, r.WorkloadName, r.MatchPercent)
		} else {
			fmt.Printf("  [DETAIL] %s — %.1f%% match\n", r.Target.DisplayName, r.MatchPercent)
		}
		fmt.Println("  " + strings.Repeat("-", 54))

		comp := r.Comparison

		// Missing from model (items in A/model but not in target)
		missing := collectDriftItems(
			comp.RBAC.OnlyA, comp.DirectoryRoles.OnlyA, comp.Groups.OnlyA)
		fmt.Printf("    Missing from target (%d):\n", len(missing))
		printDriftItems(missing)

		// Extra (in target but not model)
		extra := collectDriftItems(
			comp.RBAC.OnlyB, comp.DirectoryRoles.OnlyB, comp.Groups.OnlyB)
		fmt.Printf("    Extra (not in model) (%d):\n", len(extra))
		printDriftItems(extra)

		// Inferred matches – show paired model/target scopes with diff highlighting
		if len(comp.RBAC.Inferred) > 0 {
			fmt.Printf("    Inferred Matches (%d):\n", len(comp.RBAC.Inferred))
			for _, im := range comp.RBAC.Inferred {
				fmt.Printf("      ≈ %s (%s)\n", im.Model.RoleName, im.Model.ScopeType)
				mScope, tScope := scopeDiffSegments(im.Model.Scope, im.Target.Scope)
				fmt.Printf("          Model:  %s\n", mScope)
				fmt.Printf("          Target: %s\n", tScope)
			}
		}

		fmt.Println()
	}
}

func collectDriftItems(
	rbacItems []rbac.RoleAssignment,
	roleItems []graph.DirectoryRole,
	groupItems []graph.GroupMembership,
) []modelDriftItem {
	items := make([]modelDriftItem, 0, len(rbacItems)+len(roleItems)+len(groupItems))
	for _, a := range rbacItems {
		items = append(items, modelDriftItem{category: "RBAC", label: rbacLabel(a)})
	}
	for _, r := range roleItems {
		items = append(items, modelDriftItem{category: "Role", label: r.RoleName})
	}
	for _, g := range groupItems {
		items = append(items, modelDriftItem{
			category: "Group",
			label:    fmt.Sprintf("%s (%s)", g.GroupName, g.GroupType),
		})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].category != items[j].category {
			return items[i].category < items[j].category
		}
		return items[i].label < items[j].label
	})
	return items
}

func printDriftItems(items []modelDriftItem) {
	if len(items) == 0 {
		fmt.Println("      None.")
		return
	}
	for _, item := range items {
		fmt.Printf("      ✗ %s\n", item.label)
	}
}
