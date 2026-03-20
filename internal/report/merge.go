package report

import (
	"strings"

	"github.com/jpmicrosoft/azure-rbac-inventory/internal/identity"
)

// MergeRelatedReports groups reports by display name (case-insensitive) and
// merges App Registration + Service Principal pairs that share the same AppID
// into a single combined report.
func MergeRelatedReports(reports []*Report) []*Report {
	if len(reports) <= 1 {
		return reports
	}

	type group struct {
		key     string // lower-cased display name
		reports []*Report
	}

	// Preserve first-occurrence order via ordered slice of groups.
	var groups []*group
	index := map[string]*group{}

	for _, rpt := range reports {
		key := strings.ToLower(rpt.Identity.DisplayName)
		g, ok := index[key]
		if !ok {
			g = &group{key: key}
			groups = append(groups, g)
			index[key] = g
		}
		g.reports = append(g.reports, rpt)
	}

	var merged []*Report
	for _, g := range groups {
		if len(g.reports) == 1 {
			merged = append(merged, g.reports[0])
			continue
		}

		// Check if all reports in the group share a common non-empty AppID.
		commonAppID := sharedAppID(g.reports)
		if commonAppID == "" {
			// No shared AppID — keep them all separate.
			merged = append(merged, g.reports...)
			continue
		}

		merged = append(merged, mergeGroup(g.reports, commonAppID))
	}

	return merged
}

// sharedAppID returns the common AppID if all reports with a non-empty AppID
// agree on it. Returns "" if there is no shared AppID.
func sharedAppID(reports []*Report) string {
	var appID string
	for _, rpt := range reports {
		if rpt.Identity.AppID == "" {
			continue
		}
		if appID == "" {
			appID = rpt.Identity.AppID
		} else if !strings.EqualFold(appID, rpt.Identity.AppID) {
			return ""
		}
	}
	return appID
}

// mergeGroup combines multiple reports into one.
func mergeGroup(reports []*Report, appID string) *Report {
	// Pick the SPN report for the base identity (RBAC is assigned to it).
	base := pickSPN(reports)

	merged := &Report{
		Identity: &identity.Identity{
			ObjectID:             base.Identity.ObjectID,
			AppID:                appID,
			DisplayName:          base.Identity.DisplayName,
			Type:                 identity.TypeServicePrincipal,
			ServicePrincipalType: base.Identity.ServicePrincipalType,
			IsMerged:             true,
		},
		Cloud: base.Cloud,
	}

	// Collect and deduplicate across all reports.
	rbacSeen := map[string]struct{}{}
	dirRoleSeen := map[string]struct{}{}
	pkgSeen := map[string]struct{}{}
	groupSeen := map[string]struct{}{}
	warnSeen := map[string]struct{}{}

	for _, rpt := range reports {
		for _, a := range rpt.RBACAssignments {
			key := a.RoleName + "|" + a.Scope
			if _, dup := rbacSeen[key]; !dup {
				rbacSeen[key] = struct{}{}
				merged.RBACAssignments = append(merged.RBACAssignments, a)
			}
		}
		for _, d := range rpt.DirectoryRoles {
			if _, dup := dirRoleSeen[d.RoleID]; !dup {
				dirRoleSeen[d.RoleID] = struct{}{}
				merged.DirectoryRoles = append(merged.DirectoryRoles, d)
			}
		}
		for _, p := range rpt.AccessPackages {
			key := p.PackageName + "|" + p.CatalogName
			if _, dup := pkgSeen[key]; !dup {
				pkgSeen[key] = struct{}{}
				merged.AccessPackages = append(merged.AccessPackages, p)
			}
		}
		// Access requests are not deduplicated — just concatenated.
		merged.AccessRequests = append(merged.AccessRequests, rpt.AccessRequests...)

		for _, g := range rpt.GroupMemberships {
			if _, dup := groupSeen[g.GroupName]; !dup {
				groupSeen[g.GroupName] = struct{}{}
				merged.GroupMemberships = append(merged.GroupMemberships, g)
			}
		}
		for _, w := range rpt.Warnings {
			if _, dup := warnSeen[w]; !dup {
				warnSeen[w] = struct{}{}
				merged.Warnings = append(merged.Warnings, w)
			}
		}
	}

	return merged
}

// pickSPN returns the first ServicePrincipal report, falling back to the first report.
func pickSPN(reports []*Report) *Report {
	for _, rpt := range reports {
		if rpt.Identity.Type == identity.TypeServicePrincipal {
			return rpt
		}
	}
	return reports[0]
}
