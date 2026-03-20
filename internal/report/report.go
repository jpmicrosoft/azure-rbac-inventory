package report

import (
	"github.com/jpmicrosoft/azure-rbac-inventory/internal/graph"
	"github.com/jpmicrosoft/azure-rbac-inventory/internal/identity"
	"github.com/jpmicrosoft/azure-rbac-inventory/internal/rbac"
)

// Report holds the complete results for an identity check.
type Report struct {
	Identity              *identity.Identity              `json:"identity"`
	Cloud                 string                          `json:"cloud"`
	RBACAssignments       []rbac.RoleAssignment           `json:"rbacAssignments"`
	DirectoryRoles        []graph.DirectoryRole           `json:"directoryRoles"`
	AccessPackages        []graph.AccessPackageAssignment `json:"accessPackageAssignments"`
	AccessRequests        []graph.AccessPackageRequest    `json:"accessPackageRequests"`
	GroupMemberships      []graph.GroupMembership         `json:"groupMemberships"`
	Warnings              []string                        `json:"warnings,omitempty"`
	SkippedAccessPackages bool                            `json:"skippedAccessPackages,omitempty"`
}

// MultiReport wraps multiple identity reports with aggregate stats.
type MultiReport struct {
	Reports       []*Report `json:"reports"`
	TotalRBAC     int       `json:"totalRBACAssignments"`
	TotalDirRoles int       `json:"totalDirectoryRoles"`
	TotalPackages int       `json:"totalAccessPackages"`
	TotalGroups   int       `json:"totalGroupMemberships"`
	TotalWarnings int       `json:"totalWarnings"`
}

// NewMultiReport creates a MultiReport from a slice of Reports with computed totals.
func NewMultiReport(reports []*Report) *MultiReport {
	mr := &MultiReport{Reports: reports}
	for _, r := range reports {
		mr.TotalRBAC += len(r.RBACAssignments)
		mr.TotalDirRoles += len(r.DirectoryRoles)
		mr.TotalPackages += len(r.AccessPackages)
		mr.TotalGroups += len(r.GroupMemberships)
		mr.TotalWarnings += len(r.Warnings)
	}
	return mr
}
