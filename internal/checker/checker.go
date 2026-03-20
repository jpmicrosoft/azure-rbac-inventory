package checker

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"golang.org/x/sync/errgroup"

	cloudenv "github.com/jpmicrosoft/azure-rbac-inventory/internal/cloud"
	"github.com/jpmicrosoft/azure-rbac-inventory/internal/graph"
	"github.com/jpmicrosoft/azure-rbac-inventory/internal/identity"
	"github.com/jpmicrosoft/azure-rbac-inventory/internal/rbac"
	reportpkg "github.com/jpmicrosoft/azure-rbac-inventory/internal/report"
)

// Config holds all parameters for an identity check.
type Config struct {
	IdentityID            string
	Cloud                 string
	TenantID              string
	Subscriptions         []string
	IncludeGroups         bool
	IncludeAccessPackages bool
	Verbose               bool
	OutputFormat          string
	JSONFile              string
	ExportFile            string // export file path
	IdentityType          string // identity type filter
	MaxResults            int    // max search results
	Concurrency           int    // max concurrent checks
	PerIdentity           bool   // separate output per identity
}

// Run executes the identity check: validates inputs, resolves the identity,
// runs concurrent queries, and returns an assembled Report.
func Run(ctx context.Context, cred azcore.TokenCredential, env cloudenv.Environment, cfg Config) (*reportpkg.Report, error) {
	// Validate identity ID is a UUID
	if err := identity.ValidateID(cfg.IdentityID); err != nil {
		return nil, err
	}

	// Validate tenant ID if provided
	if cfg.TenantID != "" {
		if err := identity.ValidateID(cfg.TenantID); err != nil {
			return nil, fmt.Errorf("invalid tenant ID: %w", err)
		}
	}

	// Validate subscription IDs
	for _, sub := range cfg.Subscriptions {
		if err := identity.ValidateID(sub); err != nil {
			return nil, fmt.Errorf("invalid subscription ID %q: %w", sub, err)
		}
	}

	// Create shared Graph client
	graphClient := graph.NewClient(cred, env)

	// Resolve identity
	fmt.Fprintf(os.Stderr, "Resolving identity: %s... ", cfg.IdentityID)
	resolver := identity.NewResolver(graphClient)
	ident, err := resolver.Resolve(ctx, cfg.IdentityID)
	if err != nil {
		return nil, fmt.Errorf("identity resolution failed: %w", err)
	}
	fmt.Fprintf(os.Stderr, "Found: %s (%s)\n", ident.DisplayName, ident.Type)

	report := &reportpkg.Report{
		Identity: ident,
		Cloud:    env.Name,
	}

	// Run independent queries concurrently
	rbacChecker := rbac.NewChecker(cred, env)
	dirRoleChecker := graph.NewDirectoryRoleChecker(graphClient)
	apChecker := graph.NewAccessPackageChecker(graphClient)
	groupChecker := graph.NewGroupChecker(graphClient)

	g, gctx := errgroup.WithContext(ctx)

	var mu sync.Mutex
	var allWarnings []string
	var rbacAssignments []rbac.RoleAssignment
	var dirRoles []graph.DirectoryRole
	var apAssignments []graph.AccessPackageAssignment
	var apRequests []graph.AccessPackageRequest
	var groups []graph.GroupMembership

	g.Go(func() error {
		fmt.Fprint(os.Stderr, "Querying Azure RBAC role assignments...\n")
		var err error
		var warns []string
		rbacAssignments, warns, err = rbacChecker.GetAssignments(gctx, ident.ObjectID, cfg.Subscriptions)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: RBAC query failed: %v\n", err)
		} else {
			fmt.Fprintf(os.Stderr, "RBAC role assignments: %d found\n", len(rbacAssignments))
		}
		mu.Lock()
		allWarnings = append(allWarnings, warns...)
		mu.Unlock()
		return nil
	})

	g.Go(func() error {
		fmt.Fprint(os.Stderr, "Querying Entra ID directory roles...\n")
		var err error
		dirRoles, err = dirRoleChecker.GetRoleAssignments(gctx, ident.ObjectID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Directory role query failed: %v\n", err)
		} else {
			fmt.Fprintf(os.Stderr, "Directory roles: %d found\n", len(dirRoles))
		}
		return nil
	})

	if cfg.IncludeAccessPackages {
		g.Go(func() error {
			fmt.Fprint(os.Stderr, "Querying access package assignments...\n")
			var err error
			apAssignments, err = apChecker.GetAssignments(gctx, ident.ObjectID)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: Access package query failed: %v\n", err)
			} else {
				fmt.Fprintf(os.Stderr, "Access package assignments: %d found\n", len(apAssignments))
			}
			return nil
		})

		g.Go(func() error {
			fmt.Fprint(os.Stderr, "Querying access package requests...\n")
			var err error
			apRequests, err = apChecker.GetRequests(gctx, ident.ObjectID)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: Access package request query failed: %v\n", err)
			} else {
				fmt.Fprintf(os.Stderr, "Access package requests: %d found\n", len(apRequests))
			}
			return nil
		})
	}

	g.Go(func() error {
		fmt.Fprint(os.Stderr, "Querying group memberships...\n")
		var err error
		groups, err = groupChecker.GetTransitiveMemberships(gctx, ident.ObjectID, string(ident.Type))
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Group membership query failed: %v\n", err)
		} else {
			fmt.Fprintf(os.Stderr, "Group memberships: %d found\n", len(groups))
		}
		return nil
	})

	if err := g.Wait(); err != nil {
		return nil, fmt.Errorf("concurrent queries failed: %w", err)
	}

	report.RBACAssignments = rbacAssignments
	report.DirectoryRoles = dirRoles
	report.AccessPackages = apAssignments
	report.AccessRequests = apRequests
	report.GroupMemberships = groups
	report.Warnings = allWarnings
	report.SkippedAccessPackages = !cfg.IncludeAccessPackages

	// If --include-groups, also get RBAC for each group (bounded concurrency)
	if cfg.IncludeGroups && len(report.GroupMemberships) > 0 {
		fmt.Fprint(os.Stderr, "Querying RBAC for group memberships...\n")

		grpG, grpCtx := errgroup.WithContext(ctx)
		concLimit := cfg.Concurrency
		if concLimit <= 0 {
			concLimit = 10
		}
		grpG.SetLimit(concLimit)

		var grpMu sync.Mutex
		var groupRBAC []rbac.RoleAssignment

		for _, gm := range report.GroupMemberships {
			if err := identity.ValidateID(gm.GroupID); err != nil {
				if cfg.Verbose {
					fmt.Fprintf(os.Stderr, "  Warning: skipping group %q (invalid ID format)\n", gm.GroupName)
				}
				continue
			}
			gm := gm // capture for goroutine
			grpG.Go(func() error {
				ga, warns, err := rbacChecker.GetAssignments(grpCtx, gm.GroupID, cfg.Subscriptions)
				grpMu.Lock()
				report.Warnings = append(report.Warnings, warns...)
				grpMu.Unlock()
				if err != nil {
					if cfg.Verbose {
						fmt.Fprintf(os.Stderr, "  Warning: RBAC query for group %s failed: %v\n", gm.GroupName, err)
					}
					return nil
				}
				for i := range ga {
					ga[i].AssignmentType = fmt.Sprintf("Via Group (%s)", gm.GroupName)
				}
				grpMu.Lock()
				groupRBAC = append(groupRBAC, ga...)
				grpMu.Unlock()
				return nil
			})
		}

		if err := grpG.Wait(); err != nil {
			return nil, fmt.Errorf("group RBAC queries failed: %w", err)
		}
		report.RBACAssignments = append(report.RBACAssignments, groupRBAC...)
		fmt.Fprintf(os.Stderr, "%d additional assignments via groups\n", len(groupRBAC))
	}

	fmt.Fprintln(os.Stderr)

	return report, nil
}

// ParseSubscriptions splits a comma-separated subscription string into a
// trimmed slice. Returns nil for an empty input.
func ParseSubscriptions(raw string) []string {
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}
