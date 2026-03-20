package rbac

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization/v2"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armsubscriptions"
	"golang.org/x/sync/errgroup"

	cloudenv "github.com/jpmicrosoft/azure-rbac-inventory/internal/cloud"
)

// RoleAssignment represents a resolved RBAC role assignment.
type RoleAssignment struct {
	RoleName       string `json:"roleName"`
	RoleID         string `json:"roleId"`
	Scope          string `json:"scope"`
	ScopeType      string `json:"scopeType"`
	AssignmentType string `json:"assignmentType"` // Direct or Inherited
	PrincipalID    string `json:"principalId"`
	PrincipalType  string `json:"principalType"`
	Condition      string `json:"condition,omitempty"`
}

// RBACQuerier defines the interface for querying RBAC role assignments.
type RBACQuerier interface {
	GetAssignments(ctx context.Context, principalID string, subscriptionFilter []string) ([]RoleAssignment, []string, error)
}

// maxConcurrentSubscriptions limits parallel RBAC queries across subscriptions.
const maxConcurrentSubscriptions = 10

// roleCache bundles the role definition cache with its protecting mutex.
type roleCache struct {
	mu    sync.RWMutex
	names map[string]string
}

// Checker queries Azure RBAC role assignments.
type Checker struct {
	cred  azcore.TokenCredential
	env   cloudenv.Environment
	cache roleCache
}

// NewChecker creates a new RBAC checker.
func NewChecker(cred azcore.TokenCredential, env cloudenv.Environment) *Checker {
	return &Checker{
		cred: cred,
		env:  env,
		cache: roleCache{
			names: make(map[string]string),
		},
	}
}

// GetAssignments retrieves all RBAC role assignments for the given principal ID
// across all accessible subscriptions (or filtered subscriptions).
// Warnings for individual subscription failures are returned separately.
func (c *Checker) GetAssignments(ctx context.Context, principalID string, subscriptionFilter []string) ([]RoleAssignment, []string, error) {
	subs, err := c.listSubscriptions(ctx, subscriptionFilter)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to list subscriptions: %w", err)
	}

	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(maxConcurrentSubscriptions)

	var mu sync.Mutex
	var allAssignments []RoleAssignment
	var warnings []string

	for _, sub := range subs {
		g.Go(func() error {
			assignments, err := c.getAssignmentsForSubscription(gctx, sub, principalID)
			if err != nil {
				mu.Lock()
				warnings = append(warnings, fmt.Sprintf("subscription %s: %v", sub, err))
				mu.Unlock()
				return nil
			}
			mu.Lock()
			allAssignments = append(allAssignments, assignments...)
			mu.Unlock()
			return nil
		})
	}

	g.Wait()

	// Deduplicate: management-group-level assignments appear from every child subscription
	allAssignments = deduplicateAssignments(allAssignments)

	return allAssignments, warnings, nil
}

func (c *Checker) listSubscriptions(ctx context.Context, filter []string) ([]string, error) {
	if len(filter) > 0 {
		return filter, nil
	}

	opts := &arm.ClientOptions{}
	opts.Cloud = c.env.CloudConfig

	client, err := armsubscriptions.NewClient(c.cred, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to create subscriptions client: %w", err)
	}

	var subs []string
	pager := client.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list subscriptions: %w", err)
		}
		for _, sub := range page.Value {
			if sub.SubscriptionID != nil {
				subs = append(subs, *sub.SubscriptionID)
			}
		}
	}

	return subs, nil
}

func (c *Checker) getAssignmentsForSubscription(ctx context.Context, subscriptionID string, principalID string) ([]RoleAssignment, error) {
	opts := &arm.ClientOptions{}
	opts.Cloud = c.env.CloudConfig

	assignClient, err := armauthorization.NewRoleAssignmentsClient(subscriptionID, c.cred, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to create role assignments client: %w", err)
	}

	defClient, err := armauthorization.NewRoleDefinitionsClient(c.cred, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to create role definitions client: %w", err)
	}

	filter := fmt.Sprintf("assignedTo('%s')", escapeARMFilter(principalID))
	pager := assignClient.NewListForSubscriptionPager(&armauthorization.RoleAssignmentsClientListForSubscriptionOptions{
		Filter: &filter,
	})

	var assignments []RoleAssignment
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, sanitizeARMError(err)
		}

		for _, ra := range page.Value {
			if ra.Properties == nil {
				continue
			}

			roleName := ""
			if ra.Properties.RoleDefinitionID != nil {
				roleDefID := *ra.Properties.RoleDefinitionID

				c.cache.mu.RLock()
				cached, ok := c.cache.names[roleDefID]
				c.cache.mu.RUnlock()

				if ok {
					roleName = cached
				} else {
					roleName = c.resolveRoleName(ctx, defClient, roleDefID)
					c.cache.mu.Lock()
					c.cache.names[roleDefID] = roleName
					c.cache.mu.Unlock()
				}
			}

			scope := ""
			if ra.Properties.Scope != nil {
				scope = *ra.Properties.Scope
			}

			assignment := RoleAssignment{
				RoleName:       roleName,
				RoleID:         safeDeref(ra.Properties.RoleDefinitionID),
				Scope:          scope,
				ScopeType:      classifyScope(scope),
				PrincipalID:    safeDeref(ra.Properties.PrincipalID),
				AssignmentType: "Direct",
			}

			if ra.Properties.PrincipalType != nil {
				assignment.PrincipalType = string(*ra.Properties.PrincipalType)
			}
			if ra.Properties.Condition != nil {
				assignment.Condition = *ra.Properties.Condition
			}

			assignments = append(assignments, assignment)
		}
	}

	return assignments, nil
}

func (c *Checker) resolveRoleName(ctx context.Context, client *armauthorization.RoleDefinitionsClient, roleDefID string) string {
	rd, err := client.GetByID(ctx, roleDefID, nil)
	if err != nil {
		return roleDefID
	}
	if rd.Properties != nil && rd.Properties.RoleName != nil {
		return *rd.Properties.RoleName
	}
	return roleDefID
}

func classifyScope(scope string) string {
	scope = strings.TrimRight(scope, "/")
	parts := strings.Split(scope, "/")
	switch {
	case strings.Contains(scope, "/managementGroups/"):
		return "Management Group"
	case strings.Contains(scope, "/resourceGroups/") && len(parts) > 5:
		return "Resource"
	case strings.Contains(scope, "/resourceGroups/"):
		return "Resource Group"
	case strings.HasPrefix(scope, "/subscriptions/") && !strings.Contains(scope, "/resourceGroups/"):
		return "Subscription"
	default:
		return "Other"
	}
}

func safeDeref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// sanitizeARMError extracts a concise error message from verbose ARM SDK errors
// which include full HTTP response bodies.
func sanitizeARMError(err error) error {
	msg := err.Error()
	if idx := strings.Index(msg, "\n"); idx > 0 {
		msg = strings.TrimSpace(msg[:idx])
	}
	return fmt.Errorf("%s", msg)
}

// deduplicateAssignments removes duplicate assignments that appear when the same
// management-group-level assignment is returned from multiple child subscriptions.
func deduplicateAssignments(assignments []RoleAssignment) []RoleAssignment {
	seen := make(map[string]bool)
	var unique []RoleAssignment
	for _, a := range assignments {
		// Use RoleName + Scope + PrincipalID as key because RoleID contains
		// subscription-specific paths for the same logical role definition
		key := a.RoleName + "|" + a.Scope + "|" + a.PrincipalID
		if seen[key] {
			continue
		}
		seen[key] = true
		unique = append(unique, a)
	}
	return unique
}

// escapeARMFilter escapes single quotes in ARM OData filter values.
func escapeARMFilter(s string) string {
	return strings.ReplaceAll(s, "'", "''")
}
