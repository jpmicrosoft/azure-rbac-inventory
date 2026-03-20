package graph

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
)

var roleDefIDRegex = regexp.MustCompile(
	`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// DirectoryRole represents an Entra ID directory role assignment.
type DirectoryRole struct {
	RoleName     string `json:"roleName"`
	RoleID       string `json:"roleId"`
	AssignmentID string `json:"assignmentId"`
	Status       string `json:"status"`
}

type roleDefinitionResponse struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayName"`
}

// DirectoryRoleChecker queries Entra ID directory role assignments.
type DirectoryRoleChecker struct {
	client GraphRequester
}

// NewDirectoryRoleChecker creates a new directory role checker.
func NewDirectoryRoleChecker(client GraphRequester) *DirectoryRoleChecker {
	return &DirectoryRoleChecker{client: client}
}

// GetRoleAssignments retrieves all directory role assignments for a principal.
func (d *DirectoryRoleChecker) GetRoleAssignments(ctx context.Context, principalID string) ([]DirectoryRole, error) {
	query := url.Values{}
	query.Set("$filter", fmt.Sprintf("principalId eq '%s'", principalID))
	query.Set("$expand", "roleDefinition")

	items, err := d.client.DoPagedRequest(ctx, "/v1.0/roleManagement/directory/roleAssignments", query)
	if err != nil {
		return nil, fmt.Errorf("failed to query directory role assignments: %w", err)
	}

	var roles []DirectoryRole
	for _, item := range items {
		var ra struct {
			ID               string `json:"id"`
			PrincipalID      string `json:"principalId"`
			RoleDefinitionID string `json:"roleDefinitionId"`
			RoleDefinition   struct {
				DisplayName string `json:"displayName"`
			} `json:"roleDefinition"`
		}
		if err := json.Unmarshal(item, &ra); err != nil {
			continue
		}

		roleName := ra.RoleDefinition.DisplayName
		if roleName == "" {
			roleName = d.resolveRoleName(ctx, ra.RoleDefinitionID)
		}

		roles = append(roles, DirectoryRole{
			RoleName:     roleName,
			RoleID:       ra.RoleDefinitionID,
			AssignmentID: ra.ID,
			Status:       "Active",
		})
	}

	return roles, nil
}

func (d *DirectoryRoleChecker) resolveRoleName(ctx context.Context, roleDefID string) string {
	// Validate role definition ID before interpolating into URL path
	if !roleDefIDRegex.MatchString(roleDefID) {
		return roleDefID
	}

	body, err := d.client.DoRequest(ctx,
		fmt.Sprintf("/v1.0/roleManagement/directory/roleDefinitions/%s", roleDefID),
		nil,
	)
	if err != nil {
		return roleDefID
	}

	var def roleDefinitionResponse
	if err := json.Unmarshal(body, &def); err != nil {
		return roleDefID
	}

	return def.DisplayName
}
