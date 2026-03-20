package graph

import (
	"context"
	"encoding/json"
	"fmt"
)

// GroupMembership represents a group that an identity belongs to.
type GroupMembership struct {
	GroupID    string `json:"groupId"`
	GroupName  string `json:"groupName"`
	GroupType  string `json:"groupType"`
	Membership string `json:"membership"`
}

// GroupChecker queries group memberships.
type GroupChecker struct {
	client GraphRequester
}

// NewGroupChecker creates a new group checker.
func NewGroupChecker(client GraphRequester) *GroupChecker {
	return &GroupChecker{client: client}
}

// GetTransitiveMemberships retrieves all transitive group memberships for an identity.
func (g *GroupChecker) GetTransitiveMemberships(ctx context.Context, objectID string, objectType string) ([]GroupMembership, error) {
	resource := objectTypeToResource(objectType)
	if resource == "" {
		return nil, nil
	}

	items, err := g.client.DoPagedRequest(ctx, fmt.Sprintf("/v1.0/%s/%s/transitiveMemberOf", resource, objectID), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to query group memberships: %w", err)
	}

	// Also get direct memberships to distinguish direct vs transitive
	directIDs := make(map[string]bool)
	directItems, err := g.client.DoPagedRequest(ctx, fmt.Sprintf("/v1.0/%s/%s/memberOf", resource, objectID), nil)
	if err == nil {
		for _, item := range directItems {
			var obj struct {
				ID string `json:"id"`
			}
			if json.Unmarshal(item, &obj) == nil {
				directIDs[obj.ID] = true
			}
		}
	}

	var memberships []GroupMembership
	for _, item := range items {
		var obj struct {
			ODataType   string   `json:"@odata.type"`
			ID          string   `json:"id"`
			DisplayName string   `json:"displayName"`
			GroupTypes  []string `json:"groupTypes"`
		}
		if err := json.Unmarshal(item, &obj); err != nil {
			continue
		}

		if obj.ODataType != "#microsoft.graph.group" {
			continue
		}

		membershipType := "Transitive"
		if directIDs[obj.ID] {
			membershipType = "Direct"
		}

		groupType := "Security"
		for _, gt := range obj.GroupTypes {
			if gt == "Unified" {
				groupType = "Microsoft 365"
				break
			}
		}

		memberships = append(memberships, GroupMembership{
			GroupID:    obj.ID,
			GroupName:  obj.DisplayName,
			GroupType:  groupType,
			Membership: membershipType,
		})
	}

	return memberships, nil
}

// objectTypeToResource maps an identity type to its Graph API resource path segment.
func objectTypeToResource(objectType string) string {
	switch objectType {
	case "User":
		return "users"
	case "ServicePrincipal", "ManagedIdentity":
		return "servicePrincipals"
	case "Group":
		return "groups"
	default:
		return ""
	}
}
