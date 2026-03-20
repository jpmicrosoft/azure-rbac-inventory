package graph

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"testing"
)

func TestGetTransitiveMemberships_User(t *testing.T) {
	// Arrange — transitive returns a mix of groups and directory roles;
	// direct returns only one of the groups.
	mock := &mockGraphRequester{
		doPagedRequestFunc: func(ctx context.Context, path string, query url.Values) ([]json.RawMessage, error) {
			if strings.Contains(path, "transitiveMemberOf") {
				return []json.RawMessage{
					json.RawMessage(`{
						"@odata.type": "#microsoft.graph.group",
						"id": "group-1",
						"displayName": "Engineering",
						"groupTypes": []
					}`),
					json.RawMessage(`{
						"@odata.type": "#microsoft.graph.directoryRole",
						"id": "role-1",
						"displayName": "Global Admin"
					}`),
					json.RawMessage(`{
						"@odata.type": "#microsoft.graph.group",
						"id": "group-2",
						"displayName": "All Employees",
						"groupTypes": ["Unified"]
					}`),
				}, nil
			}
			if strings.Contains(path, "memberOf") {
				// Only group-1 is a direct membership
				return []json.RawMessage{
					json.RawMessage(`{"id": "group-1"}`),
				}, nil
			}
			return nil, fmt.Errorf("unexpected path: %s", path)
		},
	}

	checker := NewGroupChecker(mock)

	// Act
	memberships, err := checker.GetTransitiveMemberships(context.Background(), "user-123", "User")

	// Assert
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Only groups should be returned, not directoryRole
	if len(memberships) != 2 {
		t.Fatalf("got %d memberships, want 2 (directory roles should be filtered out)", len(memberships))
	}

	// group-1: direct
	if memberships[0].GroupID != "group-1" {
		t.Errorf("memberships[0].GroupID = %q, want %q", memberships[0].GroupID, "group-1")
	}
	if memberships[0].GroupName != "Engineering" {
		t.Errorf("memberships[0].GroupName = %q, want %q", memberships[0].GroupName, "Engineering")
	}
	if memberships[0].Membership != "Direct" {
		t.Errorf("memberships[0].Membership = %q, want %q", memberships[0].Membership, "Direct")
	}

	// group-2: transitive (not in direct set)
	if memberships[1].GroupID != "group-2" {
		t.Errorf("memberships[1].GroupID = %q, want %q", memberships[1].GroupID, "group-2")
	}
	if memberships[1].Membership != "Transitive" {
		t.Errorf("memberships[1].Membership = %q, want %q", memberships[1].Membership, "Transitive")
	}
}

func TestGetTransitiveMemberships_Application(t *testing.T) {
	// "Application" objectType is not handled — should return nil immediately.
	mock := &mockGraphRequester{
		doPagedRequestFunc: func(ctx context.Context, path string, query url.Values) ([]json.RawMessage, error) {
			t.Fatal("DoPagedRequest should not be called for Application type")
			return nil, nil
		},
	}

	checker := NewGroupChecker(mock)

	memberships, err := checker.GetTransitiveMemberships(context.Background(), "app-123", "Application")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if memberships != nil {
		t.Errorf("expected nil memberships for Application type, got %v", memberships)
	}
}

func TestGetTransitiveMemberships_GroupTypes(t *testing.T) {
	tests := []struct {
		name          string
		groupTypes    string // JSON array
		wantGroupType string
	}{
		{
			name:          "Unified group type maps to Microsoft 365",
			groupTypes:    `["Unified"]`,
			wantGroupType: "Microsoft 365",
		},
		{
			name:          "empty groupTypes maps to Security",
			groupTypes:    `[]`,
			wantGroupType: "Security",
		},
		{
			name:          "DynamicMembership without Unified maps to Security",
			groupTypes:    `["DynamicMembership"]`,
			wantGroupType: "Security",
		},
		{
			name:          "Unified with DynamicMembership maps to Microsoft 365",
			groupTypes:    `["DynamicMembership", "Unified"]`,
			wantGroupType: "Microsoft 365",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &mockGraphRequester{
				doPagedRequestFunc: func(ctx context.Context, path string, query url.Values) ([]json.RawMessage, error) {
					if strings.Contains(path, "transitiveMemberOf") {
						item := fmt.Sprintf(`{
							"@odata.type": "#microsoft.graph.group",
							"id": "grp-test",
							"displayName": "Test Group",
							"groupTypes": %s
						}`, tt.groupTypes)
						return []json.RawMessage{json.RawMessage(item)}, nil
					}
					// direct memberships — return empty
					return []json.RawMessage{}, nil
				},
			}

			checker := NewGroupChecker(mock)
			memberships, err := checker.GetTransitiveMemberships(context.Background(), "user-1", "User")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(memberships) != 1 {
				t.Fatalf("got %d memberships, want 1", len(memberships))
			}
			if memberships[0].GroupType != tt.wantGroupType {
				t.Errorf("GroupType = %q, want %q", memberships[0].GroupType, tt.wantGroupType)
			}
		})
	}
}

func TestGetTransitiveMemberships_ServicePrincipal(t *testing.T) {
	// Verify that ServicePrincipal objectType uses the servicePrincipals endpoint.
	var capturedPaths []string
	mock := &mockGraphRequester{
		doPagedRequestFunc: func(ctx context.Context, path string, query url.Values) ([]json.RawMessage, error) {
			capturedPaths = append(capturedPaths, path)
			return []json.RawMessage{}, nil
		},
	}

	checker := NewGroupChecker(mock)
	_, err := checker.GetTransitiveMemberships(context.Background(), "spn-123", "ServicePrincipal")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(capturedPaths) < 1 {
		t.Fatal("expected at least 1 API call")
	}
	if !strings.Contains(capturedPaths[0], "/v1.0/servicePrincipals/spn-123/transitiveMemberOf") {
		t.Errorf("first path = %q, want it to contain '/v1.0/servicePrincipals/spn-123/transitiveMemberOf'", capturedPaths[0])
	}
}

func TestGetTransitiveMemberships_ManagedIdentity(t *testing.T) {
	// ManagedIdentity should use the servicePrincipals endpoint (same as ServicePrincipal).
	var capturedPaths []string
	mock := &mockGraphRequester{
		doPagedRequestFunc: func(ctx context.Context, path string, query url.Values) ([]json.RawMessage, error) {
			capturedPaths = append(capturedPaths, path)
			return []json.RawMessage{}, nil
		},
	}

	checker := NewGroupChecker(mock)
	_, err := checker.GetTransitiveMemberships(context.Background(), "mi-456", "ManagedIdentity")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(capturedPaths) < 1 {
		t.Fatal("expected at least 1 API call")
	}
	if !strings.Contains(capturedPaths[0], "/v1.0/servicePrincipals/mi-456/transitiveMemberOf") {
		t.Errorf("first path = %q, want servicePrincipals endpoint for ManagedIdentity", capturedPaths[0])
	}
}

func TestGetTransitiveMemberships_GroupObjectType(t *testing.T) {
	// "Group" objectType uses the groups endpoint.
	var capturedPaths []string
	mock := &mockGraphRequester{
		doPagedRequestFunc: func(ctx context.Context, path string, query url.Values) ([]json.RawMessage, error) {
			capturedPaths = append(capturedPaths, path)
			return []json.RawMessage{}, nil
		},
	}

	checker := NewGroupChecker(mock)
	_, err := checker.GetTransitiveMemberships(context.Background(), "group-nested", "Group")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(capturedPaths) < 1 {
		t.Fatal("expected at least 1 API call")
	}
	if !strings.Contains(capturedPaths[0], "/v1.0/groups/group-nested/transitiveMemberOf") {
		t.Errorf("first path = %q, want groups endpoint", capturedPaths[0])
	}
}

func TestGetTransitiveMemberships_TransitiveError(t *testing.T) {
	// Error from the transitive membership call should propagate.
	mock := &mockGraphRequester{
		doPagedRequestFunc: func(ctx context.Context, path string, query url.Values) ([]json.RawMessage, error) {
			if strings.Contains(path, "transitiveMemberOf") {
				return nil, fmt.Errorf("permission denied")
			}
			return []json.RawMessage{}, nil
		},
	}

	checker := NewGroupChecker(mock)
	_, err := checker.GetTransitiveMemberships(context.Background(), "user-err", "User")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "group memberships") {
		t.Errorf("error should mention 'group memberships', got: %v", err)
	}
}

func TestGetTransitiveMemberships_DirectMembershipErrorIsNonFatal(t *testing.T) {
	// If direct membership call fails, transitive memberships should still be returned,
	// but all will be classified as "Transitive".
	mock := &mockGraphRequester{
		doPagedRequestFunc: func(ctx context.Context, path string, query url.Values) ([]json.RawMessage, error) {
			if strings.Contains(path, "transitiveMemberOf") {
				return []json.RawMessage{
					json.RawMessage(`{
						"@odata.type": "#microsoft.graph.group",
						"id": "grp-direct-err",
						"displayName": "Some Group",
						"groupTypes": []
					}`),
				}, nil
			}
			// Direct membership lookup fails
			return nil, fmt.Errorf("direct lookup failed")
		},
	}

	checker := NewGroupChecker(mock)
	memberships, err := checker.GetTransitiveMemberships(context.Background(), "user-direct-err", "User")
	if err != nil {
		t.Fatalf("unexpected error (direct failure should be non-fatal): %v", err)
	}
	if len(memberships) != 1 {
		t.Fatalf("got %d memberships, want 1", len(memberships))
	}
	// Since direct lookup failed, all memberships should be "Transitive"
	if memberships[0].Membership != "Transitive" {
		t.Errorf("Membership = %q, want %q (direct lookup failed, so all should be Transitive)", memberships[0].Membership, "Transitive")
	}
}

func TestGetTransitiveMemberships_UnknownObjectType(t *testing.T) {
	mock := &mockGraphRequester{
		doPagedRequestFunc: func(ctx context.Context, path string, query url.Values) ([]json.RawMessage, error) {
			t.Fatal("DoPagedRequest should not be called for unknown type")
			return nil, nil
		},
	}

	checker := NewGroupChecker(mock)
	memberships, err := checker.GetTransitiveMemberships(context.Background(), "obj-unknown", "SomethingElse")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if memberships != nil {
		t.Errorf("expected nil for unknown objectType, got %v", memberships)
	}
}

func TestGetTransitiveMemberships_EmptyResult(t *testing.T) {
	mock := &mockGraphRequester{
		doPagedRequestFunc: func(ctx context.Context, path string, query url.Values) ([]json.RawMessage, error) {
			return []json.RawMessage{}, nil
		},
	}

	checker := NewGroupChecker(mock)
	memberships, err := checker.GetTransitiveMemberships(context.Background(), "user-empty", "User")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(memberships) != 0 {
		t.Errorf("got %d memberships, want 0", len(memberships))
	}
}

func TestGetTransitiveMemberships_MalformedJSONSkipped(t *testing.T) {
	// Malformed JSON items should be silently skipped; valid items should be returned.
	mock := &mockGraphRequester{
		doPagedRequestFunc: func(ctx context.Context, path string, query url.Values) ([]json.RawMessage, error) {
			if strings.Contains(path, "transitiveMemberOf") {
				return []json.RawMessage{
					json.RawMessage(`{not valid json at all}`),
					json.RawMessage(`{
						"@odata.type": "#microsoft.graph.group",
						"id": "good-group",
						"displayName": "Valid Group",
						"groupTypes": []
					}`),
				}, nil
			}
			return []json.RawMessage{}, nil
		},
	}

	checker := NewGroupChecker(mock)
	memberships, err := checker.GetTransitiveMemberships(context.Background(), "user-mixed", "User")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(memberships) != 1 {
		t.Fatalf("got %d memberships, want 1 (malformed items should be skipped)", len(memberships))
	}
	if memberships[0].GroupID != "good-group" {
		t.Errorf("GroupID = %q, want %q", memberships[0].GroupID, "good-group")
	}
}

func TestGetTransitiveMemberships_NonGroupODataTypesFiltered(t *testing.T) {
	// Items with @odata.type other than #microsoft.graph.group should be excluded.
	mock := &mockGraphRequester{
		doPagedRequestFunc: func(ctx context.Context, path string, query url.Values) ([]json.RawMessage, error) {
			if strings.Contains(path, "transitiveMemberOf") {
				return []json.RawMessage{
					json.RawMessage(`{
						"@odata.type": "#microsoft.graph.directoryRole",
						"id": "role-1",
						"displayName": "Some Role"
					}`),
					json.RawMessage(`{
						"@odata.type": "#microsoft.graph.administrativeUnit",
						"id": "au-1",
						"displayName": "Some AU"
					}`),
				}, nil
			}
			return []json.RawMessage{}, nil
		},
	}

	checker := NewGroupChecker(mock)
	memberships, err := checker.GetTransitiveMemberships(context.Background(), "user-roles-only", "User")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(memberships) != 0 {
		t.Errorf("got %d memberships, want 0 (non-group types should be filtered out)", len(memberships))
	}
}
