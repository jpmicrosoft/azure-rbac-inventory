package graph

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"testing"
)

func TestGetRoleAssignments_Success(t *testing.T) {
	// Arrange — mock returns valid items with roleDefinition expanded.
	mock := &mockGraphRequester{
		doPagedRequestFunc: func(ctx context.Context, path string, query url.Values) ([]json.RawMessage, error) {
			items := []json.RawMessage{
				json.RawMessage(`{
					"id": "assign-1",
					"principalId": "user-abc",
					"roleDefinitionId": "role-def-1",
					"roleDefinition": {
						"displayName": "Global Administrator"
					}
				}`),
				json.RawMessage(`{
					"id": "assign-2",
					"principalId": "user-abc",
					"roleDefinitionId": "role-def-2",
					"roleDefinition": {
						"displayName": "User Administrator"
					}
				}`),
			}
			return items, nil
		},
	}

	checker := NewDirectoryRoleChecker(mock)

	// Act
	roles, err := checker.GetRoleAssignments(context.Background(), "user-abc")

	// Assert
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(roles) != 2 {
		t.Fatalf("got %d roles, want 2", len(roles))
	}

	// First role
	if roles[0].RoleName != "Global Administrator" {
		t.Errorf("roles[0].RoleName = %q, want %q", roles[0].RoleName, "Global Administrator")
	}
	if roles[0].RoleID != "role-def-1" {
		t.Errorf("roles[0].RoleID = %q, want %q", roles[0].RoleID, "role-def-1")
	}
	if roles[0].AssignmentID != "assign-1" {
		t.Errorf("roles[0].AssignmentID = %q, want %q", roles[0].AssignmentID, "assign-1")
	}
	if roles[0].Status != "Active" {
		t.Errorf("roles[0].Status = %q, want %q", roles[0].Status, "Active")
	}

	// Second role
	if roles[1].RoleName != "User Administrator" {
		t.Errorf("roles[1].RoleName = %q, want %q", roles[1].RoleName, "User Administrator")
	}
	if roles[1].RoleID != "role-def-2" {
		t.Errorf("roles[1].RoleID = %q, want %q", roles[1].RoleID, "role-def-2")
	}
}

func TestGetRoleAssignments_FallbackResolve(t *testing.T) {
	// Arrange — doPagedRequestFunc returns assignment with empty displayName in roleDefinition,
	// doRequestFunc (role definition lookup) returns the name.
	callCount := 0
	mock := &mockGraphRequester{
		doPagedRequestFunc: func(ctx context.Context, path string, query url.Values) ([]json.RawMessage, error) {
			items := []json.RawMessage{
				json.RawMessage(`{
					"id": "assign-fallback",
					"principalId": "user-xyz",
					"roleDefinitionId": "00000000-0000-0000-0000-000000000099",
					"roleDefinition": {
						"displayName": ""
					}
				}`),
			}
			return items, nil
		},
		doRequestFunc: func(ctx context.Context, path string, query url.Values) ([]byte, error) {
			callCount++
			if strings.Contains(path, "roleDefinitions/00000000-0000-0000-0000-000000000099") {
				return []byte(`{
					"id": "00000000-0000-0000-0000-000000000099",
					"displayName": "Resolved Role Name"
				}`), nil
			}
			return nil, fmt.Errorf("unexpected path: %s", path)
		},
	}

	checker := NewDirectoryRoleChecker(mock)

	// Act
	roles, err := checker.GetRoleAssignments(context.Background(), "user-xyz")

	// Assert
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(roles) != 1 {
		t.Fatalf("got %d roles, want 1", len(roles))
	}
	if roles[0].RoleName != "Resolved Role Name" {
		t.Errorf("roles[0].RoleName = %q, want %q (fallback resolution)", roles[0].RoleName, "Resolved Role Name")
	}
	if callCount < 1 {
		t.Errorf("expected at least 1 DoRequest call (fallback), got %d", callCount)
	}
}

func TestGetRoleAssignments_FallbackResolve_Error(t *testing.T) {
	// When the fallback role definition lookup fails, the role ID should be used as the name.
	mock := &mockGraphRequester{
		doPagedRequestFunc: func(ctx context.Context, path string, query url.Values) ([]json.RawMessage, error) {
			items := []json.RawMessage{
				json.RawMessage(`{
					"id": "assign-fb-err",
					"principalId": "user-fallback-err",
					"roleDefinitionId": "00000000-0000-0000-0000-0000000000ab",
					"roleDefinition": {
						"displayName": ""
					}
				}`),
			}
			return items, nil
		},
		doRequestFunc: func(ctx context.Context, path string, query url.Values) ([]byte, error) {
			// Simulate failure on role definition lookup
			return nil, fmt.Errorf("network error")
		},
	}

	checker := NewDirectoryRoleChecker(mock)

	roles, err := checker.GetRoleAssignments(context.Background(), "user-fallback-err")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(roles) != 1 {
		t.Fatalf("got %d roles, want 1", len(roles))
	}
	// When fallback fails, the role definition ID is used as the name
	if roles[0].RoleName != "00000000-0000-0000-0000-0000000000ab" {
		t.Errorf("roles[0].RoleName = %q, want %q (should fall back to role def ID)", roles[0].RoleName, "00000000-0000-0000-0000-0000000000ab")
	}
}

func TestGetRoleAssignments_Error(t *testing.T) {
	// Arrange — mock returns an error from the API call.
	mock := &mockGraphRequester{
		doPagedRequestFunc: func(ctx context.Context, path string, query url.Values) ([]json.RawMessage, error) {
			return nil, fmt.Errorf("Graph API error (HTTP 403): Authorization_RequestDenied: access denied")
		},
	}

	checker := NewDirectoryRoleChecker(mock)

	// Act
	roles, err := checker.GetRoleAssignments(context.Background(), "user-nope")

	// Assert
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if roles != nil {
		t.Errorf("expected nil roles on error, got %v", roles)
	}
	if !strings.Contains(err.Error(), "directory role assignments") {
		t.Errorf("error should mention 'directory role assignments', got: %v", err)
	}
}

func TestGetRoleAssignments_EmptyResult(t *testing.T) {
	mock := &mockGraphRequester{
		doPagedRequestFunc: func(ctx context.Context, path string, query url.Values) ([]json.RawMessage, error) {
			return nil, nil
		},
	}

	checker := NewDirectoryRoleChecker(mock)

	roles, err := checker.GetRoleAssignments(context.Background(), "user-no-roles")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(roles) != 0 {
		t.Errorf("got %d roles, want 0", len(roles))
	}
}

func TestGetRoleAssignments_VerifiesQueryParams(t *testing.T) {
	// Verify the correct filter and expand are sent to the API.
	var capturedPath string
	var capturedQuery url.Values

	mock := &mockGraphRequester{
		doPagedRequestFunc: func(ctx context.Context, path string, query url.Values) ([]json.RawMessage, error) {
			capturedPath = path
			capturedQuery = query
			return nil, nil
		},
	}

	checker := NewDirectoryRoleChecker(mock)
	_, _ = checker.GetRoleAssignments(context.Background(), "test-principal-id")

	if capturedPath != "/v1.0/roleManagement/directory/roleAssignments" {
		t.Errorf("path = %q, want %q", capturedPath, "/v1.0/roleManagement/directory/roleAssignments")
	}
	if f := capturedQuery.Get("$filter"); f != "principalId eq 'test-principal-id'" {
		t.Errorf("$filter = %q, want %q", f, "principalId eq 'test-principal-id'")
	}
	if e := capturedQuery.Get("$expand"); e != "roleDefinition" {
		t.Errorf("$expand = %q, want %q", e, "roleDefinition")
	}
}

func TestGetRoleAssignments_InvalidJSON(t *testing.T) {
	mock := &mockGraphRequester{
		doPagedRequestFunc: func(ctx context.Context, path string, query url.Values) ([]json.RawMessage, error) {
			items := []json.RawMessage{
				json.RawMessage(`{not valid json}`),
			}
			return items, nil
		},
	}

	checker := NewDirectoryRoleChecker(mock)

	roles, err := checker.GetRoleAssignments(context.Background(), "user-badjson")
	if err != nil {
		t.Fatalf("expected no error (bad items are skipped), got: %v", err)
	}
	if len(roles) != 0 {
		t.Errorf("got %d roles, want 0 (bad items should be skipped)", len(roles))
	}
}
