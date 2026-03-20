package graph

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"testing"
)

func TestMapAssignmentState(t *testing.T) {
	tests := []struct {
		name  string
		state string
		want  string
	}{
		// Known states — lowercase variants
		{
			name:  "delivered lowercase",
			state: "delivered",
			want:  "Delivered",
		},
		{
			name:  "Delivered capitalized",
			state: "Delivered",
			want:  "Delivered",
		},
		{
			name:  "partiallyDelivered",
			state: "partiallyDelivered",
			want:  "Partially Delivered",
		},
		{
			name:  "delivering",
			state: "delivering",
			want:  "Delivering",
		},
		{
			name:  "expired",
			state: "expired",
			want:  "Expired",
		},
		{
			name:  "deliveryFailed",
			state: "deliveryFailed",
			want:  "Delivery Failed",
		},
		{
			name:  "pendingApproval",
			state: "pendingApproval",
			want:  "Pending Approval",
		},
		// Unknown state — passthrough
		{
			name:  "unknown state passes through",
			state: "someUnknownState",
			want:  "someUnknownState",
		},
		{
			name:  "empty string passes through",
			state: "",
			want:  "",
		},
		{
			name:  "random casing not matched passes through",
			state: "DELIVERED",
			want:  "DELIVERED",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mapAssignmentState(tt.state)
			if got != tt.want {
				t.Errorf("mapAssignmentState(%q) = %q, want %q", tt.state, got, tt.want)
			}
		})
	}
}

// ---------- GetAssignments tests (via GraphRequester mock) ----------

func TestGetAssignments_Success(t *testing.T) {
	mock := &mockGraphRequester{
		doPagedRequestFunc: func(ctx context.Context, path string, query url.Values) ([]json.RawMessage, error) {
			items := []json.RawMessage{
				json.RawMessage(`{
					"id": "asgn-1",
					"state": "delivered",
					"schedule": {
						"expiration": {
							"endDateTime": "2025-12-31T23:59:59Z",
							"type": "afterDateTime"
						}
					},
					"accessPackage": {
						"displayName": "Developer Tools",
						"catalog": {
							"displayName": "IT Catalog"
						}
					}
				}`),
				json.RawMessage(`{
					"id": "asgn-2",
					"state": "pendingApproval",
					"schedule": {
						"expiration": {
							"endDateTime": "2026-06-15T00:00:00Z",
							"type": "afterDateTime"
						}
					},
					"accessPackage": {
						"displayName": "VPN Access",
						"catalog": {
							"displayName": "Network Catalog"
						}
					}
				}`),
			}
			return items, nil
		},
	}

	checker := NewAccessPackageChecker(mock)
	assignments, err := checker.GetAssignments(context.Background(), "user-ap-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(assignments) != 2 {
		t.Fatalf("got %d assignments, want 2", len(assignments))
	}

	// First assignment
	if assignments[0].ID != "asgn-1" {
		t.Errorf("assignments[0].ID = %q, want %q", assignments[0].ID, "asgn-1")
	}
	if assignments[0].PackageName != "Developer Tools" {
		t.Errorf("assignments[0].PackageName = %q, want %q", assignments[0].PackageName, "Developer Tools")
	}
	if assignments[0].CatalogName != "IT Catalog" {
		t.Errorf("assignments[0].CatalogName = %q, want %q", assignments[0].CatalogName, "IT Catalog")
	}
	if assignments[0].Status != "Delivered" {
		t.Errorf("assignments[0].Status = %q, want %q", assignments[0].Status, "Delivered")
	}
	if assignments[0].ExpirationDate != "2025-12-31T23:59:59Z" {
		t.Errorf("assignments[0].ExpirationDate = %q, want %q", assignments[0].ExpirationDate, "2025-12-31T23:59:59Z")
	}

	// Second assignment
	if assignments[1].Status != "Pending Approval" {
		t.Errorf("assignments[1].Status = %q, want %q", assignments[1].Status, "Pending Approval")
	}
}

func TestGetAssignments_NoExpiration(t *testing.T) {
	mock := &mockGraphRequester{
		doPagedRequestFunc: func(ctx context.Context, path string, query url.Values) ([]json.RawMessage, error) {
			items := []json.RawMessage{
				json.RawMessage(`{
					"id": "asgn-noexp",
					"state": "delivered",
					"schedule": {
						"expiration": {
							"endDateTime": "",
							"type": "noExpiration"
						}
					},
					"accessPackage": {
						"displayName": "Permanent Access",
						"catalog": {
							"displayName": "Core Catalog"
						}
					}
				}`),
			}
			return items, nil
		},
	}

	checker := NewAccessPackageChecker(mock)
	assignments, err := checker.GetAssignments(context.Background(), "user-noexp")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(assignments) != 1 {
		t.Fatalf("got %d assignments, want 1", len(assignments))
	}
	if assignments[0].ExpirationDate != "No Expiration" {
		t.Errorf("ExpirationDate = %q, want %q", assignments[0].ExpirationDate, "No Expiration")
	}
}

func TestGetAssignments_Error(t *testing.T) {
	mock := &mockGraphRequester{
		doPagedRequestFunc: func(ctx context.Context, path string, query url.Values) ([]json.RawMessage, error) {
			return nil, fmt.Errorf("connection timeout")
		},
	}

	checker := NewAccessPackageChecker(mock)
	_, err := checker.GetAssignments(context.Background(), "user-err")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "access package assignments") {
		t.Errorf("error should mention 'access package assignments', got: %v", err)
	}
}

func TestGetAssignments_EmptyResult(t *testing.T) {
	mock := &mockGraphRequester{
		doPagedRequestFunc: func(ctx context.Context, path string, query url.Values) ([]json.RawMessage, error) {
			return nil, nil
		},
	}

	checker := NewAccessPackageChecker(mock)
	assignments, err := checker.GetAssignments(context.Background(), "user-empty")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(assignments) != 0 {
		t.Errorf("got %d assignments, want 0", len(assignments))
	}
}

// ---------- GetRequests tests (via GraphRequester mock) ----------

func TestGetRequests_Success(t *testing.T) {
	mock := &mockGraphRequester{
		doPagedRequestFunc: func(ctx context.Context, path string, query url.Values) ([]json.RawMessage, error) {
			items := []json.RawMessage{
				json.RawMessage(`{
					"id": "req-1",
					"requestType": "userAdd",
					"state": "delivered",
					"createdDateTime": "2025-01-15T10:30:00Z",
					"accessPackage": {
						"displayName": "Engineering Tools"
					}
				}`),
				json.RawMessage(`{
					"id": "req-2",
					"requestType": "userUpdate",
					"state": "denied",
					"createdDateTime": "2025-01-10T08:00:00Z",
					"accessPackage": {
						"displayName": "Admin Portal"
					}
				}`),
			}
			return items, nil
		},
	}

	checker := NewAccessPackageChecker(mock)
	requests, err := checker.GetRequests(context.Background(), "user-req-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(requests) != 2 {
		t.Fatalf("got %d requests, want 2", len(requests))
	}

	// First request
	if requests[0].ID != "req-1" {
		t.Errorf("requests[0].ID = %q, want %q", requests[0].ID, "req-1")
	}
	if requests[0].PackageName != "Engineering Tools" {
		t.Errorf("requests[0].PackageName = %q, want %q", requests[0].PackageName, "Engineering Tools")
	}
	if requests[0].RequestType != "userAdd" {
		t.Errorf("requests[0].RequestType = %q, want %q", requests[0].RequestType, "userAdd")
	}
	if requests[0].Status != "delivered" {
		t.Errorf("requests[0].Status = %q, want %q", requests[0].Status, "delivered")
	}
	if requests[0].CreatedDate != "2025-01-15T10:30:00Z" {
		t.Errorf("requests[0].CreatedDate = %q, want %q", requests[0].CreatedDate, "2025-01-15T10:30:00Z")
	}

	// Second request
	if requests[1].PackageName != "Admin Portal" {
		t.Errorf("requests[1].PackageName = %q, want %q", requests[1].PackageName, "Admin Portal")
	}
	if requests[1].Status != "denied" {
		t.Errorf("requests[1].Status = %q, want %q", requests[1].Status, "denied")
	}
}

func TestGetRequests_Error(t *testing.T) {
	mock := &mockGraphRequester{
		doPagedRequestFunc: func(ctx context.Context, path string, query url.Values) ([]json.RawMessage, error) {
			return nil, fmt.Errorf("server unavailable")
		},
	}

	checker := NewAccessPackageChecker(mock)
	_, err := checker.GetRequests(context.Background(), "user-req-err")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "access package requests") {
		t.Errorf("error should mention 'access package requests', got: %v", err)
	}
}

func TestGetRequests_VerifiesQueryParams(t *testing.T) {
	var capturedPath string
	var capturedQuery url.Values

	mock := &mockGraphRequester{
		doPagedRequestFunc: func(ctx context.Context, path string, query url.Values) ([]json.RawMessage, error) {
			capturedPath = path
			capturedQuery = query
			return nil, nil
		},
	}

	checker := NewAccessPackageChecker(mock)
	_, _ = checker.GetRequests(context.Background(), "principal-id-123")

	if capturedPath != "/v1.0/identityGovernance/entitlementManagement/assignmentRequests" {
		t.Errorf("path = %q, want correct entitlement management requests path", capturedPath)
	}
	if f := capturedQuery.Get("$filter"); !strings.Contains(f, "principal-id-123") {
		t.Errorf("$filter = %q, want it to contain principal ID", f)
	}
	if top := capturedQuery.Get("$top"); top != "50" {
		t.Errorf("$top = %q, want %q", top, "50")
	}
	if ob := capturedQuery.Get("$orderby"); ob != "createdDateTime desc" {
		t.Errorf("$orderby = %q, want %q", ob, "createdDateTime desc")
	}
}

func TestGetAssignments_AllStates(t *testing.T) {
	// Table-driven test verifying all known state mappings flow through GetAssignments.
	tests := []struct {
		apiState   string
		wantStatus string
	}{
		{"delivered", "Delivered"},
		{"Delivered", "Delivered"},
		{"partiallyDelivered", "Partially Delivered"},
		{"delivering", "Delivering"},
		{"expired", "Expired"},
		{"deliveryFailed", "Delivery Failed"},
		{"pendingApproval", "Pending Approval"},
		{"unknownState", "unknownState"},
	}

	for _, tt := range tests {
		t.Run(tt.apiState, func(t *testing.T) {
			mock := &mockGraphRequester{
				doPagedRequestFunc: func(ctx context.Context, path string, query url.Values) ([]json.RawMessage, error) {
					item := json.RawMessage(fmt.Sprintf(`{
						"id": "test",
						"state": %q,
						"schedule": {"expiration": {"endDateTime": "2025-12-31T00:00:00Z", "type": "afterDateTime"}},
						"accessPackage": {"displayName": "Pkg", "catalog": {"displayName": "Cat"}}
					}`, tt.apiState))
					return []json.RawMessage{item}, nil
				},
			}

			checker := NewAccessPackageChecker(mock)
			assignments, err := checker.GetAssignments(context.Background(), "user-state-test")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(assignments) != 1 {
				t.Fatalf("got %d assignments, want 1", len(assignments))
			}
			if assignments[0].Status != tt.wantStatus {
				t.Errorf("Status = %q, want %q", assignments[0].Status, tt.wantStatus)
			}
		})
	}
}

func TestGetAssignments_InvalidJSON(t *testing.T) {
	mock := &mockGraphRequester{
		doPagedRequestFunc: func(ctx context.Context, path string, query url.Values) ([]json.RawMessage, error) {
			items := []json.RawMessage{
				json.RawMessage(`{not valid json}`),
			}
			return items, nil
		},
	}

	checker := NewAccessPackageChecker(mock)
	assignments, err := checker.GetAssignments(context.Background(), "user-badjson")
	if err != nil {
		t.Fatalf("expected no error (bad items are skipped), got: %v", err)
	}
	if len(assignments) != 0 {
		t.Errorf("got %d assignments, want 0 (bad items should be skipped)", len(assignments))
	}
}

func TestGetRequests_InvalidJSON(t *testing.T) {
	mock := &mockGraphRequester{
		doPagedRequestFunc: func(ctx context.Context, path string, query url.Values) ([]json.RawMessage, error) {
			items := []json.RawMessage{
				json.RawMessage(`{broken json}`),
			}
			return items, nil
		},
	}

	checker := NewAccessPackageChecker(mock)
	requests, err := checker.GetRequests(context.Background(), "user-badjson")
	if err != nil {
		t.Fatalf("expected no error (bad items are skipped), got: %v", err)
	}
	if len(requests) != 0 {
		t.Errorf("got %d requests, want 0 (bad items should be skipped)", len(requests))
	}
}

func TestGetRequests_EmptyResult(t *testing.T) {
	mock := &mockGraphRequester{
		doPagedRequestFunc: func(ctx context.Context, path string, query url.Values) ([]json.RawMessage, error) {
			return nil, nil
		},
	}

	checker := NewAccessPackageChecker(mock)
	requests, err := checker.GetRequests(context.Background(), "user-empty")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(requests) != 0 {
		t.Errorf("got %d requests, want 0", len(requests))
	}
}

func TestGetAssignments_VerifiesQueryParams(t *testing.T) {
	var capturedPath string
	var capturedQuery url.Values

	mock := &mockGraphRequester{
		doPagedRequestFunc: func(ctx context.Context, path string, query url.Values) ([]json.RawMessage, error) {
			capturedPath = path
			capturedQuery = query
			return nil, nil
		},
	}

	checker := NewAccessPackageChecker(mock)
	_, _ = checker.GetAssignments(context.Background(), "principal-id-abc")

	if capturedPath != "/v1.0/identityGovernance/entitlementManagement/assignments" {
		t.Errorf("path = %q, want correct entitlement management assignments path", capturedPath)
	}
	if f := capturedQuery.Get("$filter"); !strings.Contains(f, "principal-id-abc") {
		t.Errorf("$filter = %q, want it to contain the principal ID", f)
	}
	if e := capturedQuery.Get("$expand"); !strings.Contains(e, "accessPackage") {
		t.Errorf("$expand = %q, want it to contain 'accessPackage'", e)
	}
}

// ---------------------------------------------------------------------------
// Security regression: OData escaping in principalId filters
// ---------------------------------------------------------------------------

func TestGetAssignments_EscapesPrincipalID(t *testing.T) {
	var capturedQuery url.Values
	mock := &mockGraphRequester{
		doPagedRequestFunc: func(ctx context.Context, path string, query url.Values) ([]json.RawMessage, error) {
			capturedQuery = query
			return nil, nil
		},
	}

	checker := NewAccessPackageChecker(mock)
	_, _ = checker.GetAssignments(context.Background(), "id-with-'quote")

	filter := capturedQuery.Get("$filter")
	if strings.Contains(filter, "id-with-'quote") {
		t.Errorf("filter contains unescaped single quote — injection possible: %s", filter)
	}
	if !strings.Contains(filter, "id-with-''quote") {
		t.Errorf("filter should contain doubled single quote, got: %s", filter)
	}
}

func TestGetRequests_EscapesPrincipalID(t *testing.T) {
	var capturedQuery url.Values
	mock := &mockGraphRequester{
		doPagedRequestFunc: func(ctx context.Context, path string, query url.Values) ([]json.RawMessage, error) {
			capturedQuery = query
			return nil, nil
		},
	}

	checker := NewAccessPackageChecker(mock)
	_, _ = checker.GetRequests(context.Background(), "id-with-'quote")

	filter := capturedQuery.Get("$filter")
	if strings.Contains(filter, "id-with-'quote") {
		t.Errorf("filter contains unescaped single quote — injection possible: %s", filter)
	}
	if !strings.Contains(filter, "id-with-''quote") {
		t.Errorf("filter should contain doubled single quote, got: %s", filter)
	}
}
