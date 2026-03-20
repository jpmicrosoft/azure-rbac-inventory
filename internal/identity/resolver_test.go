package identity

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"testing"

	"github.com/jpmicrosoft/azure-rbac-inventory/internal/graph"
)

func TestValidateID_ValidUUID(t *testing.T) {
	err := ValidateID("550e8400-e29b-41d4-a716-446655440000")
	if err != nil {
		t.Errorf("ValidateID with valid UUID returned error: %v", err)
	}
}

func TestValidateID_InvalidFormat(t *testing.T) {
	err := ValidateID("not-a-uuid")
	if err == nil {
		t.Error("expected error for invalid UUID format, got nil")
	}
}

func TestValidateID_Empty(t *testing.T) {
	err := ValidateID("")
	if err == nil {
		t.Error("expected error for empty string, got nil")
	}
}

func TestValidateID_UpperCase(t *testing.T) {
	err := ValidateID("550E8400-E29B-41D4-A716-446655440000")
	if err != nil {
		t.Errorf("ValidateID with uppercase UUID returned error: %v", err)
	}
}

func TestValidateID_TableDriven(t *testing.T) {
	tests := []struct {
		name    string
		id      string
		wantErr bool
	}{
		{
			name:    "valid lowercase UUID",
			id:      "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
			wantErr: false,
		},
		{
			name:    "valid uppercase UUID",
			id:      "A1B2C3D4-E5F6-7890-ABCD-EF1234567890",
			wantErr: false,
		},
		{
			name:    "valid mixed case UUID",
			id:      "a1B2c3D4-E5f6-7890-AbCd-eF1234567890",
			wantErr: false,
		},
		{
			name:    "all zeros UUID",
			id:      "00000000-0000-0000-0000-000000000000",
			wantErr: false,
		},
		{
			name:    "all f's UUID",
			id:      "ffffffff-ffff-ffff-ffff-ffffffffffff",
			wantErr: false,
		},
		{
			name:    "empty string",
			id:      "",
			wantErr: true,
		},
		{
			name:    "plain text",
			id:      "not-a-uuid",
			wantErr: true,
		},
		{
			name:    "UUID without dashes",
			id:      "550e8400e29b41d4a716446655440000",
			wantErr: true,
		},
		{
			name:    "UUID with extra characters",
			id:      "550e8400-e29b-41d4-a716-446655440000-extra",
			wantErr: true,
		},
		{
			name:    "UUID with braces",
			id:      "{550e8400-e29b-41d4-a716-446655440000}",
			wantErr: true,
		},
		{
			name:    "too short",
			id:      "550e8400-e29b-41d4-a716",
			wantErr: true,
		},
		{
			name:    "contains non-hex character",
			id:      "550e8400-e29b-41d4-a716-44665544000g",
			wantErr: true,
		},
		{
			name:    "whitespace around valid UUID",
			id:      " 550e8400-e29b-41d4-a716-446655440000 ",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateID(tt.id)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateID(%q) error = %v, wantErr = %v", tt.id, err, tt.wantErr)
			}
		})
	}
}

// ---------- mock GraphRequester for Resolver tests ----------

type mockGraphRequester struct {
	doRequestFunc            func(ctx context.Context, path string, query url.Values) ([]byte, error)
	doRequestWithHeadersFunc func(ctx context.Context, path string, query url.Values, headers map[string]string) ([]byte, error)
	doPagedRequestFunc       func(ctx context.Context, path string, query url.Values) ([]json.RawMessage, error)
}

func (m *mockGraphRequester) DoRequest(ctx context.Context, path string, query url.Values) ([]byte, error) {
	if m.doRequestFunc != nil {
		return m.doRequestFunc(ctx, path, query)
	}
	return nil, nil
}

func (m *mockGraphRequester) DoRequestWithHeaders(ctx context.Context, path string, query url.Values, headers map[string]string) ([]byte, error) {
	if m.doRequestWithHeadersFunc != nil {
		return m.doRequestWithHeadersFunc(ctx, path, query, headers)
	}
	// Fall back to DoRequest if no specific handler is set.
	return m.DoRequest(ctx, path, query)
}

func (m *mockGraphRequester) DoPagedRequest(ctx context.Context, path string, query url.Values) ([]json.RawMessage, error) {
	if m.doPagedRequestFunc != nil {
		return m.doPagedRequestFunc(ctx, path, query)
	}
	return nil, nil
}

// Compile-time check that our mock satisfies the interface.
var _ graph.GraphRequester = (*mockGraphRequester)(nil)

// ---------- Resolver tests ----------

func TestResolve_ByObjectID_User(t *testing.T) {
	mock := &mockGraphRequester{
		doRequestFunc: func(ctx context.Context, path string, query url.Values) ([]byte, error) {
			if strings.Contains(path, "/directoryObjects/") {
				return []byte(`{
					"@odata.type": "#microsoft.graph.user",
					"id": "user-obj-1",
					"displayName": "Jane Doe",
					"appId": ""
				}`), nil
			}
			return nil, fmt.Errorf("unexpected path: %s", path)
		},
	}

	resolver := NewResolver(mock)
	identity, err := resolver.Resolve(context.Background(), "user-obj-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if identity.Type != TypeUser {
		t.Errorf("Type = %q, want %q", identity.Type, TypeUser)
	}
	if identity.ObjectID != "user-obj-1" {
		t.Errorf("ObjectID = %q, want %q", identity.ObjectID, "user-obj-1")
	}
	if identity.DisplayName != "Jane Doe" {
		t.Errorf("DisplayName = %q, want %q", identity.DisplayName, "Jane Doe")
	}
}

func TestResolve_ByObjectID_ServicePrincipal(t *testing.T) {
	mock := &mockGraphRequester{
		doRequestFunc: func(ctx context.Context, path string, query url.Values) ([]byte, error) {
			if strings.Contains(path, "/directoryObjects/") {
				return []byte(`{
					"@odata.type": "#microsoft.graph.servicePrincipal",
					"id": "spn-obj-1",
					"displayName": "My App SPN",
					"appId": "app-id-123",
					"servicePrincipalType": "Application"
				}`), nil
			}
			return nil, fmt.Errorf("unexpected path: %s", path)
		},
	}

	resolver := NewResolver(mock)
	identity, err := resolver.Resolve(context.Background(), "spn-obj-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if identity.Type != TypeServicePrincipal {
		t.Errorf("Type = %q, want %q", identity.Type, TypeServicePrincipal)
	}
	if identity.AppID != "app-id-123" {
		t.Errorf("AppID = %q, want %q", identity.AppID, "app-id-123")
	}
	if identity.ServicePrincipalType != "Application" {
		t.Errorf("ServicePrincipalType = %q, want %q", identity.ServicePrincipalType, "Application")
	}
}

func TestResolve_ByObjectID_ManagedIdentity(t *testing.T) {
	mock := &mockGraphRequester{
		doRequestFunc: func(ctx context.Context, path string, query url.Values) ([]byte, error) {
			if strings.Contains(path, "/directoryObjects/") {
				return []byte(`{
					"@odata.type": "#microsoft.graph.servicePrincipal",
					"id": "mi-obj-1",
					"displayName": "my-vm-identity",
					"appId": "mi-app-id",
					"servicePrincipalType": "ManagedIdentity"
				}`), nil
			}
			return nil, fmt.Errorf("unexpected path: %s", path)
		},
	}

	resolver := NewResolver(mock)
	identity, err := resolver.Resolve(context.Background(), "mi-obj-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if identity.Type != TypeManagedIdentity {
		t.Errorf("Type = %q, want %q", identity.Type, TypeManagedIdentity)
	}
	if identity.ServicePrincipalType != "ManagedIdentity" {
		t.Errorf("ServicePrincipalType = %q, want %q", identity.ServicePrincipalType, "ManagedIdentity")
	}
}

func TestResolve_ByObjectID_Group(t *testing.T) {
	mock := &mockGraphRequester{
		doRequestFunc: func(ctx context.Context, path string, query url.Values) ([]byte, error) {
			if strings.Contains(path, "/directoryObjects/") {
				return []byte(`{
					"@odata.type": "#microsoft.graph.group",
					"id": "group-obj-1",
					"displayName": "Security Group"
				}`), nil
			}
			return nil, fmt.Errorf("unexpected path: %s", path)
		},
	}

	resolver := NewResolver(mock)
	identity, err := resolver.Resolve(context.Background(), "group-obj-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if identity.Type != TypeGroup {
		t.Errorf("Type = %q, want %q", identity.Type, TypeGroup)
	}
}

func TestResolve_ByObjectID_Application(t *testing.T) {
	mock := &mockGraphRequester{
		doRequestFunc: func(ctx context.Context, path string, query url.Values) ([]byte, error) {
			if strings.Contains(path, "/directoryObjects/") {
				return []byte(`{
					"@odata.type": "#microsoft.graph.application",
					"id": "app-obj-1",
					"displayName": "My Application",
					"appId": "app-reg-id"
				}`), nil
			}
			return nil, fmt.Errorf("unexpected path: %s", path)
		},
	}

	resolver := NewResolver(mock)
	identity, err := resolver.Resolve(context.Background(), "app-obj-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if identity.Type != TypeApplication {
		t.Errorf("Type = %q, want %q", identity.Type, TypeApplication)
	}
}

func TestResolve_ByObjectID_UnknownType(t *testing.T) {
	mock := &mockGraphRequester{
		doRequestFunc: func(ctx context.Context, path string, query url.Values) ([]byte, error) {
			if strings.Contains(path, "/directoryObjects/") {
				return []byte(`{
					"@odata.type": "#microsoft.graph.someNewThing",
					"id": "unknown-obj-1",
					"displayName": "Mystery Object"
				}`), nil
			}
			return nil, fmt.Errorf("unexpected path: %s", path)
		},
	}

	resolver := NewResolver(mock)
	identity, err := resolver.Resolve(context.Background(), "unknown-obj-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if identity.Type != TypeUnknown {
		t.Errorf("Type = %q, want %q", identity.Type, TypeUnknown)
	}
}

func TestResolve_FallbackToAppID(t *testing.T) {
	// First call (directoryObjects) fails, second call (servicePrincipals filter) succeeds.
	mock := &mockGraphRequester{
		doRequestFunc: func(ctx context.Context, path string, query url.Values) ([]byte, error) {
			if strings.Contains(path, "/directoryObjects/") {
				return nil, fmt.Errorf("Request_ResourceNotFound: not found")
			}
			if strings.Contains(path, "/servicePrincipals") {
				return []byte(`{
					"value": [
						{
							"@odata.type": "#microsoft.graph.servicePrincipal",
							"id": "spn-from-appid",
							"displayName": "App Via AppID",
							"appId": "the-app-id",
							"servicePrincipalType": "Application"
						}
					]
				}`), nil
			}
			return nil, fmt.Errorf("unexpected path: %s", path)
		},
	}

	resolver := NewResolver(mock)
	identity, err := resolver.Resolve(context.Background(), "the-app-id")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if identity.Type != TypeServicePrincipal {
		t.Errorf("Type = %q, want %q", identity.Type, TypeServicePrincipal)
	}
	if identity.ObjectID != "spn-from-appid" {
		t.Errorf("ObjectID = %q, want %q", identity.ObjectID, "spn-from-appid")
	}
	if identity.AppID != "the-app-id" {
		t.Errorf("AppID = %q, want %q", identity.AppID, "the-app-id")
	}
}

func TestResolve_BothFail(t *testing.T) {
	mock := &mockGraphRequester{
		doRequestFunc: func(ctx context.Context, path string, query url.Values) ([]byte, error) {
			if strings.Contains(path, "/directoryObjects/") {
				return nil, fmt.Errorf("object not found")
			}
			if strings.Contains(path, "/servicePrincipals") {
				return nil, fmt.Errorf("service principal not found")
			}
			return nil, fmt.Errorf("unexpected path: %s", path)
		},
	}

	resolver := NewResolver(mock)
	_, err := resolver.Resolve(context.Background(), "nonexistent-id")
	if err == nil {
		t.Fatal("expected error when both lookups fail, got nil")
	}

	errMsg := err.Error()
	if !strings.Contains(errMsg, "object not found") {
		t.Errorf("error should contain objectID lookup error, got: %v", err)
	}
	if !strings.Contains(errMsg, "service principal not found") {
		t.Errorf("error should contain appID lookup error, got: %v", err)
	}
	if !strings.Contains(errMsg, "nonexistent-id") {
		t.Errorf("error should contain the ID that failed, got: %v", err)
	}
}

func TestResolve_FallbackToAppID_NoResults(t *testing.T) {
	// objectID lookup fails, appID lookup succeeds but returns empty list.
	mock := &mockGraphRequester{
		doRequestFunc: func(ctx context.Context, path string, query url.Values) ([]byte, error) {
			if strings.Contains(path, "/directoryObjects/") {
				return nil, fmt.Errorf("not found")
			}
			if strings.Contains(path, "/servicePrincipals") {
				return []byte(`{"value": []}`), nil
			}
			return nil, fmt.Errorf("unexpected path: %s", path)
		},
	}

	resolver := NewResolver(mock)
	_, err := resolver.Resolve(context.Background(), "no-match-anywhere")
	if err == nil {
		t.Fatal("expected error when both lookups fail, got nil")
	}
	if !strings.Contains(err.Error(), "no-match-anywhere") {
		t.Errorf("error should contain the failing ID, got: %v", err)
	}
}
