package identity

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/jpmicrosoft/azure-rbac-inventory/internal/graph"
)

var uuidRegex = regexp.MustCompile(
	`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// ValidateID checks that the given string is a valid UUID format.
func ValidateID(id string) error {
	if !uuidRegex.MatchString(id) {
		return fmt.Errorf("invalid identity ID format (expected UUID): %q", id)
	}
	return nil
}

// IsPattern reports whether the input is a search pattern rather than an exact ID.
// It returns true if the input contains wildcard characters (* or ?) or is not a
// valid UUID. It returns false only when the input is a valid UUID (exact match mode).
func IsPattern(input string) bool {
	if strings.ContainsAny(input, "*?") {
		return true
	}
	return !uuidRegex.MatchString(input)
}

// IdentityType represents the type of Azure AD identity.
type IdentityType string

const (
	// TypeUser represents an Entra ID user account.
	TypeUser IdentityType = "User"
	// TypeServicePrincipal represents an application service principal.
	TypeServicePrincipal IdentityType = "ServicePrincipal"
	// TypeManagedIdentity represents an Azure managed identity (system- or user-assigned).
	TypeManagedIdentity IdentityType = "ManagedIdentity"
	// TypeApplication represents an Entra ID application registration.
	TypeApplication IdentityType = "Application"
	// TypeGroup represents an Entra ID security or Microsoft 365 group.
	TypeGroup IdentityType = "Group"
	// TypeUnknown represents an unrecognized directory object type.
	TypeUnknown IdentityType = "Unknown"
)

// Identity holds resolved identity details.
type Identity struct {
	ObjectID             string       `json:"objectId"`
	AppID                string       `json:"appId,omitempty"`
	DisplayName          string       `json:"displayName"`
	Type                 IdentityType `json:"type"`
	ServicePrincipalType string       `json:"servicePrincipalType,omitempty"`
	IsMerged             bool         `json:"isMerged,omitempty"`
}

type directoryObject struct {
	ODataType            string `json:"@odata.type"`
	ID                   string `json:"id"`
	DisplayName          string `json:"displayName"`
	AppID                string `json:"appId"`
	ServicePrincipalType string `json:"servicePrincipalType"`
}

// Resolver resolves Azure AD object IDs or app IDs to identity details.
type Resolver struct {
	graphClient graph.GraphRequester
}

// NewResolver creates a new identity resolver.
func NewResolver(client graph.GraphRequester) *Resolver {
	return &Resolver{graphClient: client}
}

// Resolve attempts to resolve the given ID (object ID or app ID) to an Identity.
func (r *Resolver) Resolve(ctx context.Context, id string) (*Identity, error) {
	// First try as an object ID via /directoryObjects/{id}
	identity, objErr := r.resolveByObjectID(ctx, id)
	if objErr == nil {
		return identity, nil
	}

	// If that fails, try as an app ID via /servicePrincipals?$filter=appId eq '{id}'
	identity, appErr := r.resolveByAppID(ctx, id)
	if appErr == nil {
		return identity, nil
	}

	return nil, fmt.Errorf("could not resolve identity for ID %s (objectID lookup: %w; appID lookup: %w)", id, objErr, appErr)
}

func (r *Resolver) resolveByObjectID(ctx context.Context, objectID string) (*Identity, error) {
	body, err := r.graphClient.DoRequest(ctx,
		fmt.Sprintf("/v1.0/directoryObjects/%s", objectID),
		nil,
	)
	if err != nil {
		return nil, err
	}

	var obj directoryObject
	if err := json.Unmarshal(body, &obj); err != nil {
		return nil, fmt.Errorf("failed to parse directory object: %w", err)
	}

	return r.mapToIdentity(obj), nil
}

func (r *Resolver) resolveByAppID(ctx context.Context, appID string) (*Identity, error) {
	query := url.Values{}
	query.Set("$filter", fmt.Sprintf("appId eq '%s'", appID))

	body, err := r.graphClient.DoRequest(ctx, "/v1.0/servicePrincipals", query)
	if err != nil {
		return nil, err
	}

	var resp struct {
		Value []directoryObject `json:"value"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse service principals: %w", err)
	}

	if len(resp.Value) == 0 {
		return nil, fmt.Errorf("no service principal found with appId: %s", appID)
	}

	ident := r.mapToIdentity(resp.Value[0])
	// /servicePrincipals endpoint may not include @odata.type — default to SPN
	if ident.Type == TypeUnknown {
		if ident.ServicePrincipalType == "ManagedIdentity" {
			ident.Type = TypeManagedIdentity
		} else {
			ident.Type = TypeServicePrincipal
		}
	}
	return ident, nil
}

func (r *Resolver) mapToIdentity(obj directoryObject) *Identity {
	identity := &Identity{
		ObjectID:    obj.ID,
		DisplayName: obj.DisplayName,
		AppID:       obj.AppID,
	}

	switch obj.ODataType {
	case "#microsoft.graph.user":
		identity.Type = TypeUser
	case "#microsoft.graph.servicePrincipal":
		identity.ServicePrincipalType = obj.ServicePrincipalType
		if obj.ServicePrincipalType == "ManagedIdentity" {
			identity.Type = TypeManagedIdentity
		} else {
			identity.Type = TypeServicePrincipal
		}
	case "#microsoft.graph.application":
		identity.Type = TypeApplication
	case "#microsoft.graph.group":
		identity.Type = TypeGroup
	default:
		identity.Type = TypeUnknown
	}

	return identity
}
