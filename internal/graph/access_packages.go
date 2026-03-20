package graph

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
)

// AccessPackageAssignment represents an Identity Governance access package assignment.
type AccessPackageAssignment struct {
	ID             string `json:"id"`
	PackageName    string `json:"packageName"`
	CatalogName    string `json:"catalogName"`
	Status         string `json:"status"`
	ExpirationDate string `json:"expirationDate,omitempty"`
}

// AccessPackageRequest represents a pending/completed access package request.
type AccessPackageRequest struct {
	ID          string `json:"id"`
	PackageName string `json:"packageName"`
	RequestType string `json:"requestType"`
	Status      string `json:"status"`
	CreatedDate string `json:"createdDate"`
}

// AccessPackageChecker queries Identity Governance entitlement management.
type AccessPackageChecker struct {
	client GraphRequester
}

// NewAccessPackageChecker creates a new access package checker.
func NewAccessPackageChecker(client GraphRequester) *AccessPackageChecker {
	return &AccessPackageChecker{client: client}
}

// GetAssignments retrieves all access package assignments for a principal.
func (a *AccessPackageChecker) GetAssignments(ctx context.Context, principalID string) ([]AccessPackageAssignment, error) {
	query := url.Values{}
	query.Set("$filter", fmt.Sprintf("target/objectId eq '%s'", principalID))
	query.Set("$expand", "accessPackage($expand=catalog),target")

	items, err := a.client.DoPagedRequest(ctx, "/v1.0/identityGovernance/entitlementManagement/assignments", query)
	if err != nil {
		return nil, fmt.Errorf("failed to query access package assignments: %w", err)
	}

	var assignments []AccessPackageAssignment
	for _, raw := range items {
		var item struct {
			ID       string `json:"id"`
			State    string `json:"state"`
			Schedule struct {
				Expiration struct {
					EndDateTime string `json:"endDateTime"`
					Type        string `json:"type"`
				} `json:"expiration"`
			} `json:"schedule"`
			AccessPackage struct {
				DisplayName string `json:"displayName"`
				Catalog     struct {
					DisplayName string `json:"displayName"`
				} `json:"catalog"`
			} `json:"accessPackage"`
		}
		if err := json.Unmarshal(raw, &item); err != nil {
			continue
		}

		expiration := item.Schedule.Expiration.EndDateTime
		if item.Schedule.Expiration.Type == "noExpiration" {
			expiration = "No Expiration"
		}

		assignments = append(assignments, AccessPackageAssignment{
			ID:             item.ID,
			PackageName:    item.AccessPackage.DisplayName,
			CatalogName:    item.AccessPackage.Catalog.DisplayName,
			Status:         mapAssignmentState(item.State),
			ExpirationDate: expiration,
		})
	}

	return assignments, nil
}

// GetRequests retrieves access package requests for a principal (pending, denied, etc.).
func (a *AccessPackageChecker) GetRequests(ctx context.Context, principalID string) ([]AccessPackageRequest, error) {
	query := url.Values{}
	query.Set("$filter", fmt.Sprintf("requestor/objectId eq '%s'", principalID))
	query.Set("$expand", "accessPackage")
	query.Set("$orderby", "createdDateTime desc")
	query.Set("$top", "50")

	items, err := a.client.DoPagedRequest(ctx, "/v1.0/identityGovernance/entitlementManagement/assignmentRequests", query)
	if err != nil {
		return nil, fmt.Errorf("failed to query access package requests: %w", err)
	}

	var requests []AccessPackageRequest
	for _, raw := range items {
		var item struct {
			ID              string `json:"id"`
			RequestType     string `json:"requestType"`
			State           string `json:"state"`
			CreatedDateTime string `json:"createdDateTime"`
			AccessPackage   struct {
				DisplayName string `json:"displayName"`
			} `json:"accessPackage"`
		}
		if err := json.Unmarshal(raw, &item); err != nil {
			continue
		}

		requests = append(requests, AccessPackageRequest{
			ID:          item.ID,
			PackageName: item.AccessPackage.DisplayName,
			RequestType: item.RequestType,
			Status:      item.State,
			CreatedDate: item.CreatedDateTime,
		})
	}

	return requests, nil
}

func mapAssignmentState(state string) string {
	switch state {
	case "delivered", "Delivered":
		return "Delivered"
	case "partiallyDelivered":
		return "Partially Delivered"
	case "delivering":
		return "Delivering"
	case "expired":
		return "Expired"
	case "deliveryFailed":
		return "Delivery Failed"
	case "pendingApproval":
		return "Pending Approval"
	default:
		return state
	}
}
