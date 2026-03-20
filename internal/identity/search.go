package identity

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

// SearchResult holds a found identity from pattern search.
type SearchResult struct {
	Identity *Identity
	Source   string // "servicePrincipal", "user", "group", "application"
}

// searchEndpoint defines a Graph API endpoint to search.
type searchEndpoint struct {
	path   string
	source string
}

// partialGUIDRegex matches strings containing only hex characters and dashes.
var partialGUIDRegex = regexp.MustCompile(`^[0-9a-fA-F-]+$`)

// isPartialGUID reports whether s looks like a partial GUID (hex chars and dashes,
// longer than 4 chars, but not a complete UUID).
func isPartialGUID(s string) bool {
	return len(s) > 4 && len(s) < 36 && partialGUIDRegex.MatchString(s) && !uuidRegex.MatchString(s)
}

// supportsAppID reports whether the endpoint has an appId field that can be searched.
func supportsAppID(source string) bool {
	return source == "servicePrincipal" || source == "application"
}

// ParsePattern extracts the search term from a pattern string and classifies it.
// It returns the cleaned search term and booleans indicating whether the pattern
// is a prefix match (prefix*), a contains/search match (*keyword*), or an exact
// name match (no wildcards).
func ParsePattern(input string) (term string, isPrefix bool, isContains bool, isExact bool) {
	s := strings.TrimSpace(input)
	if s == "" {
		return "", false, false, false
	}

	hasWildcard := strings.ContainsAny(s, "*?")
	if !hasWildcard {
		return s, false, false, true
	}

	// prefix* pattern (e.g., "myapp*")
	if strings.HasSuffix(s, "*") && !strings.HasPrefix(s, "*") {
		term = strings.TrimRight(s, "*")
		term = strings.ReplaceAll(term, "?", "")
		return term, true, false, false
	}

	// *suffix or *contains* pattern → use $search
	term = strings.Trim(s, "*")
	term = strings.ReplaceAll(term, "?", "")
	term = strings.ReplaceAll(term, "*", " ")
	return strings.TrimSpace(term), false, true, false
}

// escapeOData escapes single quotes for OData filter expressions by doubling them.
func escapeOData(s string) string {
	return strings.ReplaceAll(s, "'", "''")
}

// escapeODataSearch escapes double quotes in OData $search values.
func escapeODataSearch(s string) string {
	return strings.ReplaceAll(s, `"`, `\"`)
}

// Search queries Graph API to find identities matching the given pattern.
// identityType filters results: "spn", "user", "group", "managed-identity", "app", "all".
// maxResults caps the number of results returned.
func (r *Resolver) Search(ctx context.Context, pattern string, identityType string, maxResults int) ([]*SearchResult, error) {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return nil, fmt.Errorf("search pattern must not be empty")
	}

	endpoints := endpointsForType(identityType)
	if len(endpoints) == 0 {
		return nil, fmt.Errorf("unsupported identity type: %q", identityType)
	}

	term, isPrefix, isContains, isExact := ParsePattern(pattern)
	if term == "" {
		return nil, fmt.Errorf("search pattern contains no searchable text: %q", pattern)
	}

	var allResults []*SearchResult
	seen := make(map[string]bool)

	for _, ep := range endpoints {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		results, err := r.searchEndpoint(ctx, ep, term, isPrefix, isContains, isExact, identityType, maxResults)
		if err != nil {
			return nil, fmt.Errorf("searching %s: %w", ep.source, err)
		}

		for _, sr := range results {
			if !seen[sr.Identity.ObjectID] {
				seen[sr.Identity.ObjectID] = true
				allResults = append(allResults, sr)
			}
		}
	}

	sort.Slice(allResults, func(i, j int) bool {
		return strings.ToLower(allResults[i].Identity.DisplayName) < strings.ToLower(allResults[j].Identity.DisplayName)
	})

	if maxResults > 0 && len(allResults) > maxResults {
		allResults = allResults[:maxResults]
	}

	return allResults, nil
}

func endpointsForType(identityType string) []searchEndpoint {
	switch identityType {
	case "spn", "managed-identity":
		return []searchEndpoint{{path: "/v1.0/servicePrincipals", source: "servicePrincipal"}}
	case "user":
		return []searchEndpoint{{path: "/v1.0/users", source: "user"}}
	case "group":
		return []searchEndpoint{{path: "/v1.0/groups", source: "group"}}
	case "app":
		return []searchEndpoint{{path: "/v1.0/applications", source: "application"}}
	case "all":
		return []searchEndpoint{
			{path: "/v1.0/servicePrincipals", source: "servicePrincipal"},
			{path: "/v1.0/users", source: "user"},
			{path: "/v1.0/groups", source: "group"},
			{path: "/v1.0/applications", source: "application"},
		}
	default:
		return nil
	}
}

func (r *Resolver) searchEndpoint(
	ctx context.Context,
	ep searchEndpoint,
	term string,
	isPrefix, isContains, isExact bool,
	identityType string,
	maxResults int,
) ([]*SearchResult, error) {
	query := url.Values{}

	// Limit server-side response size
	top := maxResults
	if top <= 0 || top > 100 {
		top = 100
	}
	query.Set("$top", fmt.Sprintf("%d", top))

	switch {
	case isPrefix:
		filter := fmt.Sprintf("startswith(displayName, '%s')", escapeOData(term))
		// Also search appId for partial GUID patterns on endpoints that support it
		if isPartialGUID(term) && supportsAppID(ep.source) {
			filter = fmt.Sprintf("(startswith(displayName, '%s') or startswith(appId, '%s'))", escapeOData(term), escapeOData(term))
		}
		if identityType == "managed-identity" {
			filter += " and servicePrincipalType eq 'ManagedIdentity'"
		}
		query.Set("$filter", filter)
	case isContains:
		query.Set("$search", fmt.Sprintf(`"displayName:%s"`, escapeODataSearch(term)))
		query.Set("$count", "true")
		if identityType == "managed-identity" {
			query.Set("$filter", "servicePrincipalType eq 'ManagedIdentity'")
		}
	case isExact:
		filter := fmt.Sprintf("displayName eq '%s'", escapeOData(term))
		// Also search appId for partial GUID patterns on endpoints that support it
		if isPartialGUID(term) && supportsAppID(ep.source) {
			filter = fmt.Sprintf("(displayName eq '%s' or startswith(appId, '%s'))", escapeOData(term), escapeOData(term))
		}
		if identityType == "managed-identity" {
			filter += " and servicePrincipalType eq 'ManagedIdentity'"
		}
		query.Set("$filter", filter)
	}

	var body []byte
	var err error

	if isContains {
		headers := map[string]string{"ConsistencyLevel": "eventual"}
		body, err = r.graphClient.DoRequestWithHeaders(ctx, ep.path, query, headers)
	} else {
		body, err = r.graphClient.DoRequest(ctx, ep.path, query)
	}
	if err != nil {
		return nil, err
	}

	var resp struct {
		Value []directoryObject `json:"value"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse search results: %w", err)
	}

	var results []*SearchResult
	for i := range resp.Value {
		ident := r.mapToIdentity(resp.Value[i])
		if ident.Type == TypeUnknown {
			ident.Type = typeFromSource(ep.source, resp.Value[i].ServicePrincipalType)
		}
		results = append(results, &SearchResult{
			Identity: ident,
			Source:   ep.source,
		})
	}

	return results, nil
}

func typeFromSource(source string, spType string) IdentityType {
	switch source {
	case "servicePrincipal":
		if spType == "ManagedIdentity" {
			return TypeManagedIdentity
		}
		return TypeServicePrincipal
	case "user":
		return TypeUser
	case "group":
		return TypeGroup
	case "application":
		return TypeApplication
	default:
		return TypeUnknown
	}
}
