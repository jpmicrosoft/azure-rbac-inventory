package graph

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	cloudenv "github.com/jpmicrosoft/azure-rbac-inventory/internal/cloud"
)

const (
	maxRetries       = 5
	maxRetrySleep    = 60 * time.Second
	maxResponseBytes = 10 * 1024 * 1024 // 10 MB
	maxPages         = 100
)

// GraphRequester defines the interface for making Graph API requests.
type GraphRequester interface {
	DoRequest(ctx context.Context, path string, query url.Values) ([]byte, error)
	DoRequestWithHeaders(ctx context.Context, path string, query url.Values, headers map[string]string) ([]byte, error)
	DoPagedRequest(ctx context.Context, path string, query url.Values) ([]json.RawMessage, error)
}

// Client is an authenticated Microsoft Graph REST client.
type Client struct {
	cred       azcore.TokenCredential
	env        cloudenv.Environment
	httpClient *http.Client
}

// NewClient creates a new Graph API client.
func NewClient(cred azcore.TokenCredential, env cloudenv.Environment) *Client {
	return &Client{
		cred: cred,
		env:  env,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// DoRequest executes an authenticated GET request against the Graph API.
// It handles token acquisition, retry with backoff on 429, and context cancellation.
func (c *Client) DoRequest(ctx context.Context, path string, query url.Values) ([]byte, error) {
	return c.DoRequestWithHeaders(ctx, path, query, nil)
}

// DoRequestWithHeaders executes an authenticated GET request against the Graph API
// with additional custom headers. It handles token acquisition, retry with backoff
// on 429, and context cancellation.
func (c *Client) DoRequestWithHeaders(ctx context.Context, path string, query url.Values, headers map[string]string) ([]byte, error) {
	reqURL := c.env.GraphEndpoint + path
	if query != nil {
		reqURL += "?" + query.Encode()
	}

	token, err := c.cred.GetToken(ctx, policy.TokenRequestOptions{
		Scopes: []string{c.env.GraphScope},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get Graph token: %w", err)
	}

	var resp *http.Response
	for attempt := 0; attempt < maxRetries; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create request: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+token.Token)
		req.Header.Set("Accept", "application/json")
		req.Header.Set("ConsistencyLevel", "eventual")
		for k, v := range headers {
			req.Header.Set(k, v)
		}

		resp, err = c.httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("request failed: %w", err)
		}

		if resp.StatusCode == http.StatusTooManyRequests {
			wait := time.Duration(attempt+1) * 5 * time.Second
			if ra := resp.Header.Get("Retry-After"); ra != "" {
				if secs, e := strconv.Atoi(ra); e == nil {
					wait = time.Duration(secs) * time.Second
				}
			}
			resp.Body.Close()
			if wait > maxRetrySleep {
				wait = maxRetrySleep
			}
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(wait):
			}
			continue
		}
		break
	}

	if resp == nil {
		return nil, fmt.Errorf("no response after %d retries", maxRetries)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode >= 400 {
		return nil, parseGraphError(resp.StatusCode, body)
	}

	return body, nil
}

// parseGraphError extracts a clean error from a Graph API error response.
func parseGraphError(statusCode int, body []byte) error {
	var graphErr struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &graphErr) == nil && graphErr.Error.Code != "" {
		return fmt.Errorf("Graph API error (HTTP %d): %s: %s",
			statusCode, graphErr.Error.Code, graphErr.Error.Message)
	}
	return fmt.Errorf("Graph API error (HTTP %d)", statusCode)
}

// graphListResponse represents a paginated Graph API response.
type graphListResponse struct {
	Value    json.RawMessage `json:"value"`
	NextLink string          `json:"@odata.nextLink"`
}

// DoPagedRequest handles paginated Graph API responses, collecting all pages.
func (c *Client) DoPagedRequest(ctx context.Context, path string, query url.Values) ([]json.RawMessage, error) {
	var allItems []json.RawMessage
	currentPath := path

	for page := 0; page < maxPages; page++ {
		body, err := c.DoRequest(ctx, currentPath, query)
		if err != nil {
			return nil, err
		}

		var listResp graphListResponse
		if err := json.Unmarshal(body, &listResp); err != nil {
			return nil, fmt.Errorf("failed to parse response: %w", err)
		}

		if listResp.Value == nil {
			break
		}

		var items []json.RawMessage
		if err := json.Unmarshal(listResp.Value, &items); err != nil {
			// Single object response, not a list
			allItems = append(allItems, listResp.Value)
			break
		}
		allItems = append(allItems, items...)

		if listResp.NextLink == "" {
			break
		}

		parsed, err := url.Parse(listResp.NextLink)
		if err != nil {
			return nil, fmt.Errorf("failed to parse nextLink: %w", err)
		}

		// Validate nextLink points to the expected Graph endpoint.
		// A compromised or malicious API response could try to redirect
		// pagination to an attacker-controlled server to steal the Bearer token.
		if parsed.Host != "" {
			expectedURL, _ := url.Parse(c.env.GraphEndpoint)
			nextOrigin := parsed.Scheme + "://" + parsed.Host
			expectedOrigin := expectedURL.Scheme + "://" + expectedURL.Host
			if nextOrigin != expectedOrigin {
				return nil, fmt.Errorf("nextLink origin %q does not match expected Graph endpoint %q", nextOrigin, expectedOrigin)
			}
		}

		currentPath = parsed.Path
		query = parsed.Query()
	}

	return allItems, nil
}
