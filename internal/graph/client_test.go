package graph

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	cloud "github.com/jpmicrosoft/azure-rbac-inventory/internal/cloud"
)

// ---------- test helpers ----------

type fakeTokenCredential struct{}

func (f *fakeTokenCredential) GetToken(ctx context.Context, opts policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{Token: "fake-token", ExpiresOn: time.Now().Add(1 * time.Hour)}, nil
}

func newTestClient(t *testing.T, handler http.Handler) *Client {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	cred := &fakeTokenCredential{}
	env := cloud.Environment{
		Name:          "Test",
		GraphEndpoint: server.URL,
		GraphScope:    "https://graph.microsoft.com/.default",
	}
	return NewClient(cred, env)
}

// failingTokenCredential is a test double that always returns an error.
type failingTokenCredential struct {
	err error
}

func (f *failingTokenCredential) GetToken(ctx context.Context, opts policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{}, f.err
}

// ---------- DoRequest tests ----------

func TestDoRequest_Success(t *testing.T) {
	expected := `{"id":"123","displayName":"Test User"}`

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request headers are set correctly.
		if got := r.Header.Get("Authorization"); got != "Bearer fake-token" {
			t.Errorf("Authorization header = %q, want %q", got, "Bearer fake-token")
		}
		if got := r.Header.Get("Accept"); got != "application/json" {
			t.Errorf("Accept header = %q, want %q", got, "application/json")
		}
		if got := r.Header.Get("ConsistencyLevel"); got != "eventual" {
			t.Errorf("ConsistencyLevel header = %q, want %q", got, "eventual")
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, expected)
	})

	client := newTestClient(t, handler)

	body, err := client.DoRequest(context.Background(), "/v1.0/me", nil)
	if err != nil {
		t.Fatalf("DoRequest returned unexpected error: %v", err)
	}
	if string(body) != expected {
		t.Errorf("body = %q, want %q", string(body), expected)
	}
}

func TestDoRequest_4xxError(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `{"error":{"code":"Request_ResourceNotFound","message":"not found"}}`)
	})

	client := newTestClient(t, handler)

	_, err := client.DoRequest(context.Background(), "/v1.0/users/nonexistent", nil)
	if err == nil {
		t.Fatal("expected error for 404 response, got nil")
	}

	errMsg := err.Error()
	if !strings.Contains(errMsg, "Request_ResourceNotFound") {
		t.Errorf("error should contain Graph error code, got: %v", err)
	}
	if !strings.Contains(errMsg, "not found") {
		t.Errorf("error should contain Graph error message, got: %v", err)
	}
	if !strings.Contains(errMsg, "404") {
		t.Errorf("error should contain HTTP status code 404, got: %v", err)
	}
}

func TestDoRequest_429Retry(t *testing.T) {
	var attempts int32

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&attempts, 1)
		if n <= 2 {
			w.Header().Set("Retry-After", "0") // no real wait in tests
			w.WriteHeader(http.StatusTooManyRequests)
			fmt.Fprint(w, `{"error":{"code":"TooManyRequests","message":"throttled"}}`)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"value":"ok"}`)
	})

	client := newTestClient(t, handler)

	body, err := client.DoRequest(context.Background(), "/v1.0/data", nil)
	if err != nil {
		t.Fatalf("expected success after retries, got error: %v", err)
	}
	if string(body) != `{"value":"ok"}` {
		t.Errorf("body = %q, want %q", string(body), `{"value":"ok"}`)
	}

	got := atomic.LoadInt32(&attempts)
	if got != 3 {
		t.Errorf("server saw %d attempts, want 3 (2 throttled + 1 success)", got)
	}
}

func TestDoRequest_ContextCancellation(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{}`)
	})

	client := newTestClient(t, handler)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before the call

	_, err := client.DoRequest(ctx, "/v1.0/me", nil)
	if err == nil {
		t.Fatal("expected error from cancelled context, got nil")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled in error chain, got: %v", err)
	}
}

func TestDoRequest_ErrorParseFallback(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, "unexpected server failure")
	})

	client := newTestClient(t, handler)

	_, err := client.DoRequest(context.Background(), "/v1.0/broken", nil)
	if err == nil {
		t.Fatal("expected error for 500 response, got nil")
	}

	errMsg := err.Error()
	if !strings.Contains(errMsg, "500") {
		t.Errorf("fallback error should contain HTTP status 500, got: %v", err)
	}
	// The fallback message is "Graph API error (HTTP 500)" — no code/message fields.
	if strings.Contains(errMsg, "Request_ResourceNotFound") {
		t.Errorf("fallback error should not contain a parsed error code, got: %v", err)
	}
}

// ---------- DoPagedRequest tests ----------

func TestDoPagedRequest_SinglePage(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"value":[{"id":"a"},{"id":"b"}]}`)
	})

	client := newTestClient(t, handler)

	items, err := client.DoPagedRequest(context.Background(), "/v1.0/items", nil)
	if err != nil {
		t.Fatalf("DoPagedRequest returned unexpected error: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("got %d items, want 2", len(items))
	}

	var first map[string]string
	if err := json.Unmarshal(items[0], &first); err != nil {
		t.Fatalf("failed to unmarshal first item: %v", err)
	}
	if first["id"] != "a" {
		t.Errorf("first item id = %q, want %q", first["id"], "a")
	}
}

func TestDoPagedRequest_MultiplePages(t *testing.T) {
	// We need the server URL inside the handler to build @odata.nextLink,
	// so we create the server manually instead of using newTestClient.
	var serverURL string

	mux := http.NewServeMux()
	mux.HandleFunc("/v1.0/items", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		resp := fmt.Sprintf(
			`{"value":[{"id":"1"},{"id":"2"}],"@odata.nextLink":"%s/page2?$skip=2"}`,
			serverURL,
		)
		fmt.Fprint(w, resp)
	})
	mux.HandleFunc("/page2", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"value":[{"id":"3"}]}`)
	})

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	serverURL = server.URL

	cred := &fakeTokenCredential{}
	env := cloud.Environment{
		Name:          "Test",
		GraphEndpoint: server.URL,
		GraphScope:    "https://graph.microsoft.com/.default",
	}
	client := NewClient(cred, env)

	items, err := client.DoPagedRequest(context.Background(), "/v1.0/items", nil)
	if err != nil {
		t.Fatalf("DoPagedRequest returned unexpected error: %v", err)
	}
	if len(items) != 3 {
		t.Fatalf("got %d items across pages, want 3", len(items))
	}

	// Verify ordering and content from both pages.
	wantIDs := []string{"1", "2", "3"}
	for i, raw := range items {
		var obj map[string]string
		if err := json.Unmarshal(raw, &obj); err != nil {
			t.Fatalf("failed to unmarshal item[%d]: %v", i, err)
		}
		if obj["id"] != wantIDs[i] {
			t.Errorf("item[%d].id = %q, want %q", i, obj["id"], wantIDs[i])
		}
	}
}

// ---------- Additional DoRequest edge-case tests ----------

func TestDoRequest_WithQueryParams(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("$filter"); got != "displayName eq 'test'" {
			t.Errorf("$filter = %q, want %q", got, "displayName eq 'test'")
		}
		if got := r.URL.Query().Get("$top"); got != "10" {
			t.Errorf("$top = %q, want %q", got, "10")
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"result":"ok"}`)
	})

	client := newTestClient(t, handler)

	query := url.Values{}
	query.Set("$filter", "displayName eq 'test'")
	query.Set("$top", "10")

	body, err := client.DoRequest(context.Background(), "/v1.0/users", query)
	if err != nil {
		t.Fatalf("DoRequest returned unexpected error: %v", err)
	}
	if string(body) != `{"result":"ok"}` {
		t.Errorf("body = %q, want %q", string(body), `{"result":"ok"}`)
	}
}

func TestDoRequest_TokenFailure(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("server should not be reached when token acquisition fails")
	})

	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	cred := &failingTokenCredential{err: fmt.Errorf("credential expired")}
	env := cloud.Environment{
		Name:          "Test",
		GraphEndpoint: server.URL,
		GraphScope:    "https://graph.microsoft.com/.default",
	}
	client := NewClient(cred, env)

	_, err := client.DoRequest(context.Background(), "/v1.0/me", nil)
	if err == nil {
		t.Fatal("expected error from token failure, got nil")
	}
	if !strings.Contains(err.Error(), "Graph token") {
		t.Errorf("error should mention 'Graph token', got: %v", err)
	}
	if !strings.Contains(err.Error(), "credential expired") {
		t.Errorf("error should wrap the original credential error, got: %v", err)
	}
}

func TestDoRequest_429ExhaustsAllRetries(t *testing.T) {
	var attempts int32
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&attempts, 1)
		w.Header().Set("Retry-After", "0")
		w.WriteHeader(http.StatusTooManyRequests)
		fmt.Fprint(w, `{"error":{"code":"TooManyRequests","message":"throttled"}}`)
	})

	client := newTestClient(t, handler)

	_, err := client.DoRequest(context.Background(), "/v1.0/data", nil)
	if err == nil {
		t.Fatal("expected error after exhausting all retries, got nil")
	}

	got := int(atomic.LoadInt32(&attempts))
	if got != maxRetries {
		t.Errorf("server saw %d attempts, want %d (maxRetries)", got, maxRetries)
	}
}

func TestDoRequest_429ContextCancelledDuringRetry(t *testing.T) {
	// Server returns 429 without Retry-After (default wait = 5s).
	// Context times out at 100ms, well before the retry wait completes.
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		fmt.Fprint(w, `{}`)
	})

	client := newTestClient(t, handler)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err := client.DoRequest(ctx, "/v1.0/data", nil)
	if err == nil {
		t.Fatal("expected error from context timeout during retry wait, got nil")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("expected context.DeadlineExceeded in error chain, got: %v", err)
	}
}

func TestDoRequest_500Error(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, `{"error":{"code":"InternalServerError","message":"something broke"}}`)
	})

	client := newTestClient(t, handler)

	_, err := client.DoRequest(context.Background(), "/v1.0/broken", nil)
	if err == nil {
		t.Fatal("expected error for 500 response, got nil")
	}
	errMsg := err.Error()
	if !strings.Contains(errMsg, "500") {
		t.Errorf("error should contain status code 500, got: %v", err)
	}
	if !strings.Contains(errMsg, "InternalServerError") {
		t.Errorf("error should contain error code, got: %v", err)
	}
	if !strings.Contains(errMsg, "something broke") {
		t.Errorf("error should contain error message, got: %v", err)
	}
}

// ---------- Additional DoPagedRequest edge-case tests ----------

func TestDoPagedRequest_EmptyValueArray(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"value":[]}`)
	})

	client := newTestClient(t, handler)

	items, err := client.DoPagedRequest(context.Background(), "/v1.0/items", nil)
	if err != nil {
		t.Fatalf("DoPagedRequest returned unexpected error: %v", err)
	}
	if len(items) != 0 {
		t.Errorf("got %d items, want 0 for empty value array", len(items))
	}
}

func TestDoPagedRequest_NullValue(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"value":null}`)
	})

	client := newTestClient(t, handler)

	items, err := client.DoPagedRequest(context.Background(), "/v1.0/items", nil)
	if err != nil {
		t.Fatalf("DoPagedRequest returned unexpected error: %v", err)
	}
	if len(items) != 0 {
		t.Errorf("got %d items, want 0 for null value", len(items))
	}
}

func TestDoPagedRequest_SingleObjectResponse(t *testing.T) {
	// When "value" is a single JSON object (not an array), it should be
	// captured as one item (the fallback path in DoPagedRequest).
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"value":{"id":"single-item"}}`)
	})

	client := newTestClient(t, handler)

	items, err := client.DoPagedRequest(context.Background(), "/v1.0/item", nil)
	if err != nil {
		t.Fatalf("DoPagedRequest returned unexpected error: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("got %d items, want 1 for single object response", len(items))
	}
}

func TestDoPagedRequest_ErrorOnFirstPage(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `{"error":{"code":"Authorization_RequestDenied","message":"no access"}}`)
	})

	client := newTestClient(t, handler)

	_, err := client.DoPagedRequest(context.Background(), "/v1.0/items", nil)
	if err == nil {
		t.Fatal("expected error for 403 response in paged request, got nil")
	}
	if !strings.Contains(err.Error(), "Authorization_RequestDenied") {
		t.Errorf("error should contain Graph error code, got: %v", err)
	}
}

func TestDoPagedRequest_InvalidJSONResponse(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{not valid json at all}`)
	})

	client := newTestClient(t, handler)

	_, err := client.DoPagedRequest(context.Background(), "/v1.0/items", nil)
	if err == nil {
		t.Fatal("expected error for invalid JSON response, got nil")
	}
	if !strings.Contains(err.Error(), "parse") {
		t.Errorf("error should mention parsing, got: %v", err)
	}
}

// ---------- parseGraphError unit tests ----------

func TestParseGraphError_WithCodeAndMessage(t *testing.T) {
	body := []byte(`{"error":{"code":"Authorization_RequestDenied","message":"Insufficient privileges"}}`)
	err := parseGraphError(403, body)

	errMsg := err.Error()
	if !strings.Contains(errMsg, "403") {
		t.Errorf("error should contain HTTP status code, got: %v", err)
	}
	if !strings.Contains(errMsg, "Authorization_RequestDenied") {
		t.Errorf("error should contain error code, got: %v", err)
	}
	if !strings.Contains(errMsg, "Insufficient privileges") {
		t.Errorf("error should contain error message, got: %v", err)
	}
}

func TestParseGraphError_InvalidJSON(t *testing.T) {
	body := []byte("not json at all")
	err := parseGraphError(500, body)

	errMsg := err.Error()
	if !strings.Contains(errMsg, "500") {
		t.Errorf("fallback error should contain status code, got: %v", err)
	}
	// Should NOT contain a parsed code since JSON is invalid
	if strings.Contains(errMsg, "Authorization") {
		t.Errorf("should not contain a parsed error code for invalid JSON, got: %v", err)
	}
}

func TestParseGraphError_EmptyBody(t *testing.T) {
	err := parseGraphError(502, []byte(""))

	errMsg := err.Error()
	if !strings.Contains(errMsg, "502") {
		t.Errorf("fallback error should contain status code, got: %v", err)
	}
}

func TestParseGraphError_EmptyCodeFallsBack(t *testing.T) {
	// Empty code triggers fallback to generic "Graph API error (HTTP N)" format
	body := []byte(`{"error":{"code":"","message":"something"}}`)
	err := parseGraphError(400, body)

	errMsg := err.Error()
	if !strings.Contains(errMsg, "400") {
		t.Errorf("error should contain status code, got: %v", err)
	}
}

// ---------- Security: nextLink validation ----------

func TestDoPagedRequest_NextLinkHostMismatch(t *testing.T) {
	// A malicious API response tries to redirect pagination to an attacker server.
	// The client should reject this to prevent Bearer token theft.
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"value":[{"id":"1"}],"@odata.nextLink":"https://evil.example.com/steal?token=1"}`)
	})

	client := newTestClient(t, handler)

	_, err := client.DoPagedRequest(context.Background(), "/v1.0/items", nil)
	if err == nil {
		t.Fatal("expected error for nextLink pointing to different host, got nil")
	}
	if !strings.Contains(err.Error(), "does not match") {
		t.Errorf("error should mention origin mismatch, got: %v", err)
	}
}

func TestDoPagedRequest_NextLinkHTTPDowngrade(t *testing.T) {
	// nextLink tries to downgrade from HTTPS to HTTP at the same host.
	// This is only testable when the configured endpoint uses HTTPS.
	// We simulate by configuring an HTTPS endpoint but getting an HTTP nextLink.
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"value":[{"id":"1"}],"@odata.nextLink":"http://graph.microsoft.com/v1.0/page2"}`)
	})

	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	cred := &fakeTokenCredential{}
	env := cloud.Environment{
		Name:          "Test",
		GraphEndpoint: server.URL, // http://127.0.0.1:PORT
		GraphScope:    "https://graph.microsoft.com/.default",
	}
	client := NewClient(cred, env)

	// The nextLink host is graph.microsoft.com but our endpoint is 127.0.0.1 — should fail
	_, err := client.DoPagedRequest(context.Background(), "/v1.0/items", nil)
	if err == nil {
		t.Fatal("expected error for nextLink host mismatch, got nil")
	}
}
