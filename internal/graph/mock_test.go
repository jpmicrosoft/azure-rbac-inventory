package graph

import (
	"context"
	"encoding/json"
	"net/url"
)

// mockGraphRequester is a test double implementing GraphRequester.
// Set the function fields to control behaviour per-test.
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
