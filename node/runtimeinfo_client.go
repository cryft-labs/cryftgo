package node

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/cryft-labs/cryftgo/node/runtimeinfo"
)

// RuntimeInfoClient is a minimal interface used by Node to fetch runtime info
// from the external Cryftee sidecar.
type RuntimeInfoClient interface {
	GetRuntimeInfo(ctx context.Context) (*runtimeinfo.RuntimeInfo, error)
}

// httpRuntimeInfoClient implements RuntimeInfoClient over HTTP.
type httpRuntimeInfoClient struct {
	baseURL    *url.URL
	httpClient *http.Client
}

// NewHTTPRuntimeInfoClient returns a RuntimeInfoClient that calls the given
// Cryftee base URL (for example, http://127.0.0.1:9099) at /runtime/self.
// If the URL is invalid, it returns nil.
func NewHTTPRuntimeInfoClient(rawURL string, timeout time.Duration) RuntimeInfoClient {
	if rawURL == "" {
		return nil
	}

	u, err := url.Parse(rawURL)
	if err != nil {
		return nil
	}

	// Ensure we have a host component; this also catches obvious bad URLs early.
	if u.Host == "" {
		return nil
	}

	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout: timeout,
		}).DialContext,
		TLSHandshakeTimeout:   timeout,
		ExpectContinueTimeout: timeout,
		ResponseHeaderTimeout: timeout,
	}

	return &httpRuntimeInfoClient{
		baseURL: u,
		httpClient: &http.Client{
			Timeout:   timeout,
			Transport: transport,
		},
	}
}

// GetRuntimeInfo calls GET {baseURL}/runtime/self and decodes the JSON body
// into runtimeinfo.RuntimeInfo. It returns an error on any failure.
func (c *httpRuntimeInfoClient) GetRuntimeInfo(ctx context.Context) (*runtimeinfo.RuntimeInfo, error) {
	// Build the full URL: base + /runtime/self
	u := *c.baseURL // shallow copy
	u.Path = "/runtime/self"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("build runtime info request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request runtime info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("runtime info request failed: status %s", resp.Status)
	}

	var ri runtimeinfo.RuntimeInfo
	if err := json.NewDecoder(resp.Body).Decode(&ri); err != nil {
		return nil, fmt.Errorf("decode runtime info: %w", err)
	}

	return &ri, nil
}
