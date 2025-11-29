// Copyright (C) 2019-2024, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package node

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/cryft-labs/cryftgo/node/runtimeinfo"
)

// RuntimeInfoClient is an interface for fetching runtime info from cryftee.
type RuntimeInfoClient interface {
	GetRuntimeInfo(ctx context.Context) (*runtimeinfo.RuntimeInfo, error)
}

// RuntimeInfoClientConfig holds configuration for the runtime info client.
type RuntimeInfoClientConfig struct {
	Transport string        // "uds" (default), "http", or "https"
	Socket    string        // UDS socket path (when transport=uds)
	URL       string        // HTTP(S) address (when transport=http/https)
	Timeout   time.Duration // Request timeout
}

// runtimeInfoClient implements RuntimeInfoClient.
type runtimeInfoClient struct {
	httpClient *http.Client
	transport  string
	url        string
}

// NewRuntimeInfoClient creates a new RuntimeInfoClient.
func NewRuntimeInfoClient(config RuntimeInfoClientConfig) RuntimeInfoClient {
	timeout := config.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}

	transport := config.Transport
	if transport == "" {
		transport = "uds"
	}

	var httpClient *http.Client
	switch transport {
	case "uds":
		httpClient = &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					return net.Dial("unix", config.Socket)
				},
			},
		}
	default:
		httpClient = &http.Client{Timeout: timeout}
	}

	return &runtimeInfoClient{
		httpClient: httpClient,
		transport:  transport,
		url:        config.URL,
	}
}

// GetRuntimeInfo fetches runtime info from the cryftee sidecar.
func (c *runtimeInfoClient) GetRuntimeInfo(ctx context.Context) (*runtimeinfo.RuntimeInfo, error) {
	var url string
	switch c.transport {
	case "uds":
		// For UDS, we use http://localhost as a placeholder host
		// The actual connection goes through the unix socket
		// IMPORTANT: cryftee API uses /v1 prefix
		url = "http://localhost/v1/runtime/self"
	case "https":
		url = "https://" + c.url + "/v1/runtime/self"
	default: // "http"
		url = "http://" + c.url + "/v1/runtime/self"
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch runtime info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("runtime info request failed with status %d", resp.StatusCode)
	}

	var info runtimeinfo.RuntimeInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, fmt.Errorf("failed to decode runtime info: %w", err)
	}

	return &info, nil
}
