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

// RuntimeInfoClientConfig holds configuration for the runtime info client.
type RuntimeInfoClientConfig struct {
	Transport string // "uds" or "http"
	Socket    string // UDS path (when transport=uds)
	URL       string // HTTP URL (when transport=http)
	Timeout   time.Duration
}

// HTTPRuntimeInfoClient implements RuntimeInfoClient using HTTP or UDS.
type HTTPRuntimeInfoClient struct {
	config     RuntimeInfoClientConfig
	httpClient *http.Client
}

// NewRuntimeInfoClient creates a new RuntimeInfoClient based on config.
func NewRuntimeInfoClient(config RuntimeInfoClientConfig) RuntimeInfoClient {
	var transport http.RoundTripper

	if config.Transport == "uds" || config.Transport == "" {
		// Default: Unix Domain Socket
		transport = &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", config.Socket)
			},
		}
	} else {
		// HTTP transport
		transport = http.DefaultTransport
	}

	return &HTTPRuntimeInfoClient{
		config: config,
		httpClient: &http.Client{
			Timeout:   config.Timeout,
			Transport: transport,
		},
	}
}

// GetRuntimeInfo fetches runtime information from the cryftee sidecar.
func (c *HTTPRuntimeInfoClient) GetRuntimeInfo(ctx context.Context) (*runtimeinfo.RuntimeInfo, error) {
	var url string
	if c.config.Transport == "uds" || c.config.Transport == "" {
		// For UDS, use http://localhost as placeholder (socket handles routing)
		url = "http://localhost/runtime/self"
	} else {
		url = c.config.URL + "/runtime/self"
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
