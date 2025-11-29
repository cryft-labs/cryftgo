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

// runtimeInfoClientFromManager wraps CryfteeManager to implement RuntimeInfoClient.
type runtimeInfoClientFromManager struct {
	manager *CryfteeManager
}

// NewRuntimeInfoClientFromManager creates a RuntimeInfoClient backed by a CryfteeManager.
func NewRuntimeInfoClientFromManager(manager *CryfteeManager) RuntimeInfoClient {
	return &runtimeInfoClientFromManager{manager: manager}
}

// GetRuntimeInfo fetches runtime info from the cryftee sidecar via the manager.
func (c *runtimeInfoClientFromManager) GetRuntimeInfo(ctx context.Context) (*runtimeinfo.RuntimeInfo, error) {
	resp, err := c.manager.callAPI(ctx, http.MethodGet, "/v1/runtime/self", nil)
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

// standaloneRuntimeInfoClient implements RuntimeInfoClient without requiring CryfteeManager.
// Use this when you need runtime info but don't have the full manager lifecycle.
type standaloneRuntimeInfoClient struct {
	httpClient *http.Client
	baseURL    string
}

// NewRuntimeInfoClient creates a standalone RuntimeInfoClient.
// This is useful for lightweight clients that only need runtime info.
func NewRuntimeInfoClient(config RuntimeInfoClientConfig) RuntimeInfoClient {
	timeout := config.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}

	transport := config.Transport
	if transport == "" {
		transport = "uds" // Default per spec
	}

	socket := config.Socket
	if socket == "" {
		socket = DefaultCryfteeSocketPath // /tmp/cryftee.sock
	}

	url := config.URL
	if url == "" {
		url = DefaultCryfteeHTTPAddr // 127.0.0.1:8443
	}

	client := &standaloneRuntimeInfoClient{}

	switch transport {
	case "uds":
		client.httpClient = &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					return net.Dial("unix", socket)
				},
			},
		}
		client.baseURL = "http://localhost" // Host ignored for UDS
	case "https":
		client.httpClient = &http.Client{Timeout: timeout}
		client.baseURL = "https://" + url
	default: // "http"
		client.httpClient = &http.Client{Timeout: timeout}
		client.baseURL = "http://" + url
	}

	return client
}

// GetRuntimeInfo fetches runtime info from the cryftee sidecar.
func (c *standaloneRuntimeInfoClient) GetRuntimeInfo(ctx context.Context) (*runtimeinfo.RuntimeInfo, error) {
	url := c.baseURL + "/v1/runtime/self"

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
