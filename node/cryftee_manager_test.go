// Copyright (C) 2019-2024, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package node

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cryft-labs/cryftgo/utils/logging"
)

func TestCryfteeManager_GetStakingStatus(t *testing.T) {
	require := require.New(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/staking/status":
			json.NewEncoder(w).Encode(StakingStatus{
				Ready:         true,
				Web3SignerURL: "http://localhost:9000",
				Web3SignerOK:  true,
				BLSPubkeys:    []string{"0xabc123"},
				TLSPubkeys:    []string{"0xdef456"},
				ModuleVersion: "1.0.0",
				Capabilities:  []string{"bls_sign", "tls_sign"},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	// Extract host:port from server URL
	addr := server.URL[7:] // Strip "http://"

	manager := NewCryfteeManager(CryfteeManagerConfig{
		Transport: TransportHTTP,
		HTTPAddr:  addr,
	}, logging.NoLog{})
	manager.initHTTPClient()

	status, err := manager.GetStakingStatus(context.Background())
	require.NoError(err)
	require.True(status.Ready)
	require.True(status.Web3SignerOK)
	require.Len(status.BLSPubkeys, 1)
	require.Equal("0xabc123", status.BLSPubkeys[0])
}

func TestCryfteeManager_InitKeys_NewKeys(t *testing.T) {
	require := require.New(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/staking/status":
			json.NewEncoder(w).Encode(StakingStatus{
				Ready:        true,
				Web3SignerOK: true,
				BLSPubkeys:   []string{},
				TLSPubkeys:   []string{},
			})
		case "/v1/staking/bls/register":
			json.NewEncoder(w).Encode(map[string]string{
				"pubkey":      "0xnewblskey",
				"secret_path": "/vault/bls",
			})
		case "/v1/staking/tls/register":
			json.NewEncoder(w).Encode(map[string]string{
				"pubkey":      "0xnewtlskey",
				"secret_path": "/vault/tls",
				"node_id":     "NodeID-TestNode123",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	addr := server.URL[7:]
	tempDir := t.TempDir()

	manager := NewCryfteeManager(CryfteeManagerConfig{
		Transport:  TransportHTTP,
		HTTPAddr:   addr,
		KeyDataDir: tempDir,
	}, logging.NoLog{})
	manager.initHTTPClient()

	status := &StakingStatus{
		Ready:        true,
		Web3SignerOK: true,
		BLSPubkeys:   []string{},
		TLSPubkeys:   []string{},
	}

	blsKey, tlsKey, err := manager.InitKeys(context.Background(), status)
	require.NoError(err)
	require.NotNil(blsKey)
	require.NotNil(tlsKey)
	require.Equal("0xnewblskey", blsKey.PublicKey)
	require.Equal("NodeID-TestNode123", tlsKey.NodeID)
}
