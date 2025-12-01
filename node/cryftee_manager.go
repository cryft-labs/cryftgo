// Copyright (C) 2019-2024, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package node

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/cryft-labs/cryftgo/utils/logging"
)

const (
	// CryfteeVerifiedBinaryHashEnv is the environment variable name that cryftee
	// reads to obtain the externally-verified binary hash for attestation.
	CryfteeVerifiedBinaryHashEnv = "CRYFTEE_VERIFIED_BINARY_HASH"

	// Timeouts - use config defaults but keep internal constants for clarity
	defaultCryfteeStartupTimeout = 30 * time.Second
	defaultCryfteeHTTPTimeout    = 30 * time.Second

	// Key data directory for persisting key metadata
	DefaultKeyDataDir = "/var/lib/cryftgo/keys"

	// Cryftee default configuration values
	DefaultCryfteeSocketPath = "/tmp/cryftee.sock"
	DefaultCryfteeHTTPAddr   = "127.0.0.1:8443"
	DefaultWeb3SignerURL     = "http://localhost:9000"
)

// CryfteeTransport defines the transport type for cryftee communication.
type CryfteeTransport string

const (
	TransportUDS   CryfteeTransport = "uds"   // Default - Unix Domain Socket
	TransportHTTP  CryfteeTransport = "http"  // Optional - requires explicit config
	TransportHTTPS CryfteeTransport = "https" // Optional - requires explicit config + TLS
)

// CryfteeAttestation represents the attestation response from cryftee's
// /v1/runtime/attestation endpoint.
type CryfteeAttestation struct {
	CoreBinaryHash string   `json:"core_binary_hash"`
	ManifestHash   string   `json:"manifest_hash"`
	CryfteeVersion string   `json:"cryftee_version"`
	Timestamp      string   `json:"timestamp"`
	LoadedModules  []string `json:"loaded_modules,omitempty"`
}

// BLSKeyInfo holds BLS key metadata (public info only, secret stays in Vault).
type BLSKeyInfo struct {
	PublicKey  string `json:"pubkey"`
	SecretPath string `json:"secret_path"`
	CreatedAt  int64  `json:"created_at"`
}

// TLSKeyInfo holds TLS key metadata and derived Node ID.
type TLSKeyInfo struct {
	PublicKey   string `json:"pubkey"`
	NodeID      string `json:"node_id"`
	SecretPath  string `json:"secret_path"`
	Certificate string `json:"certificate,omitempty"`
	CreatedAt   int64  `json:"created_at"`
}

// NodeIdentity holds all cryptographic identities for the node.
type NodeIdentity struct {
	NodeID        string              `json:"node_id"`
	BLSKey        *BLSKeyInfo         `json:"bls_key"`
	TLSKey        *TLSKeyInfo         `json:"tls_key"`
	Attestation   *CryfteeAttestation `json:"attestation"`
	InitializedAt int64               `json:"initialized_at"`
}

// CryfteeManagerConfig holds configuration for launching and managing cryftee.
type CryfteeManagerConfig struct {
	// BinaryPath is the filesystem path to the cryftee executable.
	BinaryPath string

	// Transport type: uds (default), http, or https
	Transport CryfteeTransport

	// SocketPath is the UDS path (used when Transport=uds)
	// Default: /var/run/cryftee.sock
	SocketPath string

	// HTTPAddr is the address where cryftee's HTTP API is accessible.
	// Format: "host:port" (e.g., "127.0.0.1:8787")
	// Default: 127.0.0.1:8787 (only used when Transport=http)
	HTTPAddr string

	// Web3SignerURL is the URL of the Web3Signer instance
	// Default: http://localhost:9000
	Web3SignerURL string

	// StartupTimeout is how long to wait for cryftee to start.
	StartupTimeout time.Duration

	// ExpectedHashes is an optional list of known-good binary hashes.
	ExpectedHashes []string

	// Args are additional command-line arguments to pass to cryftee.
	Args []string

	// KeyDataDir is the directory for persisting key metadata.
	KeyDataDir string

	// Web3SignerEnabled indicates whether Web3Signer mode is active.
	Web3SignerEnabled bool

	// Web3SignerEphemeral indicates ephemeral key mode.
	Web3SignerEphemeral bool

	// Web3SignerKeyMaterialB64 is the base64-encoded BLS key for ephemeral mode.
	Web3SignerKeyMaterialB64 string
}

// CryfteeManager handles the lifecycle of the cryftee sidecar process.
type CryfteeManager struct {
	config       CryfteeManagerConfig
	log          logging.Logger
	verifiedHash string
	process      *exec.Cmd
	httpClient   *http.Client
}

// NewCryfteeManager creates a new CryfteeManager with the given configuration.
func NewCryfteeManager(cfg CryfteeManagerConfig, log logging.Logger) *CryfteeManager {
	// Apply defaults from config package
	if cfg.StartupTimeout == 0 {
		cfg.StartupTimeout = defaultCryfteeStartupTimeout
	}
	if cfg.Transport == "" {
		cfg.Transport = TransportUDS // DEFAULT: Unix Domain Socket
	}
	if cfg.Transport == "" {
		cfg.Transport = TransportUDS // DEFAULT: Unix Domain Socket
	}
	if cfg.SocketPath == "" {
		cfg.SocketPath = DefaultCryfteeSocketPath // DEFAULT: /tmp/cryftee.sock
	}
	if cfg.HTTPAddr == "" {
		cfg.HTTPAddr = DefaultCryfteeHTTPAddr // DEFAULT: 127.0.0.1:8443
	}
	if cfg.Web3SignerURL == "" {
		cfg.Web3SignerURL = DefaultWeb3SignerURL // DEFAULT: http://localhost:9000
	}

	// Log configuration for debugging
	log.Info("initializing CryfteeManager",
		zap.String("transport", string(cfg.Transport)),
		zap.String("socketPath", cfg.SocketPath),
		zap.String("httpAddr", cfg.HTTPAddr),
		zap.String("web3SignerURL", cfg.Web3SignerURL),
		zap.String("keyDataDir", cfg.KeyDataDir),
		zap.Duration("startupTimeout", cfg.StartupTimeout),
		zap.Bool("web3SignerEnabled", cfg.Web3SignerEnabled),
		zap.String("binaryPath", cfg.BinaryPath),
	)

	return &CryfteeManager{
		config: cfg,
		log:    log,
	}
}

// initHTTPClient initializes the HTTP client based on configured transport.
func (m *CryfteeManager) initHTTPClient() {
	switch m.config.Transport {
	case TransportUDS:
		m.httpClient = &http.Client{
			Timeout: defaultCryfteeHTTPTimeout,
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					return net.Dial("unix", m.config.SocketPath)
				},
			},
		}
	default:
		m.httpClient = &http.Client{Timeout: defaultCryfteeHTTPTimeout}
	}
}

// callAPI makes a request to cryftee via configured transport.
func (m *CryfteeManager) callAPI(ctx context.Context, method, endpoint string, body []byte) (*http.Response, error) {
	var url string
	switch m.config.Transport {
	case TransportUDS:
		url = "http://localhost" + endpoint
	case TransportHTTPS:
		url = "https://" + m.config.HTTPAddr + endpoint
	default:
		url = "http://" + m.config.HTTPAddr + endpoint
	}

	var req *http.Request
	var err error
	if body != nil {
		req, err = http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
	} else {
		req, err = http.NewRequestWithContext(ctx, method, url, nil)
	}
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	return m.httpClient.Do(req)
}

// ComputeBinaryHash computes the SHA256 hash of the cryftee binary.
// Returns the hash in format "sha256:<64-char-hex>".
func (m *CryfteeManager) ComputeBinaryHash() (string, error) {
	data, err := os.ReadFile(m.config.BinaryPath)
	if err != nil {
		return "", fmt.Errorf("failed to read cryftee binary at %s: %w", m.config.BinaryPath, err)
	}

	hash := sha256.Sum256(data)
	return fmt.Sprintf("sha256:%x", hash), nil
}

// VerifyBinaryIntegrity checks if the computed hash matches any of the expected hashes.
// If no expected hashes are configured, this always returns nil.
func (m *CryfteeManager) VerifyBinaryIntegrity(computedHash string) error {
	if len(m.config.ExpectedHashes) == 0 {
		m.log.Warn("no expected cryftee binary hashes configured; skipping integrity check")
		return nil
	}

	for _, expected := range m.config.ExpectedHashes {
		if computedHash == expected {
			m.log.Info("cryftee binary hash matches expected value",
				zap.String("hash", computedHash),
			)
			return nil
		}
	}

	return fmt.Errorf("cryftee binary hash %s does not match any expected hash", computedHash)
}

// Start launches the cryftee process with the verified binary hash in the environment.
func (m *CryfteeManager) Start(ctx context.Context) error {
	// Step 1: Compute binary hash BEFORE launching
	hash, err := m.ComputeBinaryHash()
	if err != nil {
		return fmt.Errorf("failed to compute cryftee binary hash: %w", err)
	}
	m.verifiedHash = hash

	m.log.Info("computed cryftee binary hash",
		zap.String("hash", hash),
		zap.String("binaryPath", m.config.BinaryPath),
	)

	// Step 2: Optionally verify against known-good hashes
	if err := m.VerifyBinaryIntegrity(hash); err != nil {
		return err
	}

	// Step 3: Build command with verified hash in the environment
	m.process = exec.CommandContext(ctx, m.config.BinaryPath, m.config.Args...)

	// Set up environment with verified hash and transport config
	// These values MUST match what cryftee expects
	env := os.Environ()
	env = append(env, fmt.Sprintf("%s=%s", CryfteeVerifiedBinaryHashEnv, hash))
	env = append(env, fmt.Sprintf("CRYFTEE_API_TRANSPORT=%s", m.config.Transport))

	if m.config.Transport == TransportUDS {
		env = append(env, fmt.Sprintf("CRYFTEE_UDS_PATH=%s", m.config.SocketPath))
	} else {
		env = append(env, fmt.Sprintf("CRYFTEE_HTTP_ADDR=%s", m.config.HTTPAddr))
	}

	// Pass Web3Signer URL
	if m.config.Web3SignerURL != "" {
		env = append(env, fmt.Sprintf("CRYFTEE_WEB3SIGNER_URL=%s", m.config.Web3SignerURL))
	}

	// Pass Web3Signer configuration if enabled
	if m.config.Web3SignerEnabled {
		env = append(env, "CRYFTEE_WEB3SIGNER_ENABLED=true")
		if m.config.Web3SignerEphemeral {
			env = append(env, "CRYFTEE_WEB3SIGNER_EPHEMERAL=true")
		}
		if m.config.Web3SignerKeyMaterialB64 != "" {
			env = append(env, fmt.Sprintf("CRYFTEE_WEB3SIGNER_KEY_MATERIAL=%s", m.config.Web3SignerKeyMaterialB64))
		}
	}

	m.process.Env = env
	m.process.Stdout = os.Stdout
	m.process.Stderr = os.Stderr

	// Step 4: Start the process
	if err := m.process.Start(); err != nil {
		return fmt.Errorf("failed to start cryftee: %w", err)
	}

	m.log.Info("started cryftee sidecar",
		zap.Int("pid", m.process.Process.Pid),
		zap.String("verifiedHash", m.verifiedHash),
		zap.String("transport", string(m.config.Transport)),
		zap.String("socketPath", m.config.SocketPath),
		zap.String("httpAddr", m.config.HTTPAddr),
		zap.String("web3SignerURL", m.config.Web3SignerURL),
	)

	m.initHTTPClient()

	// Step 5: Verify connection is working
	if err := m.verifyConnection(ctx); err != nil {
		_ = m.process.Process.Kill()
		return fmt.Errorf("cryftee connection verification failed: %w", err)
	}

	if err := m.waitForReady(ctx); err != nil {
		_ = m.process.Process.Kill()
		return fmt.Errorf("cryftee startup failed: %w", err)
	}

	if err := m.VerifyAttestation(ctx); err != nil {
		_ = m.process.Process.Kill()
		return fmt.Errorf("cryftee attestation verification failed: %w", err)
	}

	return nil
}

// verifyConnection verifies that we can connect to cryftee via the configured transport
func (m *CryfteeManager) verifyConnection(ctx context.Context) error {
	deadline := time.Now().Add(m.config.StartupTimeout)

	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		switch m.config.Transport {
		case TransportUDS:
			// Check if socket file exists and we can connect
			if _, err := os.Stat(m.config.SocketPath); err == nil {
				conn, err := net.Dial("unix", m.config.SocketPath)
				if err == nil {
					conn.Close()
					m.log.Info("UDS connection verified",
						zap.String("socket", m.config.SocketPath),
					)
					return nil
				}
			}
		case TransportHTTP, TransportHTTPS:
			// Try HTTP health check
			resp, err := m.callAPI(ctx, http.MethodGet, "/v1/staking/status", nil)
			if err == nil {
				resp.Body.Close()
				m.log.Info("HTTP connection verified",
					zap.String("addr", m.config.HTTPAddr),
				)
				return nil
			}
		}
		time.Sleep(500 * time.Millisecond)
	}

	return fmt.Errorf("failed to connect to cryftee via %s after %v", m.config.Transport, m.config.StartupTimeout)
}

func (m *CryfteeManager) waitForReady(ctx context.Context) error {
	deadline := time.Now().Add(m.config.StartupTimeout)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		resp, err := m.callAPI(ctx, http.MethodGet, "/v1/staking/status", nil)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("timeout waiting for cryftee after %v", m.config.StartupTimeout)
}

// VerifyAttestation calls the cryftee attestation endpoint and verifies
// the reported binary hash matches what we computed.
func (m *CryfteeManager) VerifyAttestation(ctx context.Context) error {
	resp, err := m.callAPI(ctx, http.MethodGet, "/v1/runtime/attestation", nil)
	if err != nil {
		return fmt.Errorf("failed to call attestation endpoint: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("attestation endpoint returned status %d", resp.StatusCode)
	}

	var attestation CryfteeAttestation
	if err := json.NewDecoder(resp.Body).Decode(&attestation); err != nil {
		return fmt.Errorf("failed to decode attestation response: %w", err)
	}

	if attestation.CoreBinaryHash != m.verifiedHash {
		return fmt.Errorf("attestation hash mismatch: expected %s, got %s",
			m.verifiedHash, attestation.CoreBinaryHash)
	}

	m.log.Info("cryftee attestation verified successfully",
		zap.String("cryfteeVersion", attestation.CryfteeVersion),
		zap.String("binaryHash", attestation.CoreBinaryHash),
	)

	return nil
}

// InitKeys verifies existing keys or generates new ones based on CryftGo's local store.
// This follows the rule: CryftGo's local store is the source of truth for key existence.
// - If keys exist locally → use "verify" mode to confirm they exist in Web3Signer
// - If keys don't exist locally → use "generate" mode to create new keys
// - If verify fails → FATAL ERROR - node cannot start with missing keys
func (m *CryfteeManager) InitKeys(ctx context.Context, status *StakingStatus) (*BLSKeyInfo, *TLSKeyInfo, error) {
	var blsKey *BLSKeyInfo
	var tlsKey *TLSKeyInfo

	// Load any previously saved pubkeys from CryftGo's local store
	savedBLSPubkey := m.loadSavedBLSPubkey()
	savedTLSPubkey := m.loadSavedTLSPubkey()

	// ═══════════════════════════════════════════════════════════════════════
	// BLS KEY LOGIC
	// ═══════════════════════════════════════════════════════════════════════
	if savedBLSPubkey != "" {
		// We have a key locally - VERIFY it exists in Web3Signer
		m.log.Info("verifying existing BLS key from local store",
			zap.String("pubkey", truncateKey(savedBLSPubkey)),
		)

		resp, err := m.verifyKey(ctx, "/v1/staking/bls/register", savedBLSPubkey)
		if err != nil {
			return nil, nil, fmt.Errorf(
				"FATAL: BLS key %s from local store not found in Web3Signer. "+
					"This indicates key loss or Web3Signer misconfiguration. "+
					"The node cannot start safely without its staking key. Error: %w",
				truncateKey(savedBLSPubkey), err)
		}

		blsKey = &BLSKeyInfo{
			PublicKey:  savedBLSPubkey,
			SecretPath: resp.KeyHandle,
			CreatedAt:  time.Now().Unix(),
		}
		m.log.Info("✓ BLS key verified in Web3Signer",
			zap.String("pubkey", truncateKey(savedBLSPubkey)),
		)

	} else {
		// No key locally - generate new one
		m.log.Info("no BLS key in local store, generating new key via Web3Signer")

		resp, err := m.generateKey(ctx, "/v1/staking/bls/register", "BLS", "validator")
		if err != nil {
			return nil, nil, fmt.Errorf("BLS key generation failed: %w", err)
		}

		blsKey = &BLSKeyInfo{
			PublicKey:  resp.PublicKey,
			SecretPath: resp.KeyHandle,
			CreatedAt:  time.Now().Unix(),
		}

		// IMPORTANT: Save to local store for future verifications
		if err := m.saveBLSPubkey(resp.PublicKey); err != nil {
			m.log.Warn("failed to save BLS pubkey to local store", zap.Error(err))
		}

		m.log.Info("✓ generated new BLS key",
			zap.String("pubkey", truncateKey(resp.PublicKey)),
		)
	}

	// ═══════════════════════════════════════════════════════════════════════
	// TLS KEY LOGIC (same pattern)
	// ═══════════════════════════════════════════════════════════════════════
	if savedTLSPubkey != "" {
		m.log.Info("verifying existing TLS key from local store",
			zap.String("pubkey", truncateKey(savedTLSPubkey)),
		)

		resp, err := m.verifyKey(ctx, "/v1/staking/tls/register", savedTLSPubkey)
		if err != nil {
			return nil, nil, fmt.Errorf(
				"FATAL: TLS key %s from local store not found in Web3Signer. "+
					"Node ID would change if we regenerated - this is not safe. "+
					"Error: %w",
				truncateKey(savedTLSPubkey), err)
		}

		tlsKey = &TLSKeyInfo{
			PublicKey:  savedTLSPubkey,
			NodeID:     deriveNodeID(savedTLSPubkey),
			SecretPath: resp.KeyHandle,
			CreatedAt:  time.Now().Unix(),
		}
		m.log.Info("✓ TLS key verified in Web3Signer",
			zap.String("nodeID", tlsKey.NodeID),
		)

	} else {
		m.log.Info("no TLS key in local store, generating new key via Web3Signer")

		resp, err := m.generateKey(ctx, "/v1/staking/tls/register", "SECP256K1", "node_tls")
		if err != nil {
			return nil, nil, fmt.Errorf("TLS key generation failed: %w", err)
		}

		nodeID := resp.NodeID
		if nodeID == "" {
			nodeID = deriveNodeID(resp.PublicKey)
		}

		tlsKey = &TLSKeyInfo{
			PublicKey:   resp.PublicKey,
			NodeID:      nodeID,
			SecretPath:  resp.KeyHandle,
			Certificate: resp.Certificate,
			CreatedAt:   time.Now().Unix(),
		}

		if err := m.saveTLSPubkey(resp.PublicKey); err != nil {
			m.log.Warn("failed to save TLS pubkey to local store", zap.Error(err))
		}

		m.log.Info("✓ generated new TLS key",
			zap.String("nodeID", nodeID),
			zap.String("pubkey", truncateKey(resp.PublicKey)),
		)
	}

	return blsKey, tlsKey, nil
}

// RegisterKeyResponse is the response from a key registration request
type RegisterKeyResponse struct {
	KeyHandle   string `json:"keyHandle"`
	PublicKey   string `json:"blsPubKeyB64"` // or pubkey depending on endpoint
	ModuleID    string `json:"moduleId"`
	NodeID      string `json:"node_id,omitempty"`
	Certificate string `json:"certificate,omitempty"`
}

// verifyKey sends a verify request to confirm a key exists in Web3Signer
func (m *CryfteeManager) verifyKey(ctx context.Context, endpoint, publicKey string) (*RegisterKeyResponse, error) {
	req := map[string]interface{}{
		"mode":      "verify",
		"publicKey": publicKey,
	}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal verify request: %w", err)
	}

	resp, err := m.callAPI(ctx, http.MethodPost, endpoint, body)
	if err != nil {
		return nil, fmt.Errorf("verify request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("key not found in Web3Signer: %s", string(bodyBytes))
	}

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("verify returned status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var result RegisterKeyResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode verify response: %w", err)
	}

	return &result, nil
}

// generateKey sends a generate request to create a new key in Web3Signer
func (m *CryfteeManager) generateKey(ctx context.Context, endpoint, keyType, purpose string) (*RegisterKeyResponse, error) {
	req := map[string]interface{}{
		"mode":     "generate",
		"key_type": keyType,
		"purpose":  purpose,
	}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal generate request: %w", err)
	}

	resp, err := m.callAPI(ctx, http.MethodPost, endpoint, body)
	if err != nil {
		return nil, fmt.Errorf("generate request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("generate returned status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var result struct {
		KeyHandle   string `json:"keyHandle"`
		PublicKey   string `json:"blsPubKeyB64"`
		Pubkey      string `json:"pubkey"` // Alternative field name
		ModuleID    string `json:"moduleId"`
		NodeID      string `json:"node_id,omitempty"`
		Certificate string `json:"certificate,omitempty"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode generate response: %w", err)
	}

	// Handle both pubkey field names
	pubkey := result.PublicKey
	if pubkey == "" {
		pubkey = result.Pubkey
	}

	if pubkey == "" {
		return nil, fmt.Errorf("generate response missing public key")
	}

	return &RegisterKeyResponse{
		KeyHandle:   result.KeyHandle,
		PublicKey:   pubkey,
		ModuleID:    result.ModuleID,
		NodeID:      result.NodeID,
		Certificate: result.Certificate,
	}, nil
}

// SendHeartbeat sends a heartbeat to CryftTEE for connection monitoring
func (m *CryfteeManager) SendHeartbeat(ctx context.Context, nodeID, version string) error {
	req := map[string]interface{}{
		"cryftgo_version": version,
		"node_id":         nodeID,
		"timestamp":       time.Now().UnixMilli(),
	}
	body, err := json.Marshal(req)
	if err != nil {
		return err
	}

	resp, err := m.callAPI(ctx, http.MethodPost, "/v1/runtime/heartbeat", body)
	if err != nil {
		return fmt.Errorf("heartbeat request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("heartbeat returned status %d", resp.StatusCode)
	}

	var result struct {
		Acknowledged bool `json:"acknowledged"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("failed to decode heartbeat response: %w", err)
	}

	if !result.Acknowledged {
		return fmt.Errorf("heartbeat not acknowledged")
	}

	return nil
}

// GetConnectionStatus fetches the CryftGo↔CryftTEE connection status
func (m *CryfteeManager) GetConnectionStatus(ctx context.Context) (*ConnectionStatus, error) {
	resp, err := m.callAPI(ctx, http.MethodGet, "/v1/runtime/connection", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get connection status: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("connection status returned %d", resp.StatusCode)
	}

	var status ConnectionStatus
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		return nil, fmt.Errorf("failed to decode connection status: %w", err)
	}

	return &status, nil
}

// ConnectionStatus represents the CryftGo↔CryftTEE connection health
type ConnectionStatus struct {
	Connected      bool      `json:"connected"`
	Transport      string    `json:"transport"`
	Endpoint       string    `json:"endpoint"`
	LastSeen       time.Time `json:"last_seen"`
	LatencyMs      int64     `json:"latency_ms"`
	CryftGoVersion string    `json:"cryftgo_version,omitempty"`
	CryftGoNodeID  string    `json:"cryftgo_node_id,omitempty"`
	RequestCount   uint64    `json:"request_count"`
	ErrorCount     uint64    `json:"error_count"`
	LastError      string    `json:"last_error,omitempty"`
	SignerReady    bool      `json:"signer_ready"`
}

// StakingStatus represents the response from /v1/staking/status
type StakingStatus struct {
	Ready         bool     `json:"ready"`
	Web3SignerURL string   `json:"web3signer_url"`
	Web3SignerOK  bool     `json:"web3signer_connected"`
	BLSPubkeys    []string `json:"bls_pubkeys"`
	TLSPubkeys    []string `json:"tls_pubkeys"`
	ModuleVersion string   `json:"module_version"`
	Capabilities  []string `json:"capabilities"`
}

// GetStakingStatus queries cryftee for available keys from Web3Signer
func (m *CryfteeManager) GetStakingStatus(ctx context.Context) (*StakingStatus, error) {
	resp, err := m.callAPI(ctx, http.MethodGet, "/v1/staking/status", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get staking status: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("staking status returned %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var status StakingStatus
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		return nil, fmt.Errorf("failed to decode staking status: %w", err)
	}

	return &status, nil
}

// VerifySignerReady checks that cryftee has Web3Signer module enabled and connected
func (m *CryfteeManager) VerifySignerReady(ctx context.Context) (*StakingStatus, error) {
	status, err := m.GetStakingStatus(ctx)
	if err != nil {
		return nil, err
	}

	if !status.Ready {
		return nil, fmt.Errorf("staking module not ready")
	}

	if !status.Web3SignerOK {
		return nil, fmt.Errorf("Web3Signer not connected (url: %s)", status.Web3SignerURL)
	}

	m.log.Info("Web3Signer ready",
		zap.String("url", status.Web3SignerURL),
		zap.String("moduleVersion", status.ModuleVersion),
		zap.Int("blsKeys", len(status.BLSPubkeys)),
		zap.Int("tlsKeys", len(status.TLSPubkeys)),
	)

	return status, nil
}

// deriveNodeID derives a NodeID from a hex-encoded public key
func deriveNodeID(pubkeyHex string) string {
	pubkey := strings.TrimPrefix(pubkeyHex, "0x")
	pubkeyBytes, err := hex.DecodeString(pubkey)
	if err != nil {
		return ""
	}
	hash := sha256.Sum256(pubkeyBytes)
	return fmt.Sprintf("NodeID-%s", hex.EncodeToString(hash[:20]))
}

// saveBLSPubkey persists the BLS public key reference locally
func (m *CryfteeManager) saveBLSPubkey(pubkey string) error {
	if err := os.MkdirAll(m.config.KeyDataDir, 0700); err != nil {
		return fmt.Errorf("failed to create key data dir: %w", err)
	}
	return os.WriteFile(filepath.Join(m.config.KeyDataDir, "bls_pubkey"), []byte(pubkey), 0600)
}

// loadSavedBLSPubkey loads the previously saved BLS public key
func (m *CryfteeManager) loadSavedBLSPubkey() string {
	data, err := os.ReadFile(filepath.Join(m.config.KeyDataDir, "bls_pubkey"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// saveTLSPubkey persists the TLS public key reference locally
func (m *CryfteeManager) saveTLSPubkey(pubkey string) error {
	if err := os.MkdirAll(m.config.KeyDataDir, 0700); err != nil {
		return fmt.Errorf("failed to create key data dir: %w", err)
	}
	return os.WriteFile(filepath.Join(m.config.KeyDataDir, "tls_pubkey"), []byte(pubkey), 0600)
}

// loadSavedTLSPubkey loads the previously saved TLS public key
func (m *CryfteeManager) loadSavedTLSPubkey() string {
	data, err := os.ReadFile(filepath.Join(m.config.KeyDataDir, "tls_pubkey"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// SignBLS signs data using the BLS key via cryftee.
func (m *CryfteeManager) SignBLS(ctx context.Context, pubkey string, data []byte, sigType string) ([]byte, error) {
	req := map[string]interface{}{
		"pubkey": pubkey,
		"data":   data,
		"type":   sigType,
	}
	body, _ := json.Marshal(req)

	resp, err := m.callAPI(ctx, http.MethodPost, "/v1/staking/bls/sign", body)
	if err != nil {
		return nil, fmt.Errorf("BLS sign request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("BLS sign returned status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var result struct {
		Signature string `json:"signature"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode BLS sign response: %w", err)
	}

	return hex.DecodeString(strings.TrimPrefix(result.Signature, "0x"))
}

// SignTLS signs data using the TLS key via cryftee.
func (m *CryfteeManager) SignTLS(ctx context.Context, pubkey string, data []byte) ([]byte, error) {
	req := map[string]interface{}{
		"pubkey": pubkey,
		"data":   data,
	}
	body, _ := json.Marshal(req)

	resp, err := m.callAPI(ctx, http.MethodPost, "/v1/staking/tls/sign", body)
	if err != nil {
		return nil, fmt.Errorf("TLS sign request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("TLS sign returned status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var result struct {
		Signature string `json:"signature"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode TLS sign response: %w", err)
	}

	return hex.DecodeString(strings.TrimPrefix(result.Signature, "0x"))
}

// Stop gracefully stops the cryftee process.
func (m *CryfteeManager) Stop() error {
	if m.process == nil {
		return nil
	}

	// Attempt graceful shutdown
	if err := m.process.Process.Signal(os.Interrupt); err != nil {
		return fmt.Errorf("failed to send interrupt signal to cryftee: %w", err)
	}

	// Wait for process to exit
	done := make(chan error)
	go func() {
		_, err := m.process.Process.Wait()
		done <- err
	}()

	select {
	case err := <-done:
		if err != nil {
			return fmt.Errorf("cryftee did not exit cleanly: %w", err)
		}
	case <-time.After(5 * time.Second):
		return fmt.Errorf("timeout waiting for cryftee to exit")
	}

	m.process = nil
	return nil
}

// VerifiedHash returns the computed and verified binary hash.
func (m *CryfteeManager) VerifiedHash() string {
	return m.verifiedHash
}

// IsRunning returns true if the cryftee process is currently running.
func (m *CryfteeManager) IsRunning() bool {
	if m.process == nil {
		return false
	}

	// Check if the process is still running
	if err := m.process.Process.Signal(os.Interrupt); err != nil {
		if err.Error() == "os: process already finished" {
			return false
		}
	}

	return true
}
