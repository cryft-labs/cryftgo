// Copyright (C) 2019-2024, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package node

import (
	"context"
	"crypto/tls"
)

// KeyMode represents the mode for key registration with Cryftee/Web3Signer.
type KeyMode string

const (
	KeyModeEphemeral  KeyMode = "ephemeral"
	KeyModePersistent KeyMode = "persistent"
	KeyModeImport     KeyMode = "import"
)

// BLSRegisterRequest is the request body for POST /v1/staking/bls/register.
type BLSRegisterRequest struct {
	Mode            KeyMode `json:"mode"`
	EphemeralKeyB64 string  `json:"ephemeralKeyB64,omitempty"`
	NetworkID       uint32  `json:"networkID"`
	NodeLabel       string  `json:"nodeLabel,omitempty"`
}

// BLSRegisterResponse is the response from POST /v1/staking/bls/register.
type BLSRegisterResponse struct {
	KeyHandle    string `json:"keyHandle"`
	BLSPubKeyB64 string `json:"blsPubKeyB64"`
}

// BLSSignRequest is the request body for POST /v1/staking/bls/sign.
type BLSSignRequest struct {
	KeyHandle string `json:"keyHandle"`
	Message   string `json:"message"` // base64-encoded
}

// BLSSignResponse is the response from POST /v1/staking/bls/sign.
type BLSSignResponse struct {
	SignatureB64 string `json:"signatureB64"`
}

// TLSRegisterRequest is the request body for POST /v1/staking/tls/register.
type TLSRegisterRequest struct {
	Mode            KeyMode `json:"mode"`
	EphemeralKeyPEM string  `json:"ephemeralKeyPEM,omitempty"`
	CSRPEM          string  `json:"csrPEM,omitempty"`
	NetworkID       uint32  `json:"networkID"`
	NodeLabel       string  `json:"nodeLabel,omitempty"`
}

// TLSRegisterResponse is the response from POST /v1/staking/tls/register.
type TLSRegisterResponse struct {
	KeyHandle    string `json:"keyHandle"`
	CertChainPEM string `json:"certChainPEM"`
}

// TLSSignRequest is the request body for POST /v1/staking/tls/sign.
type TLSSignRequest struct {
	KeyHandle string `json:"keyHandle"`
	Digest    string `json:"digest"`    // base64-encoded
	Algorithm string `json:"algorithm"` // e.g., "ECDSA_P256_SHA256"
}

// TLSSignResponse is the response from POST /v1/staking/tls/sign.
type TLSSignResponse struct {
	SignatureB64 string `json:"signatureB64"`
}

// RemoteBLSSigner abstracts BLS signing operations via Cryftee/Web3Signer.
// CryfteeManager provides this functionality via InitBLSKey() and SignBLS().
type RemoteBLSSigner interface {
	// Register registers or obtains a BLS staking key.
	Register(ctx context.Context, req BLSRegisterRequest) (*BLSRegisterResponse, error)

	// PublicKey returns the BLS public key bytes.
	PublicKey() ([]byte, error)

	// Sign produces a BLS signature over msg.
	Sign(ctx context.Context, msg []byte) ([]byte, error)
}

// RemoteTLSSigner abstracts TLS signing operations via Cryftee/Web3Signer.
// CryfteeManager provides this functionality via InitTLSKey() and SignTLS().
type RemoteTLSSigner interface {
	// RegisterTLS registers or obtains a TLS staking identity.
	RegisterTLS(ctx context.Context, req TLSRegisterRequest) (*TLSRegisterResponse, error)

	// TLSConfig returns a tls.Config backed by remote signing.
	TLSConfig() (*tls.Config, error)

	// CertificatePEM returns the PEM-encoded certificate chain.
	CertificatePEM() ([]byte, error)
}
