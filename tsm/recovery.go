package tsm

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
)

// The native proof contains 128 RSA ciphertexts, which can exceed the normal response limit.
const maxRecoveryResponse = 512 << 10

func (s *ecdsaService) GenerateRecoveryData(ctx context.Context, session *SessionConfig, keyID string, key *rsa.PublicKey, label []byte) ([]byte, error) {
	return s.client.generateRecoveryData(ctx, "/ecdsa/keys", "ecdsa", session, keyID, key, label)
}

func (s *schnorrService) GenerateRecoveryData(ctx context.Context, session *SessionConfig, keyID string, key *rsa.PublicKey, label []byte) ([]byte, error) {
	return s.client.generateRecoveryData(ctx, s.path, "frost", session, keyID, key, label)
}

func (c *Client) generateRecoveryData(ctx context.Context, endpoint, algorithm string, session *SessionConfig, keyID string, key *rsa.PublicKey, label []byte) ([]byte, error) {
	if !keyIDPattern.MatchString(keyID) || session == nil || len(session.players) < 2 ||
		key == nil || key.N == nil || key.N.Sign() <= 0 || key.E < 3 {
		return nil, fmt.Errorf("%w: recovery data needs a valid key ID, a session with at least two players, and an RSA public key", ErrInvalidInput)
	}
	path := endpoint + "/" + keyID
	if !c.native {
		request := struct {
			ERSPublicKey      *rsa.PublicKey `json:"ersPublicKey"`
			Label             []byte         `json:"label"`
			OutputPlayerIndex int            `json:"outputPlayerIndex"`
		}{key, label, -1}
		var response struct {
			RecoveryInfos []json.RawMessage `json:"recoveryInfos"`
		}
		if err := c.requestWithLimit(ctx, http.MethodPost, path+"/recoveryinfo", session, request, &response, maxRecoveryResponse); err != nil {
			return nil, err
		}
		var info struct{ Version string }
		if len(response.RecoveryInfos) == 0 || json.Unmarshal(response.RecoveryInfos[0], &info) != nil || info.Version == "" {
			return nil, fmt.Errorf("%w: invalid Builder Vault recovery data", ErrOperationFailed)
		}
		return response.RecoveryInfos[0], nil
	}
	if keyID == "_" || key.N.BitLen() < 2048 || key.N.BitLen() > 8192 || key.N.Bit(0) != 1 || key.E != 65537 || len(label) > 1024 {
		return nil, fmt.Errorf("%w: invalid native key ID, recovery RSA public key or label", ErrInvalidInput)
	}
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return nil, fmt.Errorf("%w: could not encode recovery RSA public key", ErrInvalidInput)
	}
	// The node binds the label's JSON representation to the session.
	if len(label) == 0 {
		label = nil
	}
	request := struct {
		RecoveryKey []byte `json:"recoveryKey"`
		Label       []byte `json:"label"`
	}{der, label}
	var raw json.RawMessage
	if err := c.requestWithLimit(ctx, http.MethodPost, path+"/recoverydata", session, request, &raw, maxRecoveryResponse); err != nil {
		return nil, err
	}
	var partial struct {
		Manifest struct {
			Version     int
			Algorithm   string
			KeyID       string
			SessionID   string
			RecoveryKey []byte
			Label       []byte
		}
		PartyID string
		Proof   *struct{}
	}
	if err := json.Unmarshal(raw, &partial); err != nil || partial.PartyID == "" || partial.Proof == nil {
		return nil, fmt.Errorf("%w: invalid recovery data", ErrOperationFailed)
	}
	m := partial.Manifest
	if m.Version != 1 || m.Algorithm != algorithm || m.KeyID != keyID || m.SessionID != session.id ||
		!bytes.Equal(m.RecoveryKey, der) || !bytes.Equal(m.Label, label) {
		return nil, fmt.Errorf("%w: recovery data does not match the request", ErrOperationFailed)
	}
	return raw, nil
}
