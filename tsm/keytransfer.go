package tsm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// ECDSAWrappedKeyShare contains one player's encrypted export and its public key.
// On mpc-node-api, WrappedKeyShare contains the complete JSON envelope, including
// the encrypted chain code, and WrappedChainCode is empty.
type ECDSAWrappedKeyShare struct {
	WrappedKeyShare  []byte
	WrappedChainCode []byte
	JSONPublicKey    []byte
}

// SchnorrWrappedKeyShare contains one player's encrypted Ed25519 export and its public key.
type SchnorrWrappedKeyShare ECDSAWrappedKeyShare

const maxKeyTransferResponse = 512 << 10

type nativeWrappedKeyShare struct {
	Version    int    `json:"version"`
	WrappedKey []byte `json:"wrappedKey"`
	Ciphertext []byte `json:"ciphertext"`
}

func (s nativeWrappedKeyShare) valid() bool {
	return s.Version == 1 && len(s.WrappedKey) >= 256 && len(s.WrappedKey) <= 1024 &&
		len(s.Ciphertext) >= 28 && len(s.Ciphertext) <= 1<<18
}

func parseNativeWrappedKeyShare(data []byte) (nativeWrappedKeyShare, bool) {
	var share nativeWrappedKeyShare
	ok := len(data) <= maxKeyTransferResponse && json.Unmarshal(data, &share) == nil && share.valid()
	return share, ok
}

func (c *Client) requestWrappedKeyShare(ctx context.Context, path string, session *SessionConfig, request any) ([]byte, error) {
	var raw json.RawMessage
	if err := c.requestWithLimit(ctx, http.MethodPost, path, session, request, &raw, maxKeyTransferResponse); err != nil {
		return nil, err
	}
	if _, ok := parseNativeWrappedKeyShare(raw); !ok {
		return nil, fmt.Errorf("%w: invalid exported key envelope", ErrOperationFailed)
	}
	return raw, nil
}

func (s *ecdsaService) ExportKey(ctx context.Context, session *SessionConfig, keyID string, path []uint32, wrappingKey []byte) (*ECDSAWrappedKeyShare, error) {
	return s.client.exportKey(ctx, "/ecdsa/keys", "ECDSA", session, keyID, path, wrappingKey)
}

func (s *schnorrService) ExportKey(ctx context.Context, session *SessionConfig, keyID string, path []uint32, wrappingKey []byte) (*SchnorrWrappedKeyShare, error) {
	result, err := s.client.exportKey(ctx, s.path, SchnorrEd25519, session, keyID, path, wrappingKey)
	return (*SchnorrWrappedKeyShare)(result), err
}

func (c *Client) exportKey(ctx context.Context, endpoint, scheme string, session *SessionConfig, keyID string, path []uint32, wrappingKey []byte) (*ECDSAWrappedKeyShare, error) {
	if !keyIDPattern.MatchString(keyID) || (c.native && keyID == "_") || session == nil || len(session.players) < 2 || len(wrappingKey) == 0 {
		return nil, fmt.Errorf("%w: export needs a valid key ID, wrapping public key and at least two players", ErrInvalidInput)
	}
	// An empty path has one representation in the native MPC session binding.
	if len(path) == 0 {
		path = nil
	}
	request := struct {
		ChainPath   []uint32 `json:"chainPath"`
		WrappingKey []byte   `json:"wrappingKey"`
	}{path, wrappingKey}
	route := endpoint + "/" + keyID + "/exportkey"
	if c.native {
		public, err := c.publicKey(ctx, endpoint, scheme, keyID, path)
		if err != nil {
			return nil, err
		}
		wrapped, err := c.requestWrappedKeyShare(ctx, route, session, request)
		if err != nil {
			return nil, err
		}
		return &ECDSAWrappedKeyShare{WrappedKeyShare: wrapped, JSONPublicKey: public}, nil
	}
	var response struct {
		publicKeyResponse
		WrappedKeyShare  []byte `json:"wrappedKeyShare"`
		WrappedChainCode []byte `json:"wrappedChainCode"`
	}
	if err := c.requestWithLimit(ctx, http.MethodPost, route, session, request, &response, maxKeyTransferResponse); err != nil {
		return nil, err
	}
	if len(response.WrappedKeyShare) == 0 {
		return nil, fmt.Errorf("%w: missing exported key share", ErrOperationFailed)
	}
	public, err := response.publicKeyResponse.normalize(scheme)
	if err != nil {
		return nil, err
	}
	publicJSON, err := json.Marshal(public)
	if err != nil {
		return nil, err
	}
	return &ECDSAWrappedKeyShare{response.WrappedKeyShare, response.WrappedChainCode, publicJSON}, nil
}

func (s *ecdsaService) ImportKey(ctx context.Context, session *SessionConfig, threshold int, wrappedKeyShare, wrappedChainCode, jsonPublicKey []byte, desiredID string) (string, error) {
	return s.client.importKey(ctx, "/ecdsa/keys", "ECDSA", session, threshold, ECDSAWrappedKeyShare{wrappedKeyShare, wrappedChainCode, jsonPublicKey}, desiredID)
}

func (s *schnorrService) ImportKey(ctx context.Context, session *SessionConfig, threshold int, wrappedKeyShare, wrappedChainCode, jsonPublicKey []byte, desiredID string) (string, error) {
	return s.client.importKey(ctx, s.path, SchnorrEd25519, session, threshold, ECDSAWrappedKeyShare{wrappedKeyShare, wrappedChainCode, jsonPublicKey}, desiredID)
}

func (c *Client) importKey(ctx context.Context, endpoint, scheme string, session *SessionConfig, threshold int, bundle ECDSAWrappedKeyShare, desiredID string) (string, error) {
	if len(bundle.WrappedKeyShare) == 0 {
		return "", fmt.Errorf("%w: missing wrapped key share", ErrInvalidInput)
	}
	var public encodedPublicKey
	if !c.native || len(bundle.JSONPublicKey) != 0 {
		if json.Unmarshal(bundle.JSONPublicKey, &public) != nil || public.Scheme != scheme {
			return "", fmt.Errorf("%w: invalid public key for import", ErrInvalidInput)
		}
		key, err := (publicKeyResponse{Curve: public.Curve, PublicKey: public.Point}).normalize(scheme)
		if err != nil {
			return "", fmt.Errorf("%w: invalid public key for import", ErrInvalidInput)
		}
		public = key
	}
	route := endpoint + "/importkey"
	if c.native {
		wrapped, ok := parseNativeWrappedKeyShare(bundle.WrappedKeyShare)
		if len(bundle.WrappedChainCode) != 0 || !ok {
			return "", fmt.Errorf("%w: expected an mpc-node-api wrapped key envelope", ErrInvalidInput)
		}
		request := struct {
			KeyID           string                `json:"keyID"`
			Threshold       int                   `json:"threshold"`
			WrappedKeyShare nativeWrappedKeyShare `json:"wrappedKeyShare"`
		}{desiredID, threshold, wrapped}
		keyID, err := c.requestNewKeyID(ctx, route, session, threshold, desiredID, request)
		if err != nil || len(bundle.JSONPublicKey) == 0 {
			return keyID, err
		}
		// The native import commits the envelope before the SDK can compare its public key.
		actual, err := c.publicKey(ctx, endpoint, scheme, keyID, nil)
		if err != nil {
			return keyID, fmt.Errorf("imported key %q but could not verify its root public key: %w", keyID, err)
		}
		expected, _ := json.Marshal(public)
		if !bytes.Equal(actual, expected) {
			return keyID, fmt.Errorf("%w: imported key %q has a different root public key", ErrOperationFailed, keyID)
		}
		return keyID, nil
	}
	request := struct {
		publicKeyResponse
		KeyID     string `json:"keyID"`
		Threshold int    `json:"threshold"`
		KeyShare  []byte `json:"keyShare"`
		ChainCode []byte `json:"chainCode"`
	}{
		publicKeyResponse: publicKeyResponse{Curve: public.Curve, PublicKey: public.Point},
		KeyID:             desiredID, Threshold: threshold, KeyShare: bundle.WrappedKeyShare, ChainCode: bundle.WrappedChainCode,
	}
	if scheme == SchnorrEd25519 {
		request.Variant = scheme
	}
	return c.requestNewKeyID(ctx, route, session, threshold, desiredID, request)
}
