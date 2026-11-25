package tsm

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"

	"filippo.io/edwards25519"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	ecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

type ECDSAPartialSignResult struct {
	PresignatureID   string
	PartialSignature []byte
}

type SchnorrPartialSignResult struct {
	PresignatureID   string
	PartialSignature []byte
}

func (s *ecdsaService) Sign(ctx context.Context, session *SessionConfig, keyID string, path []uint32, digest []byte) (*ECDSAPartialSignResult, error) {
	if !s.client.validSigningDigest(digest) {
		return nil, fmt.Errorf("%w: invalid ECDSA digest length", ErrInvalidInput)
	}
	request := struct {
		ChainPath       []uint32 `json:"chainPath"`
		MessageHash     []byte   `json:"messageHash"`
		SignatureFormat string   `json:"signatureFormat,omitempty"`
	}{path, digest, s.client.signFormat()}
	part, presigID, err := s.client.sign(ctx, "/ecdsa/keys", "ECDSA", session, keyID, request)
	if err != nil {
		return nil, err
	}
	return &ECDSAPartialSignResult{presigID, part}, nil
}

func (s *schnorrService) Sign(ctx context.Context, session *SessionConfig, keyID string, path []uint32, message []byte) (*SchnorrPartialSignResult, error) {
	if message == nil {
		message = []byte{}
	}
	request := struct {
		ChainPath       []uint32 `json:"chainPath"`
		Message         []byte   `json:"message"`
		SignatureFormat string   `json:"signatureFormat,omitempty"`
	}{path, message, s.client.signFormat()}
	part, presigID, err := s.client.sign(ctx, s.path, SchnorrEd25519, session, keyID, request)
	if err != nil {
		return nil, err
	}
	return &SchnorrPartialSignResult{presigID, part}, nil
}

func (c *Client) signFormat() string {
	if c.native {
		return "partial"
	}
	return ""
}

func (c *Client) validSigningDigest(digest []byte) bool {
	return len(digest) > 0 && (!c.native || len(digest) == sha256.Size)
}

func (c *Client) sign(ctx context.Context, endpoint, scheme string, session *SessionConfig, keyID string, request any) ([]byte, string, error) {
	if !keyIDPattern.MatchString(keyID) || session == nil || len(session.players) < 2 {
		return nil, "", fmt.Errorf("%w: signing needs a valid key ID and a session with at least two players", ErrInvalidInput)
	}
	return c.requestSigningShare(ctx, endpoint+"/"+keyID+"/sign", scheme, session, request)
}

func (c *Client) requestSigningShare(ctx context.Context, endpoint, scheme string, session *SessionConfig, request any) ([]byte, string, error) {
	var response struct {
		builderSignResponse
		Signature []byte `json:"signature"`
	}
	if err := c.request(ctx, http.MethodPost, endpoint, session, request, &response); err != nil {
		return nil, "", err
	}
	if c.native && session != nil && len(response.Signature) != 0 {
		return nil, "", signatureError("upgrade mpc-node-api to enable signing shares")
	}
	part, err := response.builderSignResponse.partial(scheme)
	return part, response.PresignatureID, err
}

// ECDSASignature holds the canonical DER signature and its public-key recovery ID.
type ECDSASignature struct {
	der        []byte
	r, s       [32]byte
	recoveryID int
}

func (s *ECDSASignature) ASN1() []byte    { return bytes.Clone(s.der) }
func (s *ECDSASignature) R() []byte       { return bytes.Clone(s.r[:]) }
func (s *ECDSASignature) S() []byte       { return bytes.Clone(s.s[:]) }
func (s *ECDSASignature) RecoveryID() int { return s.recoveryID }

// ECDSAFinalizeSignature combines the signing shares and verifies the result
// when the caller supplies the message hash.
func ECDSAFinalizeSignature(messageHash []byte, partialSignatures [][]byte) (*ECDSASignature, error) {
	if len(partialSignatures) == 0 {
		return nil, signatureError("no ECDSA signing responses")
	}
	return finalizeBuilderECDSA(messageHash, partialSignatures)
}

// SchnorrFinalizeSignature combines the signing shares into a standard
// 64-byte Ed25519 signature and verifies it when message is non-nil.
func SchnorrFinalizeSignature(message []byte, partialSignatures [][]byte) ([]byte, error) {
	if len(partialSignatures) == 0 {
		return nil, signatureError("no Ed25519 signing responses")
	}
	return finalizeBuilderSchnorr(message, partialSignatures)
}

// ECDSAVerifySignature verifies DER against the public key JSON returned by PublicKey.
func ECDSAVerifySignature(jsonPublicKey, messageHash, asn1Signature []byte) error {
	key, err := decodeECDSAPublicKey(jsonPublicKey)
	if err != nil {
		return err
	}
	sig, err := ecdsa.ParseDERSignature(asn1Signature)
	if err != nil || !sig.Verify(messageHash, key) {
		return signatureError("ECDSA signature verification failed")
	}
	return nil
}

// SchnorrVerifySignature verifies an Ed25519 signature over the original message.
func SchnorrVerifySignature(jsonPublicKey, message, signature []byte) error {
	var key encodedPublicKey
	if json.Unmarshal(jsonPublicKey, &key) != nil || key.Scheme != SchnorrEd25519 || key.Curve != "ED-25519" {
		return signatureError("invalid Ed25519 public key envelope")
	}
	point, err := new(edwards25519.Point).SetBytes(key.Point)
	if err != nil || !validEd25519Point(point) || !ed25519.Verify(ed25519.PublicKey(point.Bytes()), message, signature) {
		return signatureError("Ed25519 signature verification failed")
	}
	return nil
}

func decodeECDSAPublicKey(data []byte) (*secp256k1.PublicKey, error) {
	var key encodedPublicKey
	if json.Unmarshal(data, &key) != nil || key.Scheme != "ECDSA" || key.Curve != "secp256k1" {
		return nil, signatureError("invalid ECDSA public key envelope")
	}
	point, err := secp256k1.ParsePubKey(key.Point)
	if err != nil {
		return nil, signatureError("invalid secp256k1 point")
	}
	return point, nil
}

func (s *ECDSASignature) recoverPublicKey(id int, messageHash []byte) (*secp256k1.PublicKey, error) {
	var compact [65]byte
	compact[0] = byte(27 + id)
	copy(compact[1:33], s.r[:])
	copy(compact[33:], s.s[:])
	key, _, err := ecdsa.RecoverCompact(compact[:], messageHash)
	return key, err
}

func signatureError(message string) error { return fmt.Errorf("%w: %s", ErrOperationFailed, message) }
