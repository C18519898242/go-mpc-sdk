package tsm

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"math"
	"math/big"
	"net/http"

	thresholdrsa "github.com/C18519898242/circl/tss/rsa"
)

// RSAAPI provides public key lookup on both backends and threshold operations on mpc-node-api.
type RSAAPI interface {
	// GenerateKey participates in a trusted-dealer session requiring threshold+1 signers.
	// Every selected player must call it with the same session, threshold, size and desired ID.
	GenerateKey(ctx context.Context, session *SessionConfig, threshold, bits int, desiredKeyID string) (string, error)
	// GenerateDecryptionKey generates a key dedicated to RSA-OAEP decryption over HTTPS.
	// It uses the same session and threshold conventions as GenerateKey.
	GenerateDecryptionKey(ctx context.Context, session *SessionConfig, threshold, bits int, desiredKeyID string) (string, error)
	// PublicKey returns the RSA public key as SPKI DER, matching Builder Vault.
	PublicKey(ctx context.Context, keyID string) ([]byte, error)
	// PublicKeyInfo returns the mpc-node-api public key and its signing parameters.
	PublicKeyInfo(ctx context.Context, keyID string) (*RSAPublicKey, error)
	// Sign returns this node's partial signature for a 32-byte SHA-256 digest.
	Sign(ctx context.Context, keyID string, digest []byte) ([]byte, error)
	// Decrypt returns this node's partial RSA-OAEP decryption over HTTPS.
	Decrypt(ctx context.Context, keyID string, ciphertext []byte) ([]byte, error)
}

// RSAPublicKey holds the SPKI DER public key and the parameters fixed at key creation.
type RSAPublicKey struct {
	PublicKey       []byte `json:"publicKey"`
	Players         uint   `json:"players"`
	RequiredSigners uint   `json:"requiredSigners"`
}

// RSA returns the node's RSA service. It panics if the node disables it.
func (c *Client) RSA() RSAAPI {
	if c.rsa == nil {
		panic("RSA service is not enabled")
	}
	return c.rsa
}

type rsaService struct{ client *Client }

func (s *rsaService) GenerateKey(ctx context.Context, session *SessionConfig, threshold, bits int, desiredID string) (string, error) {
	if !s.client.native {
		return "", fmt.Errorf("%w: RSA key generation requires mpc-node-api", ErrOperationFailed)
	}
	return s.generateKey(ctx, session, threshold, bits, desiredID, "")
}

func (s *rsaService) GenerateDecryptionKey(ctx context.Context, session *SessionConfig, threshold, bits int, desiredID string) (string, error) {
	if err := s.requireDecryptionTransport(); err != nil {
		return "", err
	}
	return s.generateKey(ctx, session, threshold, bits, desiredID, "decrypt")
}

func (s *rsaService) generateKey(ctx context.Context, session *SessionConfig, threshold, bits int, desiredID, usage string) (string, error) {
	if bits != 2048 && bits != 3072 && bits != 4096 {
		return "", fmt.Errorf("%w: RSA key size must be 2048, 3072 or 4096 bits", ErrInvalidInput)
	}
	request := struct {
		Threshold int    `json:"threshold"`
		Bits      int    `json:"bits"`
		KeyID     string `json:"keyID"`
		Usage     string `json:"usage,omitempty"`
	}{threshold, bits, desiredID, usage}
	return s.client.requestNewKeyID(ctx, "/rsa/keys", session, threshold, desiredID, request)
}

func (s *rsaService) PublicKey(ctx context.Context, keyID string) ([]byte, error) {
	result, err := s.requestPublicKey(ctx, keyID)
	if err != nil {
		return nil, err
	}
	if _, err := parseRSAPublicKeyDER(result.PublicKey); err != nil {
		return nil, signatureError("invalid RSA public key response")
	}
	return result.PublicKey, nil
}

func (s *rsaService) PublicKeyInfo(ctx context.Context, keyID string) (*RSAPublicKey, error) {
	if !s.client.native {
		return nil, fmt.Errorf("%w: RSA signing parameters require mpc-node-api", ErrOperationFailed)
	}
	result, err := s.requestPublicKey(ctx, keyID)
	if err != nil {
		return nil, err
	}
	if _, err := result.validate(); err != nil {
		return nil, signatureError("invalid RSA public key response")
	}
	return result, nil
}

func (s *rsaService) requestPublicKey(ctx context.Context, keyID string) (*RSAPublicKey, error) {
	if !keyIDPattern.MatchString(keyID) {
		return nil, fmt.Errorf("%w: invalid RSA key ID", ErrInvalidInput)
	}
	method := http.MethodGet
	var input any
	if s.client.native {
		method, input = http.MethodPost, struct{}{}
	}
	var result RSAPublicKey
	if err := s.client.request(ctx, method, "/rsa/keys/"+keyID+"/publickey", nil, input, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// RSAEncryptOAEP encrypts plaintext locally using a trusted SPKI DER RSA public key,
// SHA-256 for OAEP and MGF1, and the optional label used by the decryptor.
func RSAEncryptOAEP(publicKeyDER, plaintext, label []byte) ([]byte, error) {
	publicKey, err := parseRSAPublicKeyDER(publicKeyDER)
	if err != nil {
		return nil, err
	}
	return rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, plaintext, label)
}

func (s *rsaService) Sign(ctx context.Context, keyID string, digest []byte) ([]byte, error) {
	if !s.client.native {
		return nil, fmt.Errorf("%w: RSA partial signing requires mpc-node-api", ErrOperationFailed)
	}
	if !keyIDPattern.MatchString(keyID) || len(digest) != sha256.Size {
		return nil, fmt.Errorf("%w: RSA signing requires a valid key ID and SHA-256 digest", ErrInvalidInput)
	}
	request := struct {
		MessageHash []byte `json:"messageHash"`
	}{digest}
	var response struct {
		PartialSignature []byte `json:"partialSignature"`
	}
	if err := s.client.request(ctx, http.MethodPost, "/rsa/keys/"+keyID+"/sign", nil, request, &response); err != nil {
		return nil, err
	}
	if _, ok := decodeRSASignShare(response.PartialSignature, 4096/8); !ok {
		return nil, signatureError("invalid RSA partial signature response")
	}
	return response.PartialSignature, nil
}

// RSAFinalizeSignature combines distinct signing shares and verifies the signature
// using the trusted public key information obtained independently of the shares.
func RSAFinalizeSignature(key *RSAPublicKey, digest []byte, partialSignatures [][]byte) ([]byte, error) {
	publicKey, err := key.validate()
	if err != nil {
		return nil, err
	}
	if len(digest) != sha256.Size || uint(len(partialSignatures)) < key.RequiredSigners || uint(len(partialSignatures)) > key.Players {
		return nil, fmt.Errorf("%w: invalid RSA digest or signing share count", ErrInvalidInput)
	}
	shares := make([]thresholdrsa.SignShare, len(partialSignatures))
	seen := make(map[uint]bool, len(shares))
	one := big.NewInt(1)
	for i, part := range partialSignatures {
		share, ok := decodeRSASignShare(part, publicKey.Size())
		if !ok || share.Players != key.Players || share.Threshold != key.RequiredSigners || seen[share.Index] {
			return nil, signatureError("invalid or duplicate RSA signing share")
		}
		// CIRCL requires each share to be invertible modulo the public modulus.
		value := new(big.Int).SetBytes(part[8:])
		if value.Cmp(publicKey.N) >= 0 || new(big.Int).GCD(nil, nil, value, publicKey.N).Cmp(one) != 0 {
			return nil, signatureError("invalid RSA signing share value")
		}
		shares[i] = share
		seen[share.Index] = true
	}
	padded, err := (thresholdrsa.PKCS1v15Padder{}).Pad(publicKey, crypto.SHA256, digest)
	if err != nil {
		return nil, signatureError("could not encode RSA digest")
	}
	signature, err := thresholdrsa.CombineSignShares(publicKey, key.Players, key.RequiredSigners, shares, padded)
	if err != nil || rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, digest, signature) != nil {
		return nil, signatureError("combined RSA signature failed verification")
	}
	return signature, nil
}

// RSAVerifySignature verifies a standard PKCS#1 v1.5 signature over a SHA-256 digest.
func RSAVerifySignature(publicKeyDER, digest, signature []byte) error {
	publicKey, err := parseRSAPublicKey(publicKeyDER)
	if err != nil {
		return err
	}
	if len(digest) != sha256.Size {
		return fmt.Errorf("%w: RSA verification requires a SHA-256 digest", ErrInvalidInput)
	}
	if rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, digest, signature) != nil {
		return signatureError("RSA signature failed verification")
	}
	return nil
}

func (key *RSAPublicKey) validate() (*rsa.PublicKey, error) {
	if key == nil || key.Players > math.MaxUint16 || key.RequiredSigners < 2 || key.RequiredSigners > key.Players {
		return nil, fmt.Errorf("%w: invalid RSA signing parameters", ErrInvalidInput)
	}
	return parseRSAPublicKey(key.PublicKey)
}

func parseRSAPublicKey(der []byte) (*rsa.PublicKey, error) {
	key, err := parseRSAPublicKeyDER(der)
	if err != nil || key.E != 65537 || key.N.Bit(0) == 0 {
		return nil, fmt.Errorf("%w: invalid RSA public key", ErrInvalidInput)
	}
	switch key.N.BitLen() {
	case 2048, 3072, 4096:
		return key, nil
	default:
		return nil, fmt.Errorf("%w: unsupported RSA public key size", ErrInvalidInput)
	}
}

func parseRSAPublicKeyDER(der []byte) (*rsa.PublicKey, error) {
	parsed, err := x509.ParsePKIXPublicKey(der)
	key, ok := parsed.(*rsa.PublicKey)
	if err != nil || !ok {
		return nil, fmt.Errorf("%w: invalid RSA public key", ErrInvalidInput)
	}
	return key, nil
}

func decodeRSASignShare(data []byte, maxSize int) (thresholdrsa.SignShare, bool) {
	var share thresholdrsa.SignShare
	// CIRCL v1 encodes four uint16 fields before the signature share value.
	if len(data) <= 8 || len(data) > 8+maxSize || int(binary.BigEndian.Uint16(data[6:8])) != len(data)-8 || share.UnmarshalBinary(data) != nil {
		return share, false
	}
	return share, share.Index > 0 && share.Index <= share.Players && share.Threshold >= 2 && share.Threshold <= share.Players
}
