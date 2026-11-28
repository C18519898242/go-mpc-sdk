package tsm

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"net/http"
	"slices"
	"strconv"
	"strings"

	thresholdrsa "github.com/C18519898242/circl/tss/rsa"
)

const (
	rsaImportFormat    = "circl-rsa-sign-import-v1"
	rsaImportMaxBody   = 64 << 10
	nativeKeyWrapLabel = "mpc-node-api/key-transfer/v1"
)

type rsaImportShare struct {
	Format    string   `json:"format"`
	SplitID   []byte   `json:"splitID"`
	Players   []string `json:"players"`
	PublicKey []byte   `json:"publicKey"`
	Share     []byte   `json:"share"`
}

// RSASecretShare splits a trusted, two-safe-prime RSA signing key offline.
// Threshold is one below the required share count. Players are SDK indices.
// Wrap each returned secret share for its intended node before sending it.
func RSASecretShare(threshold int, players []int, privateKey *rsa.PrivateKey) (map[int][]byte, error) {
	if threshold < 1 || threshold >= len(players) || len(players) > math.MaxUint16 {
		return nil, fmt.Errorf("%w: invalid RSA import threshold or player count", ErrInvalidInput)
	}
	ordered := slices.Clone(players)
	partyID := func(player int) string { return strconv.FormatUint(uint64(player)+1, 10) }
	for _, player := range ordered {
		if player < 0 {
			return nil, fmt.Errorf("%w: RSA import player indices must be nonnegative", ErrInvalidInput)
		}
	}
	slices.SortFunc(ordered, func(a, b int) int { return strings.Compare(partyID(a), partyID(b)) })
	roster := make([]string, len(ordered))
	for i, player := range ordered {
		if i > 0 && ordered[i-1] == player {
			return nil, fmt.Errorf("%w: duplicate RSA import player", ErrInvalidInput)
		}
		roster[i] = partyID(player)
	}
	publicDER, err := rsaImportPublicKey(privateKey)
	if err != nil {
		return nil, err
	}
	shares, err := thresholdrsa.Deal(rand.Reader, uint(len(players)), uint(threshold+1), privateKey, false)
	if err != nil {
		return nil, fmt.Errorf("%w: could not split RSA key", ErrOperationFailed)
	}
	splitID := make([]byte, sha256.Size)
	rand.Read(splitID)
	result := make(map[int][]byte, len(players))
	for i, player := range ordered {
		share, err := shares[i].MarshalBinary()
		if err != nil {
			for _, encoded := range result {
				clear(encoded)
			}
			return nil, fmt.Errorf("%w: could not serialize RSA share", ErrOperationFailed)
		}
		encoded, err := json.Marshal(rsaImportShare{rsaImportFormat, splitID, roster, publicDER, share})
		clear(share)
		if err != nil {
			for _, previous := range result {
				clear(previous)
			}
			return nil, fmt.Errorf("%w: could not encode RSA share", ErrOperationFailed)
		}
		result[player] = encoded
	}
	return result, nil
}

func rsaImportPublicKey(key *rsa.PrivateKey) ([]byte, error) {
	invalid := fmt.Errorf("%w: expected a valid RSA signing key of 2048, 3072 or 4096 bits with exponent 65537 and two distinct safe primes", ErrInvalidInput)
	if key == nil || key.N == nil || key.N.Sign() <= 0 || key.D == nil || key.D.Sign() <= 0 ||
		key.E != 65537 || len(key.Primes) != 2 {
		return nil, invalid
	}
	bits := key.N.BitLen()
	if bits != 2048 && bits != 3072 && bits != 4096 {
		return nil, invalid
	}
	p, q := key.Primes[0], key.Primes[1]
	if p == nil || q == nil || p.Cmp(q) == 0 {
		return nil, invalid
	}
	for _, prime := range key.Primes {
		if prime.Sign() <= 0 || prime.BitLen() != bits/2 || !prime.ProbablyPrime(32) ||
			!new(big.Int).Rsh(prime, 1).ProbablyPrime(32) {
			return nil, invalid
		}
	}
	if key.Validate() != nil {
		return nil, invalid
	}
	return x509.MarshalPKIXPublicKey(&key.PublicKey)
}

// RSAWrapKeyShare encrypts an offline RSA share to a node's SPKI DER wrapping key.
// The result can be passed to ImportKey for that node.
func RSAWrapKeyShare(wrappingPublicKeyDER, share []byte) ([]byte, error) {
	key, err := parseRSAPublicKeyDER(wrappingPublicKeyDER)
	if err != nil || key.N.BitLen() < 2048 || key.N.BitLen() > 8192 || key.E < 65537 || len(share) == 0 {
		return nil, fmt.Errorf("%w: invalid RSA wrapping public key or empty share", ErrInvalidInput)
	}
	// The REST body encodes this JSON envelope again as Base64.
	if len(share) > rsaImportMaxBody/2 {
		return nil, fmt.Errorf("%w: RSA share is too large", ErrInvalidInput)
	}
	var secret [32]byte
	rand.Read(secret[:])
	defer clear(secret[:])
	block, err := aes.NewCipher(secret[:])
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return nil, err
	}
	label := []byte(nativeKeyWrapLabel)
	wrapped, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, key, secret[:], label)
	if err != nil {
		return nil, err
	}
	return json.Marshal(nativeWrappedKeyShare{Version: 1, WrappedKey: wrapped, Ciphertext: aead.Seal(nil, nil, share, label)})
}

func (s *rsaService) ImportKey(ctx context.Context, session *SessionConfig, wrappedKeyShare []byte, desiredKeyID string) (string, error) {
	if !s.client.native {
		return "", fmt.Errorf("%w: RSA import requires mpc-node-api", ErrOperationFailed)
	}
	if s.client.base.Scheme != "https" || session == nil || len(session.players) < 2 {
		return "", fmt.Errorf("%w: RSA import requires HTTPS and at least two players", ErrInvalidInput)
	}
	if _, ok := parseNativeWrappedKeyShare(wrappedKeyShare); !ok || len(wrappedKeyShare) > rsaImportMaxBody*3/4-128 {
		return "", fmt.Errorf("%w: expected an encrypted RSA import share", ErrInvalidInput)
	}
	request := struct {
		KeyID           string `json:"keyID"`
		WrappedKeyShare []byte `json:"wrappedKeyShare"`
	}{desiredKeyID, wrappedKeyShare}
	return s.client.requestKeyID(ctx, "/rsa/keys/importkey", session, desiredKeyID, request)
}

func (s *rsaService) ExportKey(ctx context.Context, session *SessionConfig, keyID string, wrappingKey []byte) (*RSAWrappedKeyShare, error) {
	if !s.client.native {
		return nil, fmt.Errorf("%w: RSA export requires mpc-node-api", ErrOperationFailed)
	}
	if s.client.base.Scheme != "https" || session == nil || len(session.players) < 2 ||
		!keyIDPattern.MatchString(keyID) {
		return nil, fmt.Errorf("%w: RSA export requires HTTPS, a valid key ID and at least two players", ErrInvalidInput)
	}
	wrappingPublic, err := parseRSAPublicKeyDER(wrappingKey)
	if err != nil || wrappingPublic.N.BitLen() < 2048 || wrappingPublic.N.BitLen() > 8192 || wrappingPublic.E < 65537 {
		return nil, fmt.Errorf("%w: invalid RSA wrapping public key", ErrInvalidInput)
	}
	request := struct {
		WrappingKey []byte `json:"wrappingKey"`
	}{wrappingKey}
	var response struct {
		WrappedKeyShare []byte `json:"wrappedKeyShare"`
		PublicKey       []byte `json:"publicKey"`
	}
	if err := s.client.requestWithLimit(ctx, http.MethodPost, "/rsa/keys/"+keyID+"/exportkey", session, request, &response, rsaImportMaxBody); err != nil {
		return nil, err
	}
	if _, ok := parseNativeWrappedKeyShare(response.WrappedKeyShare); !ok || len(response.WrappedKeyShare) > rsaImportMaxBody*3/4-128 {
		return nil, fmt.Errorf("%w: invalid exported RSA key envelope", ErrOperationFailed)
	}
	if _, err := parseRSAPublicKey(response.PublicKey); err != nil {
		return nil, signatureError("invalid exported RSA public key")
	}
	return &RSAWrappedKeyShare{
		WrappedKeyShare: response.WrappedKeyShare,
		PKIXPublicKey:   response.PublicKey,
	}, nil
}
