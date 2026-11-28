package tsm

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"net/http"
	"slices"
	"strconv"

	thresholdrsa "github.com/C18519898242/circl/tss/rsa"
)

const rsaPSSFormat = "circl-rsa-pss-sha256-v1"

// Account for base64 encoding and the JSON response envelope.
const maxRSAPSSResponseSize = maxBuilderRSAPartSize*4/3 + 1024

type rsaPSSEnvelope struct {
	Format       string   `json:"format"`
	SessionID    string   `json:"sessionID"`
	KeyID        string   `json:"keyID"`
	HashFunction string   `json:"hash"`
	PublicKey    []byte   `json:"publicKey"`
	Players      uint     `json:"players"`
	Threshold    uint     `json:"threshold"`
	PlayerIndex  uint     `json:"playerIndex"`
	Signers      []string `json:"signers"`
	Digest       []byte   `json:"digest"`
	Salt         []byte   `json:"salt"`
	Share        []byte   `json:"share"`
}

func (s *rsaService) SignPSS(ctx context.Context, session *SessionConfig, keyID, hashFunction string, digest []byte) ([]byte, error) {
	if session == nil || len(session.players) < 2 || !keyIDPattern.MatchString(keyID) ||
		hashFunction != HashFunctionSHA256 || len(digest) != sha256.Size {
		return nil, fmt.Errorf("%w: RSA-PSS signing requires a session, valid key ID, SHA256 and a 32-byte digest", ErrInvalidInput)
	}
	request := struct {
		Hash        crypto.Hash `json:"hash"`
		MessageHash []byte      `json:"messageHash"`
		Players     []int       `json:"players"`
	}{Hash: crypto.SHA256, MessageHash: digest}
	var response struct {
		PartialSignature []byte `json:"partialSignature"`
	}
	if err := s.client.requestWithPlayerIDs(ctx, http.MethodPost, "/rsa/keys/"+keyID+"/signpss", session, request, &response, maxRSAPSSResponseSize, false); err != nil {
		return nil, err
	}
	if !s.client.native {
		part, err := decodeBuilderRSAPart(response.PartialSignature)
		if err != nil || part.Threshold >= len(session.players) || !slices.Contains(session.players, part.PlayerIndex) {
			return nil, signatureError("invalid Builder Vault RSA-PSS partial signature response")
		}
		return response.PartialSignature, nil
	}
	expectedSigners := make([]string, len(session.players))
	for i, player := range session.players {
		expectedSigners[i] = strconv.FormatUint(uint64(player)+1, 10)
	}
	slices.Sort(expectedSigners)
	part, _, _, err := decodeRSAPSSEnvelope(response.PartialSignature)
	if err != nil || part.SessionID != session.SessionID() || part.KeyID != keyID ||
		part.HashFunction != hashFunction || !bytes.Equal(part.Digest, digest) ||
		!slices.Equal(part.Signers, expectedSigners) {
		return nil, signatureError("invalid RSA-PSS partial signature response")
	}
	return response.PartialSignature, nil
}

// RSAFinalizeSignaturePSS combines RSA-PSS shares from one session on either
// backend. Supply the expected digest to verify it during combination. When
// combining Builder Vault shares with no digest, verify the result separately
// against the expected digest and a trusted public key.
func RSAFinalizeSignaturePSS(hashFunction string, digest []byte, partialSignatures [][]byte) ([]byte, error) {
	if hashFunction != HashFunctionSHA256 || (len(digest) != 0 && len(digest) != sha256.Size) {
		return nil, fmt.Errorf("%w: RSA-PSS requires SHA256 and, if supplied, a 32-byte digest", ErrInvalidInput)
	}
	if len(partialSignatures) < 2 {
		return nil, signatureError("insufficient RSA-PSS signing shares")
	}
	firstEncoded := partialSignatures[0]
	if len(firstEncoded) > 16<<10 || !json.Valid(firstEncoded) {
		return finalizeBuilderRSAPSS(digest, partialSignatures)
	}
	first, publicKey, firstShare, err := decodeRSAPSSEnvelope(firstEncoded)
	if err != nil {
		return nil, err
	}
	if len(digest) == 0 {
		digest = first.Digest
	} else if !bytes.Equal(first.Digest, digest) {
		return nil, signatureError("RSA-PSS signing share digest mismatch")
	}
	if uint(len(partialSignatures)) < first.Threshold || uint(len(partialSignatures)) > first.Players || len(partialSignatures) > len(first.Signers) {
		return nil, signatureError("invalid RSA-PSS signing share count")
	}
	shares := make([]thresholdrsa.SignShare, len(partialSignatures))
	shares[0] = firstShare
	seen := make(map[uint]bool, len(partialSignatures))
	seen[firstShare.Index] = true
	for i, encoded := range partialSignatures[1:] {
		part, _, share, err := decodeRSAPSSEnvelope(encoded)
		if err != nil {
			return nil, err
		}
		if seen[share.Index] || part.SessionID != first.SessionID || part.KeyID != first.KeyID ||
			part.HashFunction != first.HashFunction || !bytes.Equal(part.PublicKey, first.PublicKey) ||
			part.Players != first.Players || part.Threshold != first.Threshold ||
			!slices.Equal(part.Signers, first.Signers) || !bytes.Equal(part.Digest, first.Digest) ||
			!bytes.Equal(part.Salt, first.Salt) {
			return nil, signatureError("inconsistent or duplicate RSA-PSS signing shares")
		}
		seen[share.Index] = true
		shares[i+1] = share
	}
	padder := &thresholdrsa.PSSPadder{
		Rand: bytes.NewReader(first.Salt),
		Opts: &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256},
	}
	padded, err := padder.Pad(publicKey, crypto.SHA256, digest)
	if err != nil {
		return nil, signatureError("could not encode RSA-PSS digest")
	}
	signature, err := thresholdrsa.CombineSignShares(publicKey, first.Players, first.Threshold, shares, padded)
	opts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256}
	if err != nil || rsa.VerifyPSS(publicKey, crypto.SHA256, digest, signature, opts) != nil {
		return nil, signatureError("combined RSA-PSS signature failed verification")
	}
	return signature, nil
}

// RSAVerifySignaturePSS verifies a standard RSA-PSS signature over a SHA-256 digest.
// It determines the salt length from the signature, as Builder Vault does.
func RSAVerifySignaturePSS(publicKeyDER []byte, hashFunction string, digest, signature []byte) error {
	publicKey, err := parseRSAPublicKeyDER(publicKeyDER)
	if err != nil {
		return err
	}
	if hashFunction != HashFunctionSHA256 || len(digest) != sha256.Size {
		return fmt.Errorf("%w: RSA-PSS verification requires SHA256 and a 32-byte digest", ErrInvalidInput)
	}
	if rsa.VerifyPSS(publicKey, crypto.SHA256, digest, signature, nil) != nil {
		return signatureError("RSA-PSS signature failed verification")
	}
	return nil
}

func decodeRSAPSSEnvelope(encoded []byte) (rsaPSSEnvelope, *rsa.PublicKey, thresholdrsa.SignShare, error) {
	var part rsaPSSEnvelope
	var share thresholdrsa.SignShare
	if len(encoded) > 16<<10 || json.Unmarshal(encoded, &part) != nil || part.Format != rsaPSSFormat ||
		!sessionIDPattern.MatchString(part.SessionID) || !keyIDPattern.MatchString(part.KeyID) ||
		part.HashFunction != HashFunctionSHA256 || len(part.Digest) != sha256.Size || len(part.Salt) != sha256.Size ||
		part.Players > math.MaxUint16 || part.Threshold < 2 || part.Threshold > part.Players ||
		part.PlayerIndex == 0 || part.PlayerIndex > part.Players ||
		len(part.Signers) < int(part.Threshold) || len(part.Signers) > int(part.Players) || !validPSSSigners(part.Signers) {
		return part, nil, share, signatureError("invalid RSA-PSS partial signature envelope")
	}
	publicKey, err := parseRSAPublicKey(part.PublicKey)
	if err != nil {
		return part, nil, share, signatureError("invalid RSA-PSS public key")
	}
	share, ok := decodeRSASignShare(part.Share, publicKey.Size())
	if !ok || share.Index != part.PlayerIndex || share.Players != part.Players || share.Threshold != part.Threshold {
		return part, nil, share, signatureError("invalid RSA-PSS signature share metadata")
	}
	value := new(big.Int).SetBytes(part.Share[8:])
	if value.Cmp(publicKey.N) >= 0 || new(big.Int).GCD(nil, nil, value, publicKey.N).Cmp(big.NewInt(1)) != 0 {
		return part, nil, share, signatureError("invalid RSA-PSS signature share value")
	}
	return part, publicKey, share, nil
}

func validPSSSigners(signers []string) bool {
	for i, signer := range signers {
		if signer == "" || (i > 0 && signers[i-1] >= signer) {
			return false
		}
	}
	return true
}
