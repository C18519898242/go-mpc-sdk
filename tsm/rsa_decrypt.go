package tsm

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math"
	"net/http"

	thresholdrsa "github.com/C18519898242/circl/tss/rsa"
)

// HashFunctionSHA256 selects SHA-256 for RSA OAEP and MGF1.
const HashFunctionSHA256 = "SHA256"

const rsaDecryptionFormat = "circl-rsa-oaep-sha256-v1"

type rsaDecryptionEnvelope struct {
	Format     string `json:"format"`
	KeyID      string `json:"keyID"`
	PublicKey  []byte `json:"publicKey"`
	Players    uint   `json:"players"`
	Threshold  uint   `json:"threshold"`
	Ciphertext []byte `json:"ciphertext"`
	Share      []byte `json:"share"`
}

func (s *rsaService) requireDecryptionTransport() error {
	if !s.client.native {
		return fmt.Errorf("%w: RSA decryption requires mpc-node-api", ErrOperationFailed)
	}
	if !s.client.rsaDecryptionAuth {
		return fmt.Errorf("%w: RSA decryption requires WithRSADecryptionAuthentication", ErrInvalidInput)
	}
	return nil
}

func (s *rsaService) Decrypt(ctx context.Context, keyID string, ciphertext []byte) ([]byte, error) {
	if err := s.requireDecryptionTransport(); err != nil {
		return nil, err
	}
	if !keyIDPattern.MatchString(keyID) || (len(ciphertext) != 2048/8 && len(ciphertext) != 3072/8 && len(ciphertext) != 4096/8) {
		return nil, fmt.Errorf("%w: invalid RSA key ID or ciphertext size", ErrInvalidInput)
	}
	request := struct {
		Ciphertext []byte `json:"ciphertext"`
	}{ciphertext}
	var response struct {
		PartialDecryption []byte `json:"partialDecryption"`
	}
	if err := s.client.request(ctx, http.MethodPost, "/rsa/keys/"+keyID+"/decrypt", nil, request, &response); err != nil {
		return nil, err
	}
	part, _, _, err := decodeRSADecryptionEnvelope(response.PartialDecryption)
	if err != nil || part.KeyID != keyID || !bytes.Equal(part.Ciphertext, ciphertext) {
		return nil, fmt.Errorf("%w: invalid RSA partial decryption response", ErrOperationFailed)
	}
	return response.PartialDecryption, nil
}

// RSAFinalizeDecryptionOAEP combines partial decryptions from distinct trusted
// mpc-node-api participants. The caller must authenticate their provenance,
// collect only responses to the intended request, and keep them confidential.
// Supply HashFunctionSHA256 and the
// label used when encrypting (nil for an empty label).
func RSAFinalizeDecryptionOAEP(hashFunction string, label []byte, partialDecryptions [][]byte) ([]byte, error) {
	if hashFunction != HashFunctionSHA256 {
		return nil, fmt.Errorf("%w: RSA-OAEP requires SHA256", ErrInvalidInput)
	}
	if len(partialDecryptions) < 2 {
		return nil, rsa.ErrDecryption
	}
	first, key, share, err := decodeRSADecryptionEnvelope(partialDecryptions[0])
	if err != nil || uint(len(partialDecryptions)) < first.Threshold || uint(len(partialDecryptions)) > first.Players {
		return nil, rsa.ErrDecryption
	}
	shares := make([]thresholdrsa.DecryptionShare, len(partialDecryptions))
	shares[0] = share
	for i, encoded := range partialDecryptions[1:] {
		part, _, share, err := decodeRSADecryptionEnvelope(encoded)
		if err != nil || part.KeyID != first.KeyID || part.Players != first.Players || part.Threshold != first.Threshold ||
			!bytes.Equal(part.PublicKey, first.PublicKey) || !bytes.Equal(part.Ciphertext, first.Ciphertext) {
			return nil, rsa.ErrDecryption
		}
		shares[i+1] = share
	}
	return thresholdrsa.CombineDecryptionSharesOAEP(key, first.Players, first.Threshold, shares, first.Ciphertext, label)
}

func decodeRSADecryptionEnvelope(encoded []byte) (rsaDecryptionEnvelope, *rsa.PublicKey, thresholdrsa.DecryptionShare, error) {
	var part rsaDecryptionEnvelope
	var share thresholdrsa.DecryptionShare
	if len(encoded) > 4<<10 || json.Unmarshal(encoded, &part) != nil || part.Format != rsaDecryptionFormat ||
		!keyIDPattern.MatchString(part.KeyID) || part.Players > math.MaxUint16 || part.Threshold < 2 || part.Threshold > part.Players {
		return part, nil, share, rsa.ErrDecryption
	}
	key, err := parseRSAPublicKey(part.PublicKey)
	if err != nil || len(part.Ciphertext) != key.Size() {
		return part, nil, share, rsa.ErrDecryption
	}
	// CIRCL v1 encodes three uint16 fields, the SHA-256 ciphertext digest and two RSA values.
	const digestOffset = 3 * 2
	const headerSize = digestOffset + sha256.Size
	digest := sha256.Sum256(part.Ciphertext)
	if len(part.Share) != headerSize+2*key.Size() || !bytes.Equal(part.Share[digestOffset:headerSize], digest[:]) ||
		share.UnmarshalBinary(part.Share) != nil || share.Players != part.Players || share.Threshold != part.Threshold {
		return part, nil, share, rsa.ErrDecryption
	}
	return part, key, share, nil
}
