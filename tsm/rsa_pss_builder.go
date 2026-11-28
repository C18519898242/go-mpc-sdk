package tsm

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/gob"
	"fmt"
	"math"
	"math/big"
	"slices"
)

const maxBuilderRSAPartSize = 48 << 10

// Builder Vault's ADN06 result can contain a contribution for each signing subset
// that includes this player. Contributions from one subset multiply to the signature.
type builderRSAPart struct {
	Version     int
	Sharing     int
	ProtocolID  string
	PlayerIndex int
	Threshold   int
	E, N        *big.Int
	Shares      []struct {
		Players []int
		MExpDi  *big.Int
	}
	HashedInput []byte
	subsets     map[string]*big.Int
}

func decodeBuilderRSAPart(data []byte) (builderRSAPart, error) {
	var part builderRSAPart
	if len(data) == 0 || len(data) > maxBuilderRSAPartSize {
		return part, signatureError("invalid Builder Vault RSA partial signature size")
	}
	input := bytes.NewReader(data)
	const builderADN06 = 5
	if gob.NewDecoder(input).Decode(&part) != nil || input.Len() != 0 ||
		part.Version != 1 || part.Sharing != builderADN06 || part.ProtocolID != "RSA" ||
		part.PlayerIndex < 0 || part.Threshold < 1 || len(part.HashedInput) != sha256.Size ||
		part.E == nil || !part.E.IsInt64() || part.E.Int64() < 3 || part.E.Int64() > math.MaxInt32 || part.E.Bit(0) == 0 ||
		part.N == nil || part.N.Sign() != 1 || part.N.BitLen() < 1024 || part.N.BitLen() > 8192 || part.N.Bit(0) == 0 ||
		len(part.Shares) == 0 {
		return part, signatureError("invalid Builder Vault RSA partial signature")
	}
	part.subsets = make(map[string]*big.Int, len(part.Shares))
	for _, share := range part.Shares {
		if len(share.Players) != part.Threshold+1 || share.MExpDi == nil ||
			share.MExpDi.Sign() <= 0 || share.MExpDi.Cmp(part.N) >= 0 {
			return part, signatureError("invalid Builder Vault RSA-PSS contribution")
		}
		slices.Sort(share.Players)
		if share.Players[0] < 0 || len(slices.Compact(share.Players)) != len(share.Players) ||
			!slices.Contains(share.Players, part.PlayerIndex) {
			return part, signatureError("invalid Builder Vault RSA-PSS signing subset")
		}
		id := fmt.Sprint(share.Players)
		if part.subsets[id] != nil {
			return part, signatureError("duplicate Builder Vault RSA-PSS signing subset")
		}
		part.subsets[id] = share.MExpDi
	}
	return part, nil
}

func finalizeBuilderRSAPSS(digest []byte, partialSignatures [][]byte) ([]byte, error) {
	var first builderRSAPart
	type signingSubset struct {
		count   int
		product *big.Int
	}
	subsets := make(map[string]*signingSubset)
	seen := make(map[int]bool, len(partialSignatures))
	for i, encoded := range partialSignatures {
		part, err := decodeBuilderRSAPart(encoded)
		if err != nil {
			return nil, err
		}
		if seen[part.PlayerIndex] || part.Threshold >= len(partialSignatures) {
			return nil, signatureError("duplicate player or insufficient Builder Vault RSA-PSS shares")
		}
		seen[part.PlayerIndex] = true
		if i == 0 {
			first = part
		} else if part.Threshold != first.Threshold || part.E.Cmp(first.E) != 0 || part.N.Cmp(first.N) != 0 ||
			!bytes.Equal(part.HashedInput, first.HashedInput) {
			return nil, signatureError("inconsistent Builder Vault RSA-PSS shares")
		}
		for id, contribution := range part.subsets {
			subset := subsets[id]
			if subset == nil {
				subset = &signingSubset{product: big.NewInt(1)}
				subsets[id] = subset
			}
			subset.count++
			subset.product.Mul(subset.product, contribution).Mod(subset.product, part.N)
		}
	}
	publicKey := &rsa.PublicKey{N: first.N, E: int(first.E.Int64())}
	for _, subset := range subsets {
		if subset.count != first.Threshold+1 {
			continue
		}
		representative := new(big.Int).Exp(subset.product, first.E, first.N)
		inputHash := sha256.Sum256(representative.Bytes())
		if !bytes.Equal(inputHash[:], first.HashedInput) {
			continue
		}
		signature := subset.product.FillBytes(make([]byte, publicKey.Size()))
		if len(digest) == 0 || rsa.VerifyPSS(publicKey, crypto.SHA256, digest, signature, nil) == nil {
			return signature, nil
		}
	}
	return nil, signatureError("no complete Builder Vault RSA-PSS signing subset verified")
}
