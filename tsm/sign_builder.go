package tsm

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/gob"
	"errors"
	"math/big"

	"filippo.io/edwards25519"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	ecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

const (
	builderShamir           = 1
	builderAdditive         = 2
	builderSecp256k1 uint16 = 714
	builderEd25519   uint16 = 949
)

var ed25519ScalarOrder, _ = new(big.Int).SetString("1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed", 16)

type builderSignResponse struct {
	PresignatureID   string `json:"presignatureId"`
	PartialSignature []byte `json:"partialSignature"`
	Curve            string `json:"curve"`
	SchnorrVariant   string `json:"schnorr_variant"`
	PlayerIndex      int    `json:"playerIndex"`
	Threshold        int    `json:"threshold"`
	Sharing          string `json:"sharing"`
	PublicKey        []byte `json:"publicKey"`
	R                []byte `json:"r"`
	SShare           []byte `json:"sShare"`
	U                []byte `json:"u"`
	W                []byte `json:"w"`
	Challenge        []byte `json:"challenge"`
}

// Builder Vault gob encodes each point and scalar with a two-byte curve or field ID.
type builderElement []byte

func (e builderElement) MarshalBinary() ([]byte, error) { return e, nil }

func (e *builderElement) UnmarshalBinary(data []byte) error {
	*e = bytes.Clone(data)
	return nil
}

type builderPartial struct {
	Version        int
	Sharing        int
	ProtocolID     string
	PlayerIndex    int
	Threshold      int
	PublicKey      builderElement
	R              builderElement
	SShare         builderElement
	U, W           builderElement
	Challenge      []byte
	SchnorrVariant string
}

func (r builderSignResponse) partial(scheme string) ([]byte, error) {
	if len(r.PartialSignature) != 0 {
		return r.PartialSignature, nil
	}
	var curveID uint16
	var order *big.Int
	part := builderPartial{Version: 1, PlayerIndex: r.PlayerIndex, Threshold: r.Threshold, Challenge: r.Challenge}
	switch scheme {
	case "ECDSA":
		if r.Curve != "secp256k1" {
			return nil, signatureError("unsupported ECDSA signing curve")
		}
		curveID, part.ProtocolID = builderSecp256k1, "ECDSA"
		order = secp256k1.Params().N
	case SchnorrEd25519:
		if r.SchnorrVariant != SchnorrEd25519 && (r.SchnorrVariant != "" || r.Curve != "ED-25519") {
			return nil, signatureError("unsupported Schnorr signing variant")
		}
		curveID, part.ProtocolID, part.SchnorrVariant = builderEd25519, "SCHNORR", SchnorrEd25519
		order = ed25519ScalarOrder
	default:
		return nil, signatureError("unsupported signing scheme")
	}
	switch r.Sharing {
	case "shamir":
		part.Sharing = builderShamir
	case "additive":
		part.Sharing = builderAdditive
	default:
		return nil, signatureError("unsupported Builder Vault sharing type")
	}
	wrap := func(data []byte) builderElement {
		return append(binary.BigEndian.AppendUint16(nil, curveID), data...)
	}
	public, nonce := normalizeBuilderPoint(curveID, r.PublicKey), normalizeBuilderPoint(curveID, r.R)
	if public == nil || nonce == nil || r.PlayerIndex < 0 || r.Threshold < 0 {
		return nil, signatureError("invalid Builder Vault signing metadata or points")
	}
	part.PublicKey, part.R = wrap(public), wrap(nonce)
	validScalar := func(data []byte) bool {
		return len(data) == 32 && new(big.Int).SetBytes(data).Cmp(order) < 0
	}
	if scheme == "ECDSA" && len(r.SShare) == 0 {
		if !validScalar(r.U) || !validScalar(r.W) {
			return nil, signatureError("invalid Builder Vault U or W share")
		}
		part.Version, part.U, part.W = 2, wrap(r.U), wrap(r.W)
	} else {
		if !validScalar(r.SShare) {
			return nil, signatureError("invalid Builder Vault scalar share")
		}
		part.SShare = wrap(r.SShare)
	}
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(part); err != nil {
		return nil, signatureError("cannot encode Builder Vault signature share")
	}
	return buf.Bytes(), nil
}

func normalizeBuilderPoint(curveID uint16, data []byte) []byte {
	if curveID == builderSecp256k1 {
		point, err := secp256k1.ParsePubKey(data)
		if err == nil {
			return point.SerializeUncompressed()
		}
	} else {
		point, err := new(edwards25519.Point).SetBytes(data)
		if err == nil && validEd25519Point(point) {
			return point.Bytes()
		}
	}
	return nil
}

func (p *builderPartial) decode(data []byte) error {
	err := gob.NewDecoder(bytes.NewReader(data)).Decode(p)
	if err == nil {
		return nil
	}
	// SDK v1 wrapped its share in a single-element list.
	var legacy struct{ PartialSignatures []builderPartial }
	if err := gob.NewDecoder(bytes.NewReader(data)).Decode(&legacy); err != nil {
		return err
	}
	if len(legacy.PartialSignatures) != 1 {
		return errors.New("invalid legacy partial signature count")
	}
	*p = legacy.PartialSignatures[0]
	return nil
}

type builderShare struct {
	player int
	u, w   *big.Int
}

func decodeBuilderParts(parts [][]byte, curveID uint16, order *big.Int) (builderPartial, []*builderShare, error) {
	var first builderPartial
	shares := make([]*builderShare, 0, len(parts))
	players := make(map[int]bool, len(parts))
	for i, data := range parts {
		var part builderPartial
		if len(data) > 64<<10 || part.decode(data) != nil {
			return first, nil, signatureError("invalid Builder Vault signature share encoding")
		}
		if part.PlayerIndex < 0 || players[part.PlayerIndex] || part.Threshold < 0 || part.Threshold >= len(parts) {
			return first, nil, signatureError("invalid or duplicate Builder Vault signing player, or insufficient shares")
		}
		if part.Sharing != builderShamir && (part.Sharing != builderAdditive || len(parts) != part.Threshold+1) {
			return first, nil, signatureError("invalid Builder Vault sharing type or share count")
		}
		switch curveID {
		case builderSecp256k1:
			if (part.Version != 1 && part.Version != 2) ||
				(part.ProtocolID != "ECDSA" && part.ProtocolID != "DKLS19" && part.ProtocolID != "SEPH18S") {
				return first, nil, signatureError("unsupported Builder Vault ECDSA partial signature")
			}
		case builderEd25519:
			if part.Version != 1 || (part.ProtocolID != "SCHNORR" && part.ProtocolID != "SEPD19S") {
				return first, nil, signatureError("unsupported Builder Vault Ed25519 partial signature")
			}
		}
		if i == 0 {
			first = part
		} else if part.Version != first.Version || part.Sharing != first.Sharing || part.Threshold != first.Threshold ||
			!bytes.Equal(part.PublicKey, first.PublicKey) || !bytes.Equal(part.R, first.R) || !bytes.Equal(part.Challenge, first.Challenge) {
			return first, nil, signatureError("inconsistent Builder Vault signature shares")
		}
		share := &builderShare{player: part.PlayerIndex}
		switch part.Version {
		case 1:
			share.u = decodeBuilderScalar(part.SShare, curveID, order)
		case 2:
			share.u = decodeBuilderScalar(part.U, curveID, order)
			share.w = decodeBuilderScalar(part.W, curveID, order)
		}
		if share.u == nil || (part.Version == 2 && share.w == nil) {
			return first, nil, signatureError("invalid Builder Vault scalar share")
		}
		players[part.PlayerIndex] = true
		shares = append(shares, share)
	}
	return first, shares[:first.Threshold+1], nil
}

func builderElementValue(element builderElement, id uint16) []byte {
	if len(element) <= 2 || binary.BigEndian.Uint16(element) != id {
		return nil
	}
	return element[2:]
}

func decodeBuilderScalar(element builderElement, id uint16, order *big.Int) *big.Int {
	data := builderElementValue(element, id)
	if len(data) == 0 || len(data) > 32 {
		return nil
	}
	value := new(big.Int).SetBytes(data)
	if value.Cmp(order) >= 0 {
		return nil
	}
	return value
}

func combineBuilderShares(first builderPartial, shares []*builderShare, order *big.Int) (u, w *big.Int) {
	u, w = new(big.Int), new(big.Int)
	var weight, term big.Int
	for i, share := range shares {
		weight.SetInt64(1)
		if first.Sharing == builderShamir {
			// Shamir players are evaluated at coordinates playerIndex+1.
			var xi, xj, denominator big.Int
			xi.SetUint64(uint64(share.player) + 1)
			for j, other := range shares {
				if i == j {
					continue
				}
				xj.SetUint64(uint64(other.player) + 1)
				denominator.Sub(&xj, &xi)
				denominator.ModInverse(&denominator, order)
				weight.Mul(&weight, &xj)
				weight.Mul(&weight, &denominator)
				weight.Mod(&weight, order)
			}
		}
		u.Add(u, term.Mul(&weight, share.u))
		if share.w != nil {
			w.Add(w, term.Mul(&weight, share.w))
		}
	}
	return u.Mod(u, order), w.Mod(w, order)
}

func finalizeBuilderECDSA(digest []byte, parts [][]byte) (*ECDSASignature, error) {
	order := secp256k1.Params().N
	first, shares, err := decodeBuilderParts(parts, builderSecp256k1, order)
	if err != nil {
		return nil, err
	}
	public, publicErr := secp256k1.ParsePubKey(builderElementValue(first.PublicKey, builderSecp256k1))
	nonce, nonceErr := secp256k1.ParsePubKey(builderElementValue(first.R, builderSecp256k1))
	if publicErr != nil || nonceErr != nil {
		return nil, signatureError("invalid Builder Vault ECDSA point")
	}
	u, w := combineBuilderShares(first, shares, order)
	s := u
	if first.Version == 2 {
		if u.Sign() == 0 {
			return nil, signatureError("invalid Builder Vault ECDSA divisor")
		}
		s = w.Mul(w, u.ModInverse(u, order)).Mod(w, order)
	}
	nonceBytes := nonce.SerializeUncompressed()
	var rValue, sValue secp256k1.ModNScalar
	recoveryID := int(nonceBytes[64] & 1)
	if rValue.SetByteSlice(nonceBytes[1:33]) {
		recoveryID |= 2
	}
	sValue.SetByteSlice(s.Bytes())
	if rValue.IsZero() || sValue.IsZero() {
		return nil, signatureError("invalid combined Builder Vault ECDSA signature")
	}
	if sValue.IsOverHalfOrder() {
		sValue.Negate()
		recoveryID ^= 1
	}
	signature := ecdsa.NewSignature(&rValue, &sValue)
	result := &ECDSASignature{der: signature.Serialize(), r: rValue.Bytes(), s: sValue.Bytes(), recoveryID: recoveryID}
	if len(digest) != 0 {
		recovered, err := result.recoverPublicKey(recoveryID, digest)
		if err != nil || !recovered.IsEqual(public) {
			return nil, signatureError("combined Builder Vault ECDSA signature failed verification")
		}
	}
	return result, nil
}

func finalizeBuilderSchnorr(message []byte, parts [][]byte) ([]byte, error) {
	order := ed25519ScalarOrder
	first, shares, err := decodeBuilderParts(parts, builderEd25519, order)
	if err != nil {
		return nil, err
	}
	public, publicErr := new(edwards25519.Point).SetBytes(builderElementValue(first.PublicKey, builderEd25519))
	nonce, nonceErr := new(edwards25519.Point).SetBytes(builderElementValue(first.R, builderEd25519))
	if publicErr != nil || nonceErr != nil || !validEd25519Point(public) || !validEd25519Point(nonce) {
		return nil, signatureError("invalid Builder Vault Ed25519 point")
	}
	s, _ := combineBuilderShares(first, shares, order)
	signature := make([]byte, ed25519.SignatureSize)
	copy(signature, nonce.Bytes())
	var scalar [32]byte
	s.FillBytes(scalar[:])
	for i := range scalar {
		signature[32+i] = scalar[31-i]
	}
	if message != nil && !ed25519.Verify(ed25519.PublicKey(public.Bytes()), message, signature) {
		return nil, signatureError("combined Builder Vault Ed25519 signature failed verification")
	}
	return signature, nil
}
