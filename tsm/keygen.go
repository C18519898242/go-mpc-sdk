package tsm

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"filippo.io/edwards25519"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// ECDSAAPI provides Secp256k1 key creation, public key lookup and signing.
type ECDSAAPI interface {
	GenerateKey(ctx context.Context, sessionConfig *SessionConfig, threshold int, curveName, desiredKeyID string) (string, error)
	// Reshare refreshes the key's shares with all current holders.
	Reshare(ctx context.Context, sessionConfig *SessionConfig, keyID string) error
	// CopyKey creates a new sharing of the same key. A new holder supplies an
	// empty sourceKeyID and the curve name. An existing holder supplies the source ID and an empty curve name.
	CopyKey(ctx context.Context, sessionConfig *SessionConfig, sourceKeyID, curveName string, newThreshold int, desiredKeyID string) (string, error)
	PublicKey(ctx context.Context, keyID string, derivationPath []uint32) ([]byte, error)
	Sign(ctx context.Context, sessionConfig *SessionConfig, keyID string, derivationPath []uint32, messageHash []byte) (*ECDSAPartialSignResult, error)
	// GeneratePresignatures participates in a shared MPC session to generate one-time signing material.
	GeneratePresignatures(ctx context.Context, sessionConfig *SessionConfig, keyID string, presignatureCount uint64) ([]string, error)
	// SignWithPresignature consumes one local presignature and returns a signature share.
	// An empty presignatureID lets this node choose an available ID.
	SignWithPresignature(ctx context.Context, keyID, presignatureID string, derivationPath []uint32, messageHash []byte) (*ECDSAPartialSignResult, error)
}

// SchnorrAPI provides Ed25519 key creation, public key lookup and signing.
type SchnorrAPI interface {
	GenerateKey(ctx context.Context, sessionConfig *SessionConfig, threshold int, schnorrVariant, desiredKeyID string) (string, error)
	// Reshare refreshes the key's shares with all current holders.
	Reshare(ctx context.Context, sessionConfig *SessionConfig, keyID string) error
	// CopyKey creates a new sharing of the same key. A new holder supplies an
	// empty sourceKeyID and the Ed25519 variant. Existing holders use the source ID.
	CopyKey(ctx context.Context, sessionConfig *SessionConfig, sourceKeyID, schnorrVariant string, newThreshold int, desiredKeyID string) (string, error)
	PublicKey(ctx context.Context, keyID string, derivationPath []uint32) ([]byte, error)
	Sign(ctx context.Context, sessionConfig *SessionConfig, keyID string, derivationPath []uint32, message []byte) (*SchnorrPartialSignResult, error)
	// GeneratePresignatures participates in a shared MPC session to generate one-time signing material.
	GeneratePresignatures(ctx context.Context, sessionConfig *SessionConfig, keyID string, presignatureCount uint64) ([]string, error)
	// SignWithPresignature consumes one local presignature and returns a signature share.
	// An empty presignatureID lets this node choose an available ID.
	SignWithPresignature(ctx context.Context, keyID, presignatureID string, derivationPath []uint32, message []byte) (*SchnorrPartialSignResult, error)
}

// SchnorrEd25519 selects the Ed25519 variant of the Schnorr API.
const SchnorrEd25519 = "Ed25519"

// ECDSA returns the node's ECDSA service. It panics if the node disables it.
func (c *Client) ECDSA() ECDSAAPI {
	if c.ecdsa == nil {
		panic("ECDSA service is not enabled")
	}
	return c.ecdsa
}

// Schnorr returns the node's Schnorr service. It panics if the node disables it.
func (c *Client) Schnorr() SchnorrAPI {
	if c.schnorr == nil {
		panic("Schnorr service is not enabled")
	}
	return c.schnorr
}

type ecdsaService struct{ client *Client }

type schnorrService struct {
	client *Client
	path   string
}

type keygenRequest struct {
	Threshold int    `json:"threshold"`
	Variant   string `json:"schnorr_variant,omitempty"`
	Curve     string `json:"curve"`
	KeyID     string `json:"keyID"`
}

var keyIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,28}$`)

func (s *ecdsaService) GenerateKey(ctx context.Context, session *SessionConfig, threshold int, curve, desiredID string) (string, error) {
	if curve != "secp256k1" {
		return "", fmt.Errorf("%w: ECDSA key creation supports secp256k1", ErrInvalidInput)
	}
	return s.client.requestNewKeyID(ctx, "/ecdsa/keys", session, keygenRequest{Threshold: threshold, Curve: curve, KeyID: desiredID})
}

func (s *schnorrService) GenerateKey(ctx context.Context, session *SessionConfig, threshold int, variant, desiredID string) (string, error) {
	if variant != SchnorrEd25519 {
		return "", fmt.Errorf("%w: Schnorr key creation supports Ed25519", ErrInvalidInput)
	}
	request := keygenRequest{Threshold: threshold, Variant: variant, Curve: "ED-25519", KeyID: desiredID}
	if s.client.native {
		request.Variant, request.Curve = "", "ed25519"
	}
	return s.client.requestNewKeyID(ctx, s.path, session, request)
}

func (c *Client) requestNewKeyID(ctx context.Context, path string, session *SessionConfig, req keygenRequest) (string, error) {
	if session == nil || req.Threshold < 1 || req.Threshold >= len(session.players) {
		return "", fmt.Errorf("%w: threshold must be between 1 and the number of players minus 1", ErrInvalidInput)
	}
	if req.KeyID != "" && !keyIDPattern.MatchString(req.KeyID) {
		return "", fmt.Errorf("%w: invalid key ID", ErrInvalidInput)
	}
	var response struct {
		KeyID string `json:"keyID"`
	}
	if err := c.request(ctx, http.MethodPost, path, session, req, &response); err != nil {
		return "", err
	}
	if !keyIDPattern.MatchString(response.KeyID) || (req.KeyID != "" && req.KeyID != response.KeyID) {
		return "", fmt.Errorf("%w: invalid key ID in response", ErrOperationFailed)
	}
	return response.KeyID, nil
}

func (s *ecdsaService) PublicKey(ctx context.Context, keyID string, path []uint32) ([]byte, error) {
	return s.client.publicKey(ctx, "/ecdsa/keys", "ECDSA", keyID, path)
}

func (s *schnorrService) PublicKey(ctx context.Context, keyID string, path []uint32) ([]byte, error) {
	return s.client.publicKey(ctx, s.path, SchnorrEd25519, keyID, path)
}

func (c *Client) publicKey(ctx context.Context, endpoint, scheme, keyID string, path []uint32) ([]byte, error) {
	if !keyIDPattern.MatchString(keyID) {
		return nil, fmt.Errorf("%w: invalid key ID", ErrInvalidInput)
	}
	var response struct {
		Curve     string `json:"curve"`
		Variant   string `json:"schnorr_variant"`
		PublicKey []byte `json:"publicKey"`
	}
	request := struct {
		ChainPath []uint32 `json:"chainPath"`
	}{path}
	if err := c.request(ctx, http.MethodPost, endpoint+"/"+keyID+"/publickey", nil, request, &response); err != nil {
		return nil, err
	}
	curve, point := response.Curve, response.PublicKey
	if scheme == "ECDSA" {
		key, err := secp256k1.ParsePubKey(point)
		if err != nil || curve != "secp256k1" {
			return nil, fmt.Errorf("%w: invalid secp256k1 public key", ErrOperationFailed)
		}
		point = key.SerializeUncompressed()
	} else {
		key, err := new(edwards25519.Point).SetBytes(point)
		validCurve := strings.EqualFold(curve, "ed25519") || strings.EqualFold(curve, "ED-25519") || (curve == "" && response.Variant == scheme)
		if err != nil || !validCurve || (response.Variant != "" && response.Variant != scheme) || !validEd25519Point(key) {
			return nil, fmt.Errorf("%w: invalid Ed25519 public key", ErrOperationFailed)
		}
		curve, point = "ED-25519", key.Bytes()
	}
	return json.Marshal(encodedPublicKey{scheme, curve, point})
}

// v73.5.2 returns this serialized SDK public-key envelope.
type encodedPublicKey struct {
	Scheme string `json:"scheme"`
	Curve  string `json:"curve"`
	Point  []byte `json:"point"`
}

func validEd25519Point(point *edwards25519.Point) bool {
	identity := edwards25519.NewIdentityPoint()
	if point.Equal(identity) == 1 {
		return false
	}
	// Scalars are reduced mod L. Compute [L]P as [L-1]P + P.
	one := [32]byte{1}
	scalar, _ := new(edwards25519.Scalar).SetCanonicalBytes(one[:])
	var check edwards25519.Point
	check.ScalarMult(scalar.Negate(scalar), point)
	return check.Add(&check, point).Equal(identity) == 1
}
