package tsm

import (
	"context"
	"fmt"
	"net/http"
)

func (s *ecdsaService) Reshare(ctx context.Context, session *SessionConfig, keyID string) error {
	return s.client.reshare(ctx, "/ecdsa/keys", session, keyID)
}

func (s *schnorrService) Reshare(ctx context.Context, session *SessionConfig, keyID string) error {
	return s.client.reshare(ctx, s.path, session, keyID)
}

func (c *Client) reshare(ctx context.Context, endpoint string, session *SessionConfig, keyID string) error {
	if !keyIDPattern.MatchString(keyID) || session == nil || len(session.players) < 2 {
		return fmt.Errorf("%w: reshare needs a valid key ID and a session with at least two players", ErrInvalidInput)
	}
	return c.request(ctx, http.MethodPost, endpoint+"/"+keyID+"/reshare", session, nil, nil)
}

func (s *ecdsaService) CopyKey(ctx context.Context, session *SessionConfig, sourceKeyID, curve string, threshold int, desiredID string) (string, error) {
	expectedCurve := ""
	if sourceKeyID == "" || sourceKeyID == "_" {
		expectedCurve = "secp256k1"
	}
	if curve != expectedCurve {
		return "", fmt.Errorf("%w: existing holders must pass an empty curve and new holders must pass secp256k1", ErrInvalidInput)
	}
	return s.client.copyKey(ctx, "/ecdsa/keys", session, sourceKeyID, keygenRequest{Threshold: threshold, Curve: curve, KeyID: desiredID})
}

func (s *schnorrService) CopyKey(ctx context.Context, session *SessionConfig, sourceKeyID, variant string, threshold int, desiredID string) (string, error) {
	newHolder := sourceKeyID == "" || sourceKeyID == "_"
	if (newHolder && variant == "") || (variant != "" && variant != SchnorrEd25519) {
		return "", fmt.Errorf("%w: new holders must specify the Ed25519 variant", ErrInvalidInput)
	}
	if s.client.native && !newHolder {
		// The source share determines the variant on mpc-node-api.
		variant = ""
	}
	curve := ""
	if variant == SchnorrEd25519 {
		curve = "ED-25519"
	}
	return s.client.copyKey(ctx, s.path, session, sourceKeyID, keygenRequest{Threshold: threshold, Curve: curve, Variant: variant, KeyID: desiredID})
}

func (c *Client) copyKey(ctx context.Context, endpoint string, session *SessionConfig, sourceKeyID string, request keygenRequest) (string, error) {
	if sourceKeyID == "" {
		sourceKeyID = "_"
	}
	if !keyIDPattern.MatchString(sourceKeyID) {
		return "", fmt.Errorf("%w: invalid source key ID", ErrInvalidInput)
	}
	if request.KeyID == "_" || request.KeyID == sourceKeyID {
		return "", fmt.Errorf("%w: copy needs a new key ID", ErrInvalidInput)
	}
	copiedID, err := c.requestNewKeyID(ctx, endpoint+"/"+sourceKeyID+"/keycopy", session, request.Threshold, request.KeyID, request)
	if err != nil {
		return "", err
	}
	if copiedID == "_" || copiedID == sourceKeyID {
		return "", fmt.Errorf("%w: invalid copied key ID in response", ErrOperationFailed)
	}
	return copiedID, nil
}
