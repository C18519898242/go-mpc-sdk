package tsm

import (
	"context"
	"fmt"
	"net/http"
)

func (s *ecdsaService) GeneratePresignatures(ctx context.Context, session *SessionConfig, keyID string, count uint64) ([]string, error) {
	return s.client.generatePresignatures(ctx, "/ecdsa/keys", session, keyID, count)
}

func (s *schnorrService) GeneratePresignatures(ctx context.Context, session *SessionConfig, keyID string, count uint64) ([]string, error) {
	return s.client.generatePresignatures(ctx, s.path, session, keyID, count)
}

func (c *Client) generatePresignatures(ctx context.Context, endpoint string, session *SessionConfig, keyID string, count uint64) ([]string, error) {
	if !keyIDPattern.MatchString(keyID) || session == nil || len(session.players) < 2 || count == 0 {
		return nil, fmt.Errorf("%w: presignature generation needs a valid key ID, at least two players and a positive count", ErrInvalidInput)
	}
	var response struct {
		IDs []string `json:"ids"`
	}
	path := fmt.Sprintf("%s/%s/%d/presiggen", endpoint, keyID, count)
	if err := c.request(ctx, http.MethodPost, path, session, nil, &response); err != nil {
		return nil, err
	}
	if uint64(len(response.IDs)) != count {
		return nil, signatureError("incorrect number of presignature IDs returned")
	}
	seen := make(map[string]bool, len(response.IDs))
	for _, id := range response.IDs {
		if id == "" || seen[id] {
			return nil, signatureError("empty or duplicate presignature ID")
		}
		seen[id] = true
	}
	return response.IDs, nil
}

func (s *ecdsaService) SignWithPresignature(ctx context.Context, keyID, presignatureID string, path []uint32, digest []byte) (*ECDSAPartialSignResult, error) {
	if !s.client.validSigningDigest(digest) {
		return nil, fmt.Errorf("%w: invalid ECDSA digest length", ErrInvalidInput)
	}
	request := struct {
		ChainPath      []uint32 `json:"chainPath"`
		MessageHash    []byte   `json:"messageHash"`
		PresignatureID string   `json:"presignatureId"`
	}{path, digest, presignatureID}
	part, id, err := s.client.signWithPresignature(ctx, "/ecdsa/keys", "ECDSA", keyID, presignatureID, request)
	if err != nil {
		return nil, err
	}
	return &ECDSAPartialSignResult{id, part}, nil
}

func (s *schnorrService) SignWithPresignature(ctx context.Context, keyID, presignatureID string, path []uint32, message []byte) (*SchnorrPartialSignResult, error) {
	if message == nil {
		message = []byte{}
	}
	request := struct {
		ChainPath      []uint32 `json:"chainPath"`
		Message        []byte   `json:"message"`
		PresignatureID string   `json:"presignatureId"`
	}{path, message, presignatureID}
	part, id, err := s.client.signWithPresignature(ctx, s.path, SchnorrEd25519, keyID, presignatureID, request)
	if err != nil {
		return nil, err
	}
	return &SchnorrPartialSignResult{id, part}, nil
}

func (c *Client) signWithPresignature(ctx context.Context, endpoint, scheme, keyID, presignatureID string, request any) ([]byte, string, error) {
	if !keyIDPattern.MatchString(keyID) {
		return nil, "", fmt.Errorf("%w: invalid key ID", ErrInvalidInput)
	}
	part, id, err := c.requestSigningShare(ctx, endpoint+"/"+keyID+"/signwithpresig", scheme, nil, request)
	if err != nil {
		return nil, "", err
	}
	if id == "" && (c.native || presignatureID == "") {
		return nil, "", signatureError("missing presignature ID in signing response")
	}
	if id != "" && presignatureID != "" && id != presignatureID {
		return nil, "", signatureError("signing response has a different presignature ID")
	}
	return part, id, nil
}
