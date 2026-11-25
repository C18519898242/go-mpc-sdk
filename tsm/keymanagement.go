package tsm

import (
	"context"
	"fmt"
	"net/http"
)

// KeyManagementAPI manages data on the connected node without an MPC session.
type KeyManagementAPI interface {
	// DeleteKeyShare deletes the key's local shares and associated presignatures
	// in the application authenticated by this client.
	DeleteKeyShare(ctx context.Context, keyID string) error
	// CountPresignatures returns the number of available local presignatures for the key.
	CountPresignatures(ctx context.Context, keyID string) (int, error)
	// DeletePresignatures deletes all available local presignatures for the key.
	DeletePresignatures(ctx context.Context, keyID string) error
}

// KeyManagement returns the key management service for this node.
func (c *Client) KeyManagement() KeyManagementAPI {
	return &keyManagementService{client: c}
}

type keyManagementService struct{ client *Client }

func (s *keyManagementService) DeleteKeyShare(ctx context.Context, keyID string) error {
	if !keyIDPattern.MatchString(keyID) {
		return fmt.Errorf("%w: invalid key ID", ErrInvalidInput)
	}
	return s.client.request(ctx, http.MethodDelete, "/key/"+keyID, nil, nil, nil)
}

func (s *keyManagementService) CountPresignatures(ctx context.Context, keyID string) (int, error) {
	if !keyIDPattern.MatchString(keyID) {
		return 0, fmt.Errorf("%w: invalid key ID", ErrInvalidInput)
	}
	var count *int
	if err := s.client.request(ctx, http.MethodPost, "/key/"+keyID+"/count/presigs", nil, struct{}{}, &count); err != nil {
		return 0, err
	}
	if count == nil || *count < 0 {
		return 0, fmt.Errorf("%w: invalid presignature count", ErrOperationFailed)
	}
	return *count, nil
}

func (s *keyManagementService) DeletePresignatures(ctx context.Context, keyID string) error {
	if !keyIDPattern.MatchString(keyID) {
		return fmt.Errorf("%w: invalid key ID", ErrInvalidInput)
	}
	return s.client.request(ctx, http.MethodDelete, "/key/"+keyID+"/presigs", nil, nil, nil)
}
