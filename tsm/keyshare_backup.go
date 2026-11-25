package tsm

import (
	"context"
	"fmt"
	"net/http"
)

func (s *ecdsaService) ExportKeyShare(ctx context.Context, keyID string, includePresignatures bool, wrappingKey []byte) ([]byte, error) {
	return s.client.exportKeyShare(ctx, "/ecdsa/keys", keyID, includePresignatures, wrappingKey)
}

func (s *schnorrService) ExportKeyShare(ctx context.Context, keyID string, includePresignatures bool, wrappingKey []byte) ([]byte, error) {
	return s.client.exportKeyShare(ctx, s.path, keyID, includePresignatures, wrappingKey)
}

func (c *Client) exportKeyShare(ctx context.Context, endpoint, keyID string, includePresignatures bool, wrappingKey []byte) ([]byte, error) {
	if !keyIDPattern.MatchString(keyID) || len(wrappingKey) == 0 {
		return nil, fmt.Errorf("%w: share export needs a valid key ID and a wrapping public key", ErrInvalidInput)
	}
	path := endpoint + "/" + keyID + "/exportkeyshare"
	if c.native {
		if includePresignatures {
			return nil, fmt.Errorf("%w: mpc-node-api share backups only support includePresignatures=false", ErrInvalidInput)
		}
		request := struct {
			WrappingKey []byte `json:"wrappingKey"`
		}{wrappingKey}
		return c.requestWrappedKeyShare(ctx, path, nil, request)
	}
	request := struct {
		WrappingKey          []byte `json:"wrappingKey"`
		IncludePresignatures bool   `json:"includePresignatures"`
	}{wrappingKey, includePresignatures}
	var response struct {
		WrappedKeyShare []byte `json:"wrappedKeyShare"`
	}
	if err := c.requestWithLimit(ctx, http.MethodPost, path, nil, request, &response, maxKeyTransferResponse); err != nil {
		return nil, err
	}
	if len(response.WrappedKeyShare) == 0 {
		return nil, fmt.Errorf("%w: missing exported local share", ErrOperationFailed)
	}
	return response.WrappedKeyShare, nil
}

func (s *ecdsaService) ImportKeyShare(ctx context.Context, wrappedKeyShare []byte) (string, error) {
	return s.client.importKeyShare(ctx, "/ecdsa/keys", wrappedKeyShare)
}

func (s *schnorrService) ImportKeyShare(ctx context.Context, wrappedKeyShare []byte) (string, error) {
	return s.client.importKeyShare(ctx, s.path, wrappedKeyShare)
}

func (c *Client) importKeyShare(ctx context.Context, endpoint string, data []byte) (string, error) {
	path := endpoint + "/importkeyshare"
	if c.native {
		wrapped, ok := parseNativeWrappedKeyShare(data)
		if !ok {
			return "", fmt.Errorf("%w: expected an mpc-node-api wrapped key envelope", ErrInvalidInput)
		}
		request := struct {
			WrappedKeyShare nativeWrappedKeyShare `json:"wrappedKeyShare"`
		}{wrapped}
		return c.requestKeyID(ctx, path, nil, "", request)
	}
	if len(data) == 0 {
		return "", fmt.Errorf("%w: missing wrapped local key share", ErrInvalidInput)
	}
	request := struct {
		WrappedKeyShare []byte `json:"wrappedKeyShare"`
	}{data}
	return c.requestKeyID(ctx, path, nil, "", request)
}
