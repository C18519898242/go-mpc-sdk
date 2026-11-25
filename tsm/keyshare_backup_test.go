package tsm_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/C18519898242/go-mpc-sdk/tsm"
)

func TestLocalKeyShareBackupWireContract(t *testing.T) {
	type wrapped struct {
		Version    int    `json:"version"`
		WrappedKey []byte `json:"wrappedKey"`
		Ciphertext []byte `json:"ciphertext"`
	}
	nativeEnvelope := wrapped{1, make([]byte, 384), bytes.Repeat([]byte{1}, 70<<10)}
	nativePayload, _ := json.Marshal(nativeEnvelope)
	builderPayload := []byte("encrypted Builder Vault share")
	rsaDER := []byte("test RSA SPKI")
	for _, tc := range []struct {
		name, protocols, edBase string
		native                  bool
	}{
		{"mpc-node-api", `{"ecdsa":{"name":"cmp","version":1},"frost":{"name":"frost","version":1}}`, "/frost/keys", true},
		{"Builder Vault", `{"ecdsa":14,"schnorr":3}`, "/schnorr/keys", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "APIKEY test-only" || r.Header.Get("MPC-SessionID") != "" ||
					r.Header.Get("MPC-RoutingID") != "" || len(r.Header.Values("MPC-Players")) != 0 || r.URL.RawQuery != "" {
					t.Error("expected an authenticated request without MPC session metadata")
				}
				switch r.URL.Path {
				case "/version":
					io.WriteString(w, `{"version":"1"}`)
					return
				case "/info/protocols":
					io.WriteString(w, tc.protocols)
					return
				}
				if r.Method != http.MethodPost {
					t.Error("expected POST")
				}
				switch r.URL.Path {
				case "/ecdsa/keys/source-key/exportkeyshare", tc.edBase + "/source-key/exportkeyshare":
					var req struct {
						WrappingKey          []byte
						IncludePresignatures *bool
					}
					decoder := json.NewDecoder(r.Body)
					decoder.DisallowUnknownFields()
					if err := decoder.Decode(&req); err != nil || !bytes.Equal(req.WrappingKey, rsaDER) {
						t.Error("invalid local backup request")
					}
					if tc.native {
						if req.IncludePresignatures != nil {
							t.Error("native request must omit includePresignatures")
						}
						w.Write(nativePayload)
					} else {
						if req.IncludePresignatures == nil || !*req.IncludePresignatures {
							t.Error("Builder Vault presignature option missing")
						}
						json.NewEncoder(w).Encode(map[string][]byte{"wrappedKeyShare": builderPayload})
					}
				case "/ecdsa/keys/importkeyshare", tc.edBase + "/importkeyshare":
					var req struct{ WrappedKeyShare json.RawMessage }
					decoder := json.NewDecoder(r.Body)
					decoder.DisallowUnknownFields()
					if err := decoder.Decode(&req); err != nil {
						t.Errorf("invalid local restore request: %v", err)
					}
					if tc.native {
						if !bytes.Equal(req.WrappedKeyShare, nativePayload) {
							t.Error("wrong native encrypted envelope")
						}
					} else {
						var data []byte
						if err := json.Unmarshal(req.WrappedKeyShare, &data); err != nil || !bytes.Equal(data, builderPayload) {
							t.Error("wrong Builder Vault encrypted share")
						}
					}
					io.WriteString(w, `{"keyID":"source-key"}`)
				default:
					t.Errorf("unexpected route %s", r.URL.Path)
					http.NotFound(w, r)
				}
			}))
			t.Cleanup(server.Close)
			client, err := tsm.NewClient(tsm.Configuration{URL: server.URL}.WithAPIKeyAuthentication("test-only"))
			if err != nil {
				t.Fatal(err)
			}
			ctx := t.Context()
			want := builderPayload
			if tc.native {
				want = nativePayload
			}
			for _, api := range []struct {
				exportShare func(context.Context, string, bool, []byte) ([]byte, error)
				importShare func(context.Context, []byte) (string, error)
			}{
				{client.ECDSA().ExportKeyShare, client.ECDSA().ImportKeyShare},
				{client.Schnorr().ExportKeyShare, client.Schnorr().ImportKeyShare},
			} {
				if tc.native {
					if _, err := api.exportShare(ctx, "source-key", true, rsaDER); !errors.Is(err, tsm.ErrInvalidInput) {
						t.Fatalf("native presignature export error = %v", err)
					}
					if _, err := api.importShare(ctx, builderPayload); !errors.Is(err, tsm.ErrInvalidInput) {
						t.Fatalf("invalid native envelope error = %v", err)
					}
				}
				data, err := api.exportShare(ctx, "source-key", !tc.native, rsaDER)
				if err != nil || !bytes.Equal(data, want) {
					t.Fatalf("local export failed: %v", err)
				}
				if id, err := api.importShare(ctx, data); err != nil || id != "source-key" {
					t.Fatalf("local restore = %q, %v", id, err)
				}
				if _, err := api.exportShare(ctx, strings.Repeat("a", 29), false, rsaDER); !errors.Is(err, tsm.ErrInvalidInput) {
					t.Fatalf("invalid key ID error = %v", err)
				}
			}
		})
	}
}
