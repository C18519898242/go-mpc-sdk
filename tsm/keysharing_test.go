package tsm_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/C18519898242/go-mpc-sdk/tsm"
)

func TestReshareAndCopyWireContract(t *testing.T) {
	for _, tc := range []struct {
		name, edEndpoint, protocols string
		players                     []string
	}{
		{"mpc-node-api", "frost", `{"ecdsa":{"name":"cmp","version":1},"frost":{"name":"frost","version":1}}`, []string{"1", "2", "3"}},
		{"builder-vault", "schnorr", `{"ecdsa":14,"schnorr":3}`, []string{"0", "1", "2"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			edBase := "/" + tc.edEndpoint + "/keys"
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "APIKEY test-only" {
					t.Error("API Key header missing")
				}
				switch r.URL.Path {
				case "/version":
					io.WriteString(w, `{"version":"1"}`)
					return
				case "/info/protocols":
					io.WriteString(w, tc.protocols)
					return
				}
				if r.Method != http.MethodPost || r.Header.Get("MPC-SessionID") != "key_sharing" ||
					r.Header.Get("MPC-RoutingID") == "" || r.URL.Query().Get("mpc_routing_id") != r.Header.Get("MPC-RoutingID") ||
					!slices.Equal(r.Header.Values("MPC-Players"), tc.players) {
					t.Error("invalid MPC session metadata")
				}
				curve, variant := "", ""
				switch r.URL.Path {
				case "/ecdsa/keys/source-key/reshare", edBase + "/source-key/reshare":
					if body, err := io.ReadAll(r.Body); err != nil || len(body) != 0 {
						t.Error("reshare request must have an empty body")
					}
					w.WriteHeader(http.StatusNoContent)
					return
				case "/ecdsa/keys/source-key/keycopy", edBase + "/source-key/keycopy":
				case "/ecdsa/keys/_/keycopy":
					curve = "secp256k1"
				case edBase + "/_/keycopy":
					curve, variant = "ED-25519", tsm.SchnorrEd25519
				default:
					t.Errorf("unexpected request %s", r.URL.Path)
					http.NotFound(w, r)
					return
				}
				var req struct {
					KeyID     string `json:"keyID"`
					Threshold int    `json:"threshold"`
					Curve     string `json:"curve"`
					Variant   string `json:"schnorr_variant"`
				}
				if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Threshold != 2 ||
					req.Curve != curve || req.Variant != variant || (req.KeyID != "" && req.KeyID != "target-key") {
					t.Errorf("invalid copy request: %+v, %v", req, err)
				}
				if req.KeyID == "" {
					req.KeyID = "generated-key"
				}
				json.NewEncoder(w).Encode(map[string]string{"keyID": req.KeyID})
			}))
			t.Cleanup(server.Close)
			client, err := tsm.NewClient(tsm.Configuration{URL: server.URL}.WithAPIKeyAuthentication("test-only"))
			if err != nil {
				t.Fatal(err)
			}
			ctx := t.Context()
			session := tsm.NewStaticSessionConfig("key_sharing", 3)
			for _, scheme := range []struct {
				name      string
				reshare   func(context.Context, *tsm.SessionConfig, string) error
				copyKey   func(context.Context, *tsm.SessionConfig, string, string, int, string) (string, error)
				algorithm string
			}{
				{"ecdsa", client.ECDSA().Reshare, client.ECDSA().CopyKey, "secp256k1"},
				{"ed25519", client.Schnorr().Reshare, client.Schnorr().CopyKey, tsm.SchnorrEd25519},
			} {
				t.Run(scheme.name, func(t *testing.T) {
					if err := scheme.reshare(ctx, session, "source-key"); err != nil {
						t.Fatal(err)
					}
					if id, err := scheme.copyKey(ctx, session, "source-key", "", 2, "target-key"); err != nil || id != "target-key" {
						t.Fatalf("copy from existing share = %q, %v", id, err)
					}
					if id, err := scheme.copyKey(ctx, session, "", scheme.algorithm, 2, ""); err != nil || id != "generated-key" {
						t.Fatalf("copy to new holder = %q, %v", id, err)
					}
					if _, err := scheme.copyKey(ctx, session, "source-key", "", 2, "source-key"); !errors.Is(err, tsm.ErrInvalidInput) {
						t.Fatalf("copy with same target ID: %v", err)
					}
					if _, err := scheme.copyKey(ctx, session, "source-key", "", 3, "target-key"); !errors.Is(err, tsm.ErrInvalidInput) {
						t.Fatalf("copy with invalid threshold: %v", err)
					}
					if err := scheme.reshare(ctx, nil, "source-key"); !errors.Is(err, tsm.ErrInvalidInput) {
						t.Fatalf("reshare without a session: %v", err)
					}
				})
			}
		})
	}
}
