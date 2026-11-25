package tsm_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/C18519898242/go-mpc-sdk/tsm"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

func TestKeyTransferWireContract(t *testing.T) {
	for _, tc := range []struct {
		name, protocols, edEndpoint string
		players                     []string
		native                      bool
	}{
		{"mpc-node-api", `{"ecdsa":{"name":"cmp","version":1},"frost":{"name":"frost","version":1}}`, "frost", []string{"1", "3"}, true},
		{"builder-vault", `{"ecdsa":14,"schnorr":3}`, "schnorr", []string{"0", "2"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rsaDER := []byte("fixture DER")
			encryptedScalar, encryptedChain := []byte("wrapped share"), []byte("wrapped chain code")
			envelope, _ := json.Marshal(map[string]any{"version": 1, "wrappedKey": make([]byte, 256), "ciphertext": make([]byte, 28)})
			ecdsaPoint := secp256k1.PrivKeyFromBytes([]byte{9}).PubKey().SerializeUncompressed()
			wrongPoint := secp256k1.PrivKeyFromBytes([]byte{10}).PubKey().SerializeUncompressed()
			edPoint := bytes.Repeat([]byte{0x66}, 32)
			edPoint[0] = 0x58
			path := []uint32{0, 1}
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
				curve, variant, point := "secp256k1", "", ecdsaPoint
				if strings.HasPrefix(r.URL.Path, "/"+tc.edEndpoint+"/keys/") {
					curve, variant, point = "ED-25519", tsm.SchnorrEd25519, edPoint
				}
				if r.Method != http.MethodPost {
					t.Error("expected POST")
				}
				if strings.HasSuffix(r.URL.Path, "/publickey") {
					if !tc.native || r.Header.Get("MPC-SessionID") != "" || r.URL.RawQuery != "" {
						t.Error("unexpected public key lookup")
					}
					if strings.Contains(r.URL.Path, "/wrong-import/") {
						point = wrongPoint
					}
					if body, _ := io.ReadAll(r.Body); strings.Contains(r.URL.Path, "/source-key/") && string(body) != `{"chainPath":[0,1]}` {
						t.Error("expected derived public key")
					} else if !strings.Contains(r.URL.Path, "/source-key/") && string(body) != `{"chainPath":null}` {
						t.Error("expected imported root public key")
					}
					json.NewEncoder(w).Encode(map[string]any{"curve": curve, "schnorr_variant": variant, "publicKey": point})
					return
				}
				if !slices.Equal(r.Header.Values("MPC-Players"), tc.players) || r.Header.Get("MPC-SessionID") == "" ||
					r.Header.Get("MPC-RoutingID") == "" || r.URL.Query().Get("mpc_routing_id") != r.Header.Get("MPC-RoutingID") {
					t.Error("invalid MPC session metadata")
				}
				switch {
				case strings.HasSuffix(r.URL.Path, "/source-key/exportkey"), strings.HasSuffix(r.URL.Path, "/root-key/exportkey"):
					body, err := io.ReadAll(r.Body)
					var req struct {
						ChainPath   []uint32
						WrappingKey []byte
					}
					if err != nil || json.Unmarshal(body, &req) != nil || !bytes.Equal(req.WrappingKey, rsaDER) {
						t.Error("invalid export request")
					}
					if strings.Contains(r.URL.Path, "/root-key/") {
						if !bytes.Contains(body, []byte(`"chainPath":null`)) {
							t.Error("empty root path must have a canonical encoding")
						}
					} else if !slices.Equal(req.ChainPath, path) {
						t.Error("invalid export derivation path")
					}
					if tc.native {
						w.Write(envelope)
					} else {
						json.NewEncoder(w).Encode(map[string]any{"curve": curve, "schnorr_variant": variant, "publicKey": point,
							"wrappedKeyShare": encryptedScalar, "wrappedChainCode": encryptedChain})
					}
				case strings.HasSuffix(r.URL.Path, "/keys/importkey"):
					body, err := io.ReadAll(r.Body)
					var req struct {
						KeyID                          string
						Threshold                      int
						WrappedKeyShare                json.RawMessage
						KeyShare, ChainCode, PublicKey []byte
						Curve                          string
						Variant                        string `json:"schnorr_variant"`
					}
					if err != nil || json.Unmarshal(body, &req) != nil || req.Threshold != 1 {
						t.Error("invalid import request")
					}
					if (tc.native || variant == "") && bytes.Contains(body, []byte(`"schnorr_variant"`)) {
						t.Error("unexpected Schnorr variant field")
					}
					if tc.native {
						var got, want map[string]any
						if json.Unmarshal(req.WrappedKeyShare, &got) != nil || json.Unmarshal(envelope, &want) != nil ||
							len(got) != len(want) || got["version"] != want["version"] ||
							got["wrappedKey"] != want["wrappedKey"] || got["ciphertext"] != want["ciphertext"] ||
							req.KeyShare != nil || req.ChainCode != nil || req.PublicKey != nil {
							t.Error("native import requires the unmodified export envelope")
						}
					} else if req.WrappedKeyShare != nil || !bytes.Equal(req.KeyShare, encryptedScalar) ||
						!bytes.Equal(req.ChainCode, encryptedChain) || !bytes.Equal(req.PublicKey, point) || req.Curve != curve || req.Variant != variant {
						t.Error("invalid Builder Vault import request")
					}
					if req.KeyID == "" {
						req.KeyID = "generated-key"
					}
					json.NewEncoder(w).Encode(map[string]string{"keyID": req.KeyID})
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
			export := tsm.NewSessionConfig("export_session", []int{0, 2}, nil, nil)
			restore := tsm.NewSessionConfig("import_session", []int{0, 2}, nil, nil)
			ec, err := client.ECDSA().ExportKey(ctx, export, "source-key", path, rsaDER)
			if err != nil {
				t.Fatal(err)
			}
			if id, err := client.ECDSA().ImportKey(ctx, restore, 1, ec.WrappedKeyShare, ec.WrappedChainCode, ec.JSONPublicKey, "target-key"); err != nil || id != "target-key" {
				t.Fatalf("ECDSA import = %q, %v", id, err)
			}
			ed, err := client.Schnorr().ExportKey(ctx, export, "source-key", path, rsaDER)
			if err != nil {
				t.Fatal(err)
			}
			if id, err := client.Schnorr().ImportKey(ctx, restore, 1, ed.WrappedKeyShare, ed.WrappedChainCode, ed.JSONPublicKey, ""); err != nil || id != "generated-key" {
				t.Fatalf("Ed25519 import = %q, %v", id, err)
			}
			if tc.native {
				if _, err := client.ECDSA().ExportKey(ctx, export, "root-key", []uint32{}, rsaDER); err != nil {
					t.Fatal(err)
				}
				id, err := client.ECDSA().ImportKey(ctx, restore, 1, ec.WrappedKeyShare, nil, ec.JSONPublicKey, "wrong-import")
				if id != "wrong-import" || err == nil {
					t.Fatalf("mismatched imported public key = %q, %v", id, err)
				}
			}
		})
	}
}
