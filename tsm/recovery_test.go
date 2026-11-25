package tsm_test

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/C18519898242/go-mpc-sdk/tsm"
)

func TestGenerateRecoveryDataWireContract(t *testing.T) {
	publicKey := &rsa.PublicKey{N: new(big.Int).SetBit(big.NewInt(1), 4095, 1), E: 65537}
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, protocols, edEndpoint, operation string
		players                                []string
		native                                 bool
	}{
		{"mpc-node-api", `{"ecdsa":{"name":"cmp","version":1},"frost":{"name":"frost","version":1}}`, "frost", "recoverydata", []string{"1", "3"}, true},
		{"builder-vault", `{"ecdsa":14,"schnorr":3}`, "schnorr", "recoveryinfo", []string{"0", "2"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			label := []byte("wallet/test")
			const sid = "recovery_session"
			makePartial := func(algorithm, keyID string) []byte {
				data, _ := json.Marshal(map[string]any{
					"manifest": map[string]any{
						"version": 1, "algorithm": algorithm, "keyID": keyID,
						"sessionID": sid, "recoveryKey": der, "label": label,
					},
					"partyID": "1", "proof": map[string]string{"fixture": strings.Repeat("x", 96<<10)},
				})
				return data
			}
			vendorPartial := []byte(`{"version":"1","player_index":0,"threshold":1}`)
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
				route := strings.Split(r.URL.Path, "/")
				if len(route) != 5 || route[2] != "keys" || route[4] != tc.operation ||
					(route[1] != "ecdsa" && route[1] != tc.edEndpoint) {
					t.Errorf("unexpected path %s", r.URL.Path)
					http.NotFound(w, r)
					return
				}
				if r.Method != http.MethodPost || !slices.Equal(r.Header.Values("MPC-Players"), tc.players) ||
					r.Header.Get("MPC-SessionID") != sid || r.Header.Get("MPC-RoutingID") == "" ||
					r.URL.Query().Get("mpc_routing_id") != r.Header.Get("MPC-RoutingID") {
					t.Error("invalid recovery MPC session")
				}
				var req struct {
					RecoveryKey       []byte
					ERSPublicKey      *rsa.PublicKey
					Label             []byte
					OutputPlayerIndex *int
				}
				decoder := json.NewDecoder(r.Body)
				decoder.DisallowUnknownFields()
				if err := decoder.Decode(&req); err != nil || !bytes.Equal(req.Label, label) {
					t.Errorf("invalid recovery request label or body: %v", err)
				}
				if tc.native {
					if !bytes.Equal(req.RecoveryKey, der) || req.ERSPublicKey != nil || req.OutputPlayerIndex != nil {
						t.Error("invalid native RSA recovery key request")
					}
					if route[3] == "forbidden" {
						w.WriteHeader(http.StatusForbidden)
						return
					}
					keyID := route[3]
					if keyID == "bad-response" {
						keyID = "wrong-key"
					}
					w.Write(makePartial(route[1], keyID))
					return
				}
				if req.RecoveryKey != nil || req.ERSPublicKey == nil || !req.ERSPublicKey.Equal(publicKey) ||
					req.OutputPlayerIndex == nil || *req.OutputPlayerIndex != -1 {
					t.Error("invalid Builder Vault RSA recovery key request")
				}
				if route[3] == "bad-response" {
					io.WriteString(w, `{"recoveryInfos":[]}`)
					return
				}
				io.WriteString(w, `{"recoveryInfos":[`+string(vendorPartial)+`]}`)
			}))
			t.Cleanup(server.Close)
			client, err := tsm.NewClient(tsm.Configuration{URL: server.URL}.WithAPIKeyAuthentication("test-only"))
			if err != nil {
				t.Fatal(err)
			}
			session := tsm.NewSessionConfig(sid, []int{0, 2}, nil, nil)
			ctx := t.Context()
			for _, api := range []struct {
				algorithm string
				generate  func(context.Context, *tsm.SessionConfig, string, *rsa.PublicKey, []byte) ([]byte, error)
			}{
				{"ecdsa", client.ECDSA().GenerateRecoveryData},
				{tc.edEndpoint, client.Schnorr().GenerateRecoveryData},
			} {
				want := vendorPartial
				if tc.native {
					want = makePartial(api.algorithm, "my-key")
				}
				got, err := api.generate(ctx, session, "my-key", publicKey, label)
				if err != nil || !bytes.Equal(got, want) {
					t.Fatalf("recovery data round trip failed for %s: %v", api.algorithm, err)
				}
				if _, err := api.generate(ctx, session, "bad-response", publicKey, label); !errors.Is(err, tsm.ErrOperationFailed) {
					t.Fatalf("invalid recovery response error = %v", err)
				}
				if _, err := api.generate(ctx, session, "my-key", nil, label); !errors.Is(err, tsm.ErrInvalidInput) {
					t.Fatalf("missing RSA key error = %v", err)
				}
				if tc.native {
					if _, err := api.generate(ctx, session, "forbidden", publicKey, label); !errors.Is(err, tsm.ErrAccess) {
						t.Fatalf("disabled recovery error = %v", err)
					}
				}
			}
		})
	}
}
