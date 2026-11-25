package tsm_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/C18519898242/go-mpc-sdk/tsm"
)

func TestWalletWireContract(t *testing.T) {
	configured := tsm.NewSessionConfig("configured_wallet", []int{2, 0, 1}, nil, nil)
	uploaded := tsm.NewStaticSessionConfig("uploaded_wallet", 3)
	keyFingerprint := strings.Repeat("a", 64)
	wrapped, ciphertext, aad := []byte("rsa ciphertext"), bytes.Repeat([]byte{7}, 32), []byte("authenticated metadata")
	manifest := json.RawMessage(`{"version":1,"players":["1","2","3"],"ecdsa":{},"frost":{}}`)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "APIKEY test-only" {
			t.Error("wallet request lost API Key authentication")
		}
		switch r.Method + " " + r.URL.Path {
		case "GET /version":
			io.WriteString(w, `{"version":"1"}`)
		case "GET /info/protocols":
			io.WriteString(w, `{"ecdsa":{"name":"cmp","version":1},"frost":{"name":"frost","version":1}}`)
		case "POST /wallets":
			routing := r.Header.Get("MPC-RoutingID")
			if routing == "" || r.URL.Query().Get("mpc_routing_id") != routing || r.Header.Get("Content-Type") != "application/json" ||
				!slices.Equal(r.Header.Values("MPC-Players"), []string{"1", "2", "3"}) {
				t.Error("invalid wallet MPC session")
			}
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Error(err)
			}
			switch r.Header.Get("MPC-SessionID") {
			case configured.SessionID():
				if string(body) != "{}" {
					t.Errorf("configured wallet request = %s", body)
				}
			case uploaded.SessionID():
				var req struct{ BackupPublicKeys map[string][]byte }
				if err := json.Unmarshal(body, &req); err != nil || len(req.BackupPublicKeys) != 3 ||
					string(req.BackupPublicKeys["1"]) != "first" || string(req.BackupPublicKeys["2"]) != "second" || string(req.BackupPublicKeys["3"]) != "third" {
					t.Error("wallet backup keys were not mapped to node party IDs")
				}
			case "unexpected_wallet":
				io.WriteString(w, `{"walletID":"wallet-a","ecdsaKeyID":"key-a"}`)
				return
			default:
				t.Error("unexpected wallet session")
			}
			io.WriteString(w, `{"walletID":"wallet-a","ecdsaKeyID":"key-a","frostKeyID":"key-b"}`)
		case "GET /wallets/wallet-a/backup", "GET /wallets/mismatched-wallet/backup":
			if r.URL.RawQuery != "" || r.Header.Get("MPC-SessionID") != "" || r.Header.Get("MPC-RoutingID") != "" ||
				len(r.Header.Values("MPC-Players")) != 0 {
				t.Error("wallet backup download must omit MPC session metadata")
			}
			if body, err := io.ReadAll(r.Body); err != nil || len(body) != 0 {
				t.Error("wallet backup request body must be empty")
			}
			json.NewEncoder(w).Encode(map[string]any{
				"walletID": "wallet-a", "formatVersion": 1, "applicationID": "wallet-app", "partyID": "2",
				"backupKeyID": keyFingerprint, "wrappedKey": wrapped, "ciphertext": ciphertext, "aad": aad, "manifest": manifest,
			})
		case "GET /wallets/other-app-wallet/backup":
			http.NotFound(w, r)
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	client, err := tsm.NewClient(tsm.Configuration{URL: server.URL}.WithAPIKeyAuthentication("test-only"))
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	keys := map[int][]byte{0: []byte("first"), 1: []byte("second"), 2: []byte("third")}
	for _, tc := range []struct {
		session *tsm.SessionConfig
		keys    map[int][]byte
	}{{configured, nil}, {uploaded, keys}} {
		wallet, err := client.CreateWallet(ctx, tc.session, tc.keys)
		if err != nil || wallet.WalletID != "wallet-a" || wallet.ECDSAKeyID != "key-a" || wallet.FROSTKeyID != "key-b" {
			t.Fatalf("create wallet: %+v, %v", wallet, err)
		}
	}
	if _, err := client.CreateWallet(ctx, tsm.NewStaticSessionConfig("two_players", 2), nil); !errors.Is(err, tsm.ErrInvalidInput) {
		t.Fatalf("create wallet with two players: %v", err)
	}
	if _, err := client.CreateWallet(ctx, uploaded, map[int][]byte{0: keys[0], 1: keys[1], 3: keys[2]}); !errors.Is(err, tsm.ErrInvalidInput) {
		t.Fatalf("create wallet with an unexpected backup player: %v", err)
	}
	if _, err := client.CreateWallet(ctx, tsm.NewStaticSessionConfig("unexpected_wallet", 3), nil); !errors.Is(err, tsm.ErrOperationFailed) {
		t.Fatalf("missing wallet response field: %v", err)
	}
	backup, err := client.GetWalletBackup(ctx, "wallet-a")
	if err != nil || backup.WalletID != "wallet-a" || backup.PartyID != "2" || backup.ApplicationID != "wallet-app" ||
		backup.FormatVersion != 1 || backup.BackupKeyID != keyFingerprint || !bytes.Equal(backup.WrappedKey, wrapped) ||
		!bytes.Equal(backup.Ciphertext, ciphertext) || !bytes.Equal(backup.AAD, aad) || !bytes.Equal(backup.Manifest, manifest) {
		t.Fatalf("download wallet backup: %v", err)
	}
	if _, err := client.GetWalletBackup(ctx, "mismatched-wallet"); !errors.Is(err, tsm.ErrOperationFailed) {
		t.Fatalf("mismatched wallet backup response: %v", err)
	}
	if _, err := client.GetWalletBackup(ctx, "other-app-wallet"); !errors.Is(err, tsm.ErrInvalidInput) {
		t.Fatalf("other application's wallet backup error = %v", err)
	}
}
