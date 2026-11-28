package tsm

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"sync/atomic"
	"testing"
)

func TestRSAExportKeyWireContract(t *testing.T) {
	wrappingKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	wrappingDER, err := x509.MarshalPKIXPublicKey(&wrappingKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	sourceKey := rsaImportTestKey(t)
	players := []int{1, 9}
	shares, err := RSASecretShare(1, players, sourceKey)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := RSAWrapKeyShare(wrappingDER, shares[9])
	if err != nil {
		t.Fatal(err)
	}
	sourcePubDER, err := x509.MarshalPKIXPublicKey(&sourceKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	// Non-native (Builder Vault) backend must reject RSA ExportKey in v1.
	bvServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeRSADecryptDiscovery(w, r, `{"rsa":12}`)
	}))
	t.Cleanup(bvServer.Close)
	bvClient, err := NewClient(Configuration{URL: bvServer.URL}.WithAPIKeyAuthentication("fixture"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bvClient.RSA().ExportKey(t.Context(), NewSessionConfig("bv-export", players, nil, nil), "src", wrappingDER); !errors.Is(err, ErrOperationFailed) {
		t.Fatalf("Builder Vault ExportKey returned %v, want ErrOperationFailed", err)
	}

	// Plaintext HTTP native client must refuse ExportKey before sending any request.
	plainServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/rsa/keys/src/exportkey" {
			t.Error("sent RSA export over plaintext HTTP")
		}
		writeRSADecryptDiscovery(w, r, `{"rsa":{"name":"circl-tss-rsa","version":1}}`)
	}))
	t.Cleanup(plainServer.Close)
	plainClient, err := NewClient(Configuration{URL: plainServer.URL}.WithAPIKeyAuthentication("fixture"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := plainClient.RSA().ExportKey(t.Context(), NewSessionConfig("plain-export", players, nil, nil), "src", wrappingDER); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("plaintext HTTP ExportKey returned %v, want ErrInvalidInput", err)
	}

	var corruptEnvelope, badPubKey atomic.Bool
	node := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/rsa/keys/src-key/exportkey", "/rsa/keys/_/exportkey":
			var req struct {
				WrappingKey []byte `json:"wrappingKey"`
			}
			if r.Method != http.MethodPost || r.TLS == nil || r.Header.Get("Authorization") != "APIKEY fixture" ||
				r.Header.Get("MPC-SessionID") != "rsa-export-sess" ||
				r.Header.Get("MPC-RoutingID") != r.URL.Query().Get("mpc_routing_id") ||
				!slices.Equal(r.Header.Values("MPC-Players"), []string{"2", "10"}) ||
				json.NewDecoder(r.Body).Decode(&req) != nil || !bytes.Equal(req.WrappingKey, wrappingDER) {
				t.Error("unexpected RSA export request")
				http.Error(w, "bad export request", http.StatusBadRequest)
				return
			}
			wrapped := bundle
			pub := sourcePubDER
			if corruptEnvelope.Load() {
				wrapped = []byte(`{"version":1}`)
			}
			if badPubKey.Load() {
				pub = []byte("not-der")
			}
			_ = json.NewEncoder(w).Encode(map[string][]byte{
				"wrappedKeyShare": wrapped,
				"publicKey":       pub,
			})
		case "/rsa/keys/importkey":
			var req struct {
				KeyID           string `json:"keyID"`
				WrappedKeyShare []byte `json:"wrappedKeyShare"`
			}
			if r.Method != http.MethodPost || json.NewDecoder(r.Body).Decode(&req) != nil ||
				!bytes.Equal(req.WrappedKeyShare, bundle) || req.KeyID != "dst-key" {
				t.Error("unexpected RSA import request after export")
				http.Error(w, "bad import request", http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"keyID": req.KeyID})
		default:
			writeRSADecryptDiscovery(w, r, `{"rsa":{"name":"circl-tss-rsa","version":1}}`)
		}
	}))
	t.Cleanup(node.Close)
	root := filepath.Join(t.TempDir(), "node.pem")
	if err := os.WriteFile(root, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: node.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	client, err := NewClient(Configuration{URL: node.URL}.WithHTTPSAuthentication("fixture").WithRootCAFile(root))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.http.CloseIdleConnections)

	session := NewSessionConfig("rsa-export-sess", players, nil, nil)
	exported, err := client.RSA().ExportKey(t.Context(), session, "src-key", wrappingDER)
	if err != nil {
		t.Fatalf("ExportKey failed: %v", err)
	}
	if !bytes.Equal(exported.WrappedKeyShare, bundle) || !bytes.Equal(exported.PKIXPublicKey, sourcePubDER) {
		t.Fatal("ExportKey returned unexpected payload or public key")
	}
	if importedID, err := client.RSA().ImportKey(t.Context(), NewSessionConfig("rsa-import-sess", players, nil, nil), exported.WrappedKeyShare, "dst-key"); err != nil || importedID != "dst-key" {
		t.Fatalf("ImportKey with exported share returned (%q, %v)", importedID, err)
	}
	if underscoreExport, err := client.RSA().ExportKey(t.Context(), session, "_", wrappingDER); err != nil ||
		!bytes.Equal(underscoreExport.WrappedKeyShare, bundle) || !bytes.Equal(underscoreExport.PKIXPublicKey, sourcePubDER) {
		t.Fatalf("ExportKey for keyID _ failed: %v", err)
	}

	smallKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	smallDER, _ := x509.MarshalPKIXPublicKey(&smallKey.PublicKey)
	for name, call := range map[string]func() error{
		"nil session":        func() error { _, e := client.RSA().ExportKey(t.Context(), nil, "src-key", wrappingDER); return e },
		"single player":      func() error { _, e := client.RSA().ExportKey(t.Context(), NewStaticSessionConfig("s", 1), "src-key", wrappingDER); return e },
		"invalid keyID":      func() error { _, e := client.RSA().ExportKey(t.Context(), session, "bad/id", wrappingDER); return e },
		"invalid wrap key":   func() error { _, e := client.RSA().ExportKey(t.Context(), session, "src-key", []byte("bad")); return e },
		"small wrapping key": func() error { _, e := client.RSA().ExportKey(t.Context(), session, "src-key", smallDER); return e },
	} {
		if err := call(); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("%s returned %v, want ErrInvalidInput", name, err)
		}
	}

	corruptEnvelope.Store(true)
	if _, err := client.RSA().ExportKey(t.Context(), session, "src-key", wrappingDER); !errors.Is(err, ErrOperationFailed) {
		t.Fatalf("corrupt envelope returned %v, want ErrOperationFailed", err)
	}
	corruptEnvelope.Store(false)
	badPubKey.Store(true)
	if _, err := client.RSA().ExportKey(t.Context(), session, "src-key", wrappingDER); !errors.Is(err, ErrOperationFailed) {
		t.Fatalf("invalid public key returned %v, want ErrOperationFailed", err)
	}
}
