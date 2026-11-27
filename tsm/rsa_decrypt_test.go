package tsm

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"testing"

	thresholdrsa "github.com/C18519898242/circl/tss/rsa"
)

func TestRSADecryptAndFinalize(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	publicKey := &privateKey.PublicKey
	publicDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	message, label := []byte("threshold OAEP message"), []byte("sdk-test")
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, message, label)
	if err != nil {
		t.Fatal(err)
	}
	keyShares, err := thresholdrsa.Deal(rand.Reader, 3, 2, privateKey, false)
	if err != nil {
		t.Fatal(err)
	}

	var partials [][]byte
	for _, index := range []int{2, 0} {
		decrypter, err := thresholdrsa.NewOAEPDecrypter(publicKey, &keyShares[index])
		if err != nil {
			t.Fatal(err)
		}
		share, err := decrypter.DecryptShare(ciphertext)
		if err != nil {
			t.Fatal(err)
		}
		shareBytes, err := share.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		envelope := map[string]any{
			"format": "circl-rsa-oaep-sha256-v1", "keyID": "decrypt-key",
			"publicKey": publicDER, "players": 3, "threshold": 2,
			"ciphertext": ciphertext, "share": shareBytes,
		}
		var wrongKey atomic.Bool
		node := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/rsa/keys":
				var input struct {
					Bits, Threshold int
					KeyID, Usage    string
				}
				if r.TLS == nil || r.Method != http.MethodPost || r.Header.Get("Authorization") != "APIKEY fixture" ||
					r.Header.Get("MPC-SessionID") != "rsa-session" || !reflect.DeepEqual(r.Header.Values("MPC-Players"), []string{"1", "2", "3"}) ||
					json.NewDecoder(r.Body).Decode(&input) != nil || input.KeyID != "decrypt-key" || input.Bits != 2048 || input.Threshold != 1 || input.Usage != "decrypt" {
					t.Error("unexpected RSA decryption keygen request")
				}
				_, _ = w.Write([]byte(`{"keyID":"decrypt-key"}`))
			case "/rsa/keys/decrypt-key/decrypt":
				var input struct{ Ciphertext []byte }
				if r.TLS == nil || r.Method != http.MethodPost || r.Header.Get("Authorization") != "APIKEY fixture" ||
					r.Header.Get("MPC-SessionID") != "" || json.NewDecoder(r.Body).Decode(&input) != nil || !bytes.Equal(input.Ciphertext, ciphertext) {
					t.Error("unexpected RSA decryption request")
				}
				if wrongKey.Load() {
					envelope["keyID"] = "different-key"
				}
				encoded, err := json.Marshal(envelope)
				if err != nil {
					t.Errorf("encode RSA part: %v", err)
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				_ = json.NewEncoder(w).Encode(map[string][]byte{"partialDecryption": encoded})
			default:
				writeRSADecryptDiscovery(w, r, `{"rsa":{"name":"circl-tss-rsa","version":1}}`)
			}
		}))
		t.Cleanup(node.Close)
		root := filepath.Join(t.TempDir(), "node.pem")
		if err := os.WriteFile(root, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: node.Certificate().Raw}), 0o600); err != nil {
			t.Fatal(err)
		}
		client, err := NewClient(Configuration{URL: node.URL}.WithRSADecryptionAuthentication("fixture").WithRootCAFile(root))
		if err != nil {
			t.Fatal(err)
		}
		ordinary, err := NewClient(Configuration{URL: node.URL}.WithAPIKeyAuthentication("fixture").WithRootCAFile(root))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(ordinary.http.CloseIdleConnections)
		if _, err := ordinary.RSA().Decrypt(t.Context(), "decrypt-key", ciphertext); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("Decrypt with ordinary authentication returned %v", err)
		}
		session := NewStaticSessionConfig("rsa-session", 3)
		if id, err := client.RSA().GenerateDecryptionKey(t.Context(), session, 1, 2048, "decrypt-key"); err != nil || id != "decrypt-key" {
			t.Fatalf("GenerateDecryptionKey returned (%q, %v)", id, err)
		}
		part, err := client.RSA().Decrypt(t.Context(), "decrypt-key", ciphertext)
		if err != nil {
			t.Fatal(err)
		}
		partials = append(partials, part)
		wrongKey.Store(true)
		if _, err := client.RSA().Decrypt(t.Context(), "decrypt-key", ciphertext); !errors.Is(err, ErrOperationFailed) {
			t.Fatalf("Decrypt returned %v for an envelope bound to a different key", err)
		}
	}

	plaintext, err := RSAFinalizeDecryptionOAEP(HashFunctionSHA256, label, partials)
	if err != nil || !bytes.Equal(plaintext, message) {
		t.Fatalf("RSAFinalizeDecryptionOAEP returned (%q, %v)", plaintext, err)
	}
	var aliased map[string]json.RawMessage
	if err := json.Unmarshal(partials[1], &aliased); err != nil {
		t.Fatal(err)
	}
	aliased["keyID"] = json.RawMessage(`"different-key"`)
	aliasedPart, err := json.Marshal(aliased)
	if err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		label    []byte
		partials [][]byte
	}{
		"insufficient": {label, partials[:1]},
		"duplicate":    {label, [][]byte{partials[0], partials[0]}},
		"wrong label":  {nil, partials},
		"malformed":    {label, [][]byte{partials[0], []byte(`{"format":"circl-rsa-oaep-sha256-v1"}`)}},
		"mixed key ID": {label, [][]byte{partials[0], aliasedPart}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := RSAFinalizeDecryptionOAEP("SHA256", tc.label, tc.partials); !errors.Is(err, rsa.ErrDecryption) {
				t.Fatalf("RSAFinalizeDecryptionOAEP returned %v", err)
			}
		})
	}
	if _, err := RSAFinalizeDecryptionOAEP("SHA512", label, partials); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("unsupported hash returned %v", err)
	}
}

func TestRSADecryptionRejectsHTTP(t *testing.T) {
	node := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/version" && r.URL.Path != "/info/protocols" {
			t.Errorf("unexpected RSA request over HTTP: %s %s", r.Method, r.URL.Path)
		}
		writeRSADecryptDiscovery(w, r, `{"rsa":{"name":"circl-tss-rsa","version":1}}`)
	}))
	t.Cleanup(node.Close)
	client, err := NewClient(Configuration{URL: node.URL}.WithAPIKeyAuthentication("fixture"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.RSA().Decrypt(t.Context(), "decrypt-key", make([]byte, 256)); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("Decrypt over HTTP returned %v", err)
	}
	session := NewStaticSessionConfig("rsa-session", 3)
	if _, err := client.RSA().GenerateDecryptionKey(t.Context(), session, 1, 2048, "decrypt-key"); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("GenerateDecryptionKey over HTTP returned %v", err)
	}
}

func TestDecryptionAuthenticationRejectsHTTPBeforeDiscovery(t *testing.T) {
	node := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected discovery request over HTTP: %s", r.URL.Path)
		http.NotFound(w, r)
	}))
	t.Cleanup(node.Close)
	if _, err := NewClient(Configuration{URL: node.URL}.WithRSADecryptionAuthentication("fixture")); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("HTTP node returned %v", err)
	}
}

func TestDecryptionAuthenticationUsesDirectTLS(t *testing.T) {
	node := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeRSADecryptDiscovery(w, r, `{"rsa":{"name":"circl-tss-rsa","version":1}}`)
	}))
	t.Cleanup(node.Close)
	root := filepath.Join(t.TempDir(), "node.pem")
	if err := os.WriteFile(root, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: node.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	original := http.DefaultTransport
	transport := &http.Transport{
		Proxy: func(*http.Request) (*url.URL, error) {
			return nil, errors.New("test default proxy was consulted")
		},
	}
	http.DefaultTransport = transport
	t.Cleanup(func() { http.DefaultTransport = original })
	cfg := Configuration{URL: node.URL}
	client, err := NewClient(cfg.WithRSADecryptionAuthentication("fixture").WithRootCAFile(root))
	if err != nil {
		t.Fatalf("decryption client could not connect directly: %v", err)
	}
	t.Cleanup(client.http.CloseIdleConnections)
	if _, err := NewClient(cfg.WithAPIKeyAuthentication("fixture").WithRootCAFile(root)); err == nil {
		t.Fatal("ordinary client bypassed the default transport proxy")
	}
}

func writeRSADecryptDiscovery(w http.ResponseWriter, r *http.Request, protocols string) {
	switch r.URL.Path {
	case "/version":
		_, _ = w.Write([]byte(`{"version":"1"}`))
	case "/info/protocols":
		_, _ = w.Write([]byte(protocols))
	default:
		http.NotFound(w, r)
	}
}
