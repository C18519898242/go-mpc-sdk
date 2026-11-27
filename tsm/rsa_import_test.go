package tsm

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"testing"

	thresholdrsa "github.com/C18519898242/circl/tss/rsa"
)

func TestRSAImportRejectsOrdinaryKeyAndPlaintextTransport(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := RSASecretShare(1, []int{0, 1, 2}, key); err == nil {
		t.Fatal("accepted an RSA key without safe primes")
	}

	node := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/rsa/keys/importkey" {
			t.Error("sent an import request over plaintext HTTP")
		}
		writeRSADecryptDiscovery(w, r, `{"rsa":{"name":"circl-tss-rsa","version":1}}`)
	}))
	t.Cleanup(node.Close)
	client, err := NewClient(Configuration{URL: node.URL}.WithAPIKeyAuthentication("fixture"))
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := json.Marshal(nativeWrappedKeyShare{
		Version: 1, WrappedKey: bytes.Repeat([]byte{1}, 256), Ciphertext: bytes.Repeat([]byte{2}, 40),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.RSA().ImportKey(t.Context(), NewStaticSessionConfig("test-import", 3), wrapped, "imported"); err == nil {
		t.Fatal("allowed RSA import over plaintext HTTP")
	}
}

func TestHTTPSAuthenticationRejectsHTTPBeforeDiscovery(t *testing.T) {
	node := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("HTTPS-only client sent an HTTP discovery request")
		http.NotFound(w, r)
	}))
	t.Cleanup(node.Close)
	if _, err := NewClient(Configuration{URL: node.URL}.WithHTTPSAuthentication("fixture")); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("plaintext discovery returned %v", err)
	}
}

func TestRSAImportHTTPSContract(t *testing.T) {
	key := rsaImportTestKey(t)
	players := []int{1, 9}
	shares, err := RSASecretShare(1, players, key)
	if err != nil {
		t.Fatal(err)
	}
	for i, player := range []int{9, 1} {
		var part rsaImportShare
		var decoded thresholdrsa.KeyShare
		if err := json.Unmarshal(shares[player], &part); err != nil {
			t.Fatal(err)
		}
		if err := decoded.UnmarshalBinary(part.Share); err != nil || decoded.Index != uint(i+1) ||
			decoded.Players != 2 || decoded.Threshold != 2 || !slices.Equal(part.Players, []string{"10", "2"}) {
			t.Fatalf("unexpected share roster or index: %v", err)
		}
	}
	wrappingKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	wrappingDER, err := x509.MarshalPKIXPublicKey(&wrappingKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := RSAWrapKeyShare(wrappingDER, make([]byte, rsaImportMaxBody/2+1)); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("oversized plaintext share returned %v", err)
	}
	bundle, err := RSAWrapKeyShare(wrappingDER, shares[9])
	if err != nil {
		t.Fatal(err)
	}
	envelope, ok := parseNativeWrappedKeyShare(bundle)
	if !ok {
		t.Fatal("invalid wrapping envelope")
	}
	label := []byte("mpc-node-api/key-transfer/v1")
	secret, err := rsa.DecryptOAEP(sha256.New(), nil, wrappingKey, envelope.WrappedKey, label)
	if err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(secret)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := aead.Open(nil, nil, envelope.Ciphertext, label)
	if err != nil || !bytes.Equal(plaintext, shares[9]) {
		t.Fatalf("could not unwrap original share: %v", err)
	}

	node := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/rsa/keys/importkey" {
			writeRSADecryptDiscovery(w, r, `{"rsa":{"name":"circl-tss-rsa","version":1}}`)
			return
		}
		var request struct {
			KeyID           string `json:"keyID"`
			WrappedKeyShare []byte `json:"wrappedKeyShare"`
		}
		if r.Method != http.MethodPost || r.TLS == nil || r.Header.Get("Authorization") != "APIKEY fixture" ||
			r.Header.Get("MPC-SessionID") != "rsa-import-fixture" || !slices.Equal(r.Header.Values("MPC-Players"), []string{"2", "10"}) ||
			json.NewDecoder(r.Body).Decode(&request) != nil || !bytes.Equal(request.WrappedKeyShare, bundle) {
			t.Error("invalid RSA import request")
			http.Error(w, "invalid fixture request", http.StatusBadRequest)
			return
		}
		if request.KeyID == "" {
			request.KeyID = "generated"
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"keyID": request.KeyID})
	}))
	t.Cleanup(node.Close)
	root := filepath.Join(t.TempDir(), "node.pem")
	if err := os.WriteFile(root, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: node.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	original := http.DefaultTransport
	http.DefaultTransport = &http.Transport{Proxy: func(*http.Request) (*url.URL, error) {
		return nil, errors.New("environment proxy was consulted")
	}}
	t.Cleanup(func() { http.DefaultTransport = original })
	client, err := NewClient(Configuration{URL: node.URL}.WithHTTPSAuthentication("fixture").WithRootCAFile(root))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.http.CloseIdleConnections)
	session := NewSessionConfig("rsa-import-fixture", players, nil, nil)
	if _, err := client.RSA().ImportKey(t.Context(), NewStaticSessionConfig("single-player", 1), bundle, ""); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("single-player import returned %v", err)
	}
	for _, desired := range []string{"specified", ""} {
		want := desired
		if want == "" {
			want = "generated"
		}
		if got, err := client.RSA().ImportKey(t.Context(), session, bundle, desired); err != nil || got != want {
			t.Fatalf("ImportKey returned %q, %v", got, err)
		}
	}
}

// The fixture uses public 1024-bit primes from RFC 2409 §6.2 and RFC 5054 Appendix A.
func rsaImportTestKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	p, okP := new(big.Int).SetString("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"+
		"020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"+
		"4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"+
		"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF", 16)
	q, okQ := new(big.Int).SetString("EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C9C256576"+
		"D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE48E495C1D6089DAD1"+
		"5DC7D7B46154D6B6CE8EF4AD69B15D4982559B297BCF1885C529F566660E57EC"+
		"68EDBC3C05726CC02FD4CBF4976EAA9AFD5138FE8376435B9FC61D2FC0EB06E3", 16)
	if !okP || !okQ {
		t.Fatal("invalid public prime fixture")
	}
	one := big.NewInt(1)
	phi := new(big.Int).Mul(new(big.Int).Sub(p, one), new(big.Int).Sub(q, one))
	key := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{N: new(big.Int).Mul(p, q), E: 65537},
		D:         new(big.Int).ModInverse(big.NewInt(65537), phi), Primes: []*big.Int{p, q},
	}
	if err := key.Validate(); err != nil {
		t.Fatal(err)
	}
	return key
}
