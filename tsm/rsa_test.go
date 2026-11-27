package tsm

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	thresholdrsa "github.com/cloudflare/circl/tss/rsa"
)

func TestRSAGenerateKeyWireContract(t *testing.T) {
	requests := make(chan struct{}, 2)
	node := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/version":
			_, _ = w.Write([]byte(`{"version":"1"}`))
		case "/info/protocols":
			_, _ = w.Write([]byte(`{"rsa":{"name":"circl-tss-rsa","version":1}}`))
		case "/rsa/keys":
			requests <- struct{}{}
			var body struct {
				Threshold, Bits int
				KeyID           string
			}
			if r.Method != http.MethodPost || json.NewDecoder(r.Body).Decode(&body) != nil || body.Threshold != 1 || body.Bits != 2048 || body.KeyID != "test-rsa" {
				t.Error("unexpected RSA keygen request")
			}
			if r.Header.Get("Authorization") != "APIKEY fixture" || r.Header.Get("MPC-SessionID") != "rsa-session" || !reflect.DeepEqual(r.Header.Values("MPC-Players"), []string{"1", "2", "3"}) {
				t.Error("unexpected RSA keygen authentication or session")
			}
			_, _ = w.Write([]byte(`{"keyID":"test-rsa"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(node.Close)
	client, err := NewClient(Configuration{URL: node.URL}.WithAPIKeyAuthentication("fixture"))
	if err != nil {
		t.Fatal(err)
	}
	session := NewStaticSessionConfig("rsa-session", 3)
	if id, err := client.RSA().GenerateKey(t.Context(), session, 1, 2048, "test-rsa"); err != nil || id != "test-rsa" {
		t.Fatalf("GenerateKey returned (%q, %v)", id, err)
	}
	if _, err := client.RSA().GenerateKey(t.Context(), session, 1, 1024, "test-rsa"); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("invalid key size returned %v", err)
	}
	if len(requests) != 1 {
		t.Fatalf("got %d RSA HTTP requests, want one", len(requests))
	}
}

func TestRSASignAndFinalize(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	shares, err := thresholdrsa.Deal(rand.Reader, 3, 2, privateKey, false)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("RSA signing test"))
	padded, err := (thresholdrsa.PKCS1v15Padder{}).Pad(&privateKey.PublicKey, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	var partials [][]byte
	var key *RSAPublicKey
	for _, index := range []int{2, 0} {
		share, err := shares[index].Sign(rand.Reader, &privateKey.PublicKey, padded, true)
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := share.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		node := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "APIKEY fixture" {
				t.Error("RSA request lost API authentication")
			}
			switch r.URL.Path {
			case "/version":
				_, _ = w.Write([]byte(`{"version":"1"}`))
			case "/info/protocols":
				_, _ = w.Write([]byte(`{"rsa":{"name":"circl-tss-rsa","version":1}}`))
			case "/rsa/keys/test-rsa/publickey":
				if r.Method != http.MethodPost {
					t.Error("unexpected RSA public key method")
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"publicKey": publicKey, "players": 3, "requiredSigners": 2})
			case "/rsa/keys/test-rsa/sign":
				var input struct{ MessageHash []byte }
				if r.Method != http.MethodPost || r.Header.Get("MPC-SessionID") != "" || json.NewDecoder(r.Body).Decode(&input) != nil || !bytes.Equal(input.MessageHash, digest[:]) {
					t.Error("unexpected RSA signing request")
				}
				_ = json.NewEncoder(w).Encode(map[string][]byte{"partialSignature": encoded})
			default:
				http.NotFound(w, r)
			}
		}))
		t.Cleanup(node.Close)
		client, err := NewClient(Configuration{URL: node.URL}.WithAPIKeyAuthentication("fixture"))
		if err != nil {
			t.Fatal(err)
		}
		key, err = client.RSA().PublicKey(t.Context(), "test-rsa")
		if err != nil || !bytes.Equal(key.PublicKey, publicKey) || key.Players != 3 || key.RequiredSigners != 2 {
			t.Fatalf("PublicKey returned (%v, %v)", key, err)
		}
		part, err := client.RSA().Sign(t.Context(), "test-rsa", digest[:])
		if err != nil {
			t.Fatal(err)
		}
		partials = append(partials, part)
	}
	signature, err := RSAFinalizeSignature(key, digest[:], partials)
	if err != nil || rsa.VerifyPKCS1v15(&privateKey.PublicKey, crypto.SHA256, digest[:], signature) != nil {
		t.Fatalf("RSAFinalizeSignature did not produce a standard RSA signature: %v", err)
	}
	if err := RSAVerifySignature(publicKey, digest[:], signature); err != nil {
		t.Fatal(err)
	}
	wrongDigest := sha256.Sum256([]byte("other message"))
	if RSAVerifySignature(publicKey, wrongDigest[:], signature) == nil {
		t.Fatal("accepted signature for a different digest")
	}
	tampered := bytes.Clone(partials[1])
	tampered[len(tampered)-1] ^= 1
	for name, invalid := range map[string][][]byte{
		"insufficient": partials[:1],
		"duplicate":    {partials[0], partials[0]},
		"tampered":     {partials[0], tampered},
		"trailing":     {partials[0], append(bytes.Clone(partials[1]), 0)},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := RSAFinalizeSignature(key, digest[:], invalid); err == nil {
				t.Fatal("accepted invalid RSA signing shares")
			}
		})
	}
}

func TestRSAIncompatibleProtocolDoesNotEnableRSA(t *testing.T) {
	node := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/version":
			_, _ = w.Write([]byte(`{"version":"1"}`))
		case "/info/protocols":
			_, _ = w.Write([]byte(`{"ecdsa":14,"rsa":{"name":"circl-tss-rsa","version":2}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(node.Close)
	client, err := NewClient(Configuration{URL: node.URL}.WithAPIKeyAuthentication("fixture"))
	if err != nil {
		t.Fatal(err)
	}
	if client.rsa != nil || client.native || client.ecdsa == nil {
		t.Fatal("incompatible RSA advertisement changed the supported protocols")
	}
}
