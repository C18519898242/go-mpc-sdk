package tsm_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/C18519898242/go-mpc-sdk/tsm"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	ecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

func TestNativeSigningWorkflow(t *testing.T) {
	ctx := context.Background()
	message := []byte("SDK signing contract")
	digest := sha256.Sum256(message)
	secpKey := secp256k1.PrivKeyFromBytes([]byte{9})
	secpSig := ecdsa.Sign(secpKey, digest[:]).Serialize()
	compact := ecdsa.SignCompact(secpKey, digest[:], false)
	edKey := ed25519.NewKeyFromSeed(digest[:])
	edSig := ed25519.Sign(edKey, message)
	nonce, err := secp256k1.ParsePubKey(append([]byte{2 + (compact[0]-27)&1}, compact[1:33]...))
	if err != nil {
		t.Fatal(err)
	}
	edScalar := bytes.Clone(edSig[32:])
	for i := 0; i < len(edScalar)/2; i++ {
		j := len(edScalar) - 1 - i
		edScalar[i], edScalar[j] = edScalar[j], edScalar[i]
	}
	session := tsm.NewSessionConfig("demo_sign", []int{0, 2}, nil, nil)
	path := []uint32{0, 1}
	var ecParts, edParts [][]byte
	var ecPublic, edPublic []byte
	for i := 0; i < 2; i++ {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "APIKEY fixture" {
				t.Error("API key was not sent")
			}
			switch r.URL.Path {
			case "/version":
				io.WriteString(w, `{"version":"1"}`)
			case "/info/protocols":
				io.WriteString(w, `{"ecdsa":{"name":"cmp","version":1},"frost":{"name":"frost","version":1}}`)
			case "/ecdsa/keys/test-key/sign", "/frost/keys/test-key/sign":
				if r.Method != http.MethodPost || r.Header.Get("MPC-SessionID") != "demo_sign" ||
					r.Header.Get("MPC-RoutingID") != "40c3db0d23956156" || r.URL.Query().Get("mpc_routing_id") != "40c3db0d23956156" ||
					!reflect.DeepEqual(r.Header.Values("MPC-Players"), []string{"1", "3"}) {
					t.Error("incorrect session metadata")
				}
				var request struct {
					ChainPath   []uint32 `json:"chainPath"`
					MessageHash []byte   `json:"messageHash"`
					Message     []byte   `json:"message"`
					Format      string   `json:"signatureFormat"`
				}
				if err := json.NewDecoder(r.Body).Decode(&request); err != nil || !reflect.DeepEqual(request.ChainPath, path) || request.Format != "partial" {
					t.Error("incorrect signing path")
				}
				partial := map[string]any{"playerIndex": i * 2, "threshold": 1, "sharing": "additive"}
				curve, rPoint, publicKey, s := "secp256k1", nonce.SerializeUncompressed(), secpKey.PubKey().SerializeUncompressed(), compact[33:]
				if r.URL.Path == "/ecdsa/keys/test-key/sign" {
					if !bytes.Equal(request.MessageHash, digest[:]) || request.Message != nil {
						t.Error("ECDSA must send the digest")
					}
				} else {
					if !bytes.Equal(request.Message, message) || request.MessageHash != nil {
						t.Error("Ed25519 must send the raw message")
					}
					curve, rPoint, publicKey, s = "ed25519", edSig[:32], edKey.Public().(ed25519.PublicKey), edScalar
					partial["schnorr_variant"] = "Ed25519"
				}
				scalar := big.NewInt(1)
				if i == 1 {
					scalar.Sub(new(big.Int).SetBytes(s), scalar)
				}
				partial["curve"], partial["r"], partial["publicKey"], partial["sShare"] = curve, rPoint, publicKey, scalar.FillBytes(make([]byte, 32))
				json.NewEncoder(w).Encode(partial)
			case "/ecdsa/keys/test-key/publickey", "/frost/keys/test-key/publickey":
				if r.Header.Get("MPC-SessionID") != "" || r.URL.RawQuery != "" {
					t.Error("public key lookup must not join the signing session")
				}
				if body, _ := io.ReadAll(r.Body); string(body) != `{"chainPath":[0,1]}` {
					t.Errorf("incorrect public key path: %s", body)
				}
				curve, key := "secp256k1", secpKey.PubKey().SerializeUncompressed()
				if r.URL.Path == "/frost/keys/test-key/publickey" {
					curve, key = "ed25519", edKey.Public().(ed25519.PublicKey)
				}
				json.NewEncoder(w).Encode(struct {
					Curve string `json:"curve"`
					Key   []byte `json:"publicKey"`
				}{curve, key})
			default:
				t.Errorf("unexpected request %s", r.URL.Path)
				http.NotFound(w, r)
			}
		}))
		t.Cleanup(server.Close)
		client, err := tsm.NewClient(tsm.Configuration{URL: server.URL}.WithAPIKeyAuthentication("fixture"))
		if err != nil {
			t.Fatal(err)
		}
		ec, err := client.ECDSA().Sign(ctx, session, "test-key", path, digest[:])
		if err != nil {
			t.Fatal(err)
		}
		ecParts = append(ecParts, ec.PartialSignature)
		ed, err := client.Schnorr().Sign(ctx, session, "test-key", path, message)
		if err != nil {
			t.Fatal(err)
		}
		edParts = append(edParts, ed.PartialSignature)
		ecPublic, err = client.ECDSA().PublicKey(ctx, "test-key", path)
		if err != nil {
			t.Fatal(err)
		}
		edPublic, err = client.Schnorr().PublicKey(ctx, "test-key", path)
		if err != nil {
			t.Fatal(err)
		}
	}
	signature, err := tsm.ECDSAFinalizeSignature(digest[:], ecParts)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(signature.ASN1(), secpSig) || signature.RecoveryID() != int(compact[0])-27 ||
		!bytes.Equal(signature.R(), compact[1:33]) || !bytes.Equal(signature.S(), compact[33:]) {
		t.Fatal("incorrect ECDSA signature components")
	}
	if err := tsm.ECDSAVerifySignature(ecPublic, digest[:], signature.ASN1()); err != nil {
		t.Fatal(err)
	}
	if _, err := tsm.ECDSAFinalizeSignature(digest[:], ecParts[:1]); err == nil {
		t.Fatal("accepted missing node response")
	}
	if _, err := tsm.ECDSAFinalizeSignature(digest[:], [][]byte{ecParts[0], ecParts[0]}); err == nil {
		t.Fatal("accepted duplicate node response")
	}
	if _, err := tsm.ECDSAFinalizeSignature(make([]byte, 32), ecParts); err == nil {
		t.Fatal("accepted a different digest")
	}
	combined, err := tsm.SchnorrFinalizeSignature(message, edParts)
	if err != nil || !bytes.Equal(combined, edSig) {
		t.Fatalf("incorrect FROST signature: %v", err)
	}
	if err := tsm.SchnorrVerifySignature(edPublic, message, combined); err != nil {
		t.Fatal(err)
	}
	if _, err := tsm.SchnorrFinalizeSignature([]byte("different"), edParts); err == nil {
		t.Fatal("accepted a different message")
	}
}
