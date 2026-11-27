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
	"sync/atomic"
	"testing"

	thresholdrsa "github.com/C18519898242/circl/tss/rsa"
)

func TestRSAPSSSignAndFinalize(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	publicKey := &privateKey.PublicKey
	publicDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	shares, err := thresholdrsa.Deal(rand.Reader, 3, 2, privateKey, false)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("RSA-PSS threshold test"))
	opts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256}

	runSession := func(sessionID string) ([]byte, [][]byte) {
		t.Helper()
		salt := make([]byte, sha256.Size)
		if _, err := rand.Read(salt); err != nil {
			t.Fatal(err)
		}
		padder := &thresholdrsa.PSSPadder{
			Rand: bytes.NewReader(salt),
			Opts: opts,
		}
		padded, err := padder.Pad(publicKey, crypto.SHA256, digest[:])
		if err != nil {
			t.Fatal(err)
		}
		var partials [][]byte
		for _, index := range []int{0, 2} {
			signShare, err := shares[index].Sign(rand.Reader, publicKey, padded, false)
			if err != nil {
				t.Fatal(err)
			}
			encodedShare, err := signShare.MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
			envelope, err := json.Marshal(map[string]any{
				"format":      "circl-rsa-pss-sha256-v1",
				"sessionID":   sessionID,
				"keyID":       "pss-key",
				"hash":        "SHA256",
				"publicKey":   publicDER,
				"players":     3,
				"threshold":   2,
				"playerIndex": index + 1,
				"signers":     []string{"1", "3"},
				"digest":      digest[:],
				"salt":        salt,
				"share":       encodedShare,
			})
			if err != nil {
				t.Fatal(err)
			}
			var tamperSession atomic.Bool
			node := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/version":
					_, _ = w.Write([]byte(`{"version":"1"}`))
				case "/info/protocols":
					_, _ = w.Write([]byte(`{"rsa":{"name":"circl-tss-rsa","version":1}}`))
				case "/rsa/keys/pss-key/signpss":
					var input struct {
						Hash        string `json:"hash"`
						MessageHash []byte `json:"messageHash"`
					}
					if r.Method != http.MethodPost || r.Header.Get("Authorization") != "APIKEY fixture" ||
						r.Header.Get("MPC-SessionID") != sessionID || !reflect.DeepEqual(r.Header.Values("MPC-Players"), []string{"1", "3"}) ||
						json.NewDecoder(r.Body).Decode(&input) != nil || input.Hash != "SHA256" || !bytes.Equal(input.MessageHash, digest[:]) {
						t.Error("unexpected RSA-PSS sign request")
					}
					payload := envelope
					if tamperSession.Load() {
						var mutated map[string]any
						_ = json.Unmarshal(envelope, &mutated)
						mutated["sessionID"] = "other-session"
						payload, _ = json.Marshal(mutated)
					}
					_ = json.NewEncoder(w).Encode(map[string][]byte{"partialSignature": payload})
				default:
					http.NotFound(w, r)
				}
			}))
			t.Cleanup(node.Close)
			client, err := NewClient(Configuration{URL: node.URL}.WithAPIKeyAuthentication("fixture"))
			if err != nil {
				t.Fatal(err)
			}
			session := NewSessionConfig(sessionID, []int{0, 2}, nil, nil)
			part, err := client.RSA().SignPSS(t.Context(), session, "pss-key", HashFunctionSHA256, digest[:])
			if err != nil {
				t.Fatal(err)
			}
			partials = append(partials, part)

			tamperSession.Store(true)
			if _, err := client.RSA().SignPSS(t.Context(), session, "pss-key", HashFunctionSHA256, digest[:]); !errors.Is(err, ErrOperationFailed) {
				t.Fatalf("tampered session response returned %v, want ErrOperationFailed", err)
			}
			if _, err := client.RSA().SignPSS(t.Context(), session, "pss-key", "SHA512", digest[:]); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("unsupported hash returned %v, want ErrInvalidInput", err)
			}
			if _, err := client.RSA().SignPSS(t.Context(), session, "pss-key", HashFunctionSHA256, []byte("short")); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("short digest returned %v, want ErrInvalidInput", err)
			}
		}
		sig, err := RSAFinalizeSignaturePSS(HashFunctionSHA256, digest[:], partials)
		if err != nil {
			t.Fatalf("RSAFinalizeSignaturePSS failed: %v", err)
		}
		if err := rsa.VerifyPSS(publicKey, crypto.SHA256, digest[:], sig, opts); err != nil {
			t.Fatalf("rsa.VerifyPSS failed: %v", err)
		}
		if err := RSAVerifySignaturePSS(publicDER, HashFunctionSHA256, digest[:], sig); err != nil {
			t.Fatalf("RSAVerifySignaturePSS failed: %v", err)
		}
		return sig, partials
	}

	sig1, parts1 := runSession("pss-session-1")
	sig2, parts2 := runSession("pss-session-2")
	if bytes.Equal(sig1, sig2) {
		t.Fatal("two RSA-PSS sessions produced identical signatures")
	}

	otherDigest := sha256.Sum256([]byte("other message"))
	if RSAVerifySignaturePSS(publicDER, HashFunctionSHA256, otherDigest[:], sig1) == nil {
		t.Fatal("RSAVerifySignaturePSS accepted wrong digest")
	}
	if err := RSAVerifySignaturePSS(publicDER, "SHA512", digest[:], sig1); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("RSAVerifySignaturePSS accepted unsupported hash: %v", err)
	}

	mutateEnvelope := func(raw []byte, update func(map[string]any)) []byte {
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatal(err)
		}
		update(m)
		out, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}

	otherPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	otherPublicDER, err := x509.MarshalPKIXPublicKey(&otherPrivateKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	mixedPublicKey := mutateEnvelope(parts1[1], func(m map[string]any) {
		m["publicKey"] = otherPublicDER
	})
	mixedSigners := mutateEnvelope(parts1[1], func(m map[string]any) {
		m["signers"] = []string{"1", "2", "3"}
	})
	mixedSalt := mutateEnvelope(parts1[1], func(m map[string]any) {
		m["salt"] = bytes.Repeat([]byte{0x42}, sha256.Size)
	})
	mixedKey := mutateEnvelope(parts1[1], func(m map[string]any) {
		m["keyID"] = "other-key"
	})
	mixedDigest := mutateEnvelope(parts1[1], func(m map[string]any) {
		m["digest"] = otherDigest[:]
	})
	tamperedShare := mutateEnvelope(parts1[1], func(m map[string]any) {
		var env rsaPSSEnvelope
		_ = json.Unmarshal(parts1[1], &env)
		env.Share[len(env.Share)-1] ^= 1
		m["share"] = env.Share
	})

	for name, tc := range map[string]struct {
		hash   string
		digest []byte
		parts  [][]byte
	}{
		"single":          {HashFunctionSHA256, digest[:], parts1[:1]},
		"duplicate":       {HashFunctionSHA256, digest[:], [][]byte{parts1[0], parts1[0]}},
		"mixed session":   {HashFunctionSHA256, digest[:], [][]byte{parts1[0], parts2[1]}},
		"mixed publicKey": {HashFunctionSHA256, digest[:], [][]byte{parts1[0], mixedPublicKey}},
		"mixed signers":   {HashFunctionSHA256, digest[:], [][]byte{parts1[0], mixedSigners}},
		"mixed salt":      {HashFunctionSHA256, digest[:], [][]byte{parts1[0], mixedSalt}},
		"mixed keyID":     {HashFunctionSHA256, digest[:], [][]byte{parts1[0], mixedKey}},
		"mixed digest":    {HashFunctionSHA256, digest[:], [][]byte{parts1[0], mixedDigest}},
		"wrong digest":    {HashFunctionSHA256, otherDigest[:], parts1},
		"tampered":        {HashFunctionSHA256, digest[:], [][]byte{parts1[0], tamperedShare}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := RSAFinalizeSignaturePSS(tc.hash, tc.digest, tc.parts); err == nil {
				t.Fatalf("RSAFinalizeSignaturePSS unexpectedly succeeded for %s", name)
			}
		})
	}
	if _, err := RSAFinalizeSignaturePSS("SHA512", digest[:], parts1); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("unsupported hash returned %v", err)
	}
}

func TestRSAPSSMultiBitAndDoubleDigitPlayers(t *testing.T) {
	opts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256}
	digest := sha256.Sum256([]byte("multi-bit and >9 players test"))

	for _, bits := range []int{3072, 4096} {
		t.Run(string(rune('0'+bits/1000))+"k", func(t *testing.T) {
			key, err := rsa.GenerateKey(rand.Reader, bits)
			if err != nil {
				t.Fatal(err)
			}
			pub := &key.PublicKey
			pubDER, err := x509.MarshalPKIXPublicKey(pub)
			if err != nil {
				t.Fatal(err)
			}
			shares, err := thresholdrsa.Deal(rand.Reader, 3, 2, key, false)
			if err != nil {
				t.Fatal(err)
			}
			salt := make([]byte, sha256.Size)
			if _, err := rand.Read(salt); err != nil {
				t.Fatal(err)
			}
			padded, err := (&thresholdrsa.PSSPadder{Rand: bytes.NewReader(salt), Opts: opts}).Pad(pub, crypto.SHA256, digest[:])
			if err != nil {
				t.Fatal(err)
			}
			partials := make([][]byte, 0, 2)
			for _, idx := range []int{0, 2} {
				share, err := shares[idx].Sign(rand.Reader, pub, padded, false)
				if err != nil {
					t.Fatal(err)
				}
				rawShare, err := share.MarshalBinary()
				if err != nil {
					t.Fatal(err)
				}
				env, err := json.Marshal(map[string]any{
					"format":      "circl-rsa-pss-sha256-v1",
					"sessionID":   "bits-sess",
					"keyID":       "bits-key",
					"hash":        "SHA256",
					"publicKey":   pubDER,
					"players":     3,
					"threshold":   2,
					"playerIndex": idx + 1,
					"signers":     []string{"1", "3"},
					"digest":      digest[:],
					"salt":        salt,
					"share":       rawShare,
				})
				if err != nil {
					t.Fatal(err)
				}
				partials = append(partials, env)
			}
			sig, err := RSAFinalizeSignaturePSS(HashFunctionSHA256, digest[:], partials)
			if err != nil {
				t.Fatalf("%d-bit RSAFinalizeSignaturePSS failed: %v", bits, err)
			}
			if err := RSAVerifySignaturePSS(pubDER, HashFunctionSHA256, digest[:], sig); err != nil {
				t.Fatalf("%d-bit RSAVerifySignaturePSS failed: %v", bits, err)
			}
		})
	}

	// Player IDs crossing 9 ("2" and "10") sort lexicographically as ["10", "2"].
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pub := &key.PublicKey
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	shares, err := thresholdrsa.Deal(rand.Reader, 10, 2, key, false)
	if err != nil {
		t.Fatal(err)
	}
	salt := make([]byte, sha256.Size)
	if _, err := rand.Read(salt); err != nil {
		t.Fatal(err)
	}
	padded, err := (&thresholdrsa.PSSPadder{Rand: bytes.NewReader(salt), Opts: opts}).Pad(pub, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	var partials [][]byte
	for _, playerIdx := range []int{1, 9} {
		signShare, err := shares[playerIdx].Sign(rand.Reader, pub, padded, false)
		if err != nil {
			t.Fatal(err)
		}
		encodedShare, err := signShare.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		envelope, err := json.Marshal(map[string]any{
			"format":      "circl-rsa-pss-sha256-v1",
			"sessionID":   "double-digit-sess",
			"keyID":       "ten-player-key",
			"hash":        "SHA256",
			"publicKey":   pubDER,
			"players":     10,
			"threshold":   2,
			"playerIndex": playerIdx + 1,
			"signers":     []string{"10", "2"},
			"digest":      digest[:],
			"salt":        salt,
			"share":       encodedShare,
		})
		if err != nil {
			t.Fatal(err)
		}
		node := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/version":
				_, _ = w.Write([]byte(`{"version":"1"}`))
			case "/info/protocols":
				_, _ = w.Write([]byte(`{"rsa":{"name":"circl-tss-rsa","version":1}}`))
			case "/rsa/keys/ten-player-key/signpss":
				if !reflect.DeepEqual(r.Header.Values("MPC-Players"), []string{"2", "10"}) {
					t.Errorf("MPC-Players = %v, want [2 10]", r.Header.Values("MPC-Players"))
				}
				_ = json.NewEncoder(w).Encode(map[string][]byte{"partialSignature": envelope})
			default:
				http.NotFound(w, r)
			}
		}))
		t.Cleanup(node.Close)
		client, err := NewClient(Configuration{URL: node.URL}.WithAPIKeyAuthentication("fixture"))
		if err != nil {
			t.Fatal(err)
		}
		session := NewSessionConfig("double-digit-sess", []int{1, 9}, nil, nil)
		part, err := client.RSA().SignPSS(t.Context(), session, "ten-player-key", HashFunctionSHA256, digest[:])
		if err != nil {
			t.Fatalf("player %d SignPSS failed: %v", playerIdx+1, err)
		}
		partials = append(partials, part)
	}
	sig, err := RSAFinalizeSignaturePSS(HashFunctionSHA256, digest[:], partials)
	if err != nil {
		t.Fatalf("double-digit RSAFinalizeSignaturePSS failed: %v", err)
	}
	if err := RSAVerifySignaturePSS(pubDER, HashFunctionSHA256, digest[:], sig); err != nil {
		t.Fatalf("double-digit RSAVerifySignaturePSS failed: %v", err)
	}
}
