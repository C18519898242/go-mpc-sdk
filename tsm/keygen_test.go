package tsm_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/C18519898242/go-mpc-sdk/tsm"
)

func TestKeygenWireContract(t *testing.T) {
	for _, tc := range []struct {
		name, version, protocols, edRoute, edBody, contentType string
		players                                                []string
	}{
		{"native", `{"version":"1"}`, `{"ecdsa":{"name":"cmp","curve":"secp256k1","version":1},"frost":{"name":"frost","curve":"ed25519","version":1}}`, "/frost/keys", `{"threshold":1,"curve":"ed25519","keyID":""}`, "application/json", []string{"1", "2", "3"}},
		{"builder-vault", `{"version":"73.5.2"}`, `{"ecdsa":14,"schnorr":3}`, "/schnorr/keys", `{"threshold":1,"schnorr_variant":"Ed25519","curve":"ED-25519","keyID":""}`, "application-type/json", []string{"0", "1", "2"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "APIKEY test-only" {
					t.Error("API Key header missing")
				}
				switch r.URL.Path {
				case "/api/version":
					_, _ = io.WriteString(w, tc.version)
				case "/api/info/protocols":
					_, _ = io.WriteString(w, tc.protocols)
				case "/api/ecdsa/keys", "/api" + tc.edRoute:
					if r.Method != http.MethodPost || r.Header.Get("Content-Type") != tc.contentType ||
						r.Header.Get("MPC-SessionID") != "demo_keygen" || r.Header.Get("MPC-RoutingID") != "07ce376e2e4cf7f0" ||
						r.URL.Query().Get("mpc_routing_id") != "07ce376e2e4cf7f0" || !reflect.DeepEqual(r.Header.Values("MPC-Players"), tc.players) {
						t.Error("incorrect keygen request metadata")
					}
					want := `{"threshold":1,"curve":"secp256k1","keyID":"requested"}`
					if r.URL.Path == "/api"+tc.edRoute {
						want = tc.edBody
					}
					if body, _ := io.ReadAll(r.Body); !bytes.Equal(body, []byte(want)) {
						t.Errorf("body = %s, want %s", body, want)
					}
					_, _ = io.WriteString(w, `{"keyID":"requested"}`)
				case "/api/ecdsa/keys/requested/publickey":
					if r.Header.Get("MPC-SessionID") != "" || r.URL.RawQuery != "" {
						t.Error("public key request should have no session metadata")
					}
					if body, _ := io.ReadAll(r.Body); string(body) != `{"chainPath":[0,1]}` {
						t.Errorf("unexpected path: %s", body)
					}
					_, _ = io.WriteString(w, `{"curve":"secp256k1","publicKey":"BHm+Zn753LusVaBilc6HCwcCm/zbLc4o2VnygVsW+BeYSDradyajxGVdpPv8DhEIqP0XtEimhVQZnEfQj/sQ1Lg="}`)
				case "/api" + tc.edRoute + "/requested/publickey", "/api" + tc.edRoute + "/invalid-order/publickey":
					point := bytes.Repeat([]byte{0x66}, 32)
					point[0] = 0x58 // Ed25519 base point.
					if strings.Contains(r.URL.Path, "/invalid-order/") {
						point = bytes.Repeat([]byte{0xff}, 32)
						point[0], point[31] = 0xec, 0x7f // The Edwards point (0, -1) has order two.
					}
					_ = json.NewEncoder(w).Encode(map[string]string{"curve": "ED-25519", "publicKey": base64.StdEncoding.EncodeToString(point)})
				default:
					t.Errorf("unexpected request: %s", r.URL.Path)
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			client, err := tsm.NewClient(tsm.Configuration{URL: server.URL + "/api"}.WithAPIKeyAuthentication("test-only"))
			if err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			session := tsm.NewSessionConfig("demo_keygen", []int{0, 1, 2}, nil, nil)
			if id, err := client.ECDSA().GenerateKey(ctx, session, 1, "secp256k1", "requested"); err != nil || id != "requested" {
				t.Fatalf("ECDSA key ID: %q, %v", id, err)
			}
			if id, err := client.Schnorr().GenerateKey(ctx, session, 1, "Ed25519", ""); err != nil || id != "requested" {
				t.Fatalf("Ed25519 key ID: %q, %v", id, err)
			}
			key, err := client.ECDSA().PublicKey(ctx, "requested", []uint32{0, 1})
			var public struct {
				Scheme, Curve string
				Point         []byte
			}
			if err != nil || json.Unmarshal(key, &public) != nil || public.Scheme != "ECDSA" || public.Curve != "secp256k1" || len(public.Point) != 65 {
				t.Fatalf("incorrect SDK public key: %s, %v", key, err)
			}
			key, err = client.Schnorr().PublicKey(ctx, "requested", nil)
			if err != nil || json.Unmarshal(key, &public) != nil || public.Scheme != "Ed25519" || public.Curve != "ED-25519" || len(public.Point) != 32 {
				t.Fatalf("incorrect SDK Ed25519 public key: %s, %v", key, err)
			}
			if _, err := client.Schnorr().PublicKey(ctx, "invalid-order", nil); !errors.Is(err, tsm.ErrOperationFailed) {
				t.Fatal("expected an Ed25519 point outside the prime-order subgroup to be rejected")
			}
		})
	}
}

func TestSessionIDShape(t *testing.T) {
	id := tsm.GenerateSessionID()
	if len(id) != 43 || strings.ContainsAny(id, "+/=") || id == tsm.GenerateSessionID() {
		t.Fatal("expected random unpadded Base64URL session IDs")
	}
}
