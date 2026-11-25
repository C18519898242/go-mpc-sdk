package tsm_test

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"

	"github.com/C18519898242/go-mpc-sdk/tsm"
)

func TestKeyManagement(t *testing.T) {
	var mu sync.Mutex
	remaining := 3
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "APIKEY test-only" || r.Header.Get("MPC-SessionID") != "" || r.URL.RawQuery != "" {
			t.Error("expected an authenticated request without MPC session metadata")
		}
		mu.Lock()
		defer mu.Unlock()
		switch r.Method + " " + r.URL.Path {
		case "GET /version":
			io.WriteString(w, `{"version":"1"}`)
		case "GET /info/protocols":
			io.WriteString(w, `{"ecdsa":{"name":"cmp","version":1}}`)
		case "POST /key/test-key/count/presigs":
			body, err := io.ReadAll(r.Body)
			if err != nil || string(body) != "{}" || r.Header.Get("Content-Type") != "application/json" {
				t.Errorf("unexpected count request body %q, error %v", body, err)
			}
			io.WriteString(w, strconv.Itoa(remaining)+"\n")
		case "DELETE /key/test-key/presigs", "DELETE /key/test-key":
			body, err := io.ReadAll(r.Body)
			if err != nil || len(body) != 0 {
				t.Errorf("unexpected delete request body %q, error %v", body, err)
			}
			remaining = 0
			w.WriteHeader(http.StatusNoContent)
		case "POST /key/malformed/count/presigs":
			io.WriteString(w, "null")
		case "POST /key/missing/count/presigs", "DELETE /key/missing/presigs", "DELETE /key/missing":
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
	ctx, keys := t.Context(), client.KeyManagement()
	if count, err := keys.CountPresignatures(ctx, "test-key"); err != nil || count != 3 {
		t.Fatalf("count before deletion = %d, error = %v", count, err)
	}
	if err := keys.DeletePresignatures(ctx, "test-key"); err != nil {
		t.Fatal(err)
	}
	if count, err := keys.CountPresignatures(ctx, "test-key"); err != nil || count != 0 {
		t.Fatalf("count after deletion = %d, error = %v", count, err)
	}
	if err := keys.DeleteKeyShare(ctx, "test-key"); err != nil {
		t.Fatal(err)
	}
	if _, err := keys.CountPresignatures(ctx, "malformed"); !errors.Is(err, tsm.ErrOperationFailed) {
		t.Fatalf("null count error = %v", err)
	}
	for _, id := range []string{"missing", "../invalid"} {
		if _, err := keys.CountPresignatures(ctx, id); !errors.Is(err, tsm.ErrInvalidInput) {
			t.Fatalf("count %q error = %v", id, err)
		}
		if err := keys.DeletePresignatures(ctx, id); !errors.Is(err, tsm.ErrInvalidInput) {
			t.Fatalf("delete %q error = %v", id, err)
		}
		if err := keys.DeleteKeyShare(ctx, id); !errors.Is(err, tsm.ErrInvalidInput) {
			t.Fatalf("delete key share %q error = %v", id, err)
		}
	}
}
