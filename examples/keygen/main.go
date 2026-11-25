package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/C18519898242/go-mpc-sdk/tsm"
)

func main() {
	addresses := flag.String("nodes", "http://127.0.0.1:8081,http://127.0.0.1:8082,http://127.0.0.1:8083", "comma-separated node URLs in SDK player order")
	algorithm := flag.String("algorithm", "ecdsa", "ecdsa or ed25519")
	threshold := flag.Int("threshold", 1, "security threshold: required signers minus one")
	keyID := flag.String("key-id", "", "optional key ID shared by all players")
	flag.Parse()
	if err := run(strings.Split(*addresses, ","), *algorithm, *threshold, *keyID); err != nil {
		log.Fatal(err)
	}
}

type keyService interface {
	GenerateKey(context.Context, *tsm.SessionConfig, int, string, string) (string, error)
	PublicKey(context.Context, string, []uint32) ([]byte, error)
}

func run(addresses []string, algorithm string, threshold int, desiredID string) error {
	var variant string
	switch algorithm {
	case "ecdsa":
		variant = "secp256k1"
	case "ed25519":
		variant = tsm.SchnorrEd25519
	default:
		return fmt.Errorf("unsupported algorithm %q", algorithm)
	}
	if threshold < 1 || threshold >= len(addresses) {
		return fmt.Errorf("threshold must be between 1 and the number of nodes minus 1")
	}
	services := make([]keyService, len(addresses))
	for i, address := range addresses {
		env := fmt.Sprintf("MPC_NODE_API_KEY_%d", i+1)
		apiKey := os.Getenv(env)
		if apiKey == "" {
			return fmt.Errorf("set %s for the node at player index %d", env, i)
		}
		cfg := tsm.Configuration{URL: strings.TrimSpace(address)}.WithAPIKeyAuthentication(apiKey)
		client, err := tsm.NewClient(cfg)
		if err != nil {
			return fmt.Errorf("player %d: %w", i, err)
		}
		if algorithm == "ecdsa" {
			services[i] = client.ECDSA()
		} else {
			services[i] = client.Schnorr()
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute+15*time.Second)
	defer cancel()
	session := tsm.NewStaticSessionConfig(tsm.GenerateSessionID(), len(services))
	ids, failures := make([]string, len(services)), make([]error, len(services))
	var wg sync.WaitGroup
	for i, service := range services {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ids[i], failures[i] = service.GenerateKey(ctx, session, threshold, variant, desiredID)
		}()
	}
	wg.Wait()
	for i, err := range failures {
		if err != nil {
			return fmt.Errorf("keygen session %s, player %d: %w", session.SessionID(), i, err)
		}
		if ids[i] != ids[0] {
			return fmt.Errorf("keygen session %s returned different key IDs", session.SessionID())
		}
	}
	var publicKey []byte
	for i, service := range services {
		key, err := service.PublicKey(ctx, ids[i], nil)
		if err != nil {
			return fmt.Errorf("read key %s from player %d: %w", ids[i], i, err)
		}
		if publicKey != nil && !bytes.Equal(publicKey, key) {
			return fmt.Errorf("key %s has different public keys across nodes", ids[i])
		}
		publicKey = key
	}
	fmt.Printf("%s keyID=%s\npublicKey=%s\n", algorithm, ids[0], publicKey)
	return nil
}
