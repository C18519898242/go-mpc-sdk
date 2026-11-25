package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"flag"
	"fmt"
	"log"
	"os"
	"slices"
	"strconv"
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
	message := flag.String("message", "", "message to sign after key generation")
	chainPath := flag.String("chain-path", "", "comma-separated non-hardened child indices for signing")
	presign := flag.Bool("presign", false, "generate and consume a presignature before combining signatures")
	flag.Parse()
	var signMessage []byte
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "message" {
			signMessage = []byte(*message)
		}
	})
	var path []uint32
	if *chainPath != "" {
		for _, value := range strings.Split(*chainPath, ",") {
			index, err := strconv.ParseUint(value, 10, 31)
			if err != nil {
				log.Fatalf("invalid chain-path index %q", value)
			}
			path = append(path, uint32(index))
		}
	}
	if *presign && signMessage == nil {
		log.Fatal("-presign requires -message")
	}
	if err := run(strings.Split(*addresses, ","), *algorithm, *threshold, *keyID, signMessage, path, *presign); err != nil {
		log.Fatal(err)
	}
}

type keyService interface {
	GenerateKey(context.Context, *tsm.SessionConfig, int, string, string) (string, error)
	PublicKey(context.Context, string, []uint32) ([]byte, error)
}

func run(addresses []string, algorithm string, threshold int, desiredID string, message []byte, path []uint32, presign bool) error {
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
	clients := make([]*tsm.Client, len(addresses))
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
		clients[i] = client
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
	if message != nil {
		// The first threshold+1 nodes are enough to sign.
		return signAndVerify(ctx, clients[:threshold+1], algorithm, ids[0], path, message, presign)
	}
	return nil
}

func signAndVerify(ctx context.Context, signers []*tsm.Client, algorithm, keyID string, path []uint32, message []byte, presign bool) error {
	session := tsm.NewStaticSessionConfig(tsm.GenerateSessionID(), len(signers))
	var presignatureID string
	if presign {
		var err error
		presignatureID, err = generatePresignature(ctx, signers, session, algorithm, keyID)
		if err != nil {
			return err
		}
	}
	digest := sha256.Sum256(message)
	parts, failures := make([][]byte, len(signers)), make([]error, len(signers))
	var wg sync.WaitGroup
	for i, client := range signers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if algorithm == "ecdsa" {
				var result *tsm.ECDSAPartialSignResult
				var err error
				if presign {
					result, err = client.ECDSA().SignWithPresignature(ctx, keyID, presignatureID, path, digest[:])
				} else {
					result, err = client.ECDSA().Sign(ctx, session, keyID, path, digest[:])
				}
				failures[i] = err
				if err == nil {
					parts[i] = result.PartialSignature
				}
			} else {
				var result *tsm.SchnorrPartialSignResult
				var err error
				if presign {
					result, err = client.Schnorr().SignWithPresignature(ctx, keyID, presignatureID, path, message)
				} else {
					result, err = client.Schnorr().Sign(ctx, session, keyID, path, message)
				}
				failures[i] = err
				if err == nil {
					parts[i] = result.PartialSignature
				}
			}
		}()
	}
	wg.Wait()
	for i, err := range failures {
		if err != nil {
			if presign {
				return fmt.Errorf("sign with presignature %s, player %d: %w", presignatureID, i, err)
			}
			return fmt.Errorf("sign session %s, player %d: %w", session.SessionID(), i, err)
		}
	}
	if algorithm == "ecdsa" {
		signature, err := tsm.ECDSAFinalizeSignature(digest[:], parts)
		if err != nil {
			return err
		}
		public, err := signers[0].ECDSA().PublicKey(ctx, keyID, path)
		if err != nil {
			return err
		}
		if err := tsm.ECDSAVerifySignature(public, digest[:], signature.ASN1()); err != nil {
			return err
		}
		fmt.Printf("signature=%x\nrecoveryID=%d\n", signature.ASN1(), signature.RecoveryID())
		return nil
	}
	signature, err := tsm.SchnorrFinalizeSignature(message, parts)
	if err != nil {
		return err
	}
	public, err := signers[0].Schnorr().PublicKey(ctx, keyID, path)
	if err != nil {
		return err
	}
	if err := tsm.SchnorrVerifySignature(public, message, signature); err != nil {
		return err
	}
	fmt.Printf("signature=%x\n", signature)
	return nil
}

func generatePresignature(ctx context.Context, signers []*tsm.Client, session *tsm.SessionConfig, algorithm, keyID string) (string, error) {
	ids, failures := make([][]string, len(signers)), make([]error, len(signers))
	var wg sync.WaitGroup
	for i, client := range signers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if algorithm == "ecdsa" {
				ids[i], failures[i] = client.ECDSA().GeneratePresignatures(ctx, session, keyID, 1)
			} else {
				ids[i], failures[i] = client.Schnorr().GeneratePresignatures(ctx, session, keyID, 1)
			}
		}()
	}
	wg.Wait()
	for i, err := range failures {
		if err != nil {
			return "", fmt.Errorf("presign session %s, player %d: %w", session.SessionID(), i, err)
		}
		if !slices.Equal(ids[i], ids[0]) {
			return "", fmt.Errorf("presign session %s returned different presignature IDs", session.SessionID())
		}
	}
	fmt.Printf("presignatureID=%s\n", ids[0][0])
	return ids[0][0], nil
}
