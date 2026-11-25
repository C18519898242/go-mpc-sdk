// Package tsm provides the Builder Vault-style Go API for MPC key creation.
package tsm

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// Configuration identifies the REST endpoint of one MPC node.
type Configuration struct {
	URL string

	apiKey            string
	rootCAFile        string
	disableKeepAlives bool
}

// WithAPIKeyAuthentication returns a copy using API Key authentication.
func (c Configuration) WithAPIKeyAuthentication(apiKey string) *Configuration {
	c.apiKey = apiKey
	return &c
}

// WithRootCAFile returns a copy that trusts the PEM roots in the specified file.
func (c Configuration) WithRootCAFile(path string) *Configuration {
	c.rootCAFile = path
	return &c
}

// WithKeepAlives returns a copy with HTTP connection reuse configured.
func (c Configuration) WithKeepAlives(enabled bool) *Configuration {
	c.disableKeepAlives = !enabled
	return &c
}

// Client represents one node. It can be used concurrently.
type Client struct {
	base    *url.URL
	apiKey  string
	http    *http.Client
	native  bool
	ecdsa   ECDSAAPI
	schnorr SchnorrAPI
}

// NewClient authenticates to a node and discovers its key generation services.
func NewClient(cfg *Configuration) (*Client, error) {
	if cfg == nil || cfg.URL == "" || cfg.apiKey == "" || strings.ContainsAny(cfg.apiKey, " \t\r\n,") {
		return nil, fmt.Errorf("%w: node URL and a valid API key are required", ErrInvalidInput)
	}
	base, err := url.Parse(cfg.URL)
	if err != nil || (base.Scheme != "http" && base.Scheme != "https") || base.Hostname() == "" ||
		base.User != nil || base.RawQuery != "" || base.ForceQuery || base.Fragment != "" {
		return nil, fmt.Errorf("%w: expected an HTTP(S) node URL with no credentials, query or fragment", ErrInvalidInput)
	}
	transport := &http.Transport{Proxy: http.ProxyFromEnvironment, ForceAttemptHTTP2: true}
	if standard, ok := http.DefaultTransport.(*http.Transport); ok && standard != nil {
		transport = standard.Clone()
	}
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	transport.DisableKeepAlives = cfg.disableKeepAlives
	if cfg.rootCAFile != "" {
		pem, err := os.ReadFile(cfg.rootCAFile)
		if err != nil {
			return nil, fmt.Errorf("read node root CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("%w: root CA file contains no PEM certificate", ErrInvalidInput)
		}
		transport.TLSClientConfig.RootCAs = pool
	}
	c := &Client{
		base: base, apiKey: cfg.apiKey,
		http: &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}},
	}
	if err := c.discover(); err != nil {
		c.http.CloseIdleConnections()
		return nil, err
	}
	return c, nil
}

func (c *Client) discover() error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	var version struct{ Version string }
	var protocols map[string]json.RawMessage
	var versionErr, protocolErr error
	wg.Add(2)
	go func() {
		defer wg.Done()
		versionErr = c.request(ctx, http.MethodGet, "/version", nil, nil, &version)
	}()
	go func() {
		defer wg.Done()
		protocolErr = c.request(ctx, http.MethodGet, "/info/protocols", nil, nil, &protocols)
	}()
	wg.Wait()
	if err := errors.Join(versionErr, protocolErr); err != nil {
		return err
	}
	if version.Version == "" || protocols == nil {
		return fmt.Errorf("%w: invalid node discovery response", ErrOperationFailed)
	}
	ecdsa, nativeECDSA, err := decodeProtocol(protocols["ecdsa"])
	if err != nil {
		return err
	}
	frost, nativeFROST, err := decodeProtocol(protocols["frost"])
	if err != nil {
		return err
	}
	schnorr, _, err := decodeProtocol(protocols["schnorr"])
	if err != nil {
		return err
	}
	c.native = nativeECDSA || nativeFROST
	if ecdsa {
		c.ecdsa = &ecdsaService{client: c}
	}
	if c.native && frost {
		c.schnorr = &schnorrService{client: c, path: "/frost/keys"}
	} else if !c.native && schnorr {
		c.schnorr = &schnorrService{client: c, path: "/schnorr/keys"}
	}
	return nil
}

func decodeProtocol(raw json.RawMessage) (enabled, native bool, err error) {
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return false, false, nil
	}
	if raw[0] == '{' {
		var protocol struct {
			Name    string
			Version int
		}
		if err := json.Unmarshal(raw, &protocol); err == nil && protocol.Name != "" && protocol.Version > 0 {
			return true, true, nil
		}
	} else {
		var number int
		if err := json.Unmarshal(raw, &number); err == nil && number >= 0 {
			return number != 0, false, nil
		}
	}
	return false, false, fmt.Errorf("%w: invalid node protocol information", ErrOperationFailed)
}

func (c *Client) request(ctx context.Context, method, path string, session *SessionConfig, input, output any) error {
	return c.requestWithLimit(ctx, method, path, session, input, output, 64<<10)
}

func (c *Client) requestWithLimit(ctx context.Context, method, path string, session *SessionConfig, input, output any, maxResponse int64) error {
	var body io.Reader
	if input != nil {
		data, err := json.Marshal(input)
		if err != nil {
			return fmt.Errorf("%w: encode %s request: %v", ErrInvalidInput, path, err)
		}
		body = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base.JoinPath(path).String(), body)
	if err != nil {
		return fmt.Errorf("%w: build %s request: %w", ErrInvalidInput, path, err)
	}
	req.Header.Set("Authorization", "APIKEY "+c.apiKey)
	if input != nil {
		contentType := "application/json"
		if !c.native {
			// Builder Vault v73 sends this literal media type.
			contentType = "application-type/json"
		}
		req.Header.Set("Content-Type", contentType)
	}
	if session != nil {
		if err := session.apply(req, c.native); err != nil {
			return err
		}
	}
	response, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %s %s: %w", ErrOperationFailed, method, path, err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, maxResponse+1))
	if err != nil {
		return fmt.Errorf("%w: read %s response: %w", ErrOperationFailed, path, err)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("%w: %s %s returned HTTP %d", statusError(response.StatusCode), method, path, response.StatusCode)
	}
	if int64(len(data)) > maxResponse || (output != nil && json.Unmarshal(data, output) != nil) {
		return fmt.Errorf("%w: invalid JSON response from %s", ErrOperationFailed, path)
	}
	return nil
}

type tsmError string

func (e tsmError) Error() string { return string(e) }

func (e tsmError) WrapWith(err error) error { return fmt.Errorf("%w: %v", e, err) }

const (
	ErrAuthentication  tsmError = "tsm authentication failed"
	ErrAccess          tsmError = "tsm access denied"
	ErrInvalidInput    tsmError = "invalid tsm input"
	ErrUnavailable     tsmError = "tsm temporarily unavailable"
	ErrOperationFailed tsmError = "tsm operation failed"
)

func statusError(code int) error {
	switch {
	case code == http.StatusUnauthorized:
		return ErrAuthentication
	case code == http.StatusForbidden:
		return ErrAccess
	case code == http.StatusServiceUnavailable:
		return ErrUnavailable
	case code >= 400 && code < 500:
		return ErrInvalidInput
	default:
		return ErrOperationFailed
	}
}
