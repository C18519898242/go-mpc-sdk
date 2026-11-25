package tsm

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"hash/fnv"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"time"
)

var sessionIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

// SessionConfig describes the participants and timing of one MPC operation.
// Use the same instance or parameters on every participating node.
type SessionConfig struct {
	id             string
	players        []int
	publicKeys     map[int][]byte
	addresses      map[int]string
	connectTimeout time.Duration
	sessionTimeout time.Duration
}

// NewSessionConfig builds a session for the specified Blockdaemon player indices.
func NewSessionConfig(sessionID string, players []int, dynamicPublicKeys map[int][]byte, dynamicAddresses map[int]string) *SessionConfig {
	return NewSessionConfigWithTimeouts(sessionID, players, dynamicPublicKeys, dynamicAddresses, "", "")
}

// NewSessionConfigWithTimeouts accepts Go duration strings. Invalid durations are ignored.
func NewSessionConfigWithTimeouts(sessionID string, players []int, dynamicPublicKeys map[int][]byte, dynamicAddresses map[int]string, connectTimeout, sessionTimeout string) *SessionConfig {
	s := &SessionConfig{id: sessionID, publicKeys: make(map[int][]byte, len(players)), addresses: make(map[int]string, len(players))}
	for _, player := range players {
		if _, seen := s.publicKeys[player]; seen {
			continue
		}
		s.players = append(s.players, player)
		s.publicKeys[player] = append([]byte(nil), dynamicPublicKeys[player]...)
		s.addresses[player] = dynamicAddresses[player]
	}
	sort.Ints(s.players)
	s.connectTimeout, _ = time.ParseDuration(connectTimeout)
	s.sessionTimeout, _ = time.ParseDuration(sessionTimeout)
	return s
}

// NewStaticSessionConfig includes all players from 0 through playerCount-1.
func NewStaticSessionConfig(sessionID string, playerCount int) *SessionConfig {
	var players []int
	for i := 0; i < playerCount; i++ {
		players = append(players, i)
	}
	return NewSessionConfig(sessionID, players, nil, nil)
}

func (s SessionConfig) SessionID() string { return s.id }

// GenerateSessionID returns 32 random bytes encoded as unpadded Base64URL.
func GenerateSessionID() string {
	var random [32]byte
	if _, err := rand.Read(random[:]); err != nil {
		panic("generate MPC session ID: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(random[:])
}

func (s *SessionConfig) apply(req *http.Request, native bool) error {
	if !sessionIDPattern.MatchString(s.id) {
		return fmt.Errorf("%w: malformed MPC session ID", ErrInvalidInput)
	}
	h := fnv.New64a()
	_, _ = h.Write([]byte(s.id))
	routing := fmt.Sprintf("%016x", h.Sum64()&0x7fffffffffffffff)
	query := req.URL.Query()
	query.Set("mpc_routing_id", routing)
	req.URL.RawQuery = query.Encode()
	req.Header.Set("MPC-SessionID", s.id)
	req.Header.Set("MPC-RoutingID", routing)
	for _, player := range s.players {
		if player < 0 {
			return fmt.Errorf("%w: negative player index", ErrInvalidInput)
		}
		key := s.publicKeys[player]
		value := strconv.Itoa(player)
		if native {
			if len(key) != 0 || s.addresses[player] != "" {
				return fmt.Errorf("%w: dynamic players are unsupported by this node", ErrInvalidInput)
			}
			value = strconv.FormatUint(uint64(player)+1, 10)
		} else if len(key) > 0 {
			value += " " + base64.RawURLEncoding.EncodeToString(key)
			if address := s.addresses[player]; address != "" {
				value += " " + base64.RawURLEncoding.EncodeToString([]byte(address))
			}
		}
		req.Header.Add("MPC-Players", value)
	}
	if s.connectTimeout > 0 {
		req.Header.Set("MPC-ConnectTimeout", strconv.FormatInt(s.connectTimeout.Nanoseconds(), 10))
	}
	if s.sessionTimeout > 0 {
		req.Header.Set("MPC-SessionTimeout", strconv.FormatInt(s.sessionTimeout.Nanoseconds(), 10))
	}
	return nil
}
