package tsm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
)

// WalletReceipt identifies the wallet and its two root keys.
type WalletReceipt struct {
	WalletID   string `json:"walletID"`
	ECDSAKeyID string `json:"ecdsaKeyID"`
	FROSTKeyID string `json:"frostKeyID"`
}

// WalletBackup is the connected node's encrypted backup for a wallet.
// WrappedKey, Ciphertext and AAD are decoded from the response's Base64 fields.
type WalletBackup struct {
	FormatVersion int             `json:"formatVersion"`
	ApplicationID string          `json:"applicationID"`
	PartyID       string          `json:"partyID"`
	WalletID      string          `json:"walletID"`
	BackupKeyID   string          `json:"backupKeyID"`
	WrappedKey    []byte          `json:"wrappedKey"`
	Ciphertext    []byte          `json:"ciphertext"`
	AAD           []byte          `json:"aad"`
	Manifest      json.RawMessage `json:"manifest"`
}

// CreateWallet participates in a three-node mpc-node-api wallet creation.
// Call all three nodes concurrently with the same session and backupPublicKeys.
// A nil or empty map uses configured public keys. A nonempty map supplies one
// PKIX DER RSA public key for each zero-based SDK player index.
func (c *Client) CreateWallet(ctx context.Context, session *SessionConfig, backupPublicKeys map[int][]byte) (*WalletReceipt, error) {
	if !c.native {
		return nil, fmt.Errorf("%w: mnemonic wallets require mpc-node-api", ErrUnavailable)
	}
	if session == nil || len(session.players) != 3 {
		return nil, fmt.Errorf("%w: wallet creation needs a session with exactly three players", ErrInvalidInput)
	}
	var request struct {
		BackupPublicKeys map[uint64][]byte `json:"backupPublicKeys,omitempty"`
	}
	if len(backupPublicKeys) != 0 {
		if len(backupPublicKeys) != len(session.players) {
			return nil, fmt.Errorf("%w: provide a backup public key for each wallet player", ErrInvalidInput)
		}
		request.BackupPublicKeys = make(map[uint64][]byte, len(backupPublicKeys))
		for _, player := range session.players {
			key := backupPublicKeys[player]
			if player < 0 || len(key) == 0 {
				return nil, fmt.Errorf("%w: invalid or missing backup public key for player %d", ErrInvalidInput, player)
			}
			request.BackupPublicKeys[uint64(player)+1] = key
		}
	}
	var receipt WalletReceipt
	if err := c.request(ctx, http.MethodPost, "/wallets", session, request, &receipt); err != nil {
		return nil, err
	}
	if !keyIDPattern.MatchString(receipt.WalletID) || !keyIDPattern.MatchString(receipt.ECDSAKeyID) ||
		!keyIDPattern.MatchString(receipt.FROSTKeyID) {
		return nil, fmt.Errorf("%w: invalid wallet receipt", ErrOperationFailed)
	}
	return &receipt, nil
}

// GetWalletBackup downloads the connected mpc-node-api node's encrypted
// mnemonic backup and offline recovery metadata without an MPC session.
func (c *Client) GetWalletBackup(ctx context.Context, walletID string) (*WalletBackup, error) {
	if !c.native {
		return nil, fmt.Errorf("%w: mnemonic wallet backups require mpc-node-api", ErrUnavailable)
	}
	if !keyIDPattern.MatchString(walletID) {
		return nil, fmt.Errorf("%w: invalid wallet ID", ErrInvalidInput)
	}
	var backup WalletBackup
	if err := c.request(ctx, http.MethodGet, "/wallets/"+walletID+"/backup", nil, nil, &backup); err != nil {
		return nil, err
	}
	fingerprint, err := hex.DecodeString(backup.BackupKeyID)
	if err != nil || len(fingerprint) != sha256.Size || backup.FormatVersion != 1 || backup.ApplicationID == "" ||
		backup.PartyID == "" || backup.WalletID != walletID || len(backup.WrappedKey) == 0 || len(backup.Ciphertext) < 28 ||
		len(backup.AAD) == 0 || len(backup.Manifest) == 0 || backup.Manifest[0] != '{' {
		return nil, fmt.Errorf("%w: invalid wallet backup response", ErrOperationFailed)
	}
	return &backup, nil
}
