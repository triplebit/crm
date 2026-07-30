package cryptox

import (
	"errors"
	"fmt"
	"strings"
)

const piiContextVersion = "triplebit-pii:v1"

// PII seals sensitive database fields with record- and field-specific
// associated data. Copying ciphertext to another record or column therefore
// fails authentication.
type PII struct {
	keyring *Keyring
}

func NewPII(keyring *Keyring) (*PII, error) {
	if keyring == nil {
		return nil, errors.New("PII keyring is required")
	}
	return &PII{keyring: keyring}, nil
}

func (p *PII) Encrypt(recordID, field string, plaintext []byte) (string, error) {
	aad, err := piiAssociatedData(recordID, field)
	if err != nil {
		return "", err
	}
	return p.keyring.Encrypt(plaintext, aad)
}

func (p *PII) Decrypt(recordID, field, ciphertext string) ([]byte, error) {
	aad, err := piiAssociatedData(recordID, field)
	if err != nil {
		return nil, err
	}
	return p.keyring.Decrypt(ciphertext, aad)
}

// Reencrypt decrypts an existing value and seals it with the active key. The
// returned boolean is false when the value already uses the active key.
func (p *PII) Reencrypt(recordID, field, ciphertext string) (string, bool, error) {
	plaintext, err := p.Decrypt(recordID, field, ciphertext)
	if err != nil {
		return "", false, err
	}
	if !p.keyring.NeedsRotation(ciphertext) {
		return ciphertext, false, nil
	}
	rotated, err := p.Encrypt(recordID, field, plaintext)
	if err != nil {
		return "", false, err
	}
	return rotated, true, nil
}

func piiAssociatedData(recordID, field string) ([]byte, error) {
	recordID = strings.TrimSpace(recordID)
	field = strings.TrimSpace(field)
	if recordID == "" || field == "" {
		return nil, errors.New("PII record id and field are required")
	}
	if strings.ContainsRune(recordID, '\x00') || strings.ContainsRune(field, '\x00') {
		return nil, fmt.Errorf("PII context cannot contain NUL")
	}
	return []byte(piiContextVersion + "\x00" + recordID + "\x00" + field), nil
}
