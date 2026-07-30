// Package cryptox contains the small, application-owned cryptographic
// primitives used by the portal. It deliberately does not make key storage
// decisions; callers must load keys from the deployment's secret store.
package cryptox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
)

const (
	envelopeVersion = "v1"
	maxEnvelopeSize = 1 << 20
)

var (
	ErrMalformedCiphertext = errors.New("malformed ciphertext")
	ErrUnknownKey          = errors.New("unknown encryption key")
	ErrAuthentication      = errors.New("ciphertext authentication failed")

	keyIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
)

// Keyring encrypts with one active AES-256-GCM key and decrypts with any key
// in the ring. Keeping old keys in the ring permits online key rotation.
//
// Ciphertexts use this opaque envelope:
//
//	v1.<key-id>.<base64url(nonce || sealed-plaintext)>
//
// Associated data is authenticated but is not stored in the envelope.
type Keyring struct {
	activeID string
	keys     map[string][]byte
	random   io.Reader
}

// NewKeyring returns an AES-256-GCM keyring. All key material is copied so the
// caller may safely clear or reuse its input buffers.
func NewKeyring(activeID string, keys map[string][]byte) (*Keyring, error) {
	return newKeyring(activeID, keys, rand.Reader)
}

func newKeyring(activeID string, keys map[string][]byte, random io.Reader) (*Keyring, error) {
	if !keyIDPattern.MatchString(activeID) {
		return nil, fmt.Errorf("active key id is invalid")
	}
	if random == nil {
		return nil, errors.New("random source is required")
	}
	if len(keys) == 0 {
		return nil, errors.New("at least one encryption key is required")
	}

	copied := make(map[string][]byte, len(keys))
	for id, key := range keys {
		if !keyIDPattern.MatchString(id) {
			return nil, fmt.Errorf("encryption key id %q is invalid", id)
		}
		if len(key) != 32 {
			return nil, fmt.Errorf("encryption key %q must contain exactly 32 bytes", id)
		}
		copied[id] = append([]byte(nil), key...)
	}
	if _, ok := copied[activeID]; !ok {
		return nil, fmt.Errorf("active encryption key %q is not in the keyring", activeID)
	}

	return &Keyring{
		activeID: activeID,
		keys:     copied,
		random:   random,
	}, nil
}

// ActiveKeyID returns the identifier placed in newly encrypted envelopes.
func (k *Keyring) ActiveKeyID() string {
	return k.activeID
}

// Encrypt seals plaintext and authenticates the supplied context.
func (k *Keyring) Encrypt(plaintext, associatedData []byte) (string, error) {
	gcm, err := newGCM(k.keys[k.activeID])
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(k.random, nonce); err != nil {
		return "", fmt.Errorf("generate encryption nonce: %w", err)
	}

	sealed := gcm.Seal(nil, nonce, plaintext, associatedData)
	payload := make([]byte, 0, len(nonce)+len(sealed))
	payload = append(payload, nonce...)
	payload = append(payload, sealed...)

	return strings.Join([]string{
		envelopeVersion,
		k.activeID,
		base64.RawURLEncoding.EncodeToString(payload),
	}, "."), nil
}

// Decrypt opens an envelope and authenticates it against associatedData.
func (k *Keyring) Decrypt(envelope string, associatedData []byte) ([]byte, error) {
	if envelope == "" || len(envelope) > maxEnvelopeSize {
		return nil, ErrMalformedCiphertext
	}

	version, keyID, encoded, err := splitEnvelope(envelope)
	if err != nil || version != envelopeVersion {
		return nil, ErrMalformedCiphertext
	}
	key, ok := k.keys[keyID]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrUnknownKey, keyID)
	}

	payload, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || base64.RawURLEncoding.EncodeToString(payload) != encoded {
		return nil, ErrMalformedCiphertext
	}
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if len(payload) < gcm.NonceSize()+gcm.Overhead() {
		return nil, ErrMalformedCiphertext
	}

	nonce := payload[:gcm.NonceSize()]
	ciphertext := payload[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, associatedData)
	if err != nil {
		return nil, ErrAuthentication
	}
	return plaintext, nil
}

// NeedsRotation reports whether an otherwise well-formed envelope was
// encrypted with a non-active key. It does not authenticate the ciphertext.
func (k *Keyring) NeedsRotation(envelope string) bool {
	version, keyID, _, err := splitEnvelope(envelope)
	return err == nil && version == envelopeVersion && keyID != k.activeID
}

func splitEnvelope(envelope string) (version, keyID, encoded string, err error) {
	parts := strings.Split(envelope, ".")
	if len(parts) != 3 || !keyIDPattern.MatchString(parts[1]) || parts[2] == "" {
		return "", "", "", ErrMalformedCiphertext
	}
	return parts[0], parts[1], parts[2], nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("initialize AES: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("initialize AES-GCM: %w", err)
	}
	return gcm, nil
}
