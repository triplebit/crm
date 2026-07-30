package cryptox

import (
	"bytes"
	"errors"
	"testing"
)

func TestKeyringRoundTripAndAuthentication(t *testing.T) {
	ring, err := NewKeyring("current", map[string][]byte{
		"current": bytes.Repeat([]byte{1}, 32),
	})
	if err != nil {
		t.Fatal(err)
	}

	sealed, err := ring.Encrypt([]byte("490154203237518"), []byte("imei:asset-1"))
	if err != nil {
		t.Fatal(err)
	}
	opened, err := ring.Decrypt(sealed, []byte("imei:asset-1"))
	if err != nil {
		t.Fatal(err)
	}
	if string(opened) != "490154203237518" {
		t.Fatalf("got %q", opened)
	}
	if _, err := ring.Decrypt(sealed, []byte("imei:asset-2")); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("expected associated-data authentication failure, got %v", err)
	}

	replacement := byte('A')
	if sealed[len(sealed)-1] == replacement {
		replacement = 'B'
	}
	tampered := sealed[:len(sealed)-1] + string(replacement)
	if _, err := ring.Decrypt(tampered, []byte("imei:asset-1")); err == nil {
		t.Fatal("tampered ciphertext was accepted")
	}
}

func TestPIIKeyRotationAndContextBinding(t *testing.T) {
	oldRing, err := NewKeyring("old", map[string][]byte{
		"old": bytes.Repeat([]byte{2}, 32),
	})
	if err != nil {
		t.Fatal(err)
	}
	oldPII, _ := NewPII(oldRing)
	sealed, err := oldPII.Encrypt("asset-1", "imei", []byte("490154203237518"))
	if err != nil {
		t.Fatal(err)
	}

	rotatingRing, err := NewKeyring("new", map[string][]byte{
		"old": bytes.Repeat([]byte{2}, 32),
		"new": bytes.Repeat([]byte{3}, 32),
	})
	if err != nil {
		t.Fatal(err)
	}
	pii, _ := NewPII(rotatingRing)
	rotated, changed, err := pii.Reencrypt("asset-1", "imei", sealed)
	if err != nil {
		t.Fatal(err)
	}
	if !changed || rotatingRing.NeedsRotation(rotated) {
		t.Fatal("ciphertext was not moved to the active key")
	}
	if _, err := pii.Decrypt("asset-2", "imei", rotated); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("ciphertext copied to a different record should fail, got %v", err)
	}
}

func TestKeyringRequiresAES256Keys(t *testing.T) {
	_, err := NewKeyring("bad", map[string][]byte{"bad": bytes.Repeat([]byte{1}, 16)})
	if err == nil {
		t.Fatal("short key accepted")
	}
}
