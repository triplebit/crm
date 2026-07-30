package config

import "encoding/base64"

// decodeBase64 accepts the four common base64 spellings of the same bytes:
// standard or URL alphabet, padded or not.
//
// Operators paste keys from password managers, `openssl rand -base64 32`,
// `head -c 32 /dev/urandom | base64`, and each other. Rejecting a key because it
// arrived with the wrong alphabet teaches nothing and invites someone to
// "fix" it by hand. What must never be relaxed is the length and content
// check in decodeKey, and that is where strictness lives.
func decodeBase64(raw string) ([]byte, error) {
	encodings := []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	}
	var lastErr error
	for _, encoding := range encodings {
		decoded, err := encoding.DecodeString(raw)
		if err == nil {
			return decoded, nil
		}
		lastErr = err
	}
	return nil, lastErr
}
