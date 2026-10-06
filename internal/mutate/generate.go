package mutate

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

const (
	// MinGenerateBytes keeps generated secrets at 128 bits of entropy or more.
	MinGenerateBytes     = 16
	MaxGenerateBytes     = 1024
	DefaultGenerateBytes = 32
	DefaultEncoding      = "base64url"
)

// Generate returns n cryptographically secure random bytes encoded as text.
//
// Supported encodings are base64url (URL-safe, unpadded), base64 (standard,
// padded), and hex (lowercase).
func Generate(n int, encoding string) (string, error) {
	if n < MinGenerateBytes || n > MaxGenerateBytes {
		return "", fmt.Errorf("--bytes must be between %d and %d", MinGenerateBytes, MaxGenerateBytes)
	}
	var encode func([]byte) string
	switch encoding {
	case "base64url":
		encode = base64.RawURLEncoding.EncodeToString
	case "base64":
		encode = base64.StdEncoding.EncodeToString
	case "hex":
		encode = hex.EncodeToString
	default:
		return "", fmt.Errorf("unsupported encoding %q; use base64url, base64, or hex", encoding)
	}
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("read random bytes: %w", err)
	}
	return encode(buf), nil
}
