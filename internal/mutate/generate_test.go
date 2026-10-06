package mutate

import (
	"encoding/base64"
	"encoding/hex"
	"testing"
)

func TestGenerateEncodesRequestedByteCount(t *testing.T) {
	decoders := map[string]func(string) ([]byte, error){
		"base64url": base64.RawURLEncoding.DecodeString,
		"base64":    base64.StdEncoding.DecodeString,
		"hex":       hex.DecodeString,
	}
	for encoding, decode := range decoders {
		value, err := Generate(32, encoding)
		if err != nil {
			t.Fatalf("Generate(32, %s) returned error: %v", encoding, err)
		}
		raw, err := decode(value)
		if err != nil {
			t.Fatalf("decode %s value: %v", encoding, err)
		}
		if len(raw) != 32 {
			t.Fatalf("%s decoded to %d bytes, want 32", encoding, len(raw))
		}
	}
}

func TestGenerateProducesDistinctValues(t *testing.T) {
	a, err := Generate(DefaultGenerateBytes, DefaultEncoding)
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}
	b, err := Generate(DefaultGenerateBytes, DefaultEncoding)
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}
	if a == b {
		t.Fatal("expected independent random values")
	}
}

func TestGenerateRejectsWeakOrInvalidOptions(t *testing.T) {
	for _, tc := range []struct {
		bytes    int
		encoding string
	}{
		{MinGenerateBytes - 1, "hex"},
		{MaxGenerateBytes + 1, "hex"},
		{32, "base32"},
	} {
		if _, err := Generate(tc.bytes, tc.encoding); err == nil {
			t.Fatalf("Generate(%d, %q) should fail", tc.bytes, tc.encoding)
		}
	}
}
