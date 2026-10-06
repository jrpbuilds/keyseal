package mutate

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"
)

// MaxSecretBytes caps a single secret value read from stdin or a descriptor.
const MaxSecretBytes = 1 << 20

// ReadSecret reads one secret value from r.
//
// Exactly one trailing newline (LF or CRLF) is removed so `echo` and `printf`
// style input behave predictably. Empty values and invalid UTF-8 are rejected.
// Error messages never include the value.
func ReadSecret(r io.Reader) (string, error) {
	data, err := io.ReadAll(io.LimitReader(r, MaxSecretBytes+1))
	if err != nil {
		return "", fmt.Errorf("read secret value: %w", err)
	}
	if len(data) > MaxSecretBytes {
		return "", fmt.Errorf("secret value exceeds %d bytes", MaxSecretBytes)
	}
	if trimmed, ok := bytes.CutSuffix(data, []byte("\n")); ok {
		data, _ = bytes.CutSuffix(trimmed, []byte("\r"))
	}
	if len(data) == 0 {
		return "", errors.New("secret value is empty")
	}
	if !utf8.Valid(data) {
		return "", errors.New("secret value must be valid UTF-8 text")
	}
	return string(data), nil
}
