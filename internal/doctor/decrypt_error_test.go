package doctor

import (
	"errors"
	"testing"
)

func TestClassifyDecryptErrorNeverReturnsRaw(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want string
	}{
		{name: "nil", err: nil, want: "decryption failed"},
		{name: "missing key file", err: errors.New("open /tmp/keys.txt: no such file or directory"), want: "age key material is missing or unreadable"},
		{name: "no matching key", err: errors.New("Error getting data key: 0 successful: no identity matched any of the recipients"), want: "no matching age key could decrypt this file"},
		{name: "failed data key", err: errors.New("Failed to get the data key required to decrypt the SOPS file"), want: "no matching age key could decrypt this file"},
		{name: "generic", err: errors.New("something unexpected from the backend"), want: "decryption failed"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := classifyDecryptError(tt.err)
			if got != tt.want {
				t.Fatalf("classifyDecryptError() = %q, want %q", got, tt.want)
			}
			if tt.err != nil && got == tt.err.Error() {
				t.Fatalf("classifyDecryptError must not return raw err.Error()")
			}
		})
	}
}
