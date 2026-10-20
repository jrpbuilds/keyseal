package secretfile_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/jrpbuilds/keyseal/internal/secretfile"
)

func TestClassifyRecognizesStates(t *testing.T) {
	dir := t.TempDir()

	tests := []struct {
		name  string
		rel   string
		body  *string
		state secretfile.State
	}{
		{name: "missing", rel: "missing.enc.yaml", body: nil, state: secretfile.StateMissing},
		{name: "empty placeholder", rel: "empty.enc.yaml", body: stringPtr(" \n\t\n"), state: secretfile.StatePlaceholder},
		{name: "encrypted", rel: "encrypted.enc.yaml", body: stringPtr("version: 1\nkind: env\nname: ENC[test]\nvalues:\n  APP_ENV: ENC[test]\nsops:\n  version: 3.9.0\n"), state: secretfile.StateEncrypted},
		{name: "plaintext", rel: "plaintext.enc.yaml", body: stringPtr("version: 1\nkind: env\nname: production/platform/app\nvalues:\n  APP_ENV: production\n"), state: secretfile.StatePlaintext},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(dir, tt.rel)
			if tt.body != nil {
				if err := os.WriteFile(path, []byte(*tt.body), 0o600); err != nil {
					t.Fatalf("WriteFile returned error: %v", err)
				}
			}
			got, err := secretfile.Classify(path)
			if err != nil {
				t.Fatalf("Classify returned error: %v", err)
			}
			if got.State != tt.state {
				t.Fatalf("expected %q, got %q", tt.state, got.State)
			}
		})
	}
}

func TestClassifyBytesMatchesClassifyForEveryFileState(t *testing.T) {
	dir := t.TempDir()
	bodies := map[string]string{
		"placeholder": " \n\t\n",
		"encrypted":   "values:\n  APP_ENV: ENC[test]\nsops:\n  version: 3.9.0\n",
		"plaintext":   "values:\n  APP_ENV: production\n",
	}
	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(dir, name+".enc.yaml")
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatalf("WriteFile returned error: %v", err)
			}
			fromPath, err := secretfile.Classify(path)
			if err != nil {
				t.Fatalf("Classify returned error: %v", err)
			}
			fromBytes := secretfile.ClassifyBytes([]byte(body))
			if fromBytes.State != fromPath.State || string(fromBytes.Raw) != string(fromPath.Raw) {
				t.Fatalf("ClassifyBytes = %q, Classify = %q", fromBytes.State, fromPath.State)
			}
			if string(fromBytes.State) != name {
				t.Fatalf("expected state %q, got %q", name, fromBytes.State)
			}
		})
	}
}

func TestClassifyBytesTreatsEmptyInputAsPlaceholder(t *testing.T) {
	if got := secretfile.ClassifyBytes(nil).State; got != secretfile.StatePlaceholder {
		t.Fatalf("expected placeholder, got %q", got)
	}
}

func stringPtr(value string) *string {
	return &value
}
