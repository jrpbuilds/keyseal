package cli

import (
	"path/filepath"
	"strings"
	"testing"
)

const fingerprintKeyMarker = "kslfpkey-0e8b64d2a91c7f35-padding"

// seedObserveRepo builds two documents that hold the opaque marker, commits
// them, then changes the worktree so every observe command has a real delta.
// A positive control proves the marker is genuinely inside the ciphertext.
func seedObserveRepo(t *testing.T) string {
	t.Helper()
	root := seedMutationRepo(t, defaultMutationSOPSRules, cliTestAgeKey)
	if _, _, err := runRootCommandIO(t, root, strings.NewReader(confidentialityMarker+"\n"), "set", "production/app", "STRIPE_SECRET_KEY", "--stdin"); err != nil {
		t.Fatalf("set failed: %v", err)
	}
	if _, err := runRootCommand(t, root, "clone", "production/app", "production/app-next"); err != nil {
		t.Fatalf("clone failed: %v", err)
	}
	commitAll(t, root)
	if _, _, err := runRootCommandIO(t, root, strings.NewReader(confidentialityMarker+"-rotated\n"), "set", "production/app-next", "STRIPE_SECRET_KEY", "--stdin"); err != nil {
		t.Fatalf("set failed: %v", err)
	}

	for _, logical := range []string{"production/app", "production/app-next"} {
		if got := decryptDoc(t, root, logical).Values["STRIPE_SECRET_KEY"]; !strings.Contains(got, confidentialityMarker) {
			t.Fatalf("positive control: %s does not hold the marker", logical)
		}
	}
	return root
}

func TestObserveCommandsNeverEmitKnownSecretValues(t *testing.T) {
	root := seedObserveRepo(t)
	keyFile := filepath.Join(t.TempDir(), "fingerprint.key")
	writeFileForCLI(t, keyFile, fingerprintKeyMarker)
	t.Setenv("KEYSEAL_FINGERPRINT_KEY_FILE", keyFile)
	tmpDir := t.TempDir()
	t.Setenv("TMPDIR", tmpDir)

	rich := []string{"--show-length", "--show-type", "--fingerprint"}
	for name, args := range map[string][]string{
		"inspect text":       {"inspect", "production/app"},
		"inspect json":       append([]string{"inspect", "production/app", "--json"}, rich...),
		"inspect revision":   append([]string{"inspect", "production/app", "--to", "HEAD", "--json"}, rich...),
		"compare text":       {"compare", "production/app", "production/app-next"},
		"compare json":       append([]string{"compare", "production/app", "production/app-next", "--json"}, rich...),
		"compare assert":     {"compare", "production/app", "production/app-next", "--key", "STRIPE_SECRET_KEY", "--assert-unequal"},
		"compare assert bad": {"compare", "production/app", "production/app-next", "--key", "STRIPE_SECRET_KEY", "--assert-equal"},
		"semantic text":      {"diff", "production/app-next", "--semantic"},
		"semantic json":      append([]string{"diff", "production/app-next", "--semantic", "--json"}, rich...),
		"semantic revision":  {"diff", "production/app-next", "--semantic", "--to", "HEAD", "--assert-equal"},
	} {
		t.Run(name, func(t *testing.T) {
			stdout, stderr, err := runRootCommandIO(t, root, nil, args...)
			assertNoSecretOutput(t, stdout, stderr, err)
			if !strings.Contains(stdout, "STRIPE_SECRET_KEY") {
				t.Fatalf("expected the report to name the key, so the scan is not vacuous:\n%s", stdout)
			}
		})
	}
	assertMarkerAbsent(t, tmpDir, root)
}

func TestObserveFailuresNeverEmitKnownSecretValues(t *testing.T) {
	root := seedObserveRepo(t)
	writeFileForCLI(t, docPath(root, "production/plain"), "version: 1\nkind: env\nvalues:\n  TOKEN: "+confidentialityMarker+"\n")
	writeFileForCLI(t, docPath(root, "production/placeholder"), " \n")
	shortKey := filepath.Join(t.TempDir(), "short.key")
	writeFileForCLI(t, shortKey, "x")

	for name, tc := range map[string]struct {
		args  []string
		setup func(t *testing.T)
	}{
		"plaintext inspect":   {args: []string{"inspect", "production/plain", "--json"}},
		"plaintext compare":   {args: []string{"compare", "production/plain", "production/app"}},
		"plaintext semantic":  {args: []string{"diff", "production/plain", "--semantic"}},
		"placeholder compare": {args: []string{"compare", "production/app", "production/placeholder"}},
		"unknown revision":    {args: []string{"inspect", "production/app", "--to", "no-such-rev"}},
		"decrypt failure inspect": {
			args:  []string{"inspect", "production/app"},
			setup: useWrongAgeKey,
		},
		"decrypt failure compare": {
			args:  []string{"compare", "production/app", "production/app-next", "--json"},
			setup: useWrongAgeKey,
		},
		"decrypt failure semantic": {
			args:  []string{"diff", "production/app", "--semantic"},
			setup: useWrongAgeKey,
		},
		"bad fingerprint key": {
			args: []string{"inspect", "production/app", "--fingerprint"},
			setup: func(t *testing.T) {
				t.Setenv("KEYSEAL_FINGERPRINT_KEY_FILE", shortKey)
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			if tc.setup != nil {
				tc.setup(t)
			}
			stdout, stderr, err := runRootCommandIO(t, root, nil, tc.args...)
			if err == nil {
				t.Fatal("expected the command to fail")
			}
			assertNoSecretOutput(t, stdout, stderr, err)
		})
	}
}

func useWrongAgeKey(t *testing.T) {
	t.Helper()
	keyPath := filepath.Join(t.TempDir(), "wrong.key")
	writeFileForCLI(t, keyPath, cliSecondAgeKey)
	t.Setenv("SOPS_AGE_KEY_FILE", keyPath)
}

// assertNoSecretOutput scans every channel a user or log collector could see.
func assertNoSecretOutput(t *testing.T, stdout, stderr string, err error) {
	t.Helper()
	all := stdout + stderr
	if err != nil {
		all += err.Error()
	}
	for _, forbidden := range []string{confidentialityMarker, fingerprintKeyMarker, "ENC[AES256_GCM", "AGE-SECRET-KEY"} {
		if strings.Contains(all, forbidden) {
			t.Fatalf("output contains %q:\nstdout=%s\nstderr=%s\nerr=%v", forbidden, stdout, stderr, err)
		}
	}
	if stderr != "" {
		t.Fatalf("unexpected stderr: %q", stderr)
	}
}
