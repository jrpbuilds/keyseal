package cli

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestRenderSelectJSONStdoutExact(t *testing.T) {
	repoRoot := seedSelectRenderRepo(t)

	stdout, stderr, err := runRootCommandIO(t, repoRoot, nil,
		"render", "production/platform/app", "--select", "APP_ENV", "--format", "json", "--stdout")
	if err != nil {
		t.Fatalf("render select returned error: %v", err)
	}
	assertNoUnselectedLeak(t, stdout, stderr, err, "DB_HOST", "db")
	var body map[string]string
	if err := json.Unmarshal([]byte(stdout), &body); err != nil {
		t.Fatalf("stdout is not JSON: %v\n%s", err, stdout)
	}
	if len(body) != 1 || body["APP_ENV"] != "production" {
		t.Fatalf("expected exactly APP_ENV=production, got %#v", body)
	}
}

func TestRenderSelectFormatsOmitUnselected(t *testing.T) {
	repoRoot := seedSelectRenderRepo(t)

	t.Run("dotenv", func(t *testing.T) {
		stdout, stderr, err := runRootCommandIO(t, repoRoot, nil,
			"render", "production/platform/app", "--select", "APP_ENV", "--format", "dotenv", "--stdout")
		if err != nil {
			t.Fatalf("render returned error: %v", err)
		}
		assertNoUnselectedLeak(t, stdout, stderr, err, "DB_HOST", "db")
		if !strings.Contains(stdout, `APP_ENV="production"`) {
			t.Fatalf("expected APP_ENV in dotenv output, got %q", stdout)
		}
	})

	t.Run("yaml", func(t *testing.T) {
		stdout, stderr, err := runRootCommandIO(t, repoRoot, nil,
			"render", "production/platform/app", "--select", "APP_ENV", "--format", "yaml", "--stdout")
		if err != nil {
			t.Fatalf("render returned error: %v", err)
		}
		assertNoUnselectedLeak(t, stdout, stderr, err, "DB_HOST", "db")
		if !strings.Contains(stdout, "APP_ENV: production") {
			t.Fatalf("expected APP_ENV in yaml output, got %q", stdout)
		}
	})

	t.Run("out", func(t *testing.T) {
		outPath := filepath.Join(repoRoot, "selected.env")
		stdout, stderr, err := runRootCommandIO(t, repoRoot, nil,
			"render", "production/platform/app", "--select", "APP_ENV", "--format", "dotenv", "--out", outPath)
		if err != nil {
			t.Fatalf("render returned error: %v", err)
		}
		body, readErr := os.ReadFile(outPath)
		if readErr != nil {
			t.Fatalf("ReadFile returned error: %v", readErr)
		}
		assertNoUnselectedLeak(t, string(body), stdout+stderr, err, "DB_HOST", "db")
		if !strings.Contains(string(body), `APP_ENV="production"`) {
			t.Fatalf("expected APP_ENV in out file, got %q", string(body))
		}
	})
}

func TestRenderWithoutSelectStillEmitsAllKeys(t *testing.T) {
	repoRoot := seedSelectRenderRepo(t)
	stdout, _, err := runRootCommandIO(t, repoRoot, nil,
		"render", "production/platform/app", "--format", "json", "--stdout")
	if err != nil {
		t.Fatalf("render returned error: %v", err)
	}
	var body map[string]string
	if err := json.Unmarshal([]byte(stdout), &body); err != nil {
		t.Fatalf("stdout is not JSON: %v\n%s", err, stdout)
	}
	if body["APP_ENV"] != "production" || body["DB_HOST"] != "db" {
		t.Fatalf("expected full document, got %#v", body)
	}
}

func TestRenderSelectSoftOmitMissingKey(t *testing.T) {
	repoRoot := seedSelectRenderRepo(t)
	stdout, stderr, err := runRootCommandIO(t, repoRoot, nil,
		"render", "production/platform/app", "--select", "MISSING", "--format", "json", "--stdout")
	if err != nil {
		t.Fatalf("soft omit should succeed, got %v", err)
	}
	assertNoUnselectedLeak(t, stdout, stderr, err, "APP_ENV", "production", "DB_HOST", "db")
	if strings.TrimSpace(stdout) != "{}" {
		t.Fatalf("expected empty JSON object, got %q", stdout)
	}
}

func TestRenderSelectRequireAllMissing(t *testing.T) {
	repoRoot := seedSelectRenderRepo(t)
	outPath := filepath.Join(repoRoot, "should-not-exist.json")

	stdout, stderr, err := runRootCommandIO(t, repoRoot, nil,
		"render", "production/platform/app",
		"--select", "APP_ENV,MISSING",
		"--require-all",
		"--format", "json",
		"--out", outPath,
	)
	if err == nil {
		t.Fatal("expected --require-all to fail when a key is missing")
	}
	if exitCodeOf(t, err) != 2 {
		t.Fatalf("expected exit code 2, got %d (%v)", exitCodeOf(t, err), err)
	}
	if stdout != "" {
		t.Fatalf("expected empty stdout on missing-key failure, got %q", stdout)
	}
	if _, statErr := os.Stat(outPath); !os.IsNotExist(statErr) {
		t.Fatal("expected no output file after require-all failure")
	}
	if !strings.Contains(err.Error(), "selected keys not found: MISSING") {
		t.Fatalf("unexpected error: %v", err)
	}
	assertNoUnselectedLeak(t, stdout, stderr, err, "production", "db")
}

func TestRenderSelectRequireAllSuccess(t *testing.T) {
	repoRoot := seedSelectRenderRepo(t)
	stdout, stderr, err := runRootCommandIO(t, repoRoot, nil,
		"render", "production/platform/app",
		"--select", "APP_ENV,DB_HOST",
		"--require-all",
		"--format", "json",
		"--stdout",
	)
	if err != nil {
		t.Fatalf("require-all success path failed: %v", err)
	}
	var body map[string]string
	if err := json.Unmarshal([]byte(stdout), &body); err != nil {
		t.Fatalf("stdout is not JSON: %v\n%s", err, stdout)
	}
	if body["APP_ENV"] != "production" || body["DB_HOST"] != "db" {
		t.Fatalf("unexpected body: %#v stderr=%q", body, stderr)
	}
}

func TestRenderSelectFlagErrors(t *testing.T) {
	repoRoot := seedSelectRenderRepo(t)
	tests := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{
			name:    "require-all without select",
			args:    []string{"render", "production/platform/app", "--require-all", "--stdout"},
			wantErr: "--require-all requires --select",
		},
		{
			name:    "empty select",
			args:    []string{"render", "production/platform/app", "--select", ",,,", "--stdout"},
			wantErr: "--select requires at least one key name",
		},
		{
			name:    "duplicate key",
			args:    []string{"render", "production/platform/app", "--select", "APP_ENV,APP_ENV", "--stdout"},
			wantErr: "key APP_ENV is listed more than once",
		},
		{
			name:    "invalid key",
			args:    []string{"render", "production/platform/app", "--select", "not-valid", "--stdout"},
			wantErr: "invalid env key",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stdout, _, err := runRootCommandIO(t, repoRoot, nil, tt.args...)
			if err == nil {
				t.Fatalf("expected %v to fail", tt.args)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("expected error containing %q, got %q", tt.wantErr, err.Error())
			}
			if stdout != "" {
				t.Fatalf("expected empty stdout on flag error, got %q", stdout)
			}
			var coded interface{ ExitCode() int }
			if errors.As(err, &coded) {
				t.Fatalf("usage failures should use default exit 1, got coded %d", coded.ExitCode())
			}
		})
	}
}

func TestRenderSelectDecryptFailureExitCode(t *testing.T) {
	repoRoot := seedSelectRenderRepo(t)
	outPath := filepath.Join(repoRoot, "should-not-exist.env")
	wrongKeyPath := filepath.Join(repoRoot, "wrong-age.key")
	if err := os.WriteFile(wrongKeyPath, []byte(cliSecondAgeKey), 0o600); err != nil {
		t.Fatalf("write wrong age key: %v", err)
	}
	t.Setenv("SOPS_AGE_KEY_FILE", wrongKeyPath)

	stdout, stderr, err := runRootCommandIO(t, repoRoot, nil,
		"render", "production/platform/app", "--select", "APP_ENV", "--format", "json", "--out", outPath)
	if err == nil {
		t.Fatal("expected decrypt failure")
	}
	if exitCodeOf(t, err) != 3 {
		t.Fatalf("expected exit code 3, got %d (%v)", exitCodeOf(t, err), err)
	}
	if stdout != "" {
		t.Fatalf("expected empty stdout on decrypt failure, got %q", stdout)
	}
	if _, statErr := os.Stat(outPath); !os.IsNotExist(statErr) {
		t.Fatal("expected no output file after decrypt failure")
	}
	// The fixture path contains the logical segment "production"; only assert
	// against the decrypted value "db" and private key material.
	assertNoUnselectedLeak(t, stdout, stderr, err, "db", "AGE-SECRET-KEY")
}

func TestRenderSelectRealSOPSSentinelConfidentiality(t *testing.T) {
	realSOPSPath(t)
	repoRoot := t.TempDir()
	writeTestConfig(t, repoRoot)
	configureLibraryDecryptFixture(t, repoRoot)

	const selected = "ksl-select-a7c91e2f44"
	const unselected = "ksl-unselect-b8d02f3a55"
	putEncryptedDoc(t, repoRoot, "production/platform/app",
		"  SELECTED: "+selected+"\n  UNSELECTED: "+unselected+"\n")

	stdout, stderr, err := runRootCommandIO(t, repoRoot, nil,
		"render", "production/platform/app",
		"--select", "SELECTED",
		"--format", "json",
		"--stdout",
	)
	if err != nil {
		t.Fatalf("selected render failed: %v", err)
	}
	assertNoUnselectedLeak(t, stdout, stderr, err, unselected, "UNSELECTED")
	var body map[string]string
	if err := json.Unmarshal([]byte(stdout), &body); err != nil {
		t.Fatalf("stdout is not JSON: %v\n%s", err, stdout)
	}
	if body["SELECTED"] != selected || len(body) != 1 {
		t.Fatalf("unexpected selected body: %#v", body)
	}

	stdout, stderr, err = runRootCommandIO(t, repoRoot, nil,
		"render", "production/platform/app",
		"--select", "SELECTED,ABSENT",
		"--require-all",
		"--format", "json",
		"--stdout",
	)
	if err == nil || exitCodeOf(t, err) != 2 {
		t.Fatalf("expected require-all exit 2, err=%v", err)
	}
	assertNoUnselectedLeak(t, stdout, stderr, err, selected, unselected)

	putEncryptedInvalidKind(t, repoRoot, "production/platform/bad", selected)

	stdout, stderr, err = runRootCommandIO(t, repoRoot, nil,
		"render", "production/platform/bad",
		"--select", "TOKEN",
		"--format", "json",
		"--stdout",
	)
	if err == nil || exitCodeOf(t, err) != 4 {
		t.Fatalf("expected invalid document exit 4, err=%v", err)
	}
	assertNoUnselectedLeak(t, stdout, stderr, err, selected, "AGE-SECRET-KEY", "ENC[")
}

func seedSelectRenderRepo(t *testing.T) string {
	t.Helper()
	repoRoot := t.TempDir()
	writeTestConfig(t, repoRoot)
	writeEncryptedFixture(t, repoRoot, "production/platform/app.enc.yaml")
	return repoRoot
}

func putEncryptedInvalidKind(t *testing.T, root, logical, sentinel string) {
	t.Helper()
	realSOPSPath(t)
	plaintext := "version: 1\nkind: notenv\nname: " + logical + "\nvalues:\n  TOKEN: " + sentinel + "\n"
	cmd := exec.Command("sops", "encrypt", "--filename-override", logical+".enc.yaml",
		"--input-type", "yaml", "--output-type", "yaml", "--age", cliTestAgePublicKey, "--encrypted-regex", "^(name|values)$")
	cmd.Stdin = strings.NewReader(plaintext)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("sops encrypt invalid kind failed: %v", err)
	}
	writeCLIFile(t, docPath(root, logical), string(out))
}

func assertNoUnselectedLeak(t *testing.T, stdout, stderr string, err error, forbidden ...string) {
	t.Helper()
	all := stdout + stderr
	if err != nil {
		all += err.Error()
	}
	for _, phrase := range forbidden {
		if phrase != "" && strings.Contains(all, phrase) {
			t.Fatalf("output leaked %q:\nstdout=%q\nstderr=%q\nerr=%v", phrase, stdout, stderr, err)
		}
	}
}
