package sopsutil_test

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/getsops/sops/v3/logging"
	"github.com/jrpbuilds/keyseal/internal/sopsutil"
)

const testAgeKey = `# created: 2026-05-23T08:04:13+01:00
# public key: age1xlp99sh4c9dheuskt900y83mdcxdhjp0zhejf2l4lkh6fdzl0dsqsx4yrx
AGE-SECRET-KEY-1640MNDQ274MATFJR6D6R6GFW3FUDJLDUAM84TXRM9L70FUCEXV0QMEH0CE
`

const wrongAgeKey = `# created: 2026-05-23T08:06:59+01:00
# public key: age1e82vhfhpxva6rxz8nql5wfd6k9pp7w30xtjmc0r2ezy49keaeursygjxza
AGE-SECRET-KEY-125U2KVSRWTT7PLRZ7M25U3SQ3RHX5ZEH3X8PEZ4Z60G94JUKJH7S99EM69
`

const testEncryptedYAML = `version: 1
kind: env
name: ENC[AES256_GCM,data:Riq9aP5zSklrQVihLs8Z6cyGFoTx9m8=,iv:afiJHqzI77QqsAAPUTkTo2x9NFHIAtVwUhZqso2SUHY=,tag:Tr1eyGNfEykmeP0NsEEeTQ==,type:str]
values:
    APP_ENV: ENC[AES256_GCM,data:EkOfgsyFrpZH4g==,iv:avltATTRTS4vEsXi1IISZD0zo/4+M+Wx/3hOL3tbj+I=,tag:uzT57+ASpUVueI0RjudbPA==,type:str]
    DB_HOST: ENC[AES256_GCM,data:CyE=,iv:wUXVOYuWG9bcInf5CS3B7nUZMYXwYxveTWs5bbZdB6c=,tag:2LNNfJcBu5MFFyzot71UiA==,type:str]
sops:
    age:
        - recipient: age1xlp99sh4c9dheuskt900y83mdcxdhjp0zhejf2l4lkh6fdzl0dsqsx4yrx
          enc: |
            -----BEGIN AGE ENCRYPTED FILE-----
            YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSByUmNYSUREdEhrSlZ6a2pt
            SUtKZjMrOHNCc2l6TEdLRTErbWRTK0hTWkcwCjVuMmJucC93WWQzVnBoMllnWGdq
            ZGNPS3dEbThVMGtpc2VPQXo3cDZaTE0KLS0tIDZEeU1hK3d5UVZDWllBZXlnU2x5
            R2orSW1LR3pyMllDZVJYR1lEazVMbzgKk6v8JQFsBbZZ7H2Jrm3wW7Stz/fc4Xws
            eDgyjtDkBhCCLjYpMh7MZoS9ryZ0YQWXquEhJIR4fZtqmCrNf5T3Xw==
            -----END AGE ENCRYPTED FILE-----
    lastmodified: "2026-05-23T07:04:13Z"
    mac: ENC[AES256_GCM,data:wbWeTqecwI4WPC0QEuJv+4POBdepZoUwnsx7qF7RLpGspMrqXAqNzMF3IVd0HVIeupWHDi42s1t6MNfTE/5adIyprH3+3Vrc900hmRGFzKERMIwATUhqgtKkhO50YQ7CGX5blevr21Jadce56Q+cXJs+rv/criVcf5V0zrhEhDo=,iv:7xhnkpYcJgtnz1jkhHW/tuZ7F4xfSJfb9/MBrW7XFGs=,tag:LZW2wKKLgMXuftGAlqiHtQ==,type:str]
    encrypted_regex: ^(name|values)$
    version: 3.12.2
`

const warningEncryptedYAML = `version: ENC[AES256_GCM,data:Dw==,iv:aSzwJu06+uKzROt6MjQaTGAiRwY8F45vLyzi4obAhso=,tag:RCljtMpsFYxM+Ykv7WWdKA==,type:int]
kind: ENC[AES256_GCM,data:WGuj,iv:6NrOkkSg+iXaaMneWbIWP3HG4n6xQ+SohzA2ChwAhSU=,tag:xxYoqiV/pmW4/y8zvIV+lA==,type:str]
name: ENC[AES256_GCM,data:4AmnoUFpetdRdE9PLqZopUilnJkmYEI=,iv:OIJ7h2CfteteX3Ou7KJ5uDbD+rAd/ycSQtbCH8b3yvk=,tag:oahY3RiZJjI/9LKxTmfpvQ==,type:str]
values:
    APP_ENV: ENC[AES256_GCM,data:z1t/XVtsFjOAqA==,iv:cSZjKsjurrPhon3vI8Q2d/BwLgNISpqOBusOuicm0DE=,tag:qmmVLmGiJfcyd4Y6+4bVTA==,type:str]
    DB_HOST: ENC[AES256_GCM,data:xt8=,iv:A30J5QFTPR5WLBeOyLUXh7iiYwkhBoObeXINN7q76hQ=,tag:19/36OzjY0o6/Un90/79Vw==,type:str]
sops:
    age:
        - recipient: age1xlp99sh4c9dheuskt900y83mdcxdhjp0zhejf2l4lkh6fdzl0dsqsx4yrx
          enc: |
            -----BEGIN AGE ENCRYPTED FILE-----
            YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBNeXBIZ1VVTnloRDdCM3Jv
            ODVGWFFJSzlWSnJxaDJiMjdJcGZJWHp0VVZrCkxjZkRkQlpXN1M4aEozQjFwMU5U
            d1ZCYitSa1R0cG0vb3R5TXNyeXRBN3MKLS0tIGcxb05DbG1XUmtBbUMvNXUrd0Iz
            V0ozekZONHRTZi92YWxTSHBCdmxCa2sKyV77QE0g/61NjFbbTVd06EHnBZ3EmvjX
            e57v2e4e1uZ/mZGWGBgcd5qcKyHglUaW1X9k6M5fPY2B/AGmovPzaw==
            -----END AGE ENCRYPTED FILE-----
    lastmodified: "2026-05-23T07:44:14Z"
    mac: ENC[AES256_GCM,data:XubQV2tkljUIbuDLv/sRTe4MUaagJ6EMmGi12ULFiqsmOV75Hn/bunl0ZEOPUhgTWhPgu4OPhi4s/tpYC5+GeyoNzP+KAD7DAg9UlX+H1YLtC8ISEfRIwzav191XC3UpW7yAw6v27oZ1LwaQ2nqEA6J5nyYH2Qu0V0V/zm+D3gg=,iv:NZMsExVfmsfBV1romlSNlj9c6ogDKob2m3tc6wj45qg=,tag:tROwg6mbnV4UKcGcbd202A==,type:str]
    unencrypted_suffix: _unencrypted
    version: 3.12.2

# dry-run smoke marker
`

func TestDecryptFileUsesSOPSLibrary(t *testing.T) {
	secretPath, keyPath := writeLibraryDecryptFixture(t, testAgeKey)

	out, err := sopsutil.DecryptFile(secretPath, "yaml", keyPath)
	if err != nil {
		t.Fatalf("DecryptFile returned error: %v", err)
	}
	got := string(out)
	if !strings.Contains(got, "APP_ENV: production") || !strings.Contains(got, "DB_HOST: db") {
		t.Fatalf("unexpected decrypt output: %q", got)
	}
}

func TestDecryptFileSuppressesSOPSLibraryWarnings(t *testing.T) {
	secretPath, keyPath := writeLibraryDecryptFixture(t, testAgeKey)
	if err := os.WriteFile(secretPath, []byte(warningEncryptedYAML), 0o600); err != nil {
		t.Fatalf("rewrite encrypted fixture: %v", err)
	}
	var logOutput bytes.Buffer
	restore := redirectSOPSLoggers(&logOutput)
	defer restore()

	if _, err := sopsutil.DecryptFile(secretPath, "yaml", keyPath); err != nil {
		t.Fatalf("DecryptFile returned error: %v", err)
	}
	if logOutput.Len() != 0 {
		t.Fatalf("expected SOPS library warnings to be suppressed, got %q", logOutput.String())
	}
}

func TestDecryptFileWithWarningsCapturesSOPSLibraryWarnings(t *testing.T) {
	secretPath, keyPath := writeLibraryDecryptFixture(t, testAgeKey)
	if err := os.WriteFile(secretPath, []byte(warningEncryptedYAML), 0o600); err != nil {
		t.Fatalf("rewrite encrypted fixture: %v", err)
	}

	out, warnings, err := sopsutil.DecryptFileWithWarnings(secretPath, "yaml", keyPath)
	if err != nil {
		t.Fatalf("DecryptFileWithWarnings returned error: %v", err)
	}
	if !strings.Contains(string(out), "APP_ENV: production") {
		t.Fatalf("expected plaintext output, got %q", string(out))
	}
	if !containsWarning(warnings, "possibly unencrypted comment") || !containsWarning(warnings, "dry-run smoke marker") {
		t.Fatalf("expected captured unencrypted comment warning, got %#v", warnings)
	}
}

func TestDecryptFileUsesConfiguredAgeKeyFileWhenEnvUnset(t *testing.T) {
	secretPath, keyPath := writeLibraryDecryptFixture(t, testAgeKey)
	t.Setenv("SOPS_AGE_KEY_FILE", "")

	out, err := sopsutil.DecryptFile(secretPath, "yaml", keyPath)
	if err != nil {
		t.Fatalf("DecryptFile returned error: %v", err)
	}
	if !strings.Contains(string(out), "APP_ENV: production") {
		t.Fatalf("expected configured age key file to decrypt fixture, got %q", string(out))
	}
}

func TestDecryptFilePrefersExistingAgeKeyEnv(t *testing.T) {
	secretPath, configuredKeyPath := writeLibraryDecryptFixture(t, wrongAgeKey)
	actualKeyPath := writeAgeKey(t, t.TempDir(), testAgeKey)
	t.Setenv("SOPS_AGE_KEY_FILE", actualKeyPath)

	out, err := sopsutil.DecryptFile(secretPath, "yaml", configuredKeyPath)
	if err != nil {
		t.Fatalf("DecryptFile returned error: %v", err)
	}
	if !strings.Contains(string(out), "APP_ENV: production") {
		t.Fatalf("expected existing env age key to win, got %q", string(out))
	}
}

func TestDecryptFileRestoresAgeKeyEnvAfterSuccess(t *testing.T) {
	secretPath, keyPath := writeLibraryDecryptFixture(t, testAgeKey)
	oldValue, hadOldValue := os.LookupEnv("SOPS_AGE_KEY_FILE")
	t.Cleanup(func() { restoreEnv(t, "SOPS_AGE_KEY_FILE", oldValue, hadOldValue) })
	if err := os.Unsetenv("SOPS_AGE_KEY_FILE"); err != nil {
		t.Fatalf("Unsetenv returned error: %v", err)
	}

	if _, err := sopsutil.DecryptFile(secretPath, "yaml", keyPath); err != nil {
		t.Fatalf("DecryptFile returned error: %v", err)
	}
	if _, ok := os.LookupEnv("SOPS_AGE_KEY_FILE"); ok {
		t.Fatal("expected SOPS_AGE_KEY_FILE to be unset after decrypt")
	}
}

func TestDecryptFileRestoresAgeKeyEnvAfterError(t *testing.T) {
	secretPath, keyPath := writeLibraryDecryptFixture(t, wrongAgeKey)
	oldValue, hadOldValue := os.LookupEnv("SOPS_AGE_KEY_FILE")
	t.Cleanup(func() { restoreEnv(t, "SOPS_AGE_KEY_FILE", oldValue, hadOldValue) })
	if err := os.Unsetenv("SOPS_AGE_KEY_FILE"); err != nil {
		t.Fatalf("Unsetenv returned error: %v", err)
	}

	if _, err := sopsutil.DecryptFile(secretPath, "yaml", keyPath); err == nil {
		t.Fatal("expected wrong age key to fail decrypt")
	}
	if _, ok := os.LookupEnv("SOPS_AGE_KEY_FILE"); ok {
		t.Fatal("expected SOPS_AGE_KEY_FILE to be unset after decrypt error")
	}
}

func TestDecryptFileFailsWithMissingOrWrongAgeKey(t *testing.T) {
	secretPath, keyPath := writeLibraryDecryptFixture(t, wrongAgeKey)

	_, err := sopsutil.DecryptFile(secretPath, "yaml", keyPath)
	if err == nil {
		t.Fatal("expected wrong age key to fail decrypt")
	}
	if !strings.Contains(err.Error(), "decrypt") {
		t.Fatalf("expected decrypt context in error, got %v", err)
	}
}

func TestDecryptFileFailsWithNoAgeKey(t *testing.T) {
	secretPath, _ := writeLibraryDecryptFixture(t, testAgeKey)
	clearAgeKeyEnv(t)

	_, err := sopsutil.DecryptFile(secretPath, "yaml", "")
	if err == nil {
		t.Fatal("expected decrypt to fail when no age key is available")
	}
	for _, phrase := range []string{"install sops", "sops binary", "sops executable", "sops --decrypt"} {
		if strings.Contains(err.Error(), phrase) {
			t.Fatalf("error must not suggest installing sops binary: %v", err)
		}
	}
	if !strings.Contains(err.Error(), "age") && !strings.Contains(err.Error(), "key") {
		t.Fatalf("expected error about age/key, got: %v", err)
	}
}

func TestDecryptFileFailsWithMissingConfiguredAgeKeyFile(t *testing.T) {
	secretPath, _ := writeLibraryDecryptFixture(t, testAgeKey)
	clearAgeKeyEnv(t)

	missingPath := filepath.Join(t.TempDir(), "nonexistent-age.key")
	_, err := sopsutil.DecryptFile(secretPath, "yaml", missingPath)
	if err == nil {
		t.Fatal("expected decrypt to fail when configured age key file does not exist")
	}
	for _, phrase := range []string{"install sops", "sops binary", "sops executable", "sops --decrypt"} {
		if strings.Contains(err.Error(), phrase) {
			t.Fatalf("error must not suggest installing sops binary: %v", err)
		}
	}
}

func TestEncryptFileWithStubBinary(t *testing.T) {
	dir := t.TempDir()
	binDir := filepath.Join(dir, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatalf("MkdirAll returned error: %v", err)
	}

	scriptPath := filepath.Join(binDir, "fake-sops")
	script := "#!/bin/sh\nif [ \"$1\" = \"encrypt\" ] && [ \"$2\" = \"--filename-override\" ]; then\n  printf 'version: 1\\nkind: env\\nname: ENC[AES256_GCM,data:name,type:str]\\nvalues:\\n  APP_ENV: ENC[AES256_GCM,data:value,type:str]\\nsops:\\n  version: 3.9.0\\n'\n  exit 0\nfi\nexit 1\n"
	if err := os.WriteFile(scriptPath, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake sops: %v", err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	out, err := sopsutil.EncryptFile("fake-sops", "", []byte("version: 1\nkind: env\nname: production/platform/app\n"), "production/platform/app.enc.yaml")
	if err != nil {
		t.Fatalf("EncryptFile returned error: %v", err)
	}
	if !strings.Contains(string(out), "sops:") {
		t.Fatalf("expected encrypted output, got %q", string(out))
	}
	if strings.Contains(string(out), "production/platform/app") {
		t.Fatalf("expected encrypted output to avoid raw plaintext, got %q", string(out))
	}
}

// TestEncryptFilePassesPlaintextOnStdinOnly verifies plaintext reaches SOPS
// through stdin, never through arguments or a temp file path.
func TestEncryptFilePassesPlaintextOnStdinOnly(t *testing.T) {
	dir := t.TempDir()
	binDir := filepath.Join(dir, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatalf("MkdirAll returned error: %v", err)
	}

	argsPath := filepath.Join(dir, "args.txt")
	stdinPath := filepath.Join(dir, "stdin.txt")
	scriptPath := filepath.Join(binDir, "fake-sops")
	script := "#!/bin/sh\nprintf '%s\\n' \"$*\" > \"" + argsPath + "\"\ncat > \"" + stdinPath + "\"\nprintf 'ENC[test]\\n'\n"
	if err := os.WriteFile(scriptPath, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake sops: %v", err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	plaintext := "version: 1\nvalues:\n  K: stdin-only-marker\n"
	if _, err := sopsutil.EncryptFile("fake-sops", "", []byte(plaintext), "production/platform/app.enc.yaml"); err != nil {
		t.Fatalf("EncryptFile returned error: %v", err)
	}

	args, err := os.ReadFile(argsPath)
	if err != nil {
		t.Fatalf("ReadFile returned error: %v", err)
	}
	if got := strings.TrimSpace(string(args)); got != "encrypt --filename-override production/platform/app.enc.yaml" {
		t.Fatalf("unexpected sops args: %q", got)
	}
	stdin, err := os.ReadFile(stdinPath)
	if err != nil {
		t.Fatalf("ReadFile returned error: %v", err)
	}
	if string(stdin) != plaintext {
		t.Fatalf("expected plaintext on stdin, got %q", string(stdin))
	}
}

// TestUpdateKeysPassesYesFlagWhenRequested verifies that non-interactive mode
// passes -y through to SOPS.
func TestUpdateKeysPassesYesFlagWhenRequested(t *testing.T) {
	dir := t.TempDir()
	binDir := filepath.Join(dir, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatalf("MkdirAll returned error: %v", err)
	}

	argsPath := filepath.Join(dir, "args.txt")
	scriptPath := filepath.Join(binDir, "fake-sops")
	script := "#!/bin/sh\nprintf '%s\\n' \"$*\" > \"" + argsPath + "\"\nexit 0\n"
	if err := os.WriteFile(scriptPath, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake sops: %v", err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	secretPath := filepath.Join(dir, "app.enc.yaml")
	if err := os.WriteFile(secretPath, []byte("sops:\n  version: 3.9.0\n"), 0o600); err != nil {
		t.Fatalf("write secret: %v", err)
	}

	if err := sopsutil.UpdateKeys("fake-sops", "", secretPath, true); err != nil {
		t.Fatalf("UpdateKeys returned error: %v", err)
	}
	body, err := os.ReadFile(argsPath)
	if err != nil {
		t.Fatalf("ReadFile returned error: %v", err)
	}
	if !strings.Contains(string(body), "updatekeys -y "+secretPath) {
		t.Fatalf("expected -y in args, got %q", string(body))
	}
}

// TestUpdateKeysOmitsYesFlagByDefault verifies that interactive mode invokes
// SOPS without the non-interactive confirmation flag.
func TestUpdateKeysOmitsYesFlagByDefault(t *testing.T) {
	dir := t.TempDir()
	binDir := filepath.Join(dir, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatalf("MkdirAll returned error: %v", err)
	}

	argsPath := filepath.Join(dir, "args.txt")
	scriptPath := filepath.Join(binDir, "fake-sops")
	script := "#!/bin/sh\nprintf '%s\\n' \"$*\" > \"" + argsPath + "\"\nexit 0\n"
	if err := os.WriteFile(scriptPath, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake sops: %v", err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	secretPath := filepath.Join(dir, "app.enc.yaml")
	if err := os.WriteFile(secretPath, []byte("sops:\n  version: 3.9.0\n"), 0o600); err != nil {
		t.Fatalf("write secret: %v", err)
	}

	if err := sopsutil.UpdateKeys("fake-sops", "", secretPath, false); err != nil {
		t.Fatalf("UpdateKeys returned error: %v", err)
	}
	body, err := os.ReadFile(argsPath)
	if err != nil {
		t.Fatalf("ReadFile returned error: %v", err)
	}
	if string(body) != "updatekeys "+secretPath+"\n" {
		t.Fatalf("expected default args without -y, got %q", string(body))
	}
}

func writeLibraryDecryptFixture(t *testing.T, keyBody string) (string, string) {
	t.Helper()
	clearAgeKeyEnv(t)
	dir := t.TempDir()
	secretPath := filepath.Join(dir, "app.enc.yaml")
	if err := os.WriteFile(secretPath, []byte(testEncryptedYAML), 0o600); err != nil {
		t.Fatalf("write encrypted fixture: %v", err)
	}
	keyPath := writeAgeKey(t, dir, keyBody)
	return secretPath, keyPath
}

func writeAgeKey(t *testing.T, dir, keyBody string) string {
	t.Helper()
	keyPath := filepath.Join(dir, "age.key")
	if err := os.WriteFile(keyPath, []byte(keyBody), 0o600); err != nil {
		t.Fatalf("write age key: %v", err)
	}
	return keyPath
}

// clearAgeKeyEnv unsets age key env vars and redirects default key paths so
// tests never accidentally pick up a real developer-machine age key.
// Previous values are restored in t.Cleanup.
func clearAgeKeyEnv(t *testing.T) {
	t.Helper()

	prevKeyFile, hadKeyFile := os.LookupEnv("SOPS_AGE_KEY_FILE")
	os.Unsetenv("SOPS_AGE_KEY_FILE")
	t.Cleanup(func() {
		if hadKeyFile {
			os.Setenv("SOPS_AGE_KEY_FILE", prevKeyFile)
		} else {
			os.Unsetenv("SOPS_AGE_KEY_FILE")
		}
	})

	prevKey, hadKey := os.LookupEnv("SOPS_AGE_KEY")
	os.Unsetenv("SOPS_AGE_KEY")
	t.Cleanup(func() {
		if hadKey {
			os.Setenv("SOPS_AGE_KEY", prevKey)
		} else {
			os.Unsetenv("SOPS_AGE_KEY")
		}
	})

	prevHome, hadHome := os.LookupEnv("HOME")
	os.Setenv("HOME", t.TempDir())
	t.Cleanup(func() {
		if hadHome {
			os.Setenv("HOME", prevHome)
		} else {
			os.Unsetenv("HOME")
		}
	})

	prevXDG, hadXDG := os.LookupEnv("XDG_CONFIG_HOME")
	os.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Cleanup(func() {
		if hadXDG {
			os.Setenv("XDG_CONFIG_HOME", prevXDG)
		} else {
			os.Unsetenv("XDG_CONFIG_HOME")
		}
	})
}

func restoreEnv(t *testing.T, key, value string, hadValue bool) {
	t.Helper()
	if hadValue {
		if err := os.Setenv(key, value); err != nil {
			t.Fatalf("Setenv returned error: %v", err)
		}
		return
	}
	if err := os.Unsetenv(key); err != nil {
		t.Fatalf("Unsetenv returned error: %v", err)
	}
}

func containsWarning(warnings []string, needle string) bool {
	for _, warning := range warnings {
		if strings.Contains(warning, needle) {
			return true
		}
	}
	return false
}

func redirectSOPSLoggers(out *bytes.Buffer) func() {
	previous := map[string]io.Writer{}
	for name, logger := range logging.Loggers {
		previous[name] = logger.Out
		logger.SetOutput(out)
	}
	return func() {
		for name, output := range previous {
			if logger, ok := logging.Loggers[name]; ok {
				logger.SetOutput(output)
			}
		}
	}
}
