package doctor_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jrpbuilds/keyseal/internal/buildinfo"
	"github.com/jrpbuilds/keyseal/internal/doctor"
)

const doctorAgeKey = `# created: 2026-05-23T08:04:13+01:00
# public key: age1xlp99sh4c9dheuskt900y83mdcxdhjp0zhejf2l4lkh6fdzl0dsqsx4yrx
AGE-SECRET-KEY-1640MNDQ274MATFJR6D6R6GFW3FUDJLDUAM84TXRM9L70FUCEXV0QMEH0CE
`

const doctorWrongAgeKey = `# created: 2026-05-23T08:06:59+01:00
# public key: age1e82vhfhpxva6rxz8nql5wfd6k9pp7w30xtjmc0r2ezy49keaeursygjxza
AGE-SECRET-KEY-125U2KVSRWTT7PLRZ7M25U3SQ3RHX5ZEH3X8PEZ4Z60G94JUKJH7S99EM69
`

const doctorEncryptedYAML = `version: 1
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

const doctorWarningEncryptedYAML = `version: ENC[AES256_GCM,data:Dw==,iv:aSzwJu06+uKzROt6MjQaTGAiRwY8F45vLyzi4obAhso=,tag:RCljtMpsFYxM+Ykv7WWdKA==,type:int]
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

func TestDoctorRunHappyPath(t *testing.T) {
	dir := t.TempDir()
	writeFakeSOPS(t, dir, "fake-sops", "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then\n  echo 'sops 3.9.0'\n  exit 0\nfi\nif [ \"$1\" = \"--decrypt\" ]; then\n  printf 'version: 1\\nkind: env\\nname: production/platform/app\\nvalues:\\n  APP_ENV: production\\n'\n  exit 0\nfi\nexit 0\n")
	writeFakeSOPS(t, dir, "age", "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then\n  echo 'age 1.2.0'\n  exit 0\nfi\nexit 0\n")
	writeDoctorConfig(t, dir, "fake-sops", "0600")
	writeSOPSConfig(t, dir, "creation_rules:\n  - path_regex: production/.*\\.enc\\.yaml$\n    age: age1realrecipient\n")
	writeEncryptedSecret(t, dir, "production/platform/app.enc.yaml")

	result, err := doctor.Run(dir, doctor.Options{})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if result.HasFailures() {
		t.Fatalf("expected doctor to pass, got %#v", result.Checks)
	}

	check := findCheck(t, result, "sops binary")
	if check.Status != doctor.StatusOK {
		t.Fatalf("expected sops binary check to pass, got %#v", check)
	}
	if !containsSubstring(check.Details, "sops 3.9.0") {
		t.Fatalf("expected version detail, got %#v", check.Details)
	}

	ageCheck := findCheck(t, result, "age binary")
	if ageCheck.Status != doctor.StatusOK {
		t.Fatalf("expected age binary check to pass, got %#v", ageCheck)
	}

	versionCheck := findCheck(t, result, doctor.CheckNameKeysealVersion)
	if versionCheck.Status != doctor.StatusOK {
		t.Fatalf("expected keyseal version check to pass when unset, got %#v", versionCheck)
	}
	if !strings.Contains(versionCheck.Summary, "No requirements.keyseal set") {
		t.Fatalf("unexpected keyseal version summary: %#v", versionCheck)
	}
}

func TestDoctorKeysealVersionRequirement(t *testing.T) {
	orig := buildinfo.Version
	t.Cleanup(func() { buildinfo.Version = orig })

	dir := t.TempDir()
	writeFakeSOPS(t, dir, "fake-sops", "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then\n  echo 'sops 3.9.0'\n  exit 0\nfi\nexit 0\n")
	writeFakeSOPS(t, dir, "age", "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then\n  echo 'age 1.2.0'\n  exit 0\nfi\nexit 0\n")
	writeDoctorConfigWithRequirement(t, dir, "fake-sops", "0600", ">=1.1.0")
	writeSOPSConfig(t, dir, "creation_rules:\n  - path_regex: production/.*\\.enc\\.yaml$\n    age: age1realrecipient\n")
	writeEncryptedSecret(t, dir, "production/platform/app.enc.yaml")

	buildinfo.Version = "v0.2.0"
	result, err := doctor.Run(dir, doctor.Options{})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if !result.HasFailures() {
		t.Fatal("expected unmet requirements.keyseal to fail doctor")
	}
	check := findCheck(t, result, doctor.CheckNameKeysealVersion)
	if check.Status != doctor.StatusFail {
		t.Fatalf("expected keyseal version fail, got %#v", check)
	}
	if !containsSubstring(check.Details, "v0.2.0") || !containsSubstring(check.Details, ">=1.1.0") {
		t.Fatalf("expected running and required versions in details, got %#v", check.Details)
	}
	skip := findCheck(t, result, "secret discovery")
	if skip.Status != doctor.StatusSkip {
		t.Fatalf("expected secret discovery skip on version fail, got %#v", skip)
	}

	buildinfo.Version = "v1.1.0"
	result, err = doctor.Run(dir, doctor.Options{})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	check = findCheck(t, result, doctor.CheckNameKeysealVersion)
	if check.Status != doctor.StatusOK {
		t.Fatalf("expected keyseal version ok when satisfied, got %#v", check)
	}
	if result.HasFailures() {
		t.Fatalf("expected doctor to pass when requirement satisfied, got %#v", result.Checks)
	}
}

func TestDoctorFailsWhenKeysealConfigMissing(t *testing.T) {
	dir := t.TempDir()

	result, err := doctor.Run(dir, doctor.Options{})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if !result.HasFailures() {
		t.Fatal("expected missing config to fail")
	}

	check := findCheck(t, result, "keyseal.yaml")
	if check.Status != doctor.StatusFail {
		t.Fatalf("expected missing keyseal.yaml failure, got %#v", check)
	}
}

func TestDoctorFailsWhenKeysealConfigInvalid(t *testing.T) {
	dir := t.TempDir()
	body := "version: 1\ndefaults:\n  file_mode: invalid\nvalidation:\n  key_pattern: \"[\"\n"
	if err := os.WriteFile(filepath.Join(dir, "keyseal.yaml"), []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	writeSOPSConfig(t, dir, "creation_rules:\n  - path_regex: production/.*\\.enc\\.yaml$\n    age: age1realrecipient\n")

	result, err := doctor.Run(dir, doctor.Options{})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	check := findCheck(t, result, "keyseal.yaml")
	if check.Status != doctor.StatusFail {
		t.Fatalf("expected invalid keyseal.yaml failure, got %#v", check)
	}
}

func TestDoctorFailsWhenSOPSConfigMissing(t *testing.T) {
	dir := t.TempDir()
	writeDoctorConfig(t, dir, "missing-sops", "0600")

	result, err := doctor.Run(dir, doctor.Options{})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	check := findCheck(t, result, ".sops.yaml")
	if check.Status != doctor.StatusFail {
		t.Fatalf("expected missing .sops.yaml failure, got %#v", check)
	}
}

func TestDoctorReportsSOPSBinaryBeforeSOPSConfig(t *testing.T) {
	dir := t.TempDir()
	writeDoctorConfig(t, dir, "missing-sops", "0600")

	result, err := doctor.Run(dir, doctor.Options{})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if len(result.Checks) < 3 {
		t.Fatalf("expected multiple checks, got %#v", result.Checks)
	}
	if result.Checks[0].Name != "sops binary" || result.Checks[1].Name != "age binary" || result.Checks[2].Name != "keyseal.yaml" {
		t.Fatalf("expected tool checks immediately after config, got %#v", result.Checks[:3])
	}
	if result.Checks[0].Status != doctor.StatusOK {
		t.Fatalf("expected missing SOPS to be informational for read-only checks, got %#v", result.Checks[0])
	}
	if !containsSubstring(result.Checks[0].Details, "Read-only") {
		t.Fatalf("expected read-only detail, got %#v", result.Checks[0].Details)
	}
	if !containsSubstring(result.Checks[0].Remediation, "mutating commands") {
		t.Fatalf("expected sops.binary remediation, got %#v", result.Checks[0].Remediation)
	}
}

func TestDoctorReportsAgeBinaryMissingAsInformational(t *testing.T) {
	dir := t.TempDir()
	writeFakeSOPS(t, dir, "fake-sops", "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then\n  echo 'sops 3.9.0'\n  exit 0\nfi\nexit 0\n")
	writeDoctorConfigWithAge(t, dir, "fake-sops", "missing-age", "0600")
	writeSOPSConfig(t, dir, "creation_rules:\n  - path_regex: production/.*\\.enc\\.yaml$\n    age: age1realrecipient\n")

	result, err := doctor.Run(dir, doctor.Options{})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	check := findCheck(t, result, "age binary")
	if check.Status != doctor.StatusOK {
		t.Fatalf("expected missing age CLI to be informational, got %#v", check)
	}
	if !containsSubstring(check.Details, "age private key material") {
		t.Fatalf("expected age key material detail, got %#v", check.Details)
	}
	if result.HasFailures() {
		t.Fatalf("did not expect missing age warning to fail doctor, got %#v", result.Checks)
	}
}

func TestDoctorDetectsPlaceholderRecipients(t *testing.T) {
	dir := t.TempDir()
	writeDoctorConfig(t, dir, "missing-sops", "0600")
	writeSOPSConfig(t, dir, "creation_rules:\n  - path_regex: production/.*\\.enc\\.yaml$\n    age: age1REPLACE_ME,age1RECOVERY_REPLACE_ME\n")

	result, err := doctor.Run(dir, doctor.Options{})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	check := findCheck(t, result, ".sops.yaml placeholders")
	if check.Status != doctor.StatusFail {
		t.Fatalf("expected placeholder failure, got %#v", check)
	}
	if !containsSubstring(check.Details, "age1REPLACE_ME") {
		t.Fatalf("expected placeholder detail, got %#v", check.Details)
	}
}

func TestDoctorFlagsPlaintextStarterFiles(t *testing.T) {
	dir := t.TempDir()
	writeDoctorConfig(t, dir, "missing-sops", "0600")
	writeSOPSConfig(t, dir, "creation_rules:\n  - path_regex: production/.*\\.enc\\.yaml$\n    age: age1realrecipient\n")
	secretPath := filepath.Join(dir, "production/platform/app.enc.yaml")
	if err := os.MkdirAll(filepath.Dir(secretPath), 0o755); err != nil {
		t.Fatalf("MkdirAll returned error: %v", err)
	}
	secret := "version: 1\nkind: env\nname: production/platform/app\nvalues:\n  APP_ENV: production\n"
	if err := os.WriteFile(secretPath, []byte(secret), 0o600); err != nil {
		t.Fatalf("write secret: %v", err)
	}

	result, err := doctor.Run(dir, doctor.Options{})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	check := findCheck(t, result, "secret production/platform/app")
	if check.Status != doctor.StatusFail {
		t.Fatalf("expected plaintext failure, got %#v", check)
	}
	if !strings.Contains(check.Summary, "non-empty plaintext") {
		t.Fatalf("unexpected summary: %q", check.Summary)
	}
}

func TestDoctorWarnsOnEmptyPlaceholderSecretFiles(t *testing.T) {
	dir := t.TempDir()
	writeDoctorConfig(t, dir, "missing-sops", "0600")
	writeSOPSConfig(t, dir, "creation_rules:\n  - path_regex: production/.*\\.enc\\.yaml$\n    age: age1realrecipient\n")
	secretPath := filepath.Join(dir, "production/platform/app.enc.yaml")
	if err := os.MkdirAll(filepath.Dir(secretPath), 0o755); err != nil {
		t.Fatalf("MkdirAll returned error: %v", err)
	}
	if err := os.WriteFile(secretPath, nil, 0o600); err != nil {
		t.Fatalf("write secret: %v", err)
	}

	result, err := doctor.Run(dir, doctor.Options{})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	check := findCheck(t, result, "secret production/platform/app")
	if check.Status != doctor.StatusWarn {
		t.Fatalf("expected empty placeholder warning, got %#v", check)
	}
	if !strings.Contains(check.Summary, "empty or uninitialized placeholder") {
		t.Fatalf("unexpected summary: %q", check.Summary)
	}
}

func TestDoctorWarnsOnWhitespaceOnlyPlaceholderSecretFiles(t *testing.T) {
	dir := t.TempDir()
	writeDoctorConfig(t, dir, "missing-sops", "0600")
	writeSOPSConfig(t, dir, "creation_rules:\n  - path_regex: production/.*\\.enc\\.yaml$\n    age: age1realrecipient\n")
	secretPath := filepath.Join(dir, "production/platform/app.enc.yaml")
	if err := os.MkdirAll(filepath.Dir(secretPath), 0o755); err != nil {
		t.Fatalf("MkdirAll returned error: %v", err)
	}
	if err := os.WriteFile(secretPath, []byte(" \n\t"), 0o600); err != nil {
		t.Fatalf("write secret: %v", err)
	}

	result, err := doctor.Run(dir, doctor.Options{})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	check := findCheck(t, result, "secret production/platform/app")
	if check.Status != doctor.StatusWarn {
		t.Fatalf("expected whitespace placeholder warning, got %#v", check)
	}
	if !strings.Contains(check.Summary, "empty or uninitialized placeholder") {
		t.Fatalf("unexpected summary: %q", check.Summary)
	}
}

func TestDoctorDecryptsWithLibraryWhenSOPSMissing(t *testing.T) {
	dir := t.TempDir()
	writeDoctorConfig(t, dir, "missing-sops", "0600")
	writeSOPSConfig(t, dir, "creation_rules:\n  - path_regex: production/.*\\.enc\\.yaml$\n    age: age1realrecipient\n")
	writeEncryptedSecret(t, dir, "production/platform/app.enc.yaml")

	result, err := doctor.Run(dir, doctor.Options{})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	binaryCheck := findCheck(t, result, "sops binary")
	if binaryCheck.Status != doctor.StatusOK {
		t.Fatalf("expected missing sops to be informational, got %#v", binaryCheck)
	}
	secretCheck := findCheck(t, result, "secret production/platform/app")
	if secretCheck.Status != doctor.StatusOK {
		t.Fatalf("expected library decrypt validation to pass without sops CLI, got %#v", secretCheck)
	}
}

func TestDoctorReportsSOPSDecryptWarnings(t *testing.T) {
	dir := t.TempDir()
	writeDoctorConfig(t, dir, "missing-sops", "0600")
	writeSOPSConfig(t, dir, "creation_rules:\n  - path_regex: production/.*\\.enc\\.yaml$\n    age: age1realrecipient\n")
	secretPath := writeEncryptedSecret(t, dir, "production/platform/app.enc.yaml")
	if err := os.WriteFile(secretPath, []byte(doctorWarningEncryptedYAML), 0o600); err != nil {
		t.Fatalf("rewrite encrypted secret with comment: %v", err)
	}

	result, err := doctor.Run(dir, doctor.Options{})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	check := findCheck(t, result, "secret production/platform/app")
	if check.Status != doctor.StatusWarn {
		t.Fatalf("expected decrypt warning to be reported as doctor warning, got %#v", check)
	}
	if !strings.Contains(check.Summary, "SOPS compatibility warnings") {
		t.Fatalf("expected compatibility warning summary, got %q", check.Summary)
	}
	if !containsSubstring(check.Details, "possibly unencrypted comment") || !containsSubstring(check.Details, "dry-run smoke marker") {
		t.Fatalf("expected captured SOPS warning details, got %#v", check.Details)
	}
	if !containsSubstring(check.Remediation, "current SOPS CLI") {
		t.Fatalf("expected SOPS CLI remediation, got %#v", check.Remediation)
	}
}

func TestDoctorWarnsOnUnsafeFileMode(t *testing.T) {
	dir := t.TempDir()
	writeDoctorConfig(t, dir, "missing-sops", "0644")
	writeSOPSConfig(t, dir, "creation_rules:\n  - path_regex: production/.*\\.enc\\.yaml$\n    age: age1realrecipient\n")

	result, err := doctor.Run(dir, doctor.Options{})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	check := findCheck(t, result, "defaults.file_mode")
	if check.Status != doctor.StatusWarn {
		t.Fatalf("expected unsafe file mode warning, got %#v", check)
	}
}

func TestDoctorFailsWhenAgeKeyIsWrong(t *testing.T) {
	dir := t.TempDir()
	writeDoctorConfig(t, dir, "missing-sops", "0600")
	writeSOPSConfig(t, dir, "creation_rules:\n  - path_regex: production/.*\\.enc\\.yaml$\n    age: age1realrecipient\n")
	writeEncryptedSecretWithKey(t, dir, "production/platform/app.enc.yaml", doctorWrongAgeKey)

	result, err := doctor.Run(dir, doctor.Options{})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	check := findCheck(t, result, "secret production/platform/app")
	if check.Status != doctor.StatusFail {
		t.Fatalf("expected wrong age key to fail decrypt validation, got %#v", check)
	}
	if !containsSubstring(check.Details, "Decrypt error") {
		t.Fatalf("expected decrypt error detail, got %#v", check.Details)
	}
	if !containsSubstring(check.Details, "no matching age key could decrypt this file") &&
		!containsSubstring(check.Details, "decryption failed") {
		t.Fatalf("expected classified decrypt category, got %#v", check.Details)
	}
	assertNoRawDecryptLeak(t, check.Details)
}

func TestDoctorFailsWhenNoAgeKey(t *testing.T) {
	dir := t.TempDir()
	writeDoctorConfig(t, dir, "missing-sops", "0600")
	writeSOPSConfig(t, dir, "creation_rules:\n  - path_regex: production/.*\\.enc\\.yaml$\n    age: age1realrecipient\n")

	secretPath := filepath.Join(dir, "production/platform/app.enc.yaml")
	if err := os.MkdirAll(filepath.Dir(secretPath), 0o755); err != nil {
		t.Fatalf("MkdirAll returned error: %v", err)
	}
	if err := os.WriteFile(secretPath, []byte(doctorEncryptedYAML), 0o600); err != nil {
		t.Fatalf("write secret: %v", err)
	}

	clearAgeKeyDoctorEnv(t)

	result, err := doctor.Run(dir, doctor.Options{})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	binaryCheck := findCheck(t, result, "sops binary")
	if binaryCheck.Status != doctor.StatusOK {
		t.Fatalf("expected missing sops to be informational, got %#v", binaryCheck)
	}

	secretCheck := findCheck(t, result, "secret production/platform/app")
	if secretCheck.Status != doctor.StatusFail {
		t.Fatalf("expected decrypt to fail without age key, got %#v", secretCheck)
	}
	if !containsSubstring(secretCheck.Details, "Decrypt error") {
		t.Fatalf("expected Decrypt error in details, got %#v", secretCheck.Details)
	}
	if !containsSubstring(secretCheck.Details, "age key material is missing or unreadable") &&
		!containsSubstring(secretCheck.Details, "no matching age key could decrypt this file") &&
		!containsSubstring(secretCheck.Details, "decryption failed") {
		t.Fatalf("expected classified decrypt category, got %#v", secretCheck.Details)
	}
	assertNoRawDecryptLeak(t, secretCheck.Details)
	for _, detail := range secretCheck.Details {
		for _, phrase := range []string{"install sops", "sops binary", "sops executable", "sops --decrypt"} {
			if strings.Contains(detail, phrase) {
				t.Fatalf("must not suggest sops binary installation: %q", detail)
			}
		}
	}
}

func assertNoRawDecryptLeak(t *testing.T, details []string) {
	t.Helper()
	for _, detail := range details {
		for _, leak := range []string{"AGE-SECRET-KEY-", "failed to get the data key", "Error getting data key", "MAC mismatch"} {
			if strings.Contains(detail, leak) {
				t.Fatalf("doctor details must not forward raw decrypt backend text %q: %q", leak, detail)
			}
		}
	}
}

func findCheck(t *testing.T, result doctor.Result, name string) doctor.CheckResult {
	t.Helper()
	for _, check := range result.Checks {
		if check.Name == name {
			return check
		}
	}
	t.Fatalf("check %q not found in %#v", name, result.Checks)
	return doctor.CheckResult{}
}

func containsSubstring(values []string, needle string) bool {
	for _, value := range values {
		if strings.Contains(value, needle) {
			return true
		}
	}
	return false
}

func writeDoctorConfig(t *testing.T, dir, binary, mode string) {
	t.Helper()
	writeDoctorConfigWithAge(t, dir, binary, "age", mode)
}

func writeDoctorConfigWithRequirement(t *testing.T, dir, binary, mode, requirement string) {
	t.Helper()
	writeDoctorConfigWithAgeAndRequirement(t, dir, binary, "age", mode, requirement)
}

func writeDoctorConfigWithAge(t *testing.T, dir, binary, ageBinary, mode string) {
	t.Helper()
	writeDoctorConfigWithAgeAndRequirement(t, dir, binary, ageBinary, mode, "")
}

func writeDoctorConfigWithAgeAndRequirement(t *testing.T, dir, binary, ageBinary, mode, requirement string) {
	t.Helper()
	cfg := `version: 1
repository:
  root: .
  encrypted_extension: .enc.yaml
sops:
  binary: ` + binary + `
  age_binary: ` + ageBinary + `
defaults:
  output_format: dotenv
  output_dir: /run/secrets
  file_mode: "` + mode + `"
validation:
  require_values: true
  key_pattern: "^[A-Z0-9_]+$"
profiles:
  default:
    renders: []
`
	if requirement != "" {
		cfg += "requirements:\n  keyseal: \"" + requirement + "\"\n"
	}
	if err := os.WriteFile(filepath.Join(dir, "keyseal.yaml"), []byte(cfg), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
}

func writeSOPSConfig(t *testing.T, dir, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, ".sops.yaml"), []byte(body), 0o600); err != nil {
		t.Fatalf("write .sops.yaml: %v", err)
	}
}

func writeEncryptedSecret(t *testing.T, dir, relativePath string) string {
	t.Helper()
	return writeEncryptedSecretWithKey(t, dir, relativePath, doctorAgeKey)
}

func writeEncryptedSecretWithKey(t *testing.T, dir, relativePath, keyBody string) string {
	t.Helper()
	secretPath := filepath.Join(dir, relativePath)
	if err := os.MkdirAll(filepath.Dir(secretPath), 0o755); err != nil {
		t.Fatalf("MkdirAll returned error: %v", err)
	}
	if err := os.WriteFile(secretPath, []byte(doctorEncryptedYAML), 0o600); err != nil {
		t.Fatalf("write secret: %v", err)
	}
	keyPath := filepath.Join(dir, "age.key")
	if err := os.WriteFile(keyPath, []byte(keyBody), 0o600); err != nil {
		t.Fatalf("write age key: %v", err)
	}
	t.Setenv("SOPS_AGE_KEY_FILE", keyPath)
	return secretPath
}

func clearAgeKeyDoctorEnv(t *testing.T) {
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

func writeFakeSOPS(t *testing.T, dir, binaryName, script string) {
	t.Helper()
	binDir := filepath.Join(dir, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatalf("mkdir bin: %v", err)
	}
	path := filepath.Join(binDir, binaryName)
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake sops: %v", err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
}
