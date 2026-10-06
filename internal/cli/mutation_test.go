package cli

import (
	"bytes"
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/jrpbuilds/keyseal/internal/schema"
	"github.com/jrpbuilds/keyseal/internal/sopsutil"
)

const (
	cliTestAgePublicKey   = "age1xlp99sh4c9dheuskt900y83mdcxdhjp0zhejf2l4lkh6fdzl0dsqsx4yrx"
	cliSecondAgePublicKey = "age18ky244sacp27ynw06qycnw0uk9ff55hs8fjm3532yty30zqjm35qmfqgpw"
	// cliSecondAgeKey is a disposable identity used only to prove that clone
	// applies the destination's creation rule.
	cliSecondAgeKey = `# public key: age18ky244sacp27ynw06qycnw0uk9ff55hs8fjm3532yty30zqjm35qmfqgpw
AGE-SECRET-KEY-19YNW9E4MRQLCMENRCZ3MXUAYJZGCHHW5VZGSWR75705NHCMDXHCQZ5JH9Z
`
)

var defaultMutationSOPSRules = `creation_rules:
  - path_regex: \.enc\.yaml$
    encrypted_regex: ^(name|values)$
    age: ` + cliTestAgePublicKey + "\n"

// realSOPSPath returns the real sops binary or skips the test. These tests
// exercise the actual SOPS CLI and SOPS library with disposable test keys.
func realSOPSPath(t *testing.T) string {
	t.Helper()
	path, err := exec.LookPath("sops")
	if err != nil {
		t.Skip("sops binary not available; skipping real SOPS mutation test")
	}
	return path
}

// seedMutationRepo creates a disposable Git repo with the given .sops.yaml,
// test age identities, and a real encrypted production/app document created
// by `keyseal add --template stripe`.
func seedMutationRepo(t *testing.T, sopsRules string, identities ...string) string {
	t.Helper()
	realSOPSPath(t)

	root := t.TempDir()
	initGitRepo(t, root)
	writeFileForCLI(t, filepath.Join(root, "keyseal.yaml"), defaultConfigYAML("default"))
	writeFileForCLI(t, filepath.Join(root, ".sops.yaml"), sopsRules)
	keyPath := filepath.Join(t.TempDir(), "keys.txt")
	writeFileForCLI(t, keyPath, strings.Join(identities, "\n"))
	t.Setenv("SOPS_AGE_KEY_FILE", keyPath)
	gitRun(t, root, "add", "--", "keyseal.yaml", ".sops.yaml")
	gitRun(t, root, "commit", "-m", "seed config")

	if _, err := runRootCommand(t, root, "add", "production/app", "--template", "stripe"); err != nil {
		t.Fatalf("seed add returned error: %v", err)
	}
	return root
}

func docPath(root, logical string) string {
	return filepath.Join(root, filepath.FromSlash(logical)+".enc.yaml")
}

func decryptDoc(t *testing.T, root, logical string) schema.EnvSecretDocument {
	t.Helper()
	plaintext, err := sopsutil.DecryptFile(docPath(root, logical), "yaml", "")
	if err != nil {
		t.Fatalf("decrypt %s: %v", logical, err)
	}
	doc, _, err := schema.ParseYAMLDocument(plaintext)
	if err != nil {
		t.Fatalf("parse %s: %v", logical, err)
	}
	return doc
}

func readBytes(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile returned error: %v", err)
	}
	return data
}

func assertUnchanged(t *testing.T, path string, before []byte) {
	t.Helper()
	if after := readBytes(t, path); !bytes.Equal(before, after) {
		t.Fatalf("expected %s to be byte-for-byte unchanged", path)
	}
}

func TestMutationCommandsEndToEnd(t *testing.T) {
	root := seedMutationRepo(t, defaultMutationSOPSRules, cliTestAgeKey)
	source := readBytes(t, docPath(root, "production/app"))
	var outputs strings.Builder
	run := func(stdin string, args ...string) {
		t.Helper()
		stdout, stderr, err := runRootCommandIO(t, root, strings.NewReader(stdin), args...)
		if err != nil {
			t.Fatalf("%v returned error: %v", args, err)
		}
		outputs.WriteString(stdout + stderr)
	}

	run("", "clone", "production/app", "production/app-next")
	run("sk_live_new\n", "set", "production/app-next", "STRIPE_SECRET_KEY", "--stdin")

	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("Pipe returned error: %v", err)
	}
	defer reader.Close()
	if _, err := writer.WriteString("whsec_new"); err != nil {
		t.Fatalf("write pipe: %v", err)
	}
	writer.Close()
	// Pass a duplicate so the command can close its descriptor independently.
	fd, err := syscall.Dup(int(reader.Fd()))
	if err != nil {
		t.Fatalf("Dup returned error: %v", err)
	}
	run("", "set", "production/app-next", "STRIPE_WEBHOOK_SECRET", "--fd", strconv.Itoa(fd))

	envFile := filepath.Join(t.TempDir(), "intake.env")
	writeFileForCLI(t, envFile, "STRIPE_CONNECT_CLIENT_ID=\"ca_new\"\nUNRELATED=ignored\n")
	run("", "import", "production/app-next", "--from-env-file", envFile, "--keys", "STRIPE_CONNECT_CLIENT_ID")
	run("", "generate", "production/app-next", "SAAS_TRIAL_FINGERPRINT_KEY", "--bytes", "32")
	run("", "unset", "production/app-next", "STRIPE_WEBHOOK_SECRET")

	assertUnchanged(t, docPath(root, "production/app"), source)
	doc := decryptDoc(t, root, "production/app-next")
	if doc.Name != "production/app-next" {
		t.Fatalf("expected clone to rename document, got %q", doc.Name)
	}
	if doc.Values["STRIPE_SECRET_KEY"] != "sk_live_new" || doc.Values["STRIPE_CONNECT_CLIENT_ID"] != "ca_new" {
		t.Fatalf("unexpected values after mutations: keys=%d", len(doc.Values))
	}
	if _, ok := doc.Values["STRIPE_WEBHOOK_SECRET"]; ok {
		t.Fatal("expected STRIPE_WEBHOOK_SECRET to be removed")
	}
	if _, ok := doc.Values["UNRELATED"]; ok {
		t.Fatal("import must only copy the listed keys")
	}
	generated := doc.Values["SAAS_TRIAL_FINGERPRINT_KEY"]
	if raw, err := base64.RawURLEncoding.DecodeString(generated); err != nil || len(raw) != 32 {
		t.Fatalf("expected 32 random bytes encoded as base64url, err=%v len=%d", err, len(raw))
	}

	text := outputs.String()
	for _, want := range []string{"cloned production/app to production/app-next", "updated STRIPE_SECRET_KEY", "updated STRIPE_WEBHOOK_SECRET", "updated STRIPE_CONNECT_CLIENT_ID", "added SAAS_TRIAL_FINGERPRINT_KEY", "removed STRIPE_WEBHOOK_SECRET", "updated production/app-next"} {
		if !strings.Contains(text, want) {
			t.Fatalf("expected output to contain %q, got:\n%s", want, text)
		}
	}
	for _, secret := range []string{"sk_live_new", "whsec_new", "ca_new", generated} {
		if strings.Contains(text, secret) {
			t.Fatal("command output must never contain secret values")
		}
	}

	info, err := os.Stat(docPath(root, "production/app-next"))
	if err != nil {
		t.Fatalf("Stat returned error: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("expected cloned document mode 0600, got %v", info.Mode().Perm())
	}

	rendered, err := runRootCommand(t, root, "render", "production/app-next", "--stdout")
	if err != nil {
		t.Fatalf("render returned error: %v", err)
	}
	if !strings.Contains(rendered, `STRIPE_SECRET_KEY="sk_live_new"`) {
		t.Fatal("expected render to read the mutated document")
	}
	if out, err := runRootCommand(t, root, "verify"); err != nil {
		t.Fatalf("verify returned error: %v\n%s", err, out)
	}
}

func TestSetUnchangedValueLeavesFileUntouched(t *testing.T) {
	root := seedMutationRepo(t, defaultMutationSOPSRules, cliTestAgeKey)
	path := docPath(root, "production/app")
	before := readBytes(t, path)

	stdout, _, err := runRootCommandIO(t, root, strings.NewReader("sk_live_REPLACE_ME"), "set", "production/app", "STRIPE_SECRET_KEY", "--stdin", "-m", "should not commit")
	if err != nil {
		t.Fatalf("set returned error: %v", err)
	}
	if !strings.Contains(stdout, "unchanged STRIPE_SECRET_KEY") || !strings.Contains(stdout, "no changes; production/app left untouched") {
		t.Fatalf("unexpected output: %q", stdout)
	}
	assertUnchanged(t, path, before)
	if got := strings.TrimSpace(gitOutput(t, root, "log", "-1", "--pretty=%s")); got != "seed config" {
		t.Fatalf("expected no commit for an unchanged document, got %q", got)
	}
}

func TestUnsetDistinguishesAbsentKey(t *testing.T) {
	root := seedMutationRepo(t, defaultMutationSOPSRules, cliTestAgeKey)
	path := docPath(root, "production/app")
	before := readBytes(t, path)

	_, err := runRootCommand(t, root, "unset", "production/app", "STRIPE_SECRET_KEY", "TWILIO_TOKEN")
	if err == nil {
		t.Fatal("expected unset of an absent key to fail")
	}
	if !strings.Contains(err.Error(), "not present in production/app: TWILIO_TOKEN; nothing changed") {
		t.Fatalf("unexpected error: %v", err)
	}
	assertUnchanged(t, path, before)

	stdout, err := runRootCommand(t, root, "unset", "production/app", "STRIPE_SECRET_KEY")
	if err != nil {
		t.Fatalf("unset returned error: %v", err)
	}
	if !strings.Contains(stdout, "removed STRIPE_SECRET_KEY") {
		t.Fatalf("unexpected output: %q", stdout)
	}
}

func TestCloneRefusesExistingDestinationUnlessForced(t *testing.T) {
	root := seedMutationRepo(t, defaultMutationSOPSRules, cliTestAgeKey)
	if _, err := runRootCommand(t, root, "add", "production/app-next"); err != nil {
		t.Fatalf("add returned error: %v", err)
	}
	dst := docPath(root, "production/app-next")
	before := readBytes(t, dst)

	_, err := runRootCommand(t, root, "clone", "production/app", "production/app-next")
	if err == nil || !strings.Contains(err.Error(), "already exists; use --force") {
		t.Fatalf("expected clone to refuse an existing destination, got %v", err)
	}
	assertUnchanged(t, dst, before)

	if _, err := runRootCommand(t, root, "clone", "production/app", "production/app-next", "--force"); err != nil {
		t.Fatalf("clone --force returned error: %v", err)
	}
	if _, ok := decryptDoc(t, root, "production/app-next").Values["STRIPE_SECRET_KEY"]; !ok {
		t.Fatal("expected --force clone to replace the destination")
	}

	if _, err := runRootCommand(t, root, "clone", "production/missing", "production/other"); err == nil {
		t.Fatal("expected clone of a missing source to fail")
	}
	if _, err := os.Stat(docPath(root, "production/other")); !os.IsNotExist(err) {
		t.Fatalf("expected no destination after failed clone, stat err = %v", err)
	}
}

func TestCloneAppliesDestinationCreationRule(t *testing.T) {
	rules := `creation_rules:
  - path_regex: app-next\.enc\.yaml$
    encrypted_regex: ^(name|values)$
    age: ` + cliSecondAgePublicKey + `
  - path_regex: \.enc\.yaml$
    encrypted_regex: ^(name|values)$
    age: ` + cliTestAgePublicKey + "\n"
	root := seedMutationRepo(t, rules, cliTestAgeKey, cliSecondAgeKey)

	if _, err := runRootCommand(t, root, "clone", "production/app", "production/app-next"); err != nil {
		t.Fatalf("clone returned error: %v", err)
	}
	source := string(readBytes(t, docPath(root, "production/app")))
	clone := string(readBytes(t, docPath(root, "production/app-next")))
	if !strings.Contains(source, cliTestAgePublicKey) || strings.Contains(source, cliSecondAgePublicKey) {
		t.Fatal("expected source to keep its original recipient")
	}
	if !strings.Contains(clone, cliSecondAgePublicKey) || strings.Contains(clone, cliTestAgePublicKey) {
		t.Fatal("expected clone to be encrypted for the destination creation rule recipient only")
	}
}

func TestCloneRefusesResultOperatorCannotDecrypt(t *testing.T) {
	rules := `creation_rules:
  - path_regex: app-next\.enc\.yaml$
    age: ` + cliSecondAgePublicKey + `
  - path_regex: \.enc\.yaml$
    age: ` + cliTestAgePublicKey + "\n"
	root := seedMutationRepo(t, rules, cliTestAgeKey)

	_, err := runRootCommand(t, root, "clone", "production/app", "production/app-next")
	if err == nil || !strings.Contains(err.Error(), "recipients for this path include your age key") {
		t.Fatalf("expected verification to reject an undecryptable result, got %v", err)
	}
	if _, err := os.Stat(docPath(root, "production/app-next")); !os.IsNotExist(err) {
		t.Fatalf("expected no destination after failed verification, stat err = %v", err)
	}
}

func TestMutationRefusesRuleThatLeavesValuesUnencrypted(t *testing.T) {
	rules := `creation_rules:
  - path_regex: \.enc\.yaml$
    encrypted_regex: ^name$
    age: ` + cliTestAgePublicKey + "\n"
	root := seedMutationRepo(t, rules, cliTestAgeKey)
	path := docPath(root, "production/app")
	before := readBytes(t, path)

	_, _, err := runRootCommandIO(t, root, strings.NewReader("sk_live_leak_marker"), "set", "production/app", "STRIPE_SECRET_KEY", "--stdin")
	if err == nil || !strings.Contains(err.Error(), "would leave values unencrypted for:") || !strings.Contains(err.Error(), "STRIPE_SECRET_KEY") {
		t.Fatalf("expected set to refuse unencrypted values, got %v", err)
	}
	if strings.Contains(err.Error(), "sk_live_leak_marker") {
		t.Fatal("error must not contain the secret value")
	}
	assertUnchanged(t, path, before)
}

func TestUpdateRefusesConcurrentChange(t *testing.T) {
	root := seedMutationRepo(t, defaultMutationSOPSRules, cliTestAgeKey)
	path := docPath(root, "production/app")
	binDir := t.TempDir()
	writeFakeSOPS(t, filepath.Join(binDir, "sops"), "#!/bin/sh\nif [ \"$1\" = \"encrypt\" ]; then printf '# concurrent edit\\n' >> \""+path+"\"; fi\nexec \""+realSOPSPath(t)+"\" \"$@\"\n")
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	expected := append(readBytes(t, path), []byte("# concurrent edit\n")...)

	_, _, err := runRootCommandIO(t, root, strings.NewReader("sk_live_new"), "set", "production/app", "STRIPE_SECRET_KEY", "--stdin")
	if err == nil || !strings.Contains(err.Error(), "changed on disk during the update") {
		t.Fatalf("expected concurrent change to abort, got %v", err)
	}
	assertUnchanged(t, path, expected)
}

func TestMutationDefaultCommitMessages(t *testing.T) {
	root := seedMutationRepo(t, defaultMutationSOPSRules, cliTestAgeKey)
	envFile := filepath.Join(t.TempDir(), "intake.env")
	writeFileForCLI(t, envFile, "STRIPE_CONNECT_CLIENT_ID=ca_imported\n")

	steps := []struct {
		args []string
		want string
	}{
		{[]string{"set", "production/app", "STRIPE_SECRET_KEY", "--stdin", "--commit"}, "Update secret production/app"},
		{[]string{"unset", "production/app", "STRIPE_WEBHOOK_SECRET", "--commit"}, "Remove keys from secret production/app"},
		{[]string{"generate", "production/app", "STRIPE_SECRET_KEY", "--commit"}, "Generate values in secret production/app"},
		{[]string{"import", "production/app", "--from-env-file", envFile, "--keys", "STRIPE_CONNECT_CLIENT_ID", "--commit"}, "Import values into secret production/app"},
	}
	for _, step := range steps {
		stdin := ""
		if step.args[0] == "set" {
			stdin = "sk_live_new\n"
		}
		if _, _, err := runRootCommandIO(t, root, strings.NewReader(stdin), step.args...); err != nil {
			t.Fatalf("%v returned error: %v", step.args, err)
		}
		if got := strings.TrimSpace(gitOutput(t, root, "log", "-1", "--pretty=%s")); got != step.want {
			t.Fatalf("%s: expected commit %q, got %q", step.args[0], step.want, got)
		}
	}
}

func TestMutationCommitIncludesOnlyAffectedDocument(t *testing.T) {
	root := seedMutationRepo(t, defaultMutationSOPSRules, cliTestAgeKey)
	gitRun(t, root, "add", "--", "production/app.enc.yaml")
	gitRun(t, root, "commit", "-m", "add app")
	writeFileForCLI(t, filepath.Join(root, "notes.txt"), "operator work in progress\n")
	gitRun(t, root, "add", "--", "notes.txt")

	_, err := runRootCommand(t, root, "generate", "production/app", "STRIPE_SECRET_KEY", "-m", "Rotate Stripe key")
	if err != nil {
		t.Fatalf("generate returned error: %v", err)
	}
	if got := strings.TrimSpace(gitOutput(t, root, "log", "-1", "--pretty=%s")); got != "Rotate Stripe key" {
		t.Fatalf("expected commit, got %q", got)
	}
	committed := strings.Fields(gitOutput(t, root, "show", "--name-only", "--pretty=format:", "HEAD"))
	if len(committed) != 1 || committed[0] != "production/app.enc.yaml" {
		t.Fatalf("expected only the document in the commit, got %v", committed)
	}
	if status := gitOutput(t, root, "status", "--porcelain"); !strings.Contains(status, "A  notes.txt") {
		t.Fatalf("expected unrelated staged file to stay staged, got %q", status)
	}
}

// seedFakeSOPSMutationRepo writes a real encrypted fixture and a fake sops
// whose encrypt step runs encryptScript, so failure paths can be forced.
func seedFakeSOPSMutationRepo(t *testing.T, encryptScript string) string {
	t.Helper()
	root := t.TempDir()
	writeTestConfig(t, root)
	configureLibraryDecryptFixture(t, root)
	writeFileForCLI(t, docPath(root, "production/app"), cliTestEncryptedYAML)
	binDir := filepath.Join(t.TempDir(), "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatalf("MkdirAll returned error: %v", err)
	}
	writeFakeSOPS(t, filepath.Join(binDir, "sops"), "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then\n  printf 'sops 3.12.2\\n'\n  exit 0\nfi\nif [ \"$1\" = \"encrypt\" ]; then\n"+encryptScript+"\nfi\nexit 1\n")
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+gitBinDir(t))
	return root
}

func TestMutationFailuresLeaveOriginalByteForByte(t *testing.T) {
	staleCiphertext := filepath.Join(t.TempDir(), "stale.enc.yaml")
	writeFileForCLI(t, staleCiphertext, cliTestEncryptedYAML)

	cases := []struct {
		name    string
		script  string
		stdin   string
		args    []string
		wantErr string
	}{
		{
			name:    "sops encrypt fails",
			script:  "cat >/dev/null\necho 'encryption failed' >&2\nexit 1",
			stdin:   "new-value",
			args:    []string{"set", "production/app", "APP_ENV", "--stdin"},
			wantErr: "encryption failed",
		},
		{
			name:    "sops returns unencrypted output",
			script:  "cat >/dev/null\nprintf 'version: 1\\n'\nexit 0",
			stdin:   "new-value",
			args:    []string{"set", "production/app", "APP_ENV", "--stdin"},
			wantErr: "does not contain SOPS metadata",
		},
		{
			name:    "sops returns ciphertext for other content",
			script:  "cat >/dev/null\ncat \"" + staleCiphertext + "\"\nexit 0",
			stdin:   "new-value",
			args:    []string{"set", "production/app", "APP_ENV", "--stdin"},
			wantErr: "does not match the intended document",
		},
		{
			name:    "schema validation fails",
			script:  "exit 1",
			args:    []string{"unset", "production/app", "APP_ENV", "DB_HOST"},
			wantErr: "values is required",
		},
		{
			name:    "invalid key name",
			script:  "exit 1",
			stdin:   "new-value",
			args:    []string{"set", "production/app", "lower_case", "--stdin"},
			wantErr: "invalid env key",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := seedFakeSOPSMutationRepo(t, tc.script)
			path := docPath(root, "production/app")
			before := readBytes(t, path)

			_, _, err := runRootCommandIO(t, root, strings.NewReader(tc.stdin), tc.args...)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("expected error containing %q, got %v", tc.wantErr, err)
			}
			if tc.stdin != "" && strings.Contains(err.Error(), tc.stdin) {
				t.Fatal("error must not contain the secret value")
			}
			assertUnchanged(t, path, before)
			entries, err := os.ReadDir(filepath.Dir(path))
			if err != nil {
				t.Fatalf("ReadDir returned error: %v", err)
			}
			if len(entries) != 1 {
				t.Fatalf("expected no leftover temp files next to the document, got %d entries", len(entries))
			}
		})
	}
}

func TestSetRequiresExactlyOneSecretSource(t *testing.T) {
	root := t.TempDir()
	writeTestConfig(t, root)
	cases := map[string][]string{
		"no source":   {"set", "production/app", "KEY"},
		"both":        {"set", "production/app", "KEY", "--stdin", "--fd", "3"},
		"reserved fd": {"set", "production/app", "KEY", "--fd", "1"},
		"value arg":   {"set", "production/app", "KEY", "value"},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := runRootCommand(t, root, args...); err == nil {
				t.Fatal("expected set to reject the arguments")
			}
		})
	}
}
