package cli

import (
	"bytes"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestAddDefaultWritesEncryptedOutputOnly(t *testing.T) {
	repoRoot := t.TempDir()
	writeTestConfig(t, repoRoot)
	binDir := filepath.Join(repoRoot, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatalf("MkdirAll returned error: %v", err)
	}
	writeFakeSOPS(t, filepath.Join(binDir, "sops"), "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then\n  printf 'sops 3.9.0\\n'\n  exit 0\nfi\nif [ \"$1\" = \"encrypt\" ] && [ \"$2\" = \"--filename-override\" ]; then\n  printf 'version: 1\\nkind: env\\nname: ENC[AES256_GCM,data:name,type:str]\\nvalues:\\n  APP_KEY: ENC[AES256_GCM,data:value,type:str]\\nsops:\\n  version: 3.9.0\\n'\n  exit 0\nfi\nexit 1\n")
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	output, err := runRootCommand(t, repoRoot, "add", "production/platform/app", "--template", "laravel")
	if err != nil {
		t.Fatalf("runRootCommand returned error: %v", err)
	}

	target := filepath.Join(repoRoot, "production/platform/app.enc.yaml")
	body, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("ReadFile returned error: %v", err)
	}
	text := string(body)
	if strings.Contains(text, "base64:REPLACE_ME") || strings.Contains(text, "ExampleApp") {
		t.Fatalf("expected encrypted file contents, got %q", text)
	}
	if !strings.Contains(text, "sops:") {
		t.Fatalf("expected encrypted output with sops metadata, got %q", text)
	}
	if !strings.Contains(output, "created encrypted starter") {
		t.Fatalf("unexpected output: %q", output)
	}
}

func TestAddDefaultMissingSOPSDoesNotCreateFinalFile(t *testing.T) {
	repoRoot := t.TempDir()
	writeTestConfig(t, repoRoot)
	t.Setenv("PATH", gitOnlyPathDir(t))

	_, err := runRootCommand(t, repoRoot, "add", "production/platform/app", "--template", "laravel")
	if err == nil {
		t.Fatal("expected encrypted add to fail without sops")
	}
	if !strings.Contains(err.Error(), "binary not found") {
		t.Fatalf("unexpected error: %v", err)
	}
	target := filepath.Join(repoRoot, "production/platform/app.enc.yaml")
	if _, statErr := os.Stat(target); !os.IsNotExist(statErr) {
		t.Fatalf("expected final file to not exist, stat err = %v", statErr)
	}
}

func TestAddForceBehaviorMatchesBothModes(t *testing.T) {
	repoRoot := t.TempDir()
	writeTestConfig(t, repoRoot)
	target := filepath.Join(repoRoot, "production/platform/app.enc.yaml")
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		t.Fatalf("MkdirAll returned error: %v", err)
	}
	if err := os.WriteFile(target, []byte("existing"), 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}

	if _, err := runRootCommand(t, repoRoot, "add", "production/platform/app"); err == nil {
		t.Fatal("expected encrypted add without --force to fail")
	}

	binDir := filepath.Join(repoRoot, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatalf("MkdirAll returned error: %v", err)
	}
	writeFakeSOPS(t, filepath.Join(binDir, "sops"), "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then\n  printf 'sops 3.9.0\\n'\n  exit 0\nfi\nif [ \"$1\" = \"encrypt\" ] && [ \"$2\" = \"--filename-override\" ]; then\n  printf 'ENC[test]\\n'\n  exit 0\nfi\nexit 1\n")
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	if _, err := runRootCommand(t, repoRoot, "add", "production/platform/app", "--force"); err != nil {
		t.Fatalf("expected encrypted add with --force to succeed: %v", err)
	}
	body, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("ReadFile returned error: %v", err)
	}
	if string(body) != "ENC[test]\n" {
		t.Fatalf("expected encrypted body after forced add, got %q", string(body))
	}
}

func TestAddHelpShowsEncryptedOnlyFlow(t *testing.T) {
	repoRoot := t.TempDir()

	output, err := runRootCommand(t, repoRoot, "add", "--help")
	if err != nil {
		t.Fatalf("runRootCommand returned error: %v", err)
	}
	if !strings.Contains(output, "Keyseal uses a non-interactive SOPS flow") {
		t.Fatalf("expected encrypted add help, got %q", output)
	}
	if !strings.Contains(output, "No plaintext starter content is written") {
		t.Fatalf("expected plaintext-safety language in help, got %q", output)
	}
	if strings.Contains(output, "--plaintext") {
		t.Fatalf("did not expect --plaintext in help, got %q", output)
	}
}

func runRootCommand(t *testing.T, cwd string, args ...string) (string, error) {
	t.Helper()

	stdout, _, err := runRootCommandIO(t, cwd, nil, args...)
	return stdout, err
}

// runRootCommandIO runs the CLI with optional stdin and returns stdout and
// stderr separately so tests can inspect both streams.
func runRootCommandIO(t *testing.T, cwd string, stdin io.Reader, args ...string) (string, string, error) {
	t.Helper()

	origWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd returned error: %v", err)
	}
	if err := os.Chdir(cwd); err != nil {
		t.Fatalf("Chdir returned error: %v", err)
	}
	defer func() {
		if err := os.Chdir(origWD); err != nil {
			t.Fatalf("restore cwd: %v", err)
		}
	}()

	cmd := newRootCommand()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	if stdin != nil {
		cmd.SetIn(stdin)
	}
	cmd.SetArgs(args)
	err = cmd.Execute()
	return stdout.String(), stderr.String(), err
}

func writeTestConfig(t *testing.T, root string) {
	t.Helper()

	initGitRepo(t, root)
	if err := os.WriteFile(filepath.Join(root, "keyseal.yaml"), []byte(defaultConfigYAML("default")), 0o644); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}
}

func writeFakeSOPS(t *testing.T, path, script string) {
	t.Helper()

	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake sops: %v", err)
	}
}

func initGitRepo(t *testing.T, root string) {
	t.Helper()

	gitRun(t, root, "init")
	gitRun(t, root, "config", "user.name", "Keyseal Test")
	gitRun(t, root, "config", "user.email", "keyseal@example.com")
}

func gitRun(t *testing.T, dir string, args ...string) {
	t.Helper()

	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v failed: %v\n%s", args, err, string(output))
	}
}

func gitOutput(t *testing.T, dir string, args ...string) string {
	t.Helper()

	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v failed: %v\n%s", args, err, string(output))
	}
	return string(output)
}

func gitBinDir(t *testing.T) string {
	t.Helper()

	path, err := exec.LookPath("git")
	if err != nil {
		t.Fatalf("git not found: %v", err)
	}
	return filepath.Dir(path)
}

func gitOnlyPathDir(t *testing.T) string {
	t.Helper()

	toolDir := t.TempDir()
	gitPath, err := exec.LookPath("git")
	if err != nil {
		t.Fatalf("git not found: %v", err)
	}
	if err := os.Symlink(gitPath, filepath.Join(toolDir, "git")); err != nil {
		t.Fatalf("Symlink returned error: %v", err)
	}
	return toolDir
}
