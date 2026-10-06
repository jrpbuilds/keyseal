package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRootHelpIncludesGitWorkflowCommands(t *testing.T) {
	output, err := runRootCommand(t, t.TempDir(), "--help")
	if err != nil {
		t.Fatalf("runRootCommand returned error: %v", err)
	}
	for _, snippet := range []string{"status", "diff", "history", "commit", "updatekeys", "rollback", "verify"} {
		if !strings.Contains(output, snippet) {
			t.Fatalf("expected root help to mention %q, got %q", snippet, output)
		}
	}
}

func TestAddHelpMentionsCommitFlags(t *testing.T) {
	output, err := runRootCommand(t, t.TempDir(), "add", "--help")
	if err != nil {
		t.Fatalf("runRootCommand returned error: %v", err)
	}
	if !strings.Contains(output, "-m implies --commit") {
		t.Fatalf("expected add help to explain commit implication, got %q", output)
	}
}

func TestStatusFailsOutsideGitRepository(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "keyseal.yaml"), []byte(defaultConfigYAML("default")), 0o644); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}

	_, err := runRootCommand(t, dir, "status")
	if err == nil {
		t.Fatal("expected status to fail outside a Git repository")
	}
	if !strings.Contains(err.Error(), "not inside a Git repository") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestStatusShowsOnlyRelevantFiles(t *testing.T) {
	repoRoot := seedKeysealRepo(t, false)
	writeFileForCLI(t, filepath.Join(repoRoot, "production/platform/app.enc.yaml"), "v1\n")
	writeFileForCLI(t, filepath.Join(repoRoot, "notes.txt"), "v1\n")
	gitRun(t, repoRoot, "add", "--", "production/platform/app.enc.yaml", "notes.txt")
	gitRun(t, repoRoot, "commit", "-m", "seed secret")
	writeFileForCLI(t, filepath.Join(repoRoot, "production/platform/app.enc.yaml"), "v2\n")
	writeFileForCLI(t, filepath.Join(repoRoot, "notes.txt"), "v2\n")

	output, err := runRootCommand(t, repoRoot, "status")
	if err != nil {
		t.Fatalf("runRootCommand returned error: %v", err)
	}
	if !strings.Contains(output, "production/platform/app.enc.yaml") {
		t.Fatalf("expected status output to include the secret file, got %q", output)
	}
	if strings.Contains(output, "notes.txt") {
		t.Fatalf("expected status output to omit unrelated files, got %q", output)
	}
}

func TestStatusJSONShowsStructuredRelevantEntries(t *testing.T) {
	repoRoot := seedKeysealRepo(t, false)
	writeFileForCLI(t, filepath.Join(repoRoot, "production/platform/app.enc.yaml"), "v1\n")
	writeFileForCLI(t, filepath.Join(repoRoot, "notes.txt"), "v1\n")

	output, err := runRootCommand(t, repoRoot, "status", "--json")
	if err != nil {
		t.Fatalf("runRootCommand returned error: %v", err)
	}

	var payload struct {
		Count   int `json:"count"`
		Entries []struct {
			Code string `json:"code"`
			Path string `json:"path"`
		} `json:"entries"`
	}
	if err := json.Unmarshal([]byte(output), &payload); err != nil {
		t.Fatalf("Unmarshal returned error: %v\noutput=%s", err, output)
	}
	if payload.Count != 1 {
		t.Fatalf("expected 1 relevant status entry, got %#v", payload)
	}
	if len(payload.Entries) != 1 || payload.Entries[0].Path != "production/platform/app.enc.yaml" {
		t.Fatalf("unexpected json status payload: %#v", payload)
	}
	if payload.Entries[0].Code != "??" {
		t.Fatalf("expected untracked status code, got %#v", payload)
	}
}

func TestStatusCanBeScopedToLogicalName(t *testing.T) {
	repoRoot := seedKeysealRepo(t, false)
	writeFileForCLI(t, filepath.Join(repoRoot, "production/platform/app.enc.yaml"), "v1\n")
	writeFileForCLI(t, filepath.Join(repoRoot, "production/platform/api.enc.yaml"), "v1\n")

	output, err := runRootCommand(t, repoRoot, "status", "production/platform/app")
	if err != nil {
		t.Fatalf("runRootCommand returned error: %v", err)
	}
	if !strings.Contains(output, "production/platform/app.enc.yaml") {
		t.Fatalf("expected scoped status to include app secret, got %q", output)
	}
	if strings.Contains(output, "production/platform/api.enc.yaml") {
		t.Fatalf("expected scoped status to exclude other secrets, got %q", output)
	}
}

func TestDiffAndHistoryResolveLogicalName(t *testing.T) {
	repoRoot := seedKeysealRepo(t, false)
	target := filepath.Join(repoRoot, "production/platform/app.enc.yaml")
	writeFileForCLI(t, target, "first\n")
	gitRun(t, repoRoot, "add", "--", "production/platform/app.enc.yaml")
	gitRun(t, repoRoot, "commit", "-m", "first secret")
	writeFileForCLI(t, target, "second\n")

	diffOutput, err := runRootCommand(t, repoRoot, "diff", "production/platform/app")
	if err != nil {
		t.Fatalf("runRootCommand returned error: %v", err)
	}
	if !strings.Contains(diffOutput, "production/platform/app.enc.yaml") {
		t.Fatalf("expected diff output to mention the target file, got %q", diffOutput)
	}

	historyOutput, err := runRootCommand(t, repoRoot, "history", "production/platform/app")
	if err != nil {
		t.Fatalf("runRootCommand returned error: %v", err)
	}
	if !strings.Contains(historyOutput, "first secret") {
		t.Fatalf("expected history output to include the commit message, got %q", historyOutput)
	}

	onelineHistory, err := runRootCommand(t, repoRoot, "history", "production/platform/app", "--oneline")
	if err != nil {
		t.Fatalf("runRootCommand returned error: %v", err)
	}
	if !strings.Contains(onelineHistory, "first secret") || strings.Contains(onelineHistory, "Author:") {
		t.Fatalf("expected one-line history output, got %q", onelineHistory)
	}
}

func TestCommitStagesOnlyKeysealManagedFiles(t *testing.T) {
	repoRoot := seedKeysealRepo(t, false)
	writeFileForCLI(t, filepath.Join(repoRoot, "production/platform/app.enc.yaml"), "old\n")
	writeFileForCLI(t, filepath.Join(repoRoot, "notes.txt"), "old\n")
	gitRun(t, repoRoot, "add", "--", "production/platform/app.enc.yaml", "notes.txt")
	gitRun(t, repoRoot, "commit", "-m", "seed files")
	writeFileForCLI(t, filepath.Join(repoRoot, "production/platform/app.enc.yaml"), "new\n")
	writeFileForCLI(t, filepath.Join(repoRoot, "notes.txt"), "new\n")

	output, err := runRootCommand(t, repoRoot, "commit", "-m", "Rotate Stripe webhook secret")
	if err != nil {
		t.Fatalf("runRootCommand returned error: %v", err)
	}
	if !strings.Contains(output, "Rotate Stripe webhook secret") {
		t.Fatalf("expected commit output to include the message, got %q", output)
	}
	if got := strings.TrimSpace(gitOutput(t, repoRoot, "log", "-1", "--pretty=%s")); got != "Rotate Stripe webhook secret" {
		t.Fatalf("expected last commit subject to match, got %q", got)
	}
	status := gitOutput(t, repoRoot, "status", "--short")
	if !strings.Contains(status, " M notes.txt") {
		t.Fatalf("expected unrelated file to remain unstaged, got %q", status)
	}
	if strings.Contains(status, "production/platform/app.enc.yaml") {
		t.Fatalf("expected secret file changes to be committed, got %q", status)
	}
}

func TestCommitIncludesBothSidesOfStagedRename(t *testing.T) {
	repoRoot := seedKeysealRepo(t, false)
	writeFileForCLI(t, filepath.Join(repoRoot, "production/a.enc.yaml"), "secret\n")
	gitRun(t, repoRoot, "add", "--", "production/a.enc.yaml")
	gitRun(t, repoRoot, "commit", "-m", "add a")
	gitRun(t, repoRoot, "mv", "production/a.enc.yaml", "production/b.enc.yaml")

	output, err := runRootCommand(t, repoRoot, "commit")
	if err != nil {
		t.Fatalf("runRootCommand returned error: %v", err)
	}
	if !strings.Contains(output, "committed Git change: Update 1 Keyseal file") {
		t.Fatalf("expected one file in the default message, got %q", output)
	}
	if got := strings.TrimSpace(gitOutput(t, repoRoot, "log", "-1", "--pretty=%s")); got != "Update 1 Keyseal file" {
		t.Fatalf("expected rename to count as one file, got %q", got)
	}
	tree := gitOutput(t, repoRoot, "ls-tree", "-r", "--name-only", "HEAD")
	if !strings.Contains(tree, "production/b.enc.yaml") || strings.Contains(tree, "production/a.enc.yaml") {
		t.Fatalf("expected HEAD to contain only the renamed file, got %q", tree)
	}
	if status := strings.TrimSpace(gitOutput(t, repoRoot, "status", "--porcelain")); status != "" {
		t.Fatalf("expected a clean working tree, got %q", status)
	}
}

func TestAddMessageImpliesCommit(t *testing.T) {
	repoRoot := seedKeysealRepo(t, false)
	configureFakeEncryptSOPS(t, repoRoot)

	_, err := runRootCommand(t, repoRoot, "add", "production/platform/app", "-m", "Add production app secret")
	if err != nil {
		t.Fatalf("runRootCommand returned error: %v", err)
	}
	if got := strings.TrimSpace(gitOutput(t, repoRoot, "log", "-1", "--pretty=%s")); got != "Add production app secret" {
		t.Fatalf("expected add to create a commit, got %q", got)
	}
}

func TestAddFailureDoesNotCreateCommit(t *testing.T) {
	repoRoot := seedKeysealRepo(t, false)
	t.Setenv("PATH", gitOnlyPathDir(t))
	before := strings.TrimSpace(gitOutput(t, repoRoot, "rev-list", "--count", "HEAD"))

	_, err := runRootCommand(t, repoRoot, "add", "production/platform/app", "-m", "should not commit")
	if err == nil {
		t.Fatal("expected add to fail without sops")
	}
	after := strings.TrimSpace(gitOutput(t, repoRoot, "rev-list", "--count", "HEAD"))
	if before != after {
		t.Fatalf("expected commit count to remain %q, got %q", before, after)
	}
}

func TestAutoCommitAndNoCommitOverrideOnAdd(t *testing.T) {
	repoRoot := seedKeysealRepo(t, true)
	configureFakeEncryptSOPS(t, repoRoot)

	_, err := runRootCommand(t, repoRoot, "add", "production/platform/app")
	if err != nil {
		t.Fatalf("runRootCommand returned error: %v", err)
	}
	if got := strings.TrimSpace(gitOutput(t, repoRoot, "log", "-1", "--pretty=%s")); got != "Add secret production/platform/app" {
		t.Fatalf("expected auto-commit message, got %q", got)
	}

	repoRoot = seedKeysealRepo(t, true)
	configureFakeEncryptSOPS(t, repoRoot)
	_, err = runRootCommand(t, repoRoot, "add", "production/platform/api", "--no-commit")
	if err != nil {
		t.Fatalf("runRootCommand returned error: %v", err)
	}
	if got := strings.TrimSpace(gitOutput(t, repoRoot, "log", "-1", "--pretty=%s")); got == "Add secret production/platform/api" {
		t.Fatalf("expected --no-commit to suppress the commit, got %q", got)
	}
}

func TestEditCommitsOnlyWhenFileChanges(t *testing.T) {
	repoRoot := seedKeysealRepo(t, false)
	target := filepath.Join(repoRoot, "production/platform/app.enc.yaml")
	writeFileForCLI(t, target, "first\n")
	gitRun(t, repoRoot, "add", "--", "production/platform/app.enc.yaml")
	gitRun(t, repoRoot, "commit", "-m", "seed secret")

	configureFakeEditSOPS(t, repoRoot, "#!/bin/sh\nprintf 'edited\\n' >> \"$1\"\n")
	_, err := runRootCommand(t, repoRoot, "edit", "production/platform/app", "-m", "Update app secret")
	if err != nil {
		t.Fatalf("runRootCommand returned error: %v", err)
	}
	if got := strings.TrimSpace(gitOutput(t, repoRoot, "log", "-1", "--pretty=%s")); got != "Update app secret" {
		t.Fatalf("expected edit to commit, got %q", got)
	}

	repoRoot = seedKeysealRepo(t, false)
	target = filepath.Join(repoRoot, "production/platform/app.enc.yaml")
	writeFileForCLI(t, target, "first\n")
	gitRun(t, repoRoot, "add", "--", "production/platform/app.enc.yaml")
	gitRun(t, repoRoot, "commit", "-m", "seed secret")
	configureFakeEditSOPS(t, repoRoot, "#!/bin/sh\nexit 0\n")
	output, err := runRootCommand(t, repoRoot, "edit", "production/platform/app", "--commit")
	if err != nil {
		t.Fatalf("runRootCommand returned error: %v", err)
	}
	if !strings.Contains(output, "file unchanged; no Git commit created") {
		t.Fatalf("expected unchanged edit message, got %q", output)
	}
	if got := strings.TrimSpace(gitOutput(t, repoRoot, "log", "-1", "--pretty=%s")); got != "seed secret" {
		t.Fatalf("expected no new commit, got %q", got)
	}
}

func TestRollbackRestoresHistoryAndSupportsCommit(t *testing.T) {
	repoRoot := seedKeysealRepo(t, false)
	target := filepath.Join(repoRoot, "production/platform/app.enc.yaml")
	writeFileForCLI(t, target, "first\n")
	gitRun(t, repoRoot, "add", "--", "production/platform/app.enc.yaml")
	gitRun(t, repoRoot, "commit", "-m", "first")
	firstCommit := strings.TrimSpace(gitOutput(t, repoRoot, "rev-parse", "HEAD"))
	writeFileForCLI(t, target, "second\n")
	gitRun(t, repoRoot, "add", "--", "production/platform/app.enc.yaml")
	gitRun(t, repoRoot, "commit", "-m", "second")

	_, err := runRootCommand(t, repoRoot, "rollback", "production/platform/app", "--to", firstCommit, "-m", "Rollback app secret")
	if err != nil {
		t.Fatalf("runRootCommand returned error: %v", err)
	}
	body, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("ReadFile returned error: %v", err)
	}
	if string(body) != "first\n" {
		t.Fatalf("expected rollback to restore historical content, got %q", string(body))
	}
	if got := strings.TrimSpace(gitOutput(t, repoRoot, "log", "-1", "--pretty=%s")); got != "Rollback app secret" {
		t.Fatalf("expected rollback commit, got %q", got)
	}
}

func TestRollbackDryRunIgnoresDirtyFileAndLeavesWorkingTreeUntouched(t *testing.T) {
	repoRoot := seedKeysealRepo(t, false)
	target := filepath.Join(repoRoot, "production/platform/app.enc.yaml")
	writeFileForCLI(t, target, "first\n")
	gitRun(t, repoRoot, "add", "--", "production/platform/app.enc.yaml")
	gitRun(t, repoRoot, "commit", "-m", "first")
	firstCommit := strings.TrimSpace(gitOutput(t, repoRoot, "rev-parse", "HEAD"))
	writeFileForCLI(t, target, "second\n")
	gitRun(t, repoRoot, "add", "--", "production/platform/app.enc.yaml")
	gitRun(t, repoRoot, "commit", "-m", "second")

	writeFileForCLI(t, target, "dirty\n")

	output, err := runRootCommand(t, repoRoot, "rollback", "production/platform/app", "--to", firstCommit, "--dry-run")
	if err != nil {
		t.Fatalf("runRootCommand returned error: %v", err)
	}
	if !strings.Contains(output, "would restore production/platform/app from "+firstCommit) {
		t.Fatalf("unexpected dry-run output: %q", output)
	}
	body, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("ReadFile returned error: %v", err)
	}
	if string(body) != "dirty\n" {
		t.Fatalf("expected dry-run to leave dirty file untouched, got %q", string(body))
	}
}

func TestRollbackRefusesDirtyFileWithoutDryRun(t *testing.T) {
	repoRoot := seedKeysealRepo(t, false)
	target := filepath.Join(repoRoot, "production/platform/app.enc.yaml")
	writeFileForCLI(t, target, "first\n")
	gitRun(t, repoRoot, "add", "--", "production/platform/app.enc.yaml")
	gitRun(t, repoRoot, "commit", "-m", "first")
	firstCommit := strings.TrimSpace(gitOutput(t, repoRoot, "rev-parse", "HEAD"))
	writeFileForCLI(t, target, "second\n")
	gitRun(t, repoRoot, "add", "--", "production/platform/app.enc.yaml")
	gitRun(t, repoRoot, "commit", "-m", "second")
	writeFileForCLI(t, target, "dirty\n")
	_, err := runRootCommand(t, repoRoot, "rollback", "production/platform/app", "--to", firstCommit)
	if err == nil {
		t.Fatal("expected rollback to refuse a dirty target file")
	}
	if !strings.Contains(err.Error(), "target file has local changes") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDefaultConfigYAMLIncludesGitAutoCommit(t *testing.T) {
	body := defaultConfigYAML("default")
	if !strings.Contains(body, "git:\n  auto_commit: false") {
		t.Fatalf("expected default config to include git.auto_commit, got %q", body)
	}
}

func seedKeysealRepo(t *testing.T, autoCommit bool) string {
	t.Helper()

	repoRoot := t.TempDir()
	initGitRepo(t, repoRoot)
	writeTrackedConfig(t, repoRoot, autoCommit)
	return repoRoot
}

func writeTrackedConfig(t *testing.T, root string, autoCommit bool) {
	t.Helper()

	body := defaultConfigYAML("default")
	if autoCommit {
		body = strings.Replace(body, "git:\n  auto_commit: false", "git:\n  auto_commit: true", 1)
	}
	writeFileForCLI(t, filepath.Join(root, "keyseal.yaml"), body)
	writeFileForCLI(t, filepath.Join(root, ".sops.yaml"), "creation_rules: []\n")
	gitRun(t, root, "add", "--", "keyseal.yaml", ".sops.yaml")
	gitRun(t, root, "commit", "-m", "seed config")
}

func configureFakeEncryptSOPS(t *testing.T, root string) {
	t.Helper()

	binDir := filepath.Join(root, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatalf("MkdirAll returned error: %v", err)
	}
	writeFakeSOPS(t, filepath.Join(binDir, "sops"), "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then\n  printf 'sops 3.9.0\\n'\n  exit 0\nfi\nif [ \"$1\" = \"encrypt\" ] && [ \"$2\" = \"--filename-override\" ]; then\n  printf 'ENC[test]\\n'\n  exit 0\nfi\nexit 1\n")
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+gitBinDir(t))
}

func configureFakeEditSOPS(t *testing.T, root, script string) {
	t.Helper()

	binDir := filepath.Join(root, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatalf("MkdirAll returned error: %v", err)
	}
	writeFakeSOPS(t, filepath.Join(binDir, "sops"), "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then\n  printf 'sops 3.9.0\\n'\n  exit 0\nfi\n"+script)
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+gitBinDir(t))
}

func writeFileForCLI(t *testing.T, path, body string) {
	t.Helper()

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("MkdirAll returned error: %v", err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}
}
