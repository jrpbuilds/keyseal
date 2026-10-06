package cli

import (
	"bytes"
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	"github.com/jrpbuilds/keyseal/internal/config"
	"github.com/jrpbuilds/keyseal/internal/gitutil"
	"github.com/jrpbuilds/keyseal/internal/repo"
	"github.com/jrpbuilds/keyseal/internal/schema"
	"github.com/jrpbuilds/keyseal/internal/secretfile"
	"github.com/jrpbuilds/keyseal/internal/sopsutil"
	"github.com/spf13/cobra"
)

type loadedDocuments struct {
	Docs                []schema.EnvSecretDocument
	LoadedLogicalNames  []string
	SkippedPlaceholders []string
}

func loadDocuments(cfg config.Config, cwd string, logicalNames []string) (loadedDocuments, error) {
	opts := validationOptions(cfg)
	root := cfg.RepoRoot(cwd)
	ageKeyFile := config.ResolvePath(cwd, cfg.SOPS.AgeKeyFile)
	result := loadedDocuments{
		Docs:               make([]schema.EnvSecretDocument, 0, len(logicalNames)),
		LoadedLogicalNames: make([]string, 0, len(logicalNames)),
	}
	for _, logical := range logicalNames {
		// Logical names are the only user-facing identifier. They must be mapped
		// through the repo package so every command applies the same path safety
		// rules and naming contract.
		path, err := repo.LogicalNameToPath(root, logical, cfg.Repository.EncryptedExtension)
		if err != nil {
			return loadedDocuments{}, err
		}
		classified, err := secretfile.Classify(path)
		if err != nil {
			return loadedDocuments{}, fmt.Errorf("inspect %s: %w", logical, err)
		}
		switch classified.State {
		case secretfile.StateMissing:
			return loadedDocuments{}, fmt.Errorf("secret %s not found at %s", logical, path)
		case secretfile.StatePlaceholder:
			result.SkippedPlaceholders = append(result.SkippedPlaceholders, logical)
			continue
		case secretfile.StatePlaintext:
			return loadedDocuments{}, fmt.Errorf("secret %s is non-empty plaintext at encrypted path %s: file does not contain SOPS metadata", logical, path)
		}
		plaintext, err := sopsutil.DecryptFile(path, "yaml", ageKeyFile)
		if err != nil {
			return loadedDocuments{}, err
		}
		doc, _, err := schema.ParseYAMLDocument(plaintext)
		if err != nil {
			return loadedDocuments{}, fmt.Errorf("parse %s: %w", logical, err)
		}
		if err := doc.Validate(opts); err != nil {
			return loadedDocuments{}, fmt.Errorf("validate %s: %w", logical, err)
		}
		result.Docs = append(result.Docs, doc)
		result.LoadedLogicalNames = append(result.LoadedLogicalNames, logical)
	}
	if len(result.Docs) == 0 && len(result.SkippedPlaceholders) > 0 {
		return loadedDocuments{}, fmt.Errorf("all requested secrets are empty or uninitialized placeholder files: %s", strings.Join(result.SkippedPlaceholders, ", "))
	}
	return result, nil
}

// ensureSOPSAvailable verifies that the configured SOPS binary resolves and
// executes before a command starts mutating encrypted files.
func ensureSOPSAvailable(cfg config.Config, cwd string) error {
	ageKeyFile := config.ResolvePath(cwd, cfg.SOPS.AgeKeyFile)
	if _, err := sopsutil.Version(cfg.SOPS.Binary, ageKeyFile); err != nil {
		return fmt.Errorf("configured SOPS binary %q is unavailable: %w", cfg.SOPS.Binary, err)
	}
	return nil
}

// gitWorkflowContext collects the Keyseal and Git roots needed to safely map
// logical names, config files, and Git pathspecs without re-deriving them in
// each command.
type gitWorkflowContext struct {
	Config      config.Config
	CWD         string
	KeysealRoot string
	GitRoot     string
	ConfigPath  string
	SOPSPath    string
}

// commitFlags models the shared commit-related CLI flags used by mutating
// commands. Keeping them together ensures `-m`, `--commit`, `--no-commit`, and
// config defaults resolve consistently everywhere.
type commitFlags struct {
	commit    bool
	noCommit  bool
	message   string
	hasCommit bool
	hasNoOp   bool
}

type commitDecision struct {
	Enabled bool
	Message string
}

func bindCommitFlags(cmd *cobra.Command, flags *commitFlags) {
	cmd.Flags().BoolVar(&flags.commit, "commit", false, "Stage the command's changed files and create a Git commit")
	cmd.Flags().BoolVar(&flags.noCommit, "no-commit", false, "Do not create a Git commit, even when git.auto_commit is enabled")
	cmd.Flags().StringVarP(&flags.message, "message", "m", "", "Git commit message; implies --commit")
}

func resolveCommitDecision(cmd *cobra.Command, cfg config.Config, flags commitFlags) (commitDecision, error) {
	flags.hasCommit = cmd.Flags().Changed("commit")
	flags.hasNoOp = cmd.Flags().Changed("no-commit")

	switch {
	case flags.hasCommit && flags.hasNoOp:
		return commitDecision{}, fmt.Errorf("--commit and --no-commit cannot be used together")
	case flags.message != "" && flags.hasNoOp:
		return commitDecision{}, fmt.Errorf("--message implies --commit and cannot be used with --no-commit")
	case flags.message != "":
		return commitDecision{Enabled: true, Message: flags.message}, nil
	case flags.hasCommit:
		return commitDecision{Enabled: flags.commit}, nil
	case flags.hasNoOp:
		return commitDecision{Enabled: false}, nil
	default:
		return commitDecision{Enabled: cfg.Git.AutoCommit}, nil
	}
}

func loadGitWorkflowContext() (gitWorkflowContext, error) {
	cfg, cwd, err := loadConfigFromCWD()
	if err != nil {
		return gitWorkflowContext{}, err
	}
	gitRoot, err := gitutil.RepoRoot("git", cwd)
	if err != nil {
		return gitWorkflowContext{}, err
	}
	return gitWorkflowContext{
		Config:      cfg,
		CWD:         cwd,
		KeysealRoot: cfg.RepoRoot(cwd),
		GitRoot:     gitRoot,
		ConfigPath:  filepath.Join(cwd, config.DefaultConfigPath),
		SOPSPath:    filepath.Join(cwd, ".sops.yaml"),
	}, nil
}

func relevantStatusEntries(ctx gitWorkflowContext) ([]gitutil.StatusEntry, error) {
	entries, err := gitutil.Status("git", ctx.GitRoot)
	if err != nil {
		return nil, err
	}
	out := make([]gitutil.StatusEntry, 0, len(entries))
	for _, entry := range entries {
		if isRelevantRepoPath(ctx, entry.Path) || (entry.OriginalPath != "" && isRelevantRepoPath(ctx, entry.OriginalPath)) {
			out = append(out, entry)
		}
	}
	return out, nil
}

func isRelevantRepoPath(ctx gitWorkflowContext, repoPath string) bool {
	if repoPath == "" {
		return false
	}
	repoPath = filepath.ToSlash(filepath.Clean(repoPath))
	configPath, err := gitutil.Pathspec(ctx.GitRoot, ctx.ConfigPath)
	if err == nil && repoPath == configPath {
		return true
	}
	sopsPath, err := gitutil.Pathspec(ctx.GitRoot, ctx.SOPSPath)
	if err == nil && repoPath == sopsPath {
		return true
	}

	secretRoot, err := gitutil.Pathspec(ctx.GitRoot, ctx.KeysealRoot)
	if err != nil {
		return false
	}
	secretRoot = strings.TrimSuffix(secretRoot, "/")
	if secretRoot == "." || secretRoot == "" {
		return strings.HasSuffix(repoPath, ctx.Config.Repository.EncryptedExtension)
	}
	return strings.HasPrefix(repoPath, secretRoot+"/") && strings.HasSuffix(repoPath, ctx.Config.Repository.EncryptedExtension)
}

func stagePathsForEntries(ctx gitWorkflowContext, entries []gitutil.StatusEntry) []string {
	seen := map[string]struct{}{}
	paths := make([]string, 0, len(entries))
	for _, entry := range entries {
		// Both sides of a staged rename must be included, because commits are
		// path-scoped and would otherwise leave the old path in HEAD.
		for _, repoPath := range []string{entry.Path, entry.OriginalPath} {
			if !isRelevantRepoPath(ctx, repoPath) {
				continue
			}
			abs := filepath.Join(ctx.GitRoot, filepath.FromSlash(repoPath))
			if _, ok := seen[abs]; ok {
				continue
			}
			seen[abs] = struct{}{}
			paths = append(paths, abs)
		}
	}
	slices.Sort(paths)
	return paths
}

func ensureRepoReadyForCommit(ctx gitWorkflowContext) error {
	return gitutil.EnsureNoConflicts("git", ctx.GitRoot)
}

func commitPaths(ctx gitWorkflowContext, paths []string, message string) error {
	if err := ensureRepoReadyForCommit(ctx); err != nil {
		return err
	}
	return gitutil.CommitPaths("git", ctx.GitRoot, message, paths)
}

func formatStatusEntries(entries []gitutil.StatusEntry) string {
	if len(entries) == 0 {
		return "no Keyseal-managed changes\n"
	}
	var buf bytes.Buffer
	for _, entry := range entries {
		fmt.Fprintf(&buf, "%s %s\n", entry.Code(), entry.Path)
	}
	return buf.String()
}

func defaultCommitMessageForSecretAdd(logical string) string {
	return fmt.Sprintf("Add secret %s", logical)
}

func defaultCommitMessageForSecretEdit(logical string) string {
	return fmt.Sprintf("Update secret %s", logical)
}

func defaultCommitMessageForSecretUnset(logical string) string {
	return fmt.Sprintf("Remove keys from secret %s", logical)
}

func defaultCommitMessageForSecretGenerate(logical string) string {
	return fmt.Sprintf("Generate values in secret %s", logical)
}

func defaultCommitMessageForSecretImport(logical string) string {
	return fmt.Sprintf("Import values into secret %s", logical)
}

func defaultCommitMessageForSecretRollback(logical, revision string) string {
	return fmt.Sprintf("Rollback secret %s to %s", logical, revision)
}

func defaultCommitMessageForBatch(count int) string {
	if count == 1 {
		return "Update 1 Keyseal file"
	}
	return fmt.Sprintf("Update %d Keyseal files", count)
}
