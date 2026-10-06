// Package updatekeys orchestrates SOPS recipient synchronization for
// Keyseal-managed encrypted files.
package updatekeys

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/jrpbuilds/keyseal/internal/config"
	"github.com/jrpbuilds/keyseal/internal/gitutil"
	"github.com/jrpbuilds/keyseal/internal/repo"
	"github.com/jrpbuilds/keyseal/internal/secretfile"
	"github.com/jrpbuilds/keyseal/internal/sopsconfig"
	"github.com/jrpbuilds/keyseal/internal/sopsutil"
)

// Options controls one updatekeys run.
type Options struct {
	// CWD is the directory containing keyseal.yaml and .sops.yaml.
	CWD string
	// Logicals are the explicit logical names requested by the user.
	Logicals []string
	// All enables repository discovery when no explicit logical names are set.
	All bool
	// Yes passes -y to sops updatekeys for non-interactive confirmation.
	Yes bool
	// Commit creates a Git commit when the full batch succeeds and files changed.
	Commit bool
	// Message is the optional Git commit message; an empty value uses a default.
	Message string
	// Stdout receives per-file progress, summaries, and commit messages.
	Stdout io.Writer
	// Stderr is reserved for command integrations that need diagnostic output.
	Stderr io.Writer
	// GitBinary is the Git executable used for optional commit behavior.
	GitBinary string
}

// Result summarizes the files processed by one updatekeys run.
type Result struct {
	// Updated contains encrypted files whose bytes changed after SOPS ran.
	Updated []TargetResult
	// Unchanged contains encrypted files whose bytes were identical after SOPS ran.
	Unchanged []TargetResult
	// Skipped contains targets intentionally skipped, currently placeholders.
	Skipped []TargetResult
	// Failed contains targets that could not be updated.
	Failed []TargetResult
	// Committed reports whether updatekeys created a Git commit.
	Committed bool
	// Message is the commit message used when Committed is true.
	Message string
}

// TargetResult records the outcome for one logical secret.
type TargetResult struct {
	// Logical is the user-facing logical secret name.
	Logical string
	// Path is the resolved encrypted file path for the logical name.
	Path string
	// Reason explains a skipped or failed target.
	Reason string
}

// target is the internal resolved form of a logical secret name and its
// absolute encrypted file path.
type target struct {
	logical string
	path    string
}

// Run validates repository state, runs SOPS updatekeys for each target, prints
// progress, and optionally commits changed encrypted files.
func Run(opts Options) (Result, error) {
	var result Result
	if opts.Stdout == nil {
		opts.Stdout = io.Discard
	}
	if opts.Stderr == nil {
		opts.Stderr = io.Discard
	}
	if opts.GitBinary == "" {
		opts.GitBinary = "git"
	}
	if opts.CWD == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return result, fmt.Errorf("get working directory: %w", err)
		}
		opts.CWD = cwd
	}
	if len(opts.Logicals) == 0 && !opts.All {
		return result, errors.New("pass one or more logical names, or use --all")
	}

	cfg, err := config.Load(filepath.Join(opts.CWD, config.DefaultConfigPath))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return result, fmt.Errorf("keyseal.yaml not found in %s; run `keyseal init` first", opts.CWD)
		}
		return result, err
	}
	repoRoot := cfg.RepoRoot(opts.CWD)
	if stat, err := os.Stat(repoRoot); err != nil {
		return result, fmt.Errorf("repository.root %s is not available: %w", repoRoot, err)
	} else if !stat.IsDir() {
		return result, fmt.Errorf("repository.root %s is not a directory", repoRoot)
	}
	if err := preflightSOPSConfig(opts.CWD); err != nil {
		return result, err
	}
	if _, err := sopsutil.Version(cfg.SOPS.Binary, config.ResolvePath(opts.CWD, cfg.SOPS.AgeKeyFile)); err != nil {
		return result, fmt.Errorf("configured SOPS binary %q is unavailable: %w", cfg.SOPS.Binary, err)
	}

	var gitRoot string
	if opts.Commit {
		gitRoot, err = gitutil.RepoRoot(opts.GitBinary, opts.CWD)
		if err != nil {
			return result, err
		}
		if err := gitutil.EnsureNoConflicts(opts.GitBinary, gitRoot); err != nil {
			return result, err
		}
	}

	targets, err := resolveTargets(repoRoot, cfg.Repository.EncryptedExtension, opts.Logicals, opts.All && len(opts.Logicals) == 0)
	if err != nil {
		return result, err
	}
	ageKeyFile := config.ResolvePath(opts.CWD, cfg.SOPS.AgeKeyFile)
	for _, target := range targets {
		classified, err := secretfile.Classify(target.path)
		if err != nil {
			result.Failed = append(result.Failed, TargetResult{Logical: target.logical, Path: target.path, Reason: err.Error()})
			fmt.Fprintf(opts.Stdout, "failed %s: %v\n", target.logical, err)
			continue
		}
		switch classified.State {
		case secretfile.StateMissing:
			result.Failed = append(result.Failed, TargetResult{Logical: target.logical, Path: target.path, Reason: "missing"})
			fmt.Fprintf(opts.Stdout, "failed %s: missing\n", target.logical)
		case secretfile.StatePlaceholder:
			result.Skipped = append(result.Skipped, TargetResult{Logical: target.logical, Path: target.path, Reason: "placeholder"})
			fmt.Fprintf(opts.Stdout, "skipped %s: placeholder\n", target.logical)
		case secretfile.StatePlaintext:
			reason := "non-empty plaintext at encrypted path"
			result.Failed = append(result.Failed, TargetResult{Logical: target.logical, Path: target.path, Reason: reason})
			fmt.Fprintf(opts.Stdout, "failed %s: %s\n", target.logical, reason)
		case secretfile.StateEncrypted:
			before := classified.Raw
			if err := sopsutil.UpdateKeys(cfg.SOPS.Binary, ageKeyFile, target.path, opts.Yes); err != nil {
				result.Failed = append(result.Failed, TargetResult{Logical: target.logical, Path: target.path, Reason: err.Error()})
				fmt.Fprintf(opts.Stdout, "failed %s: %v\n", target.logical, err)
				continue
			}
			after, err := os.ReadFile(target.path)
			if err != nil {
				result.Failed = append(result.Failed, TargetResult{Logical: target.logical, Path: target.path, Reason: err.Error()})
				fmt.Fprintf(opts.Stdout, "failed %s: read after updatekeys: %v\n", target.logical, err)
				continue
			}
			if bytes.Equal(before, after) {
				result.Unchanged = append(result.Unchanged, TargetResult{Logical: target.logical, Path: target.path})
				fmt.Fprintf(opts.Stdout, "unchanged %s\n", target.logical)
				continue
			}
			result.Updated = append(result.Updated, TargetResult{Logical: target.logical, Path: target.path})
			fmt.Fprintf(opts.Stdout, "updated %s\n", target.logical)
		}
	}

	fmt.Fprintf(opts.Stdout, "updatekeys summary: %d updated, %d unchanged, %d skipped, %d failed\n", len(result.Updated), len(result.Unchanged), len(result.Skipped), len(result.Failed))
	if len(result.Failed) > 0 {
		return result, fmt.Errorf("updatekeys failed for %d file(s)", len(result.Failed))
	}
	if !opts.Commit {
		return result, nil
	}
	if len(result.Updated) == 0 {
		fmt.Fprintln(opts.Stdout, "no files changed; no Git commit created")
		return result, nil
	}
	message := opts.Message
	if message == "" {
		message = DefaultCommitMessage(len(result.Updated))
	}
	paths := make([]string, 0, len(result.Updated))
	for _, updated := range result.Updated {
		paths = append(paths, updated.Path)
	}
	slices.Sort(paths)
	if err := gitutil.CommitPaths(opts.GitBinary, gitRoot, message, paths); err != nil {
		return result, err
	}
	result.Committed = true
	result.Message = message
	fmt.Fprintf(opts.Stdout, "committed Git change: %s\n", message)
	return result, nil
}

// DefaultCommitMessage returns the default Git commit subject for updatekeys.
func DefaultCommitMessage(count int) string {
	if count == 1 {
		return "Update SOPS recipients for 1 Keyseal file"
	}
	return fmt.Sprintf("Update SOPS recipients for %d Keyseal files", count)
}

// preflightSOPSConfig validates that .sops.yaml is present and ready before
// updatekeys is allowed to mutate any encrypted file.
func preflightSOPSConfig(cwd string) error {
	sopsPath := filepath.Join(cwd, ".sops.yaml")
	data, err := os.ReadFile(sopsPath)
	if err != nil {
		return fmt.Errorf("read .sops.yaml: %w", err)
	}
	info, err := sopsconfig.Inspect(data)
	if err != nil {
		return fmt.Errorf("inspect .sops.yaml: %w", err)
	}
	switch {
	case info.CreationRuleCount == 0:
		return errors.New(".sops.yaml does not define any creation rules")
	case info.UsableRuleCount == 0:
		return errors.New(".sops.yaml creation rules do not contain usable recipients")
	case len(info.Placeholders) > 0:
		return fmt.Errorf(".sops.yaml still contains placeholder recipient values: %s", strings.Join(info.Placeholders, ", "))
	default:
		return nil
	}
}

// resolveTargets turns either explicit logical names or --all discovery into a
// deduplicated, stable list of encrypted file targets.
func resolveTargets(root, ext string, logicals []string, all bool) ([]target, error) {
	var candidates []target
	if all {
		files, err := repo.DiscoverEncryptedFiles(root, ext)
		if err != nil {
			return nil, err
		}
		slices.Sort(files)
		for _, file := range files {
			logical, err := repo.PathToLogicalName(root, file, ext)
			if err != nil {
				return nil, err
			}
			candidates = append(candidates, target{logical: logical, path: file})
		}
	} else {
		for _, logical := range logicals {
			path, err := repo.LogicalNameToPath(root, logical, ext)
			if err != nil {
				return nil, err
			}
			candidates = append(candidates, target{logical: logical, path: path})
		}
	}

	seen := map[string]struct{}{}
	out := make([]target, 0, len(candidates))
	for _, candidate := range candidates {
		if _, ok := seen[candidate.logical]; ok {
			continue
		}
		seen[candidate.logical] = struct{}{}
		out = append(out, candidate)
	}
	return out, nil
}
