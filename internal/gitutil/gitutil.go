// Package gitutil wraps the small slice of Git behavior that Keyseal relies on
// for repository-aware workflows.
//
// The package intentionally stays narrow: it detects repository context,
// surfaces predictable error messages, stages explicit paths, creates commits,
// and exposes read-only file history helpers. It does not try to abstract all
// of Git or turn Keyseal into a generic Git client.
package gitutil

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Well-known errors returned by the git helpers.
var (
	ErrBinaryNotFound      = errors.New("git binary not found")
	ErrNotRepository       = errors.New("not inside a Git repository")
	ErrNothingToCommit     = errors.New("nothing to commit")
	ErrConflictedRepo      = errors.New("Git repository has unresolved conflicts")
	ErrFileHasLocalChanges = errors.New("target file has local changes")
)

// StatusEntry models one line of `git status --porcelain=v1` output.
//
// Staged and Unstaged contain the two porcelain status columns, while Path is
// the current repo-relative path. OriginalPath is populated for rename/copy
// entries so callers can filter by either side of the move when needed.
type StatusEntry struct {
	Staged       byte
	Unstaged     byte
	Path         string
	OriginalPath string
}

// Code returns the two-character porcelain status code.
func (e StatusEntry) Code() string {
	return string([]byte{e.Staged, e.Unstaged})
}

// IsUntracked reports whether the entry represents an untracked file.
func (e StatusEntry) IsUntracked() bool {
	return e.Staged == '?' && e.Unstaged == '?'
}

// LookPath resolves the configured Git binary.
func LookPath(binary string) (string, error) {
	path, err := exec.LookPath(binary)
	if err != nil {
		return "", fmt.Errorf("%w", ErrBinaryNotFound)
	}
	return path, nil
}

// RepoRoot resolves the Git top-level directory for cwd.
func RepoRoot(binary, cwd string) (string, error) {
	if _, err := LookPath(binary); err != nil {
		return "", err
	}
	stdout, _, err := runCaptured(cwd, binary, "rev-parse", "--show-toplevel")
	if err != nil {
		return "", fmt.Errorf("%w", ErrNotRepository)
	}
	return strings.TrimSpace(stdout), nil
}

// Status returns parsed porcelain status entries for the provided repo.
//
// The optional pathspecs are interpreted relative to repoRoot. Supplying no
// pathspecs asks Git for repository-wide status output.
func Status(binary, repoRoot string, pathspecs ...string) ([]StatusEntry, error) {
	args := []string{"status", "--porcelain=v1", "--untracked-files=all"}
	args = appendPathspecs(args, pathspecs)
	stdout, _, err := runCaptured(repoRoot, binary, args...)
	if err != nil {
		return nil, fmt.Errorf("list git status: %w", err)
	}
	return parseStatus(stdout)
}

// Diff returns `git diff` output for a single path.
func Diff(binary, repoRoot, path string) (string, error) {
	pathspec, err := Pathspec(repoRoot, path)
	if err != nil {
		return "", err
	}
	stdout, _, err := runCaptured(repoRoot, binary, "diff", "--", pathspec)
	if err != nil {
		return "", fmt.Errorf("show git diff: %w", err)
	}
	return stdout, nil
}

// History returns `git log --follow` output for a single path.
func History(binary, repoRoot, path string, oneline bool) (string, error) {
	pathspec, err := Pathspec(repoRoot, path)
	if err != nil {
		return "", err
	}
	args := []string{"log", "--follow"}
	if oneline {
		args = append(args, "--oneline")
	}
	args = append(args, "--", pathspec)
	stdout, _, err := runCaptured(repoRoot, binary, args...)
	if err != nil {
		return "", fmt.Errorf("show git history: %w", err)
	}
	return stdout, nil
}

// HasLocalChanges reports whether the provided path has any staged, unstaged,
// or untracked changes.
func HasLocalChanges(binary, repoRoot, path string) (bool, error) {
	pathspec, err := Pathspec(repoRoot, path)
	if err != nil {
		return false, err
	}
	entries, err := Status(binary, repoRoot, pathspec)
	if err != nil {
		return false, err
	}
	return len(entries) > 0, nil
}

// StagePaths stages the exact paths provided by the caller.
//
// Callers are expected to decide which files are safe to stage. This helper
// exists so CLI commands never fall back to broad `git add .` behavior.
//
// Paths missing from the working tree are staged as deletions only when HEAD
// still contains them. A missing path absent from both HEAD and the index,
// such as the old side of a `git mv`, is already staged and is skipped. A
// missing path that exists only in the index is left alone: removing it would
// discard a staged blob that has never been committed.
func StagePaths(binary, repoRoot string, paths []string) error {
	var present, deleted []string
	for _, path := range paths {
		pathspec, err := Pathspec(repoRoot, path)
		if err != nil {
			return err
		}
		_, err = os.Lstat(filepath.Join(repoRoot, filepath.FromSlash(pathspec)))
		switch {
		case err == nil:
			present = append(present, pathspec)
		case errors.Is(err, os.ErrNotExist):
			inHead, err := RevisionContainsPath(binary, repoRoot, "HEAD", pathspec)
			if err != nil {
				return err
			}
			if inHead {
				deleted = append(deleted, pathspec)
				continue
			}
			staged, err := indexContainsPath(binary, repoRoot, pathspec)
			if err != nil {
				return err
			}
			if staged {
				return fmt.Errorf("stage git paths: %s is staged but missing from the worktree", pathspec)
			}
		default:
			return fmt.Errorf("stage git paths: %w", err)
		}
	}
	if len(present) > 0 {
		args := append([]string{"add", "--"}, present...)
		if _, _, err := runCaptured(repoRoot, binary, args...); err != nil {
			return fmt.Errorf("stage git paths: %w", err)
		}
	}
	if len(deleted) > 0 {
		args := append([]string{"rm", "--cached", "--ignore-unmatch", "--quiet", "--"}, deleted...)
		if _, _, err := runCaptured(repoRoot, binary, args...); err != nil {
			return fmt.Errorf("stage removed git paths: %w", err)
		}
	}
	return nil
}

// indexContainsPath reports whether the index has a blob for pathspec.
func indexContainsPath(binary, repoRoot, pathspec string) (bool, error) {
	cmd := exec.Command(binary, "cat-file", "-e", ":"+filepath.ToSlash(pathspec))
	cmd.Dir = repoRoot
	err := cmd.Run()
	switch {
	case err == nil:
		return true, nil
	case exitCode(err) == 128:
		return false, nil
	default:
		return false, fmt.Errorf("check git index path: %w", err)
	}
}

// hasStagedChanges reports whether the index contains changes for pathspecs.
func hasStagedChanges(binary, repoRoot string, pathspecs []string) (bool, error) {
	args := appendPathspecs([]string{"diff", "--cached", "--quiet", "--exit-code"}, pathspecs)
	cmd := exec.Command(binary, args...)
	cmd.Dir = repoRoot
	err := cmd.Run()
	switch {
	case err == nil:
		return false, nil
	case exitCode(err) == 1:
		return true, nil
	default:
		return false, fmt.Errorf("check staged changes: %w", err)
	}
}

// CommitPaths stages the exact paths provided and commits only those paths.
//
// Unlike a plain `git commit`, unrelated changes the operator already staged
// stay staged and are not swept into the Keyseal commit.
func CommitPaths(binary, repoRoot, message string, paths []string) error {
	if strings.TrimSpace(message) == "" {
		return errors.New("commit message is required")
	}
	if len(paths) == 0 {
		return ErrNothingToCommit
	}
	if err := StagePaths(binary, repoRoot, paths); err != nil {
		return err
	}
	pathspecs, err := Pathspecs(repoRoot, paths)
	if err != nil {
		return err
	}
	hasChanges, err := hasStagedChanges(binary, repoRoot, pathspecs)
	if err != nil {
		return err
	}
	if !hasChanges {
		return ErrNothingToCommit
	}
	args := appendPathspecs([]string{"commit", "-m", message, "--only"}, pathspecs)
	if _, _, err := runCaptured(repoRoot, binary, args...); err != nil {
		return fmt.Errorf("create git commit: %w", err)
	}
	return nil
}

// EnsureNoConflicts fails when the repository contains unmerged paths.
func EnsureNoConflicts(binary, repoRoot string) error {
	stdout, _, err := runCaptured(repoRoot, binary, "diff", "--name-only", "--diff-filter=U")
	if err != nil {
		return fmt.Errorf("check git conflicts: %w", err)
	}
	if strings.TrimSpace(stdout) != "" {
		return ErrConflictedRepo
	}
	return nil
}

// RevisionContainsPath reports whether a path exists in a historical revision.
func RevisionContainsPath(binary, repoRoot, revision, path string) (bool, error) {
	pathspec, err := Pathspec(repoRoot, path)
	if err != nil {
		return false, err
	}
	object := revision + ":" + filepath.ToSlash(pathspec)
	cmd := exec.Command(binary, "cat-file", "-e", object)
	cmd.Dir = repoRoot
	err = cmd.Run()
	switch {
	case err == nil:
		return true, nil
	case exitCode(err) == 128:
		return false, nil
	default:
		return false, fmt.Errorf("check git revision path: %w", err)
	}
}

// RestoreFile updates the working tree copy of path to match revision.
func RestoreFile(binary, repoRoot, revision, path string) error {
	pathspec, err := Pathspec(repoRoot, path)
	if err != nil {
		return err
	}
	if _, _, err := runCaptured(repoRoot, binary, "restore", "--source", revision, "--worktree", "--", pathspec); err != nil {
		return fmt.Errorf("restore file from git history: %w", err)
	}
	return nil
}

// Pathspec converts an absolute or repo-relative path into a Git pathspec.
func Pathspec(repoRoot, path string) (string, error) {
	if path == "" {
		return "", errors.New("path is required")
	}
	if !filepath.IsAbs(path) {
		clean := filepath.Clean(path)
		if clean == ".." || strings.HasPrefix(clean, ".."+string(os.PathSeparator)) {
			return "", fmt.Errorf("path %q is outside repository root", path)
		}
		return filepath.ToSlash(clean), nil
	}
	rel, err := filepath.Rel(repoRoot, path)
	if err != nil {
		return "", fmt.Errorf("make relative git path: %w", err)
	}
	rel = filepath.Clean(rel)
	if rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("path %q is outside repository root", path)
	}
	return filepath.ToSlash(rel), nil
}

// Pathspecs converts many paths in one pass.
func Pathspecs(repoRoot string, paths []string) ([]string, error) {
	out := make([]string, 0, len(paths))
	for _, path := range paths {
		pathspec, err := Pathspec(repoRoot, path)
		if err != nil {
			return nil, err
		}
		out = append(out, pathspec)
	}
	return out, nil
}

func appendPathspecs(args []string, pathspecs []string) []string {
	if len(pathspecs) == 0 {
		return args
	}
	args = append(args, "--")
	return append(args, pathspecs...)
}

func parseStatus(stdout string) ([]StatusEntry, error) {
	stdout = strings.TrimRight(stdout, "\n")
	if stdout == "" {
		return nil, nil
	}
	lines := strings.Split(stdout, "\n")
	entries := make([]StatusEntry, 0, len(lines))
	for _, line := range lines {
		if len(line) < 4 {
			return nil, fmt.Errorf("unexpected git status output: %q", line)
		}
		entry := StatusEntry{
			Staged:   line[0],
			Unstaged: line[1],
			Path:     line[3:],
		}
		if idx := strings.Index(entry.Path, " -> "); idx >= 0 {
			entry.OriginalPath = entry.Path[:idx]
			entry.Path = entry.Path[idx+4:]
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

func runCaptured(dir, binary string, args ...string) (string, string, error) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd := exec.Command(binary, args...)
	cmd.Dir = dir
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		return stdout.String(), stderr.String(), fmt.Errorf("%s", sanitizeOutput(stderr.Bytes(), stdout.Bytes(), err))
	}
	return stdout.String(), stderr.String(), nil
}

func sanitizeOutput(primary, fallback []byte, err error) string {
	text := strings.TrimSpace(string(primary))
	if text == "" {
		text = strings.TrimSpace(string(fallback))
	}
	if text == "" {
		text = err.Error()
	}
	lines := strings.Split(text, "\n")
	if len(lines) > 3 {
		lines = lines[:3]
	}
	return strings.Join(lines, "; ")
}

func exitCode(err error) int {
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode()
	}
	return -1
}
