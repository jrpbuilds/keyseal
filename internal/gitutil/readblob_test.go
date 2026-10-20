package gitutil_test

import (
	"bytes"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jrpbuilds/keyseal/internal/gitutil"
)

const blobMarker = "kslblob-5d1e8c"

func commitBlob(t *testing.T, repoRoot, rel, body string) string {
	t.Helper()
	writeFile(t, filepath.Join(repoRoot, rel), body)
	gitRun(t, repoRoot, "add", "--", rel)
	gitRun(t, repoRoot, "commit", "-m", "seed")
	return strings.TrimSpace(gitOutput(t, repoRoot, "rev-parse", "HEAD"))
}

func TestReadBlobReturnsHistoricalBytesWithoutTouchingWorktree(t *testing.T) {
	repoRoot := newGitRepo(t)
	commit := commitBlob(t, repoRoot, "nested/secret.enc.yaml", "committed "+blobMarker+"\n")
	path := filepath.Join(repoRoot, "nested", "secret.enc.yaml")
	writeFile(t, path, "dirty worktree\n")

	got, err := gitutil.ReadBlob("git", repoRoot, commit, path)
	if err != nil {
		t.Fatalf("ReadBlob returned error: %v", err)
	}
	if want := "committed " + blobMarker + "\n"; string(got) != want {
		t.Fatalf("unexpected blob: %q", got)
	}
	if status := gitOutput(t, repoRoot, "status", "--porcelain"); !strings.Contains(status, "M nested/secret.enc.yaml") {
		t.Fatalf("worktree edit should be left alone, status: %q", status)
	}
}

func TestReadBlobAcceptsSymbolicRevision(t *testing.T) {
	repoRoot := newGitRepo(t)
	commitBlob(t, repoRoot, "secret.enc.yaml", "v1\n")

	got, err := gitutil.ReadBlob("git", repoRoot, "HEAD", "secret.enc.yaml")
	if err != nil || !bytes.Equal(got, []byte("v1\n")) {
		t.Fatalf("expected v1 from HEAD, got %q, %v", got, err)
	}
}

func TestReadBlobDistinguishesUnknownRevisionFromAbsentPath(t *testing.T) {
	repoRoot := newGitRepo(t)
	commit := commitBlob(t, repoRoot, "secret.enc.yaml", blobMarker+"\n")
	writeFile(t, filepath.Join(repoRoot, "staged.enc.yaml"), blobMarker+"\n")
	gitRun(t, repoRoot, "add", "--", "staged.enc.yaml")

	_, err := gitutil.ReadBlob("git", repoRoot, commit, "missing.enc.yaml")
	if !errors.Is(err, gitutil.ErrBlobAbsent) || errors.Is(err, gitutil.ErrUnknownRevision) {
		t.Fatalf("expected ErrBlobAbsent for a missing path, got %v", err)
	}
	_, err = gitutil.ReadBlob("git", repoRoot, "HEAD", "staged.enc.yaml")
	if !errors.Is(err, gitutil.ErrBlobAbsent) {
		t.Fatalf("a path that is only staged is absent from HEAD, got %v", err)
	}
	_, err = gitutil.ReadBlob("git", repoRoot, "no-such-revision", "secret.enc.yaml")
	if !errors.Is(err, gitutil.ErrUnknownRevision) || errors.Is(err, gitutil.ErrBlobAbsent) {
		t.Fatalf("expected ErrUnknownRevision for a bad revision, got %v", err)
	}
}

func TestReadBlobRejectsUnsafeRevisions(t *testing.T) {
	repoRoot := newGitRepo(t)
	commitBlob(t, repoRoot, "secret.enc.yaml", blobMarker+"\n")

	for _, revision := range []string{"", "--help", "-n1", "HEAD:secret.enc.yaml", "HEAD secret", "HEAD\n", ":/x"} {
		_, err := gitutil.ReadBlob("git", repoRoot, revision, "secret.enc.yaml")
		if !errors.Is(err, gitutil.ErrUnknownRevision) {
			t.Errorf("revision %q: expected ErrUnknownRevision, got %v", revision, err)
		}
	}
}

func TestReadBlobErrorsNeverCarryBlobBytes(t *testing.T) {
	repoRoot := newGitRepo(t)
	commit := commitBlob(t, repoRoot, "dir/secret.enc.yaml", blobMarker+"\n")

	// A directory is a tree object, so cat-file -e succeeds and the blob read fails.
	_, treeErr := gitutil.ReadBlob("git", repoRoot, commit, "dir")
	_, outsideErr := gitutil.ReadBlob("git", repoRoot, commit, "../outside.enc.yaml")
	_, badBinaryErr := gitutil.ReadBlob("git-binary-that-does-not-exist", repoRoot, commit, "dir/secret.enc.yaml")
	for name, err := range map[string]error{"tree": treeErr, "outside": outsideErr, "binary": badBinaryErr} {
		if err == nil {
			t.Errorf("%s: expected an error", name)
			continue
		}
		if strings.Contains(err.Error(), blobMarker) {
			t.Errorf("%s: error must not contain blob bytes: %v", name, err)
		}
		if errors.Is(err, gitutil.ErrBlobAbsent) {
			t.Errorf("%s: unexpected ErrBlobAbsent", name)
		}
	}
}
