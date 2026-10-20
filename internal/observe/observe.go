// Package observe loads secret documents and returns value-free reports.
//
// Inspect and Compare never return plaintext, ciphertext, or value maps. The
// decrypted bytes live in locals that are cleared before the call returns, and
// the pure YAML walk that reads them sits in a Go-internal package that
// internal/cli cannot import.
package observe

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/jrpbuilds/keyseal/internal/config"
	"github.com/jrpbuilds/keyseal/internal/gitutil"
	"github.com/jrpbuilds/keyseal/internal/observe/internal/redact"
	"github.com/jrpbuilds/keyseal/internal/repo"
	"github.com/jrpbuilds/keyseal/internal/secretfile"
	"github.com/jrpbuilds/keyseal/internal/sopsutil"
)

const (
	// FingerprintKeyEnv names the file holding the key for --fingerprint.
	FingerprintKeyEnv    = "KEYSEAL_FINGERPRINT_KEY_FILE"
	minFingerprintKeyLen = 32
	maxFingerprintKeyLen = 64 * 1024

	sourceWorktree = "worktree"
	sourceRevision = "revision"
)

// Ref selects one document by logical name.
type Ref struct {
	Logical string
	// Revision is a Git revision. Empty selects the worktree. observe does not
	// default it to HEAD, so callers choose that explicitly.
	Revision string
}

// Assertion is the optional CI gate on a comparison.
type Assertion string

const (
	AssertNone    Assertion = ""
	AssertEqual   Assertion = "equal"
	AssertUnequal Assertion = "unequal"
)

// Option holds no key material and no secret values, so it is safe to log.
type Option struct {
	// Keys restricts the report to these names. Empty selects every key.
	Keys        []string
	ShowLength  bool
	ShowType    bool
	Fingerprint bool
	Assertion   Assertion
	// AllowMissing lets a comparison treat one absent document as a document
	// with no keys, as a semantic diff does for a file added or deleted since
	// the revision. Both documents absent still fails. Inspect ignores it.
	AllowMissing bool
}

// Report is the only result a command may print.
type Report interface {
	// Passed is the exit policy: false means the command must exit non-zero.
	Passed() bool
	Text() string
	MarshalJSON() ([]byte, error)
}

// Scope resolves logical names for one repository and command run. It does not
// retain plaintext or fingerprint key material.
type Scope struct {
	keysealRoot string
	extension   string
	ageKeyFile  string
	gitRoot     string
}

// New builds a scope from an already-loaded config. gitRoot may be empty, in
// which case a Ref with a Revision produces a failed report.
func New(cwd string, cfg config.Config, gitRoot string) *Scope {
	return &Scope{
		keysealRoot: cfg.RepoRoot(cwd),
		extension:   cfg.Repository.EncryptedExtension,
		ageKeyFile:  config.ResolvePath(cwd, cfg.SOPS.AgeKeyFile),
		gitRoot:     gitRoot,
	}
}

// Inspect reports one document's key states. Any failure, including a file
// that is missing, a placeholder, or plaintext, is a report with Passed() false.
func (s *Scope) Inspect(ref Ref, opt Option) Report {
	doc := s.load(ref, false)
	ins := inspection{side: doc.side}

	mac, err := fingerprintKey(opt)
	defer clear(mac)
	if err != nil && ins.side.problem == "" {
		ins.side.problem = err.Error()
	}
	if ins.side.problem != "" {
		return ins
	}

	plaintext := s.decrypt(&doc)
	defer clear(plaintext)
	if doc.side.problem != "" {
		ins.side = doc.side
		return ins
	}

	projection, err := redact.Project(plaintext, redactOptions(opt), mac)
	if err != nil {
		ins.side.problem = fmt.Sprintf("document %q is not a valid env document", ref.Logical)
		return ins
	}
	ins.side.decrypted = true
	ins.side.duplicates = projection.Duplicates
	ins.keys = projection.Keys
	return ins
}

// Compare reports left (the baseline) against right (the candidate). Both
// documents are classified before either is decrypted, so a bad file does not
// cause its sibling to be decrypted.
func (s *Scope) Compare(left, right Ref, opt Option) Report {
	l, r := s.load(left, opt.AllowMissing), s.load(right, opt.AllowMissing)
	cmp := comparison{left: l.side, right: r.side, assertion: opt.Assertion}

	mac, err := fingerprintKey(opt)
	defer clear(mac)
	if err != nil {
		cmp.problems = append(cmp.problems, err.Error())
	}
	if l.side.fileState == secretfile.StateMissing && r.side.fileState == secretfile.StateMissing {
		cmp.problems = append(cmp.problems, "both documents are missing")
	}
	if l.side.problem != "" || r.side.problem != "" || len(cmp.problems) > 0 {
		return cmp
	}

	leftPlain := s.decrypt(&l)
	defer clear(leftPlain)
	rightPlain := s.decrypt(&r)
	defer clear(rightPlain)
	cmp.left, cmp.right = l.side, r.side
	if l.side.problem != "" || r.side.problem != "" {
		return cmp
	}

	result, err := redact.CompareYAML(
		redact.Source{Plaintext: leftPlain, Absent: l.side.fileState == secretfile.StateMissing},
		redact.Source{Plaintext: rightPlain, Absent: r.side.fileState == secretfile.StateMissing},
		redactOptions(opt), mac,
	)
	if err != nil {
		var invalid redact.InvalidSideError
		if errors.As(err, &invalid) && invalid.Right {
			cmp.right.problem = fmt.Sprintf("document %q is not a valid env document", right.Logical)
		} else {
			cmp.left.problem = fmt.Sprintf("document %q is not a valid env document", left.Logical)
		}
		return cmp
	}
	cmp.left.decrypted, cmp.right.decrypted = true, true
	cmp.left.duplicates, cmp.right.duplicates = result.LeftDuplicates, result.RightDuplicates
	cmp.deltas = result.Deltas
	for _, name := range result.MissingFromBoth {
		cmp.problems = append(cmp.problems, fmt.Sprintf("key %q is missing from both documents", name))
	}
	return cmp
}

func redactOptions(opt Option) redact.Options {
	return redact.Options{Keys: opt.Keys, ShowLength: opt.ShowLength, ShowType: opt.ShowType}
}

// loadedDoc is one document after file-state classification and before decrypt.
type loadedDoc struct {
	side side
	// ciphertext is set only for an encrypted document. It is never reported.
	ciphertext []byte
}

// load resolves, reads, and classifies one document. Every refusal becomes a
// problem on the side rather than an error, because the report is the result.
func (s *Scope) load(ref Ref, allowMissing bool) loadedDoc {
	sd := side{name: ref.Logical, source: sourceWorktree, revision: ref.Revision}
	if ref.Revision != "" {
		sd.source = sourceRevision
	}

	path, err := repo.LogicalNameToPath(s.keysealRoot, ref.Logical, s.extension)
	if err != nil {
		sd.problem = err.Error()
		return loadedDoc{side: sd}
	}

	var classified secretfile.Classification
	if ref.Revision == "" {
		classified, err = secretfile.Classify(path)
		if err != nil {
			sd.problem = fmt.Sprintf("document %q could not be inspected", ref.Logical)
			return loadedDoc{side: sd}
		}
	} else {
		classified, sd.problem = s.classifyRevision(ref, path)
		if sd.problem != "" {
			return loadedDoc{side: sd}
		}
	}

	sd.fileState = classified.State
	switch classified.State {
	case secretfile.StateMissing:
		if !allowMissing {
			sd.problem = fmt.Sprintf("document %q is missing", ref.Logical)
		}
	case secretfile.StatePlaceholder:
		sd.problem = fmt.Sprintf("document %q is an empty placeholder and cannot be evaluated", ref.Logical)
	case secretfile.StatePlaintext:
		sd.problem = fmt.Sprintf("document %q is plaintext at an encrypted path", ref.Logical)
	case secretfile.StateEncrypted:
		return loadedDoc{side: sd, ciphertext: classified.Raw}
	}
	return loadedDoc{side: sd}
}

func (s *Scope) classifyRevision(ref Ref, path string) (secretfile.Classification, string) {
	if s.gitRoot == "" {
		return secretfile.Classification{}, "a Git repository is required to read a revision"
	}
	blob, err := gitutil.ReadBlob("git", s.gitRoot, ref.Revision, path)
	switch {
	case errors.Is(err, gitutil.ErrBlobAbsent):
		return secretfile.Classification{State: secretfile.StateMissing}, ""
	case errors.Is(err, gitutil.ErrUnknownRevision):
		return secretfile.Classification{}, fmt.Sprintf("revision %q was not found", ref.Revision)
	case err != nil:
		return secretfile.Classification{}, fmt.Sprintf("document %q could not be read from revision %q", ref.Logical, ref.Revision)
	}
	return secretfile.ClassifyBytes(blob), ""
}

// decrypt returns the plaintext of an encrypted document, or nil for any other
// state. The SOPS error is dropped because its text can reach stderr.
func (s *Scope) decrypt(doc *loadedDoc) []byte {
	if doc.side.fileState != secretfile.StateEncrypted || doc.side.problem != "" {
		return nil
	}
	plaintext, err := sopsutil.DecryptData(doc.ciphertext, "yaml", s.ageKeyFile)
	doc.ciphertext = nil
	if err != nil {
		doc.side.problem = fmt.Sprintf("document %q could not be decrypted", doc.side.name)
		return nil
	}
	return plaintext
}

// fingerprintKey reads the MAC key when fingerprints are requested. The key
// has no fallback to the age key or to an unkeyed hash, which would let anyone
// with the repository confirm a guessed value.
func fingerprintKey(opt Option) ([]byte, error) {
	if !opt.Fingerprint {
		return nil, nil
	}
	path := os.Getenv(FingerprintKeyEnv)
	if path == "" {
		return nil, fmt.Errorf("--fingerprint needs %s to name a key file of at least %d bytes", FingerprintKeyEnv, minFingerprintKeyLen)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("fingerprint key file could not be read")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxFingerprintKeyLen {
		return nil, errors.New("fingerprint key file must be a regular file of reasonable size")
	}
	key, err := io.ReadAll(file)
	if err != nil {
		clear(key)
		return nil, errors.New("fingerprint key file could not be read")
	}
	if len(key) < minFingerprintKeyLen {
		clear(key)
		return nil, fmt.Errorf("fingerprint key file must hold at least %d bytes", minFingerprintKeyLen)
	}
	return key, nil
}
