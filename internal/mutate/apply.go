package mutate

import (
	"bytes"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/jrpbuilds/keyseal/internal/fsutil"
	"github.com/jrpbuilds/keyseal/internal/schema"
	"github.com/jrpbuilds/keyseal/internal/secretfile"
	"github.com/jrpbuilds/keyseal/internal/sopsutil"
)

// Options carries the configuration every transaction needs.
type Options struct {
	SOPSBinary string
	AgeKeyFile string
	Validation schema.ValidationOptions
}

// Target is a logical secret name and its resolved encrypted file path.
type Target struct {
	Logical string
	Path    string
}

// Result summarizes one transaction.
type Result struct {
	Changes []Change
	// Written is false when the document values did not change, in which case
	// the file was left untouched.
	Written bool
}

// Update decrypts target, applies all mutations, and replaces the file with a
// verified re-encrypted document. On any error the file is left untouched.
func Update(opts Options, target Target, apply func(*Document) ([]Change, error)) (Result, error) {
	original, doc, err := load(opts, target)
	if err != nil {
		return Result{}, err
	}
	info, err := os.Stat(target.Path)
	if err != nil {
		return Result{}, fmt.Errorf("stat %s: %w", target.Logical, err)
	}

	before := doc.Values()
	changes, err := apply(doc)
	if err != nil {
		return Result{}, err
	}
	if maps.Equal(before, doc.Values()) {
		return Result{Changes: changes}, nil
	}

	ciphertext, err := seal(opts, doc, target)
	if err != nil {
		return Result{}, err
	}
	// Refuse to overwrite edits made by someone else while we were working.
	current, err := os.ReadFile(target.Path)
	if err != nil {
		return Result{}, fmt.Errorf("re-read %s before replacing it: %w", target.Logical, err)
	}
	if !bytes.Equal(current, original) {
		return Result{}, fmt.Errorf("%s changed on disk during the update; nothing was written", target.Logical)
	}
	if err := fsutil.AtomicWriteFile(target.Path, ciphertext, info.Mode().Perm(), true); err != nil {
		return Result{}, err
	}
	return Result{Changes: changes, Written: true}, nil
}

// Clone copies src into dst, re-encrypting it with the .sops.yaml creation
// rule that matches dst. The document name is set to the destination logical
// name. An existing dst is only replaced when force is set.
func Clone(opts Options, src, dst Target, force bool) error {
	if filepath.Clean(src.Path) == filepath.Clean(dst.Path) {
		return errors.New("source and destination must be different documents")
	}
	if err := checkDestination(dst, force); err != nil {
		return err
	}
	_, doc, err := load(opts, src)
	if err != nil {
		return err
	}
	doc.SetName(dst.Logical)
	ciphertext, err := seal(opts, doc, dst)
	if err != nil {
		return err
	}
	// AtomicWriteFile re-checks the destination right before the rename.
	return fsutil.AtomicWriteFile(dst.Path, ciphertext, 0o600, force)
}

func checkDestination(dst Target, force bool) error {
	if force {
		return nil
	}
	if _, err := os.Lstat(dst.Path); err == nil {
		return fmt.Errorf("destination %s already exists; use --force to replace it", dst.Logical)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("check destination %s: %w", dst.Logical, err)
	}
	return nil
}

// load reads and decrypts an existing encrypted document. It returns the raw
// ciphertext so callers can detect concurrent changes before replacing it.
func load(opts Options, target Target) ([]byte, *Document, error) {
	classified, err := secretfile.Classify(target.Path)
	if err != nil {
		return nil, nil, fmt.Errorf("inspect %s: %w", target.Logical, err)
	}
	switch classified.State {
	case secretfile.StateMissing:
		return nil, nil, fmt.Errorf("secret %s not found at %s; create it with `keyseal add` or `keyseal clone` first", target.Logical, target.Path)
	case secretfile.StatePlaceholder:
		return nil, nil, fmt.Errorf("secret %s is an empty placeholder; run `keyseal edit %s` to initialize it first", target.Logical, target.Logical)
	case secretfile.StatePlaintext:
		return nil, nil, fmt.Errorf("secret %s is non-empty plaintext at encrypted path %s: refusing to modify a file without SOPS metadata", target.Logical, target.Path)
	}
	plaintext, err := sopsutil.DecryptData(classified.Raw, "yaml", opts.AgeKeyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("decrypt %s: %w", target.Logical, err)
	}
	doc, err := ParseDocument(plaintext)
	if err != nil {
		return nil, nil, fmt.Errorf("parse %s: %w", target.Logical, err)
	}
	return classified.Raw, doc, nil
}

// seal validates the document, encrypts it for target's path, and verifies the
// ciphertext decrypts back to exactly the intended document with the
// operator's own key. Verification also catches creation rules that would
// lock the operator out of the result.
func seal(opts Options, doc *Document, target Target) ([]byte, error) {
	body, err := doc.Marshal()
	if err != nil {
		return nil, err
	}
	intended, _, err := schema.ParseYAMLDocument(body)
	if err != nil {
		return nil, fmt.Errorf("parse updated %s: %w", target.Logical, err)
	}
	if err := intended.Validate(opts.Validation); err != nil {
		return nil, fmt.Errorf("validate updated %s: %w", target.Logical, err)
	}

	ciphertext, err := sopsutil.EncryptFile(opts.SOPSBinary, opts.AgeKeyFile, body, target.Path)
	if err != nil {
		return nil, fmt.Errorf("encrypt %s with %q: %w", target.Logical, opts.SOPSBinary, err)
	}
	if !schema.HasSOPSMetadata(ciphertext) {
		return nil, fmt.Errorf("verify encrypted %s: SOPS output does not contain SOPS metadata", target.Logical)
	}
	keys, err := unencryptedValueKeys(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("verify encrypted %s: %w", target.Logical, err)
	}
	if len(keys) > 0 {
		return nil, fmt.Errorf("verify encrypted %s: .sops.yaml would leave values unencrypted for: %s; refusing to write", target.Logical, strings.Join(keys, ", "))
	}
	decrypted, err := sopsutil.DecryptData(ciphertext, "yaml", opts.AgeKeyFile)
	if err != nil {
		return nil, fmt.Errorf("verify encrypted %s: %w; check that the .sops.yaml recipients for this path include your age key", target.Logical, err)
	}
	got, _, err := schema.ParseYAMLDocument(decrypted)
	if err != nil {
		return nil, fmt.Errorf("verify encrypted %s: %w", target.Logical, err)
	}
	if !reflect.DeepEqual(got, intended) {
		return nil, fmt.Errorf("verify encrypted %s: decrypted content does not match the intended document", target.Logical)
	}
	return ciphertext, nil
}
