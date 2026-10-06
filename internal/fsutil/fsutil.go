// Package fsutil contains small filesystem helpers for safe output handling.
package fsutil

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// ParseFileMode validates the CLI/config octal mode form used by Keyseal.
func ParseFileMode(value string) (os.FileMode, error) {
	if len(value) != 4 || value[0] != '0' {
		return 0, fmt.Errorf("must be a 4-digit octal string like 0600")
	}
	parsed, err := strconv.ParseUint(value, 8, 32)
	if err != nil {
		return 0, fmt.Errorf("invalid octal mode %q", value)
	}
	return os.FileMode(parsed), nil
}

// IsSafeFileMode reports whether a mode is owner-only with no group/world bits.
func IsSafeFileMode(mode os.FileMode) bool {
	return mode.Perm()&0o077 == 0
}

// ValidateOutputPath rejects empty or obviously escaping relative output paths.
//
// Absolute paths are allowed because the default render destination may live in
// system-managed locations like /run/secrets.
func ValidateOutputPath(path string) error {
	if path == "" {
		return errors.New("output path is required")
	}
	if !filepath.IsAbs(path) {
		clean := filepath.Clean(path)
		if clean == ".." || strings.HasPrefix(clean, "../") {
			return fmt.Errorf("relative output path %q escapes the working directory", path)
		}
	}
	return nil
}

// CheckWritableFilePath validates the output path and applies the shared
// overwrite check used before writing files.
func CheckWritableFilePath(path string, force bool) error {
	if err := ValidateOutputPath(path); err != nil {
		return err
	}
	if !force {
		if _, err := os.Stat(path); err == nil {
			return fmt.Errorf("output file %q already exists", path)
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("check output file: %w", err)
		}
	}
	return nil
}

// AtomicWriteFile writes plaintext output via a temp file in the destination
// directory and then renames it into place.
//
// Creating the temp file in the same directory keeps the final rename atomic on
// normal filesystems and avoids cross-device surprises.
func AtomicWriteFile(path string, data []byte, mode os.FileMode, force bool) error {
	if err := CheckWritableFilePath(path, force); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create parent directory: %w", err)
	}
	temp, err := os.CreateTemp(filepath.Dir(path), ".keyseal-*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)

	// The temp file gets the final permissions before rename so the destination
	// never exists momentarily with broader-than-requested access.
	if _, err := temp.Write(data); err != nil {
		temp.Close()
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := temp.Chmod(mode); err != nil {
		temp.Close()
		return fmt.Errorf("chmod temp file: %w", err)
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return fmt.Errorf("sync temp file: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Rename(tempPath, path); err != nil {
		return fmt.Errorf("rename temp file: %w", err)
	}
	return nil
}
