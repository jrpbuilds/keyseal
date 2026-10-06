package sopsutil

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"github.com/getsops/sops/v3/decrypt"
	"github.com/getsops/sops/v3/logging"
)

// decryptEnvMu serializes temporary process-wide SOPS_AGE_KEY_FILE changes.
// The current call sites decrypt sequentially, but the mutex keeps this helper
// safe if render or doctor later parallelize file validation.
var decryptEnvMu sync.Mutex

// DecryptFile decrypts a SOPS-encrypted file using the official SOPS Go
// library instead of the external sops binary.
func DecryptFile(path, format, ageKeyFile string) ([]byte, error) {
	plaintext, _, err := decryptFile(path, format, ageKeyFile, false)
	return plaintext, err
}

// DecryptFileWithWarnings decrypts a SOPS-encrypted file and returns any SOPS
// library warnings captured during decrypt without writing them to stderr.
func DecryptFileWithWarnings(path, format, ageKeyFile string) ([]byte, []string, error) {
	return decryptFile(path, format, ageKeyFile, true)
}

// DecryptData decrypts SOPS-encrypted bytes in memory using the official SOPS
// Go library. Mutating commands use it to verify ciphertext before it is
// written anywhere.
func DecryptData(data []byte, format, ageKeyFile string) ([]byte, error) {
	if strings.TrimSpace(format) == "" {
		format = "yaml"
	}
	plaintext, _, err := withAgeKeyFileEnv(ageKeyFile, false, func() ([]byte, error) {
		return decrypt.Data(data, format)
	})
	if err != nil {
		return nil, fmt.Errorf("decrypt data with SOPS library: %w", err)
	}
	return plaintext, nil
}

// decryptFile is the shared implementation behind quiet render/exec decrypts
// and diagnostic doctor decrypts.
func decryptFile(path, format, ageKeyFile string, captureWarnings bool) ([]byte, []string, error) {
	if _, err := os.Stat(path); err != nil {
		return nil, nil, fmt.Errorf("stat encrypted file: %w", err)
	}
	if strings.TrimSpace(format) == "" {
		format = "yaml"
	}

	plaintext, warnings, err := withAgeKeyFileEnv(ageKeyFile, captureWarnings, func() ([]byte, error) {
		return decrypt.File(path, format)
	})
	if err != nil {
		return nil, warnings, fmt.Errorf("decrypt %s with SOPS library: %w", path, err)
	}
	return plaintext, warnings, nil
}

// withAgeKeyFileEnv temporarily exposes Keyseal's configured age key path to
// SOPS library code while preserving SOPS_AGE_KEY_FILE as the operator override.
func withAgeKeyFileEnv(ageKeyFile string, captureWarnings bool, fn func() ([]byte, error)) ([]byte, []string, error) {
	decryptEnvMu.Lock()
	defer decryptEnvMu.Unlock()

	restoreLogs, warnings := captureSOPSLogs(captureWarnings)
	defer restoreLogs()

	previous, hadPrevious := os.LookupEnv(ageKeyEnvVar)
	// SOPS_AGE_KEY is intentionally not managed here. If callers provide inline
	// age key material through the SOPS_AGE_KEY environment variable, the SOPS
	// library reads it directly from the process environment. Keyseal only
	// temporarily supplies SOPS_AGE_KEY_FILE when the config provides a path
	// and no explicit environment value already exists.
	// Match the historical CLI behavior: a non-empty environment variable is
	// an explicit operator override, while an empty value still allows config.
	hasOverride := previous != ""
	shouldSet := !hasOverride && strings.TrimSpace(ageKeyFile) != ""
	if shouldSet {
		if err := os.Setenv(ageKeyEnvVar, ageKeyFile); err != nil {
			return nil, nil, fmt.Errorf("set %s: %w", ageKeyEnvVar, err)
		}
	}
	defer func() {
		if hadPrevious {
			_ = os.Setenv(ageKeyEnvVar, previous)
			return
		}
		if shouldSet {
			_ = os.Unsetenv(ageKeyEnvVar)
		}
	}()

	plaintext, err := fn()
	return plaintext, warnings(), err
}

// captureSOPSLogs prevents library warnings from contaminating render stdout or
// stderr. Doctor can opt into the captured warnings and show them deliberately.
func captureSOPSLogs(capture bool) (func(), func() []string) {
	var buf bytes.Buffer
	output := io.Writer(io.Discard)
	if capture {
		output = &buf
	}
	previous := make(map[string]io.Writer, len(logging.Loggers))
	for name, logger := range logging.Loggers {
		previous[name] = logger.Out
		logger.SetOutput(output)
	}
	restore := func() {
		for name, output := range previous {
			if logger, ok := logging.Loggers[name]; ok {
				logger.SetOutput(output)
			}
		}
	}
	collect := func() []string {
		text := strings.TrimSpace(buf.String())
		if text == "" {
			return nil
		}
		lines := strings.Split(text, "\n")
		out := make([]string, 0, len(lines))
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line != "" {
				out = append(out, line)
			}
		}
		return out
	}
	return restore, collect
}
