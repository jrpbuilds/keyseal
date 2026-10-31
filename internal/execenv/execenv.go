// Package execenv runs child processes with merged decrypted environment values.
package execenv

import (
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
)

// envNamePattern accepts ordinary POSIX-style environment variable names.
var envNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// Options controls how the child process inherits the parent environment.
//
// The default inherits the full parent environment. CleanEnv starts from an
// empty base and KeepEnv copies only the named parent variables into that base.
// Secret document values are always overlaid afterward and win on conflicts.
type Options struct {
	CleanEnv bool
	KeepEnv  []string
}

// BuildBaseEnv selects the parent environment entries that seed the child.
//
// When CleanEnv is false, the full parent slice is returned and KeepEnv must be
// empty. When CleanEnv is true, only explicitly named keep variables are copied.
// Missing keep names fail closed with an error that lists the names only.
// The returned slice is never nil, so assigning it to os/exec.Cmd.Env cannot
// accidentally inherit the full parent environment.
func BuildBaseEnv(parent []string, opts Options) ([]string, error) {
	keepNames, err := normalizeKeepEnv(opts.KeepEnv)
	if err != nil {
		return nil, err
	}
	if !opts.CleanEnv {
		if len(keepNames) > 0 {
			return nil, fmt.Errorf("--keep-env requires --clean-env")
		}
		if parent == nil {
			return []string{}, nil
		}
		return parent, nil
	}

	parentValues := parseEnv(parent)
	missing := make([]string, 0)
	base := make([]string, 0, len(keepNames))
	for _, name := range keepNames {
		value, ok := parentValues[name]
		if !ok {
			missing = append(missing, name)
			continue
		}
		base = append(base, name+"="+value)
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("requested keep-env variable(s) are not set in the parent environment: %s", strings.Join(missing, ", "))
	}
	return base, nil
}

// MergeEnv overlays secret values on top of a base environment.
//
// Base variables are inherited first, then secret values override matching
// keys for the child process only. The returned slice is never nil.
func MergeEnv(base []string, overrides map[string]string) []string {
	values := parseEnv(base)
	for key, value := range overrides {
		values[key] = value
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	merged := make([]string, 0, len(keys))
	for _, key := range keys {
		merged = append(merged, key+"="+values[key])
	}
	return merged
}

// Run executes the provided command with the merged environment.
//
// The child environment is built from os.Environ() at spawn time; this is safe
// because sopsutil.withAgeKeyFileEnv defer-restores any temporary
// SOPS_AGE_KEY_FILE it sets during decrypt, so the environment here reflects
// the operator's shell, not Keyseal's decrypt-time mutations.
func Run(command []string, env map[string]string, opts Options) error {
	if len(command) == 0 {
		return fmt.Errorf("command is required")
	}
	base, err := BuildBaseEnv(os.Environ(), opts)
	if err != nil {
		return err
	}
	cmd := exec.Command(command[0], command[1:]...)
	cmd.Env = MergeEnv(base, env)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func normalizeKeepEnv(names []string) ([]string, error) {
	if len(names) == 0 {
		return nil, nil
	}
	normalized := make([]string, 0, len(names))
	seen := make(map[string]struct{}, len(names))
	var invalid []string
	for _, raw := range names {
		name := strings.TrimSpace(raw)
		if name == "" || !envNamePattern.MatchString(name) {
			invalid = append(invalid, raw)
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		normalized = append(normalized, name)
	}
	if len(invalid) > 0 {
		return nil, fmt.Errorf("invalid keep-env variable name(s): %s", strings.Join(quoteNames(invalid), ", "))
	}
	return normalized, nil
}

func parseEnv(entries []string) map[string]string {
	values := make(map[string]string, len(entries))
	for _, entry := range entries {
		key, value, ok := strings.Cut(entry, "=")
		if ok {
			values[key] = value
		}
	}
	return values
}

func quoteNames(names []string) []string {
	quoted := make([]string, 0, len(names))
	for _, name := range names {
		quoted = append(quoted, fmt.Sprintf("%q", name))
	}
	return quoted
}
