// Package config loads and validates the small keyseal.yaml configuration file.
package config

import (
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/jrpbuilds/keyseal/internal/buildinfo"
	"github.com/jrpbuilds/keyseal/internal/contract"
	"github.com/jrpbuilds/keyseal/internal/fsutil"
	"github.com/jrpbuilds/keyseal/internal/repo"
	"github.com/jrpbuilds/keyseal/internal/versionreq"
)

const (
	DefaultConfigPath      = "keyseal.yaml"
	DefaultEncryptedExt    = ".enc.yaml"
	DefaultSOPSBinary      = "sops"
	DefaultAgeBinary       = "age"
	DefaultAgeKeyFile      = "~/.config/sops/age/keys.txt"
	DefaultOutputFormat    = "dotenv"
	DefaultOutputDir       = "/run/secrets"
	DefaultFileMode        = "0600"
	DefaultRequireValues   = true
	DefaultEnvKeyPattern   = "^[A-Z0-9_]+$"
	SupportedConfigVersion = 1
)

var allowedOutputFormats = map[string]struct{}{
	"dotenv": {},
	"json":   {},
	"yaml":   {},
}

// Config is the root representation of keyseal.yaml.
type Config struct {
	Version      int                `yaml:"version"`
	Repository   RepositoryConfig   `yaml:"repository"`
	SOPS         SOPSConfig         `yaml:"sops"`
	Git          GitConfig          `yaml:"git"`
	Defaults     DefaultsConfig     `yaml:"defaults"`
	Validation   ValidationConfig   `yaml:"validation"`
	Requirements RequirementsConfig `yaml:"requirements"`
	Profiles     map[string]Profile `yaml:"profiles"`

	// Contracts are decoded strictly from the contracts YAML node and are not
	// populated by the lax top-level yaml.Unmarshal used for the rest of the
	// config. yaml:"-" keeps that pin intact.
	Contracts map[string]contract.Definition `yaml:"-"`
	// ContractProblems holds per-contract definition or from-file failures.
	// Load fails when any exist; LoadLenient keeps them for doctor reporting.
	ContractProblems []contract.Problem `yaml:"-"`
}

// RequirementsConfig declares tooling compatibility constraints for this repo.
type RequirementsConfig struct {
	// Keyseal is a Masterminds-style semver constraint for the Keyseal binary
	// (for example ">=1.1.0"). Empty means no requirement.
	Keyseal string `yaml:"keyseal,omitempty"`
}

// RepositoryConfig controls repository-root and encrypted file naming behavior.
type RepositoryConfig struct {
	Root               string `yaml:"root"`
	EncryptedExtension string `yaml:"encrypted_extension"`
}

// SOPSConfig controls SOPS CLI mutation settings and age key discovery.
//
// Read-only decrypt operations use the SOPS Go library, so Binary is required
// only for commands that create, edit, or rotate encrypted files.
type SOPSConfig struct {
	Binary     string `yaml:"binary"`
	AgeBinary  string `yaml:"age_binary"`
	AgeKeyFile string `yaml:"age_key_file"`
}

// GitConfig controls small Git workflow defaults used by mutating commands.
type GitConfig struct {
	AutoCommit bool `yaml:"auto_commit"`
}

// DefaultsConfig contains render-time defaults used when flags are omitted.
type DefaultsConfig struct {
	OutputFormat string `yaml:"output_format"`
	OutputDir    string `yaml:"output_dir"`
	FileMode     string `yaml:"file_mode"`
}

// ValidationConfig controls schema checks applied to decrypted env documents.
type ValidationConfig struct {
	RequireValues bool   `yaml:"require_values"`
	KeyPattern    string `yaml:"key_pattern"`
}

// Profile is reserved for small grouped render definitions in future versions.
type Profile struct {
	Renders []RenderProfile `yaml:"renders"`
}

// RenderProfile describes a named render entry in configuration.
type RenderProfile struct {
	Name   string   `yaml:"name,omitempty"`
	Inputs []string `yaml:"inputs,omitempty"`
	Format string   `yaml:"format,omitempty"`
	Out    string   `yaml:"out,omitempty"`
	Mode   string   `yaml:"mode,omitempty"`
}

// Default returns the built-in configuration defaults for a new repository.
func Default() Config {
	return Config{
		Version: SupportedConfigVersion,
		Repository: RepositoryConfig{
			Root:               ".",
			EncryptedExtension: DefaultEncryptedExt,
		},
		SOPS: SOPSConfig{
			Binary:     DefaultSOPSBinary,
			AgeBinary:  DefaultAgeBinary,
			AgeKeyFile: DefaultAgeKeyFile,
		},
		Git: GitConfig{
			AutoCommit: false,
		},
		Defaults: DefaultsConfig{
			OutputFormat: DefaultOutputFormat,
			OutputDir:    DefaultOutputDir,
			FileMode:     DefaultFileMode,
		},
		Validation: ValidationConfig{
			RequireValues: DefaultRequireValues,
			KeyPattern:    DefaultEnvKeyPattern,
		},
		Profiles: map[string]Profile{
			"default": {Renders: []RenderProfile{}},
		},
		Contracts: map[string]contract.Definition{},
	}
}

// Load reads keyseal.yaml, applies defaults for omitted optional fields, and
// validates the final configuration, including profile render definitions and
// requirements.keyseal against the running binary.
//
// Load fails closed before callers decrypt or mutate secrets when the binary
// does not satisfy requirements.keyseal. LoadLenient skips that binary check
// so doctor can report a dedicated compatibility result.
func Load(path string) (Config, error) {
	cfg, err := load(path)
	if err != nil {
		return Config{}, err
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// CheckKeysealRequirement reports whether the running Keyseal binary satisfies
// requirements.keyseal. It is a no-op when the requirement is unset.
func (c Config) CheckKeysealRequirement(running string) error {
	constraint := strings.TrimSpace(c.Requirements.Keyseal)
	if constraint == "" {
		return nil
	}
	return versionreq.Check(running, constraint)
}

// LoadLenient behaves like Load but skips profile-definition validation and
// the running-binary requirements.keyseal check so diagnostics such as doctor
// can enumerate individual profile problems and report compatibility as a
// dedicated check. Every other validateBase rule still applies.
func LoadLenient(path string) (Config, error) {
	cfg, err := load(path)
	if err != nil {
		return Config{}, err
	}
	if err := cfg.validateBase(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// load parses keyseal.yaml and applies defaults without validating.
func load(path string) (Config, error) {
	cfg := Default()

	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}

	if err := yamlUnmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse config: %w", err)
	}

	cfg.applyDefaults()

	// Contracts are decoded strictly from the raw YAML after defaults so
	// validation.key_pattern is available. Failures are recorded as problems
	// rather than aborting load, so LoadLenient can surface them in doctor.
	result, err := contract.LoadFromConfigYAML(data, filepath.Dir(path), cfg.Validation.KeyPattern)
	if err != nil {
		return Config{}, fmt.Errorf("contracts: %w", err)
	}
	cfg.Contracts = result.Contracts
	cfg.ContractProblems = result.Problems
	if cfg.Contracts == nil {
		cfg.Contracts = map[string]contract.Definition{}
	}
	return cfg, nil
}

func (c *Config) applyDefaults() {
	def := Default()

	if c.Version == 0 {
		c.Version = def.Version
	}
	if c.Repository.Root == "" {
		c.Repository.Root = def.Repository.Root
	}
	if c.Repository.EncryptedExtension == "" {
		c.Repository.EncryptedExtension = def.Repository.EncryptedExtension
	}
	if c.SOPS.Binary == "" {
		c.SOPS.Binary = def.SOPS.Binary
	}
	if c.SOPS.AgeBinary == "" {
		c.SOPS.AgeBinary = def.SOPS.AgeBinary
	}
	if c.SOPS.AgeKeyFile == "" {
		c.SOPS.AgeKeyFile = def.SOPS.AgeKeyFile
	}
	if c.Defaults.OutputFormat == "" {
		c.Defaults.OutputFormat = def.Defaults.OutputFormat
	}
	if c.Defaults.OutputDir == "" {
		c.Defaults.OutputDir = def.Defaults.OutputDir
	}
	if c.Defaults.FileMode == "" {
		c.Defaults.FileMode = def.Defaults.FileMode
	}
	if c.Validation.KeyPattern == "" {
		c.Validation.KeyPattern = def.Validation.KeyPattern
	}
	if c.Profiles == nil {
		c.Profiles = def.Profiles
	}
	if _, ok := c.Profiles["default"]; !ok {
		c.Profiles["default"] = Profile{Renders: []RenderProfile{}}
	}
	if c.Contracts == nil {
		c.Contracts = def.Contracts
	}
}

// Validate checks the semantic constraints of a loaded config file, including
// requirements.keyseal against the running Keyseal binary, every profile
// render definition, and every secret contract definition.
//
// The binary gate runs after validateBase and before profiles/contracts so an
// unmet version requirement is not masked by later structural errors.
// LoadLenient intentionally does not call Validate.
func (c Config) Validate() error {
	if err := c.validateBase(); err != nil {
		return err
	}
	if err := c.CheckKeysealRequirement(buildinfo.DisplayVersion()); err != nil {
		return err
	}
	if err := c.ValidateProfiles(); err != nil {
		return err
	}
	return c.ValidateContracts()
}

// ValidateContracts fails fast on the first contract definition or from-file
// problem discovered during strict decode.
func (c Config) ValidateContracts() error {
	return contract.FirstProblem(c.ContractProblems)
}

// validateBase checks the non-profile semantic constraints of a loaded config.
func (c Config) validateBase() error {
	if c.Version != SupportedConfigVersion {
		return fmt.Errorf("unsupported config version %d", c.Version)
	}
	if c.Repository.Root == "" {
		return errors.New("repository.root is required")
	}
	if !strings.HasPrefix(c.Repository.EncryptedExtension, ".") || !strings.Contains(c.Repository.EncryptedExtension, ".yaml") {
		return fmt.Errorf("repository.encrypted_extension must look like %q", DefaultEncryptedExt)
	}
	if c.SOPS.Binary == "" {
		return errors.New("sops.binary is required")
	}
	if c.SOPS.AgeBinary == "" {
		return errors.New("sops.age_binary is required")
	}
	if _, ok := allowedOutputFormats[c.Defaults.OutputFormat]; !ok {
		return fmt.Errorf("defaults.output_format must be one of dotenv, json, yaml")
	}
	if _, err := fsutil.ParseFileMode(c.Defaults.FileMode); err != nil {
		return fmt.Errorf("defaults.file_mode: %w", err)
	}
	if c.Validation.KeyPattern == "" {
		return errors.New("validation.key_pattern is required")
	}
	if _, err := regexp.Compile(c.Validation.KeyPattern); err != nil {
		return fmt.Errorf("validation.key_pattern: %w", err)
	}
	if raw := c.Requirements.Keyseal; raw != "" {
		constraint := strings.TrimSpace(raw)
		if constraint == "" {
			return errors.New("requirements.keyseal must not be empty or whitespace-only")
		}
		if _, err := versionreq.ParseConstraint(constraint); err != nil {
			return err
		}
	}
	return nil
}

// ValidateProfiles checks every profile render definition and fails fast on
// the first violation, naming the profile plus the render index/name so the
// offending YAML block is easy to find.
//
// Empty `format`/`mode` fields fall back to `Defaults` before validation, but
// the fallback is computed locally and never written back to the struct so
// validation stays read-only. Only mode *parseability* is enforced here; mode
// *safety* (owner-only) stays a render-time concern, matching explicit render.
func (c *Config) ValidateProfiles() error {
	for _, profileName := range slices.Sorted(maps.Keys(c.Profiles)) {
		profile := c.Profiles[profileName]
		seenOut := make(map[string]int, len(profile.Renders))
		for idx, r := range profile.Renders {
			label := fmt.Sprintf("profiles.%s.renders[%d] (%q)", profileName, idx, r.Name)
			if strings.TrimSpace(r.Name) == "" {
				return fmt.Errorf("%s: render name is required", label)
			}
			if len(r.Inputs) == 0 {
				return fmt.Errorf("%s: inputs must list at least one logical secret name", label)
			}
			for _, input := range r.Inputs {
				if err := repo.ValidateLogicalName(input); err != nil {
					return fmt.Errorf("%s: %w", label, err)
				}
			}
			format := r.Format
			if format == "" {
				format = c.Defaults.OutputFormat
			}
			if _, ok := allowedOutputFormats[format]; !ok {
				return fmt.Errorf("%s: unknown format %q (must be one of dotenv, json, yaml)", label, r.Format)
			}
			mode := r.Mode
			if mode == "" {
				mode = c.Defaults.FileMode
			}
			if _, err := fsutil.ParseFileMode(mode); err != nil {
				return fmt.Errorf("%s: invalid mode %q: %w", label, r.Mode, err)
			}
			if strings.TrimSpace(r.Out) == "" {
				return fmt.Errorf("%s: out is required", label)
			}
			cleanOut := filepath.Clean(r.Out)
			if first, ok := seenOut[cleanOut]; ok {
				return fmt.Errorf("profiles.%s: renders[%d] and renders[%d] both write output %q; out values must be unique within a profile", profileName, first, idx, r.Out)
			}
			seenOut[cleanOut] = idx
		}
	}
	return nil
}

// AllowedOutputFormat reports whether the given render format is one of the
// supported output formats shared by explicit render, profiles, and doctor.
func AllowedOutputFormat(format string) bool {
	_, ok := allowedOutputFormats[format]
	return ok
}

// RepoRoot resolves the repository root relative to the current working tree.
func (c Config) RepoRoot(base string) string {
	if filepath.IsAbs(c.Repository.Root) {
		return c.Repository.Root
	}
	return filepath.Clean(filepath.Join(base, c.Repository.Root))
}

// ExpandUser expands a leading "~" in a path when a home directory is known.
func ExpandUser(path string) string {
	if path == "" || !strings.HasPrefix(path, "~") {
		return path
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return path
	}
	if path == "~" {
		return home
	}
	return filepath.Join(home, strings.TrimPrefix(path, "~/"))
}

// ResolvePath expands "~" and resolves relative paths from the provided base.
func ResolvePath(base, path string) string {
	path = ExpandUser(path)
	if path == "" || filepath.IsAbs(path) {
		return path
	}
	return filepath.Clean(filepath.Join(base, path))
}
