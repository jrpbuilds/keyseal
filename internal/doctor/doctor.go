package doctor

import (
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/jrpbuilds/keyseal/internal/config"
	"github.com/jrpbuilds/keyseal/internal/contract"
	"github.com/jrpbuilds/keyseal/internal/fsutil"
	"github.com/jrpbuilds/keyseal/internal/repo"
	"github.com/jrpbuilds/keyseal/internal/schema"
	"github.com/jrpbuilds/keyseal/internal/secretfile"
	"github.com/jrpbuilds/keyseal/internal/sopsconfig"
	"github.com/jrpbuilds/keyseal/internal/sopsutil"
	"github.com/jrpbuilds/keyseal/internal/toolcheck"
)

// Run executes the doctor checks for the current repository.
func Run(cwd string) (Result, error) {
	var result Result

	cfg, cfgOK := runConfigChecks(cwd, &result)
	if cfgOK {
		// Tool checks depend on keyseal.yaml values. Missing sops/age binaries
		// are informational for read-only hosts, but surfacing them early keeps
		// mutating-command setup problems easy to find.
		configCheck := result.Checks[0]
		result.Checks = result.Checks[:0]
		runSOPSBinaryChecks(cfg, cwd, &result)
		runAgeBinaryChecks(cfg, &result)
		result.Add(configCheck)
		runSOPSConfigChecks(cwd, &result)
	} else {
		runSOPSConfigChecks(cwd, &result)
		result.Add(CheckResult{
			Name:     "secret validation",
			Status:   StatusSkip,
			Severity: SeverityInformational,
			Summary:  "Skipped repository-backed checks because keyseal.yaml could not be loaded",
			Remediation: []string{
				"Create or fix keyseal.yaml, then rerun `keyseal doctor`.",
			},
		})
		return result, nil
	}

	repoRoot := cfg.RepoRoot(cwd)
	repoRootReady := runRepositoryRootCheck(repoRoot, &result)
	runOutputPathChecks(cfg, &result)
	runProfileChecks(cfg, cwd, &result)
	runContractDefinitionChecks(cfg, cwd, &result)
	runRepoArtifactChecks(repoRoot, &result)

	if !repoRootReady {
		result.Add(CheckResult{
			Name:     "secret discovery",
			Status:   StatusSkip,
			Severity: SeverityInformational,
			Summary:  "Skipped secret discovery because repository.root does not resolve to a usable directory",
			Remediation: []string{
				"Fix repository.root in keyseal.yaml so it points at the repository working tree.",
			},
		})
		return result, nil
	}

	if err := runSecretChecks(cwd, repoRoot, cfg, &result); err != nil {
		return result, fmt.Errorf("run secret checks: %w", err)
	}
	return result, nil
}

func runConfigChecks(cwd string, result *Result) (config.Config, bool) {
	cfgPath := filepath.Join(cwd, config.DefaultConfigPath)
	if _, err := os.Stat(cfgPath); err != nil {
		result.Add(CheckResult{
			Name:     "keyseal.yaml",
			Status:   StatusFail,
			Severity: SeverityError,
			Summary:  "Missing keyseal.yaml",
			Details: []string{
				fmt.Sprintf("Expected configuration file at %s.", cfgPath),
				"Keyseal commands rely on this file for repository layout, SOPS binary settings, and validation rules.",
			},
			Remediation: []string{
				"Run `keyseal init` in the repository root to create a starter config.",
			},
		})
		return config.Config{}, false
	}

	// Doctor loads the config leniently so malformed profile definitions are
	// reported as granular per-render checks (runProfileChecks) instead of
	// aborting the whole report on the first ValidateProfiles error. All
	// non-profile validation still gates the repository-backed checks here.
	cfg, err := config.LoadLenient(cfgPath)
	if err != nil {
		result.Add(CheckResult{
			Name:     "keyseal.yaml",
			Status:   StatusFail,
			Severity: SeverityError,
			Summary:  "keyseal.yaml could not be parsed or validated",
			Details: []string{
				fmt.Sprintf("Load error: %v", err),
			},
			Remediation: []string{
				"Fix the YAML syntax or invalid values in keyseal.yaml, then rerun `keyseal doctor`.",
			},
		})
		return config.Config{}, false
	}

	result.Add(CheckResult{
		Name:     "keyseal.yaml",
		Status:   StatusOK,
		Severity: SeverityInformational,
		Summary:  "Parsed and validated keyseal.yaml",
		Details: []string{
			fmt.Sprintf("repository.root resolves from %q.", cfg.Repository.Root),
			fmt.Sprintf("Encrypted extension is %q.", cfg.Repository.EncryptedExtension),
			fmt.Sprintf("Configured SOPS binary is %q.", cfg.SOPS.Binary),
		},
	})
	return cfg, true
}

func runRepositoryRootCheck(repoRoot string, result *Result) bool {
	info, err := os.Stat(repoRoot)
	if err != nil {
		result.Add(CheckResult{
			Name:     "repository.root",
			Status:   StatusFail,
			Severity: SeverityError,
			Summary:  "repository.root does not resolve to an existing directory",
			Details: []string{
				fmt.Sprintf("Resolved repository root: %s", repoRoot),
				fmt.Sprintf("Filesystem error: %v", err),
			},
			Remediation: []string{
				"Set repository.root in keyseal.yaml to a directory that exists on disk.",
			},
		})
		return false
	}
	if !info.IsDir() {
		result.Add(CheckResult{
			Name:     "repository.root",
			Status:   StatusFail,
			Severity: SeverityError,
			Summary:  "repository.root resolves to a file instead of a directory",
			Details: []string{
				fmt.Sprintf("Resolved repository root: %s", repoRoot),
			},
			Remediation: []string{
				"Set repository.root in keyseal.yaml to a directory path.",
			},
		})
		return false
	}
	result.Add(CheckResult{
		Name:     "repository.root",
		Status:   StatusOK,
		Severity: SeverityInformational,
		Summary:  "repository.root resolves to a directory",
		Details: []string{
			fmt.Sprintf("Resolved repository root: %s", repoRoot),
		},
	})
	return true
}

func runOutputPathChecks(cfg config.Config, result *Result) {
	mode, err := fsutil.ParseFileMode(cfg.Defaults.FileMode)
	if err != nil {
		result.Add(CheckResult{
			Name:     "defaults.file_mode",
			Status:   StatusFail,
			Severity: SeverityError,
			Summary:  "defaults.file_mode is invalid",
			Details: []string{
				fmt.Sprintf("Configured value: %q", cfg.Defaults.FileMode),
				fmt.Sprintf("Parse error: %v", err),
			},
			Remediation: []string{
				`Set defaults.file_mode to a four-digit owner-only mode such as "0600".`,
			},
		})
	} else if !fsutil.IsSafeFileMode(mode) {
		result.Add(CheckResult{
			Name:     "defaults.file_mode",
			Status:   StatusWarn,
			Severity: SeverityWarning,
			Summary:  fmt.Sprintf("defaults.file_mode %s allows group or world access", cfg.Defaults.FileMode),
			Details: []string{
				"Rendered secrets written with this mode may be readable by other users on the system.",
			},
			Remediation: []string{
				`Change defaults.file_mode to "0600" in keyseal.yaml.`,
			},
		})
	} else {
		result.Add(CheckResult{
			Name:     "defaults.file_mode",
			Status:   StatusOK,
			Severity: SeverityInformational,
			Summary:  fmt.Sprintf("defaults.file_mode %s is owner-only", cfg.Defaults.FileMode),
		})
	}

	pathDetails := []string{}
	pathFixes := []string{}
	pathStatus := StatusOK
	pathSeverity := SeverityInformational

	checkOutputPath := func(label, path string) {
		if err := fsutil.ValidateOutputPath(path); err != nil {
			pathStatus = StatusWarn
			pathSeverity = SeverityWarning
			pathDetails = append(pathDetails, fmt.Sprintf("%s is invalid: %v", label, err))
			pathFixes = append(pathFixes, fmt.Sprintf("Set %s to an absolute runtime path or a safe relative path inside the repo.", label))
			return
		}

		// Relative output paths are valid, but they are easy to commit by mistake
		// when users render secrets into the repository working tree.
		if !filepath.IsAbs(path) {
			pathStatus = StatusWarn
			pathSeverity = SeverityWarning
			pathDetails = append(pathDetails, fmt.Sprintf("%s is relative: %s", label, path))
			pathFixes = append(pathFixes, fmt.Sprintf("Consider changing %s to an absolute runtime path like /run/secrets/... to reduce accidental commits.", label))
		}
	}

	checkOutputPath("defaults.output_dir", cfg.Defaults.OutputDir)
	for profileName, profile := range cfg.Profiles {
		for idx, renderProfile := range profile.Renders {
			if renderProfile.Out == "" {
				continue
			}
			checkOutputPath(fmt.Sprintf("profiles.%s.renders[%d].out", profileName, idx), renderProfile.Out)
		}
	}

	if len(pathDetails) == 0 {
		result.Add(CheckResult{
			Name:     "render output paths",
			Status:   StatusOK,
			Severity: SeverityInformational,
			Summary:  "Configured render output paths look sane",
			Details: []string{
				fmt.Sprintf("defaults.output_dir: %s", cfg.Defaults.OutputDir),
			},
		})
		return
	}

	result.Add(CheckResult{
		Name:        "render output paths",
		Status:      pathStatus,
		Severity:    pathSeverity,
		Summary:     "Some configured render output paths are risky or invalid",
		Details:     pathDetails,
		Remediation: dedupeStrings(pathFixes),
	})
}

// runProfileChecks reports configuration and input-resolvability problems for
// every configured profile render as discrete aggregated checks, so users can
// fix everything in one pass.
//
// Inputs are classified by existence only — doctor never decrypts or reads
// secret content during these checks — so the reporting stays secret-safe.
func runProfileChecks(cfg config.Config, cwd string, result *Result) {
	repoRoot := cfg.RepoRoot(cwd)
	for _, profileName := range slices.Sorted(maps.Keys(cfg.Profiles)) {
		profile := cfg.Profiles[profileName]
		if len(profile.Renders) == 0 {
			continue
		}

		seenOut := map[string]string{}
		duplicateDetails := []string{}
		for idx, renderProfile := range profile.Renders {
			renderLabel := renderProfile.Name
			if strings.TrimSpace(renderLabel) == "" {
				renderLabel = fmt.Sprintf("renders[%d]", idx)
			}

			var details []string
			if len(renderProfile.Inputs) == 0 {
				details = append(details, "inputs is empty; list at least one logical secret name")
			}
			resolvable := make([]string, 0, len(renderProfile.Inputs))
			for _, input := range renderProfile.Inputs {
				if err := repo.ValidateLogicalName(input); err != nil {
					details = append(details, fmt.Sprintf("input %q is not a valid logical name: %v", input, err))
					continue
				}
				resolvable = append(resolvable, input)
			}
			format := renderProfile.Format
			if format == "" {
				format = cfg.Defaults.OutputFormat
			}
			if !config.AllowedOutputFormat(format) {
				details = append(details, fmt.Sprintf("format %q is not one of dotenv, json, yaml", renderProfile.Format))
			}
			mode := renderProfile.Mode
			if mode == "" {
				mode = cfg.Defaults.FileMode
			}
			if _, err := fsutil.ParseFileMode(mode); err != nil {
				details = append(details, fmt.Sprintf("mode %q is invalid: %v", renderProfile.Mode, err))
			}
			if strings.TrimSpace(renderProfile.Out) == "" {
				details = append(details, "out is required")
			}
			for _, input := range resolvable {
				path, err := repo.LogicalNameToPath(repoRoot, input, cfg.Repository.EncryptedExtension)
				if err != nil {
					details = append(details, fmt.Sprintf("input %q could not be mapped to a path: %v", input, err))
					continue
				}
				classified, err := secretfile.Classify(path)
				if err != nil {
					details = append(details, fmt.Sprintf("input %q could not be inspected: %v", input, err))
					continue
				}
				if classified.State == secretfile.StateMissing {
					details = append(details, fmt.Sprintf("input %q is missing at %s", input, filepath.ToSlash(path)))
				}
			}

			checkName := fmt.Sprintf("profile %q render %q", profileName, renderLabel)
			if len(details) > 0 {
				result.Add(CheckResult{
					Name:     checkName,
					Status:   StatusFail,
					Severity: SeverityError,
					Summary:  fmt.Sprintf("profiles.%s.renders[%d] (%s) has invalid configuration or missing inputs", profileName, idx, renderProfile.Name),
					Details:  details,
					Remediation: []string{
						fmt.Sprintf("Fix profiles.%s.renders[%d] in keyseal.yaml, then rerun `keyseal doctor`.", profileName, idx),
					},
				})
			} else {
				result.Add(CheckResult{
					Name:     checkName,
					Status:   StatusOK,
					Severity: SeverityInformational,
					Summary:  "Render definition is well-formed and its inputs resolve",
				})
			}

			// Track normalized output paths to surface duplicate destinations
			// once per profile after the render loop.
			if renderProfile.Out != "" {
				cleanOut := filepath.Clean(renderProfile.Out)
				if first, ok := seenOut[cleanOut]; ok {
					duplicateDetails = append(duplicateDetails, fmt.Sprintf("renders %q and %q both write output %q", first, renderLabel, renderProfile.Out))
				} else {
					seenOut[cleanOut] = renderLabel
				}
			}
		}

		duplicateCheck := CheckResult{
			Name:     fmt.Sprintf("profile %q duplicate output", profileName),
			Status:   StatusOK,
			Severity: SeverityInformational,
			Summary:  "Renders write distinct output paths",
		}
		if len(duplicateDetails) > 0 {
			duplicateCheck = CheckResult{
				Name:     fmt.Sprintf("profile %q duplicate output", profileName),
				Status:   StatusFail,
				Severity: SeverityError,
				Summary:  "Multiple renders in this profile write the same output path",
				Details:  duplicateDetails,
				Remediation: []string{
					fmt.Sprintf("Give each render in profiles.%s a unique out path in keyseal.yaml.", profileName),
				},
			}
		}
		result.Add(duplicateCheck)
	}
}

// runContractDefinitionChecks reports malformed contract definitions and
// missing document files as discrete checks. It never decrypts secrets or
// evaluates contract rules against values.
func runContractDefinitionChecks(cfg config.Config, cwd string, result *Result) {
	for _, problem := range cfg.ContractProblems {
		name := problem.Name
		if name == "" {
			name = "contracts"
		}
		result.Add(CheckResult{
			Name:     fmt.Sprintf("contract %q", name),
			Status:   StatusFail,
			Severity: SeverityError,
			Summary:  fmt.Sprintf("Contract %q has an invalid definition", name),
			Details: []string{
				problem.Message,
			},
			Remediation: []string{
				"Fix the contract definition in keyseal.yaml or its from: file, then rerun `keyseal doctor`.",
			},
		})
	}

	repoRoot := cfg.RepoRoot(cwd)
	for _, name := range slices.Sorted(maps.Keys(cfg.Contracts)) {
		def := cfg.Contracts[name]
		existence := contract.DocumentExistenceProblems(def, repoRoot, cfg.Repository.EncryptedExtension)
		if len(existence) > 0 {
			details := make([]string, 0, len(existence))
			for _, problem := range existence {
				details = append(details, problem.Message)
			}
			result.Add(CheckResult{
				Name:     fmt.Sprintf("contract %q", name),
				Status:   StatusFail,
				Severity: SeverityError,
				Summary:  fmt.Sprintf("Contract %q references missing documents", name),
				Details:  details,
				Remediation: []string{
					fmt.Sprintf("Create the missing encrypted documents listed by contract %q, or update its documents list.", name),
				},
			})
			continue
		}
		result.Add(CheckResult{
			Name:     fmt.Sprintf("contract %q", name),
			Status:   StatusOK,
			Severity: SeverityInformational,
			Summary:  "Contract definition is well-formed and its documents exist",
			Details: []string{
				fmt.Sprintf("Documents: %s", strings.Join(def.Documents, ", ")),
			},
		})
	}
}

func runSOPSConfigChecks(cwd string, result *Result) {
	sopsPath := filepath.Join(cwd, ".sops.yaml")
	data, err := os.ReadFile(sopsPath)
	if err != nil {
		result.Add(CheckResult{
			Name:     ".sops.yaml",
			Status:   StatusFail,
			Severity: SeverityError,
			Summary:  "Missing .sops.yaml",
			Details: []string{
				fmt.Sprintf("Expected SOPS creation rules at %s.", sopsPath),
				"Encrypted add/edit flows depend on valid creation rules to choose recipients.",
			},
			Remediation: []string{
				"Run `keyseal init` to create a starter .sops.yaml, then replace the placeholder recipients.",
			},
		})
		return
	}

	info, err := sopsconfig.Inspect(data)
	if err != nil {
		result.Add(CheckResult{
			Name:     ".sops.yaml",
			Status:   StatusFail,
			Severity: SeverityError,
			Summary:  ".sops.yaml could not be parsed",
			Details: []string{
				fmt.Sprintf("Parse error: %v", err),
			},
			Remediation: []string{
				"Fix the YAML syntax or recreate the file with `keyseal init`.",
			},
		})
		return
	}

	result.Add(CheckResult{
		Name:     ".sops.yaml",
		Status:   StatusOK,
		Severity: SeverityInformational,
		Summary:  "Parsed .sops.yaml",
		Details: []string{
			fmt.Sprintf("Discovered %d creation rule(s).", info.CreationRuleCount),
		},
	})

	switch {
	case info.CreationRuleCount == 0:
		result.Add(CheckResult{
			Name:     ".sops.yaml creation rules",
			Status:   StatusFail,
			Severity: SeverityError,
			Summary:  ".sops.yaml does not define any creation rules",
			Details: []string{
				"SOPS needs at least one creation rule to decide how new encrypted files should be protected.",
			},
			Remediation: []string{
				"Add at least one real creation rule with valid recipients to .sops.yaml.",
			},
		})
	case info.UsableRuleCount == 0:
		result.Add(CheckResult{
			Name:     ".sops.yaml creation rules",
			Status:   StatusFail,
			Severity: SeverityError,
			Summary:  ".sops.yaml creation rules do not contain usable recipients",
			Details: []string{
				"Rules exist, but none of them include recipient material such as age, pgp, kms, or key_groups entries.",
			},
			Remediation: []string{
				"Add real recipients to each creation rule before relying on encrypted workflows.",
			},
		})
	default:
		result.Add(CheckResult{
			Name:     ".sops.yaml creation rules",
			Status:   StatusOK,
			Severity: SeverityInformational,
			Summary:  fmt.Sprintf("%d creation rule(s) include recipient material", info.UsableRuleCount),
		})
	}

	if len(info.Placeholders) > 0 {
		result.Add(CheckResult{
			Name:     ".sops.yaml placeholders",
			Status:   StatusFail,
			Severity: SeverityError,
			Summary:  ".sops.yaml still contains placeholder recipient values",
			Details: []string{
				fmt.Sprintf("Found placeholders: %s", strings.Join(info.Placeholders, ", ")),
				"New encrypted files created with these placeholders will not be configured for real recipients.",
			},
			Remediation: []string{
				"Replace the placeholder recipients in .sops.yaml with real age recipients before relying on encrypted add/edit flows.",
			},
		})
		return
	}

	result.Add(CheckResult{
		Name:     ".sops.yaml placeholders",
		Status:   StatusOK,
		Severity: SeverityInformational,
		Summary:  "No obvious placeholder recipients were found in .sops.yaml",
	})
}

// runSOPSBinaryChecks reports whether the external SOPS CLI is ready for
// mutating commands without gating library-backed decrypt validation.
func runSOPSBinaryChecks(cfg config.Config, cwd string, result *Result) bool {
	binary := cfg.SOPS.Binary
	resolved, err := sopsutil.LookPath(binary)
	if err != nil {
		result.Add(CheckResult{
			Name:     "sops binary",
			Status:   StatusOK,
			Severity: SeverityInformational,
			Summary:  "Configured sops binary could not be resolved",
			Details: []string{
				fmt.Sprintf("Configured value: %q", binary),
				fmt.Sprintf("Lookup error: %v", err),
				"Read-only decrypt, render, exec, doctor, and verify use the official SOPS Go decrypt library and do not require the external binary.",
				"The external SOPS binary is still required for add, edit, and updatekeys.",
			},
			Remediation: []string{
				fmt.Sprintf("Install SOPS and make %q available in PATH, or update sops.binary in keyseal.yaml before running mutating commands.", binary),
			},
		})
		return false
	}

	version, err := sopsutil.Version(binary, config.ResolvePath(cwd, cfg.SOPS.AgeKeyFile))
	if err != nil {
		result.Add(CheckResult{
			Name:     "sops binary",
			Status:   StatusWarn,
			Severity: SeverityWarning,
			Summary:  "Configured sops binary was found but could not be executed",
			Details: []string{
				fmt.Sprintf("Resolved path: %s", resolved),
				fmt.Sprintf("Version check error: %v", err),
				"Read-only decrypt validation can still run through the SOPS Go library.",
			},
			Remediation: []string{
				"Ensure the configured SOPS binary is executable before running add, edit, or updatekeys.",
			},
		})
		return false
	}

	details := []string{
		fmt.Sprintf("Resolved path: %s", resolved),
	}
	status := StatusOK
	severity := SeverityInformational
	summary := "SOPS binary is available for mutating commands"
	if version != "" {
		details = append(details, fmt.Sprintf("Version: %s", version))
	} else {
		status = StatusWarn
		severity = SeverityWarning
		summary = "SOPS binary is available, but version output was empty"
	}
	result.Add(CheckResult{
		Name:     "sops binary",
		Status:   status,
		Severity: severity,
		Summary:  summary,
		Details:  details,
	})
	return true
}

// runAgeBinaryChecks reports age CLI availability for admin key workflows
// without making the age binary a read-only deployment requirement.
func runAgeBinaryChecks(cfg config.Config, result *Result) bool {
	binary := cfg.SOPS.AgeBinary
	probe, err := toolcheck.Probe(binary, nil, "--version")
	if err != nil {
		result.Add(CheckResult{
			Name:     "age binary",
			Status:   StatusOK,
			Severity: SeverityInformational,
			Summary:  "Configured age binary could not be resolved or executed",
			Details: []string{
				fmt.Sprintf("Configured value: %q", binary),
				fmt.Sprintf("Lookup or version error: %v", err),
				"Read-only decrypt operations need age private key material, not the external age CLI.",
				"The age CLI is still useful on developer/admin machines for key generation and inspection.",
			},
			Remediation: []string{
				fmt.Sprintf("Install age and make %q available in PATH only if this machine needs age key generation or inspection.", binary),
			},
		})
		return false
	}

	details := []string{
		fmt.Sprintf("Resolved path: %s", probe.Resolved),
	}
	status := StatusOK
	severity := SeverityInformational
	summary := "age binary is available for admin key workflows"
	if probe.Version != "" {
		details = append(details, fmt.Sprintf("Version: %s", probe.Version))
	} else {
		status = StatusWarn
		severity = SeverityWarning
		summary = "age binary is available, but version output was empty"
	}
	result.Add(CheckResult{
		Name:     "age binary",
		Status:   status,
		Severity: severity,
		Summary:  summary,
		Details:  details,
	})
	return true
}

func runRepoArtifactChecks(repoRoot string, result *Result) {
	var details []string
	var fixes []string

	rootBinary := filepath.Join(repoRoot, "keyseal")
	if info, err := os.Stat(rootBinary); err == nil && info.Mode().IsRegular() {
		details = append(details, fmt.Sprintf("Built binary present in repository root: %s", rootBinary))
		fixes = append(fixes, "Remove the root-level binary and use ./bin/keyseal instead of building into the repository root.")
	}

	distDir := filepath.Join(repoRoot, "dist")
	if entries, err := os.ReadDir(distDir); err == nil && len(entries) > 0 {
		details = append(details, fmt.Sprintf("dist/ contains %d artifact(s).", len(entries)))
		fixes = append(fixes, "Clean dist/ before committing release artifacts or local packaging output.")
	}

	if len(details) == 0 {
		result.Add(CheckResult{
			Name:     "repo artifacts",
			Status:   StatusOK,
			Severity: SeverityInformational,
			Summary:  "No obvious generated artifacts were found in the repository root",
		})
		return
	}

	result.Add(CheckResult{
		Name:        "repo artifacts",
		Status:      StatusWarn,
		Severity:    SeverityWarning,
		Summary:     "Found generated artifacts that are easy to commit by mistake",
		Details:     details,
		Remediation: dedupeStrings(fixes),
	})
}

func runSecretChecks(cwd, repoRoot string, cfg config.Config, result *Result) error {
	files, err := repo.DiscoverEncryptedFiles(repoRoot, cfg.Repository.EncryptedExtension)
	if err != nil {
		return err
	}

	if len(files) == 0 {
		result.Add(CheckResult{
			Name:     "secret discovery",
			Status:   StatusOK,
			Severity: SeverityInformational,
			Summary:  "No encrypted secret files were discovered yet",
			Details: []string{
				fmt.Sprintf("Looked for files ending in %s under %s.", cfg.Repository.EncryptedExtension, repoRoot),
			},
		})
		return nil
	}

	result.Add(CheckResult{
		Name:     "secret discovery",
		Status:   StatusOK,
		Severity: SeverityInformational,
		Summary:  fmt.Sprintf("Discovered %d encrypted secret file(s)", len(files)),
	})

	opts := schema.DefaultValidationOptions()
	opts.RequireValues = cfg.Validation.RequireValues
	opts.KeyPattern = cfg.Validation.KeyPattern

	for _, file := range files {
		logical, err := repo.PathToLogicalName(repoRoot, file, cfg.Repository.EncryptedExtension)
		if err != nil {
			result.Add(CheckResult{
				Name:     "secret naming",
				Status:   StatusFail,
				Severity: SeverityError,
				Summary:  fmt.Sprintf("%s does not map cleanly back to a logical name", filepath.ToSlash(file)),
				Details: []string{
					fmt.Sprintf("Mapping error: %v", err),
				},
				Remediation: []string{
					fmt.Sprintf("Rename %s so it matches the configured %s naming convention.", filepath.ToSlash(file), cfg.Repository.EncryptedExtension),
				},
			})
			continue
		}
		roundTrip, err := repo.LogicalNameToPath(repoRoot, logical, cfg.Repository.EncryptedExtension)
		if err != nil || roundTrip != file {
			result.Add(CheckResult{
				Name:     fmt.Sprintf("secret %s", logical),
				Status:   StatusFail,
				Severity: SeverityError,
				Summary:  "Logical name round-trip validation failed",
				Details: []string{
					fmt.Sprintf("Expected path: %s", filepath.ToSlash(roundTrip)),
					fmt.Sprintf("Actual path: %s", filepath.ToSlash(file)),
				},
				Remediation: []string{
					"Rename the file so the logical name maps back to the same path consistently.",
				},
			})
			continue
		}

		classified, err := secretfile.Classify(file)
		if err != nil {
			result.Add(CheckResult{
				Name:     fmt.Sprintf("secret %s", logical),
				Status:   StatusFail,
				Severity: SeverityError,
				Summary:  "Secret file could not be read",
				Details: []string{
					fmt.Sprintf("Read error: %v", err),
				},
				Remediation: []string{
					fmt.Sprintf("Fix file permissions or recreate %s.", filepath.ToSlash(file)),
				},
			})
			continue
		}
		switch classified.State {
		case secretfile.StatePlaceholder:
			result.Add(CheckResult{
				Name:     fmt.Sprintf("secret %s", logical),
				Status:   StatusWarn,
				Severity: SeverityWarning,
				Summary:  fmt.Sprintf("%s is an empty or uninitialized placeholder file", filepath.ToSlash(file)),
				Details: []string{
					"Empty or whitespace-only files at encrypted paths are skipped until they are populated.",
					"Decrypt and schema validation were not attempted for this file.",
				},
				Remediation: []string{
					fmt.Sprintf("Populate the secret with `keyseal edit %s` or recreate it with `keyseal add %s`.", logical, logical),
				},
			})
			continue
		case secretfile.StatePlaintext:
			result.Add(CheckResult{
				Name:     fmt.Sprintf("secret %s", logical),
				Status:   StatusFail,
				Severity: SeverityError,
				Summary:  fmt.Sprintf("%s is non-empty plaintext at an encrypted path", filepath.ToSlash(file)),
				Details: []string{
					"This file contains non-empty content but does not contain the top-level sops metadata block written by SOPS.",
					"Keyseal treats this as a plaintext-at-encrypted-path failure so unencrypted secret content is not ignored.",
				},
				Remediation: []string{
					fmt.Sprintf("Encrypt the file with `keyseal edit %s` or recreate it with `keyseal add %s`.", logical, logical),
				},
			})
			continue
		}

		plaintext, decryptWarnings, err := sopsutil.DecryptFileWithWarnings(file, "yaml", config.ResolvePath(cwd, cfg.SOPS.AgeKeyFile))
		if err != nil {
			result.Add(CheckResult{
				Name:     fmt.Sprintf("secret %s", logical),
				Status:   StatusFail,
				Severity: SeverityError,
				Summary:  fmt.Sprintf("Failed to decrypt %s", filepath.ToSlash(file)),
				Details: []string{
					fmt.Sprintf("Decrypt error: %v", classifyDecryptError(err)),
					"Without successful decryption, Keyseal cannot validate the secret schema or env keys.",
				},
				Remediation: []string{
					"Confirm the SOPS recipients, local age key setup, and file access, then rerun `keyseal doctor`.",
				},
			})
			continue
		}
		doc, dupes, err := schema.ParseYAMLDocument(plaintext)
		if err != nil {
			result.Add(CheckResult{
				Name:     fmt.Sprintf("secret %s", logical),
				Status:   StatusFail,
				Severity: SeverityError,
				Summary:  fmt.Sprintf("Decrypted %s is not valid YAML", filepath.ToSlash(file)),
				Details: []string{
					fmt.Sprintf("Parse error: %v", err),
				},
				Remediation: []string{
					fmt.Sprintf("Open the file with `keyseal edit %s` and fix the YAML structure.", logical),
				},
			})
			continue
		}
		if err := doc.Validate(opts); err != nil {
			result.Add(CheckResult{
				Name:     fmt.Sprintf("secret %s", logical),
				Status:   StatusFail,
				Severity: SeverityError,
				Summary:  fmt.Sprintf("Decrypted %s does not match the supported env schema", filepath.ToSlash(file)),
				Details: []string{
					fmt.Sprintf("Validation error: %v", err),
				},
				Remediation: []string{
					fmt.Sprintf("Fix the secret with `keyseal edit %s` so it includes a supported kind: env document and valid env keys.", logical),
				},
			})
			continue
		}
		if len(dupes) > 0 {
			result.Add(CheckResult{
				Name:     fmt.Sprintf("secret %s", logical),
				Status:   StatusWarn,
				Severity: SeverityWarning,
				Summary:  fmt.Sprintf("%s contains duplicate env keys", filepath.ToSlash(file)),
				Details: []string{
					fmt.Sprintf("Duplicate keys in values: %s", strings.Join(dupes, ", ")),
					"YAML keeps the last value, which can hide earlier mistakes during review.",
				},
				Remediation: []string{
					fmt.Sprintf("Edit %s and remove the duplicate keys so each env var is defined once.", filepath.ToSlash(file)),
				},
			})
			continue
		}
		if len(decryptWarnings) > 0 {
			result.Add(CheckResult{
				Name:     fmt.Sprintf("secret %s", logical),
				Status:   StatusWarn,
				Severity: SeverityWarning,
				Summary:  fmt.Sprintf("%s decrypted and validated with SOPS compatibility warnings", filepath.ToSlash(file)),
				Details: append([]string{
					"The file decrypted successfully and its schema is valid, but the SOPS Go library reported warnings while reading it.",
					"These warnings are shown here instead of during render/exec so plaintext output stays clean.",
				}, decryptWarnings...),
				Remediation: []string{
					"Open and save or re-encrypt this file with a current SOPS CLI on a developer/admin machine.",
					"Then rerun `keyseal doctor` to confirm the compatibility warning is gone.",
				},
			})
			continue
		}
		result.Add(CheckResult{
			Name:     fmt.Sprintf("secret %s", logical),
			Status:   StatusOK,
			Severity: SeverityInformational,
			Summary:  "Decrypted and validated successfully",
		})
	}

	return nil
}

// classifyDecryptError keeps doctor error details behind one helper so future
// backend-specific sanitization can happen without touching check assembly.
func classifyDecryptError(err error) string {
	return err.Error()
}

// dedupeStrings preserves first-seen order while removing repeated remediation
// lines from checks that aggregate multiple path findings.
func dedupeStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}
