package cli

import (
	"errors"
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"

	"github.com/jrpbuilds/keyseal/internal/fsutil"
	"github.com/jrpbuilds/keyseal/internal/render"
	"github.com/spf13/cobra"
)

func newRenderCommand() *cobra.Command {
	var format string
	var out string
	var stdout bool
	var mode string
	var force bool
	var profile string
	var dryRun bool
	var selectKeys []string
	var requireAll bool

	cmd := &cobra.Command{
		Use:   "render <logical-name...>",
		Short: "Decrypt, merge, and render secret files",
		Long: "Decrypt and merge one or more env documents, then render them as dotenv, JSON, or YAML.\n" +
			"Later files override earlier ones. Empty or whitespace-only placeholder files are skipped.\n" +
			"Use --stdout to print secret values, or --out to write atomically to a file.\n" +
			"Use --select to emit only named keys after the merge; --require-all fails when any\n" +
			"selected key is absent. --select filters output only: each requested document is still\n" +
			"decrypted in full. Prefer --format json for automation.\n" +
			"Use --profile to execute every render defined by a named profile in keyseal.yaml.",
		Example: "  keyseal render production/platform/app --stdout\n" +
			"  keyseal render production/platform/app --select APP_ENV,DB_HOST --format json --require-all --stdout\n" +
			"  keyseal render production/platform/app staging/platform/stripe --format json --out ./runtime/app-secrets.json\n" +
			"  keyseal render --profile prod\n" +
			"  keyseal render --profile prod --dry-run",
		Args: func(cmd *cobra.Command, args []string) error {
			if profile != "" {
				if len(args) > 0 {
					return errors.New("positional logical names cannot be combined with --profile")
				}
				return nil
			}
			return cobra.MinimumNArgs(1)(cmd, args)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if profile != "" {
				return runProfileRender(cmd, profile, dryRun, force)
			}
			if dryRun {
				return errors.New("--dry-run is only supported together with --profile")
			}
			switch {
			case stdout && out != "":
				return errors.New("choose either --out or --stdout, not both")
			case !stdout && out == "":
				return errors.New("require either --out or --stdout")
			}

			selectSet := cmd.Flags().Changed("select")
			keys, err := normalizeSelectKeys(selectKeys, selectSet)
			if err != nil {
				return err
			}
			if requireAll && !selectSet {
				return errors.New("--require-all requires --select")
			}

			cfg, cwd, err := loadConfigFromCWD()
			if err != nil {
				return err
			}
			if format == "" {
				format = cfg.Defaults.OutputFormat
			}
			if mode == "" {
				mode = cfg.Defaults.FileMode
			}
			if selectSet {
				if err := validateKeyNames(keys, validationOptions(cfg)); err != nil {
					return err
				}
			}

			// Read-only decrypt uses the SOPS Go library, so deploy hosts do not
			// need the external sops binary just to render runtime secrets.
			loaded, err := loadDocuments(cfg, cwd, args)
			if err != nil {
				return mapRenderLoadError(err)
			}
			if len(loaded.SkippedPlaceholders) > 0 {
				fmt.Fprintf(cmd.ErrOrStderr(), "skipped %d empty placeholder secret file(s): %s\n", len(loaded.SkippedPlaceholders), strings.Join(loaded.SkippedPlaceholders, ", "))
			}
			merged := render.MergeEnvDocs(loaded.Docs)
			values := merged
			if selectSet {
				selected, missing := render.Select(merged, keys)
				if requireAll && len(missing) > 0 {
					return renderExitError{
						code: 2,
						msg:  fmt.Sprintf("selected keys not found: %s", strings.Join(missing, ", ")),
					}
				}
				values = selected
			}
			body, err := render.Render(format, values)
			if err != nil {
				return err
			}

			if stdout {
				_, err = cmd.OutOrStdout().Write(body)
				return err
			}

			fileMode, err := fsutil.ParseFileMode(mode)
			if err != nil {
				return err
			}
			if !fsutil.IsSafeFileMode(fileMode) && !force {
				return fmt.Errorf("mode %s is not owner-only; use --force to override", mode)
			}
			if err := fsutil.AtomicWriteFile(out, body, fileMode, force); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "rendered %d secret file(s) to %s\n", len(loaded.Docs), out)
			return nil
		},
	}

	cmd.Flags().StringVar(&format, "format", "", "Render format: dotenv, json, yaml (defaults to keyseal.yaml)")
	cmd.Flags().StringVar(&out, "out", "", "Output file path for atomic plaintext writes")
	cmd.Flags().BoolVar(&stdout, "stdout", false, "Write decrypted secret data to stdout")
	cmd.Flags().StringVar(&mode, "mode", "", "Output file mode as an octal string (defaults to keyseal.yaml)")
	cmd.Flags().BoolVar(&force, "force", false, "Allow unsafe modes and overwrite existing output")
	cmd.Flags().StringVar(&profile, "profile", "", "Execute every render defined by this profile in keyseal.yaml")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "With --profile, resolve and validate all inputs, print the plan, and write nothing")
	cmd.Flags().StringSliceVar(&selectKeys, "select", nil, "Comma-separated keys to include after merge (repeatable)")
	cmd.Flags().BoolVar(&requireAll, "require-all", false, "With --select, fail if any selected key is absent")
	return cmd
}

// normalizeSelectKeys trims --select tokens. When the flag was set, at least
// one non-empty key is required so an empty list never means "render everything".
func normalizeSelectKeys(raw []string, selectSet bool) ([]string, error) {
	if !selectSet {
		return nil, nil
	}
	keys := make([]string, 0, len(raw))
	for _, key := range raw {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		keys = append(keys, key)
	}
	if len(keys) == 0 {
		return nil, errors.New("--select requires at least one key name")
	}
	return keys, nil
}

// renderExitError carries a non-zero process exit code while still printing a
// user-visible message. Unlike commandExitError, the message is not empty.
type renderExitError struct {
	code int
	msg  string
}

func (e renderExitError) Error() string {
	return e.msg
}

func (e renderExitError) ExitCode() int {
	return e.code
}

// mapRenderLoadError maps tagged document load failures to render exit codes
// 3 (decrypt) and 4 (invalid document) without changing the message text.
func mapRenderLoadError(err error) error {
	var loadErr documentLoadError
	if !errors.As(err, &loadErr) {
		return err
	}
	switch loadErr.kind {
	case documentLoadDecrypt:
		return renderExitError{code: 3, msg: loadErr.msg}
	case documentLoadInvalid:
		return renderExitError{code: 4, msg: loadErr.msg}
	default:
		return err
	}
}

// profileRenderPlan is one fully resolved profile render. Its decrypted body
// lives only in memory between the resolve and write phases and is never
// printed or logged. fileMode is parsed and safety-checked in Phase A so
// Phase B is a pure write loop.
type profileRenderPlan struct {
	name     string
	inputs   []string
	format   string
	mode     string
	fileMode os.FileMode
	out      string
	body     []byte
}

// runProfileRender executes every render of the named profile. All inputs are
// resolved, decrypted, and validated, and every output path is pre-flighted,
// before the first file is written so a failing input aborts the whole run
// with no partial writes. Decrypted values are never printed.
func runProfileRender(cmd *cobra.Command, name string, dryRun, force bool) error {
	// Profile renders take their format/out/mode from keyseal.yaml, so the
	// explicit-render flags have no meaning here and are rejected explicitly
	// via Changed() so even default-valued occurrences fail.
	for _, flag := range []string{"format", "out", "stdout", "mode", "select", "require-all"} {
		if cmd.Flags().Changed(flag) {
			return fmt.Errorf("--%s cannot be combined with --profile; configure it on the profile renders in keyseal.yaml instead", flag)
		}
	}

	cfg, cwd, err := loadConfigFromCWD()
	if err != nil {
		return err
	}
	profileCfg, ok := cfg.Profiles[name]
	if !ok {
		available := slices.Sorted(maps.Keys(cfg.Profiles))
		return fmt.Errorf("profile %q does not exist in keyseal.yaml; available profiles: %s", name, strings.Join(available, ", "))
	}

	// Phase A: resolve, decrypt, validate, and pre-flight every render before
	// writing anything. Nothing is persisted here, so failing fast keeps the
	// run free of partial output.
	planned := make([]profileRenderPlan, 0, len(profileCfg.Renders))
	for idx, r := range profileCfg.Renders {
		label := fmt.Sprintf("profiles.%s.renders[%d] (%q)", name, idx, r.Name)
		format := r.Format
		if format == "" {
			format = cfg.Defaults.OutputFormat
		}
		mode := r.Mode
		if mode == "" {
			mode = cfg.Defaults.FileMode
		}
		// Mode safety is a Phase A pre-flight: rejecting an unsafe mode here,
		// before any render is written, keeps multi-render profiles
		// all-or-nothing and makes dry-run fail on profiles that could not
		// actually execute.
		fileMode, err := fsutil.ParseFileMode(mode)
		if err != nil {
			return fmt.Errorf("%s: %w", label, err)
		}
		if !fsutil.IsSafeFileMode(fileMode) && !force {
			return fmt.Errorf("%s: mode %s is not owner-only; use --force to override", label, mode)
		}
		if r.Out == "" {
			return fmt.Errorf("%s: out is required", label)
		}
		loaded, err := loadDocuments(cfg, cwd, r.Inputs)
		if err != nil {
			// Preserve profile labels while still mapping decrypt/invalid-document
			// failures to the same stable exit codes as explicit render.
			return fmt.Errorf("%s: %w", label, mapRenderLoadError(err))
		}
		if len(loaded.SkippedPlaceholders) > 0 {
			fmt.Fprintf(cmd.ErrOrStderr(), "skipped %d empty placeholder secret file(s): %s\n", len(loaded.SkippedPlaceholders), strings.Join(loaded.SkippedPlaceholders, ", "))
		}
		merged := render.MergeEnvDocs(loaded.Docs)
		body, err := render.Render(format, merged)
		if err != nil {
			return fmt.Errorf("%s: %w", label, err)
		}
		if err := fsutil.CheckWritableFilePath(r.Out, force); err != nil {
			return fmt.Errorf("%s: %w", label, err)
		}
		planned = append(planned, profileRenderPlan{
			name:     r.Name,
			inputs:   r.Inputs,
			format:   format,
			mode:     mode,
			fileMode: fileMode,
			out:      r.Out,
			body:     body,
		})
	}

	if dryRun {
		printProfilePlan(cmd, name, planned)
		return nil
	}

	// Phase B: write every pre-flighted output atomically. Modes were parsed
	// and safety-checked in Phase A, so this loop performs writes only.
	// out paths resolve relative to the process CWD, matching explicit --out.
	for _, plan := range planned {
		if err := fsutil.AtomicWriteFile(plan.out, plan.body, plan.fileMode, force); err != nil {
			return err
		}
	}
	fmt.Fprintf(cmd.OutOrStdout(), "rendered %d profile output(s) for profile %q\n", len(planned), name)
	return nil
}

// printProfilePlan writes the dry-run plan for a fully validated profile.
// Only metadata (names, logical inputs, format, out, mode) is printed;
// decrypted secret values never reach stdout.
func printProfilePlan(cmd *cobra.Command, profile string, planned []profileRenderPlan) {
	fmt.Fprintf(cmd.OutOrStdout(), "dry-run: profile %q would render %d output(s)\n", profile, len(planned))
	for _, plan := range planned {
		fmt.Fprintf(cmd.OutOrStdout(),
			"render %q\n  inputs: %s\n  format: %s\n  out: %s\n  mode: %s\n",
			plan.name, strings.Join(plan.inputs, ", "), plan.format, plan.out, plan.mode,
		)
	}
}
