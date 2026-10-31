package cli

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/jrpbuilds/keyseal/internal/execenv"
	"github.com/jrpbuilds/keyseal/internal/render"
	"github.com/spf13/cobra"
)

func newExecCommand() *cobra.Command {
	var cleanEnv bool
	var keepEnv []string

	cmd := &cobra.Command{
		Use:   "exec <logical-name...> -- <command...>",
		Short: "Run a child process with decrypted env vars injected",
		Long: "Decrypt and merge one or more env documents, then execute the child command after `--`.\n" +
			"By default the child inherits the current process environment and secret values override\n" +
			"matching keys. Use --clean-env to start from an empty environment, and --keep-env to\n" +
			"copy selected parent variables into that cleaned environment. Secret document values\n" +
			"always take precedence over retained parent variables. Under --clean-env, prefer an\n" +
			"absolute path for the child command, and pass --keep-env PATH when that child will\n" +
			"launch further commands by name; lookup of the initial binary always uses the parent\n" +
			"PATH. Empty or whitespace-only placeholder files are skipped.",
		Example: "  keyseal exec production/platform/app -- env | grep APP_\n" +
			"  keyseal exec production/platform/app --clean-env -- /usr/bin/env\n" +
			"  keyseal exec production/platform/app --clean-env --keep-env PATH,HOME,LANG -- php artisan migrate\n" +
			"  keyseal exec production/platform/app production/platform/stripe -- php artisan queue:work",
		Args: func(cmd *cobra.Command, args []string) error {
			sep := cmd.ArgsLenAtDash()
			if sep < 1 {
				return errors.New("require at least one logical name before `--`")
			}
			if len(args[sep:]) == 0 {
				return errors.New("require a child command after `--`")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			opts := execenv.Options{CleanEnv: cleanEnv, KeepEnv: keepEnv}
			// Validate inheritance policy against the current parent environment
			// before decrypting so a bad flag combination never loads secrets.
			if _, err := execenv.BuildBaseEnv(os.Environ(), opts); err != nil {
				return err
			}

			cfg, cwd, err := loadConfigFromCWD()
			if err != nil {
				return err
			}
			sep := cmd.ArgsLenAtDash()
			// Like render, exec only needs library decrypt and age key material;
			// it should stay usable on deploy hosts without the sops CLI.
			loaded, err := loadDocuments(cfg, cwd, args[:sep])
			if err != nil {
				return err
			}
			if len(loaded.SkippedPlaceholders) > 0 {
				fmt.Fprintf(cmd.ErrOrStderr(), "skipped %d empty placeholder secret file(s): %s\n", len(loaded.SkippedPlaceholders), strings.Join(loaded.SkippedPlaceholders, ", "))
			}
			if err := execenv.Run(args[sep:], render.MergeEnvDocs(loaded.Docs), opts); err != nil {
				var exitErr *exec.ExitError
				if errors.As(err, &exitErr) {
					return commandExitError{code: exitErr.ExitCode()}
				}
				return fmt.Errorf("run child command: %w", err)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&cleanEnv, "clean-env", false, "Start the child from an empty environment instead of inheriting the parent")
	cmd.Flags().StringSliceVar(&keepEnv, "keep-env", nil, "With --clean-env, copy these parent variables into the child (comma-separated or repeatable; names match exactly, including case)")
	return cmd
}

type commandExitError struct {
	code int
}

func (e commandExitError) Error() string {
	return ""
}

func (e commandExitError) ExitCode() int {
	return e.code
}
