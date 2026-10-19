// Package cli wires the Cobra command tree to the internal workflow packages.
//
// The package intentionally keeps business logic out of command setup so the
// CLI surface stays readable and the underlying behavior remains testable.
package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/jrpbuilds/keyseal/internal/buildinfo"
	"github.com/jrpbuilds/keyseal/internal/config"
	"github.com/spf13/cobra"
)

// Execute runs the Keyseal root command.
func Execute() error {
	return newRootCommand().Execute()
}

func newRootCommand() *cobra.Command {
	var showVersion bool

	cmd := &cobra.Command{
		Use:   "keyseal",
		Short: "Small CLI for SOPS + age repo-backed secrets workflows",
		Long: "Keyseal is a workflow layer over SOPS, age, and Git-backed encrypted files.\n" +
			"It helps bootstrap a repo layout, scaffold starter secret documents, render decrypted env data,\n" +
			"inspect Git-backed secret history, commit intended changes, run child commands with injected secrets,\n" +
			"and validate repository health.",
		Example: "  keyseal init\n" +
			"  keyseal add production/platform/app --template laravel\n" +
			"  keyseal status\n" +
			"  keyseal diff production/platform/app\n" +
			"  keyseal history production/platform/app\n" +
			"  keyseal commit -m \"Rotate Stripe webhook secret\"\n" +
			"  keyseal edit production/platform/app\n" +
			"  keyseal clone production/platform/app production/platform/app-next\n" +
			"  keyseal set production/platform/app-next STRIPE_SECRET_KEY --stdin\n" +
			"  keyseal unset production/platform/app-next TWILIO_TOKEN\n" +
			"  keyseal generate production/platform/app-next APP_SIGNING_KEY --bytes 32\n" +
			"  keyseal import production/platform/app-next --from-env-file ./intake.env --keys STRIPE_SECRET_KEY\n" +
			"  keyseal updatekeys --all --yes\n" +
			"  keyseal rollback production/platform/app --to abc1234 --dry-run\n" +
			"  keyseal render production/platform/app --stdout\n" +
			"  keyseal exec production/platform/app -- env | grep APP_\n" +
			"  keyseal doctor\n" +
			"  keyseal verify\n" +
			"  keyseal validate production-app\n" +
			"  keyseal --version\n" +
			"  keyseal version --short",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if showVersion {
				fmt.Fprintln(cmd.OutOrStdout(), buildinfo.OneLine())
				return nil
			}
			return cmd.Help()
		},
	}
	cmd.Flags().BoolVar(&showVersion, "version", false, "Print the Keyseal version and exit")

	cmd.AddCommand(
		newInitCommand(),
		newAddCommand(),
		newEditCommand(),
		newCloneCommand(),
		newSetCommand(),
		newUnsetCommand(),
		newGenerateCommand(),
		newImportCommand(),
		newStatusCommand(),
		newDiffCommand(),
		newHistoryCommand(),
		newCommitCommand(),
		newUpdateKeysCommand(),
		newRollbackCommand(),
		newRenderCommand(),
		newExecCommand(),
		newDoctorCommand(),
		newVerifyCommand(),
		newValidateCommand(),
		newVersionCommand(),
	)
	return cmd
}

// loadConfigFromCWD loads keyseal.yaml from the current working directory.
//
// Commands operate relative to the active repository root, so the CLI fails
// early with a clear message when keyseal.yaml is missing.
func loadConfigFromCWD() (config.Config, string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return config.Config{}, "", fmt.Errorf("get working directory: %w", err)
	}
	cfg, err := config.Load(filepath.Join(cwd, config.DefaultConfigPath))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return config.Config{}, "", fmt.Errorf("keyseal.yaml not found in %s; run `keyseal init` first", cwd)
		}
		return config.Config{}, "", err
	}
	return cfg, cwd, nil
}
