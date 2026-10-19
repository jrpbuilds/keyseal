package cli

import (
	"fmt"
	"os"

	"github.com/jrpbuilds/keyseal/internal/doctor"
	"github.com/spf13/cobra"
)

func newDoctorCommand() *cobra.Command {
	var jsonOutput bool

	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Validate repository and config health",
		Long: "Validate keyseal.yaml, SOPS availability, age availability warnings, .sops.yaml readiness, placeholder recipients,\n" +
			"encrypted file consistency, plaintext mistakes, empty placeholder files, decrypted env document shape, and declarative\n" +
			"contract definitions without exposing secret values. Contract value rules are evaluated by keyseal verify and keyseal validate.\n" +
			"Use --json for machine-readable output in CI or scripts.",
		Example: "  keyseal doctor\n" +
			"  keyseal doctor --json",
		RunE: func(cmd *cobra.Command, args []string) error {
			cwd, err := os.Getwd()
			if err != nil {
				return err
			}

			result, err := doctor.Run(cwd)
			if err != nil {
				return err
			}

			if jsonOutput {
				payload, err := result.RenderJSON()
				if err != nil {
					return fmt.Errorf("marshal doctor json: %w", err)
				}
				if _, err := cmd.OutOrStdout().Write(append(payload, '\n')); err != nil {
					return err
				}
			} else {
				fmt.Fprint(cmd.OutOrStdout(), result.RenderText())
			}

			if result.HasFailures() {
				return commandExitError{code: 1}
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&jsonOutput, "json", false, "Emit structured JSON results for CI or scripts")
	return cmd
}
