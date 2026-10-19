package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/jrpbuilds/keyseal/internal/config"
	"github.com/jrpbuilds/keyseal/internal/doctor"
	"github.com/spf13/cobra"
)

// newVerifyCommand wires strict CI verification to the shared doctor engine.
func newVerifyCommand() *cobra.Command {
	var jsonOutput bool

	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Run strict CI verification checks",
		Long: "Run the same non-mutating repository checks as doctor, but fail when any warning or failure is reported.\n" +
			"Also evaluates every declarative secret contract against decrypted values.\n" +
			"Use this in CI and release gates to ensure every encrypted file decrypts and validates cleanly.",
		Example: "  keyseal verify\n" +
			"  keyseal verify --json",
		RunE: func(cmd *cobra.Command, args []string) error {
			cwd, err := os.Getwd()
			if err != nil {
				return err
			}

			result, err := doctor.Run(cwd)
			if err != nil {
				return err
			}

			// Evaluate well-formed contracts after doctor definition checks.
			// Re-load leniently so verify can access the decoded contract map
			// without failing before doctor has already reported problems.
			if cfg, loadErr := config.LoadLenient(filepath.Join(cwd, config.DefaultConfigPath)); loadErr == nil {
				appendContractEvaluationChecks(cfg, cwd, &result)
			}

			if jsonOutput {
				payload, err := result.RenderVerifyJSON()
				if err != nil {
					return fmt.Errorf("marshal verify json: %w", err)
				}
				if _, err := cmd.OutOrStdout().Write(append(payload, '\n')); err != nil {
					return err
				}
			} else {
				fmt.Fprint(cmd.OutOrStdout(), result.RenderVerifyText())
			}

			if !result.VerifyPassed() {
				return commandExitError{code: 1}
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "Emit structured JSON results for CI or scripts")
	return cmd
}
