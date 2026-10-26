package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/jrpbuilds/keyseal/internal/buildinfo"
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

			appendVerifyContractChecks(cwd, &result)

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

// CheckNameContractEvaluation is the stable verify check name used when
// keyseal.yaml cannot be reloaded for contract evaluation after doctor.
const CheckNameContractEvaluation = "contract evaluation"

// appendVerifyContractChecks reloads config after doctor and evaluates
// contracts when safe. A reload failure is reported as an explicit fail check
// so verify never silently skips contract evaluation. Unmet
// requirements.keyseal skips decrypt/eval because doctor already reported it.
func appendVerifyContractChecks(cwd string, result *doctor.Result) {
	cfg, loadErr := config.LoadLenient(filepath.Join(cwd, config.DefaultConfigPath))
	if loadErr != nil {
		result.Add(doctor.CheckResult{
			Name:     CheckNameContractEvaluation,
			Status:   doctor.StatusFail,
			Severity: doctor.SeverityError,
			Summary:  "Could not reload keyseal.yaml for contract evaluation",
			Details: []string{
				"Doctor completed, but verify could not reload configuration to evaluate secret contracts.",
				"Contract values were not decrypted or evaluated.",
			},
			Remediation: []string{
				"Fix keyseal.yaml so it loads cleanly, then rerun `keyseal verify`.",
			},
		})
		return
	}
	if err := cfg.CheckKeysealRequirement(buildinfo.DisplayVersion()); err != nil {
		return
	}
	appendContractEvaluationChecks(cfg, cwd, result)
}
