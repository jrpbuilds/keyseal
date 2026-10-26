package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/jrpbuilds/keyseal/internal/buildinfo"
	"github.com/jrpbuilds/keyseal/internal/config"
	"github.com/jrpbuilds/keyseal/internal/contract"
	"github.com/spf13/cobra"
)

type validatePayload struct {
	Contract   string               `json:"contract"`
	Passed     bool                 `json:"passed"`
	Violations []contract.Violation `json:"violations"`
	Error      string               `json:"error,omitempty"`
}

func newValidateCommand() *cobra.Command {
	var jsonOutput bool

	cmd := &cobra.Command{
		Use:   "validate <contract>",
		Short: "Evaluate one declarative secret contract",
		Long: "Decrypt the documents listed by a named contract and evaluate its rules.\n" +
			"Reports key names and failed rules without displaying secret values.\n" +
			"Use --json for machine-readable output in CI or scripts.",
		Example: "  keyseal validate production-app\n" +
			"  keyseal validate production-app --json",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runValidate(cmd, args[0], jsonOutput)
		},
	}
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "Emit structured JSON results for CI or scripts")
	return cmd
}

func runValidate(cmd *cobra.Command, name string, jsonOutput bool) error {
	cwd, err := os.Getwd()
	if err != nil {
		return writeValidateFailure(cmd, jsonOutput, name, fmt.Sprintf("get working directory: %v", err))
	}
	cfgPath := filepath.Join(cwd, config.DefaultConfigPath)
	cfg, err := config.LoadLenient(cfgPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return writeValidateFailure(cmd, jsonOutput, name, fmt.Sprintf("keyseal.yaml not found in %s; run `keyseal init` first", cwd))
		}
		return writeValidateFailure(cmd, jsonOutput, name, err.Error())
	}
	if err := cfg.CheckKeysealRequirement(buildinfo.DisplayVersion()); err != nil {
		return writeValidateFailure(cmd, jsonOutput, name, err.Error())
	}
	for _, problem := range cfg.ContractProblems {
		if problem.Name == name {
			return writeValidateFailure(cmd, jsonOutput, name, problem.Error())
		}
	}
	def, ok := cfg.Contracts[name]
	if !ok {
		return writeValidateFailure(cmd, jsonOutput, name, fmt.Sprintf("contract %q is not defined", name))
	}

	violations := evaluateContract(cfg, cwd, def)
	if err := writeValidateResult(cmd, jsonOutput, name, violations, ""); err != nil {
		return err
	}
	if len(violations) > 0 {
		return commandExitError{code: 1}
	}
	return nil
}

func writeValidateFailure(cmd *cobra.Command, jsonOutput bool, name, errMsg string) error {
	if err := writeValidateResult(cmd, jsonOutput, name, nil, errMsg); err != nil {
		return err
	}
	return commandExitError{code: 1}
}

func writeValidateResult(cmd *cobra.Command, jsonOutput bool, name string, violations []contract.Violation, errMsg string) error {
	if violations == nil {
		violations = []contract.Violation{}
	}
	passed := errMsg == "" && len(violations) == 0
	if jsonOutput {
		payload := validatePayload{
			Contract:   name,
			Passed:     passed,
			Violations: violations,
			Error:      errMsg,
		}
		body, err := json.MarshalIndent(payload, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal validate json: %w", err)
		}
		_, err = cmd.OutOrStdout().Write(append(body, '\n'))
		return err
	}
	if passed {
		fmt.Fprintf(cmd.OutOrStdout(), "validate passed: contract %q\n", name)
		return nil
	}
	if errMsg != "" {
		fmt.Fprintf(cmd.OutOrStdout(), "validate failed: contract %q\n  - %s\n", name, errMsg)
		return nil
	}
	fmt.Fprintf(cmd.OutOrStdout(), "validate failed: contract %q (%d violation(s))\n", name, len(violations))
	for _, violation := range violations {
		fmt.Fprintf(cmd.OutOrStdout(), "  - [%s] %s\n", violation.Rule, violation.Message)
	}
	return nil
}
