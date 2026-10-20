package cli

import (
	"errors"

	"github.com/jrpbuilds/keyseal/internal/observe"
	"github.com/spf13/cobra"
)

func newInspectCommand() *cobra.Command {
	var flags observeFlags
	var redacted bool
	var revision string

	cmd := &cobra.Command{
		Use:   "inspect <logical-name>",
		Short: "Show key states for one secret without its values",
		Long: "Decrypt one secret document in memory and report whether each key is present, empty, or missing.\n" +
			"Values are never printed. Optional metadata (length, type, keyed fingerprint) is opt-in.\n" +
			"A missing file, an empty placeholder, plaintext at an encrypted path, or a decrypt failure exits 1.\n" +
			"Use --to to read the document as it was at a Git revision instead of the working tree.",
		Example: "  keyseal inspect production/platform/app\n" +
			"  keyseal inspect production/platform/app --json --key DATABASE_URL --show-length --show-type\n" +
			"  keyseal inspect production/platform/app --to abc1234",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !redacted {
				return errors.New("inspect only reports redacted output; --redacted=false is not supported")
			}
			opt, err := flags.option()
			if err != nil {
				return err
			}
			scope, err := newObserveScope(revision != "")
			if err != nil {
				return err
			}
			rep := scope.Inspect(observe.Ref{Logical: args[0], Revision: revision}, opt)
			return finishReport(cmd, flags.json, rep)
		},
	}
	cmd.Flags().BoolVar(&redacted, "redacted", true, "Report states only; accepted for clarity, redaction cannot be turned off")
	cmd.Flags().StringVar(&revision, "to", "", "Git revision to read instead of the working tree")
	flags.bindReportFlags(cmd)
	return cmd
}
