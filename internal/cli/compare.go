package cli

import (
	"github.com/jrpbuilds/keyseal/internal/observe"
	"github.com/spf13/cobra"
)

func newCompareCommand() *cobra.Command {
	var flags observeFlags

	cmd := &cobra.Command{
		Use:   "compare <left-logical-name> <right-logical-name>",
		Short: "Compare two secrets key by key without showing values",
		Long: "Decrypt two secret documents in memory and report each key as equal, different, added, or removed.\n" +
			"The left document is the baseline and the right document is the candidate.\n" +
			"Values are never printed. Use --assert-equal or --assert-unequal to gate CI on the result.\n" +
			"A missing file, an empty placeholder, plaintext at an encrypted path, or a decrypt failure exits 1.",
		Example: "  keyseal compare production/platform/app production/platform/app-next\n" +
			"  keyseal compare production/platform/app production/platform/app-next --key CENTRAL_API_SECRET --assert-equal\n" +
			"  keyseal compare production/platform/app production/platform/app-next --assert-unequal --json",
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			opt, err := flags.option()
			if err != nil {
				return err
			}
			scope, err := newObserveScope(false)
			if err != nil {
				return err
			}
			rep := scope.Compare(observe.Ref{Logical: args[0]}, observe.Ref{Logical: args[1]}, opt)
			return finishReport(cmd, flags.json, rep)
		},
	}
	flags.bindReportFlags(cmd)
	flags.bindAssertFlags(cmd)
	return cmd
}
