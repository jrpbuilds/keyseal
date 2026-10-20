package cli

import (
	"fmt"

	"github.com/jrpbuilds/keyseal/internal/gitutil"
	"github.com/jrpbuilds/keyseal/internal/observe"
	"github.com/jrpbuilds/keyseal/internal/repo"
	"github.com/spf13/cobra"
)

func newDiffCommand() *cobra.Command {
	var flags observeFlags
	var semantic bool
	var revision string

	cmd := &cobra.Command{
		Use:   "diff <logical-name>",
		Short: "Show Git diff for one secret file",
		Long: "Resolve a logical name to its encrypted file path and show the Git diff for that file.\n" +
			"The command is read-only and works in a dirty repository.\n" +
			"With --semantic, decrypt the working-tree file and a Git revision (HEAD unless --to is set) in memory and\n" +
			"report each key as equal, different, added, or removed without showing values. Semantic diff compares\n" +
			"the working tree to the revision, so staged and unstaged edits both appear, and it needs your age key.",
		Example: "  keyseal diff production/platform/app\n" +
			"  keyseal diff production/platform/app --semantic\n" +
			"  keyseal diff production/platform/app --semantic --to abc1234 --json --assert-equal",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !semantic {
				for _, name := range semanticOnlyFlags {
					if cmd.Flags().Changed(name) {
						return fmt.Errorf("--%s requires --semantic", name)
					}
				}
				return runCiphertextDiff(cmd, args[0])
			}
			opt, err := flags.option()
			if err != nil {
				return err
			}
			opt.AllowMissing = true
			if revision == "" {
				revision = "HEAD"
			}
			scope, err := newObserveScope(true)
			if err != nil {
				return err
			}
			rep := scope.Compare(
				observe.Ref{Logical: args[0], Revision: revision},
				observe.Ref{Logical: args[0]},
				opt,
			)
			return finishReport(cmd, flags.json, rep)
		},
	}
	cmd.Flags().BoolVar(&semantic, "semantic", false, "Compare decrypted key states against a Git revision without showing values")
	cmd.Flags().StringVar(&revision, "to", "", "Git revision to compare against with --semantic (default HEAD)")
	flags.bindReportFlags(cmd)
	flags.bindAssertFlags(cmd)
	return cmd
}

func runCiphertextDiff(cmd *cobra.Command, logical string) error {
	ctx, err := loadGitWorkflowContext()
	if err != nil {
		return err
	}
	target, err := repo.LogicalNameToPath(ctx.KeysealRoot, logical, ctx.Config.Repository.EncryptedExtension)
	if err != nil {
		return err
	}
	diffText, err := gitutil.Diff("git", ctx.GitRoot, target)
	if err != nil {
		return err
	}
	fmt.Fprint(cmd.OutOrStdout(), diffText)
	return nil
}
