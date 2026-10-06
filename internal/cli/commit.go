package cli

import (
	"errors"
	"fmt"

	"github.com/jrpbuilds/keyseal/internal/gitutil"
	"github.com/spf13/cobra"
)

func newCommitCommand() *cobra.Command {
	var message string

	cmd := &cobra.Command{
		Use:   "commit",
		Short: "Commit current Keyseal-managed changes",
		Long: "Stage current Keyseal-managed changes and create a Git commit.\n" +
			"Only encrypted secret files plus keyseal.yaml and .sops.yaml are staged. This command never runs `git add .`.",
		Example: "  keyseal commit\n" +
			"  keyseal commit -m \"Rotate Stripe webhook secret\"",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, err := loadGitWorkflowContext()
			if err != nil {
				return err
			}
			if err := ensureRepoReadyForCommit(ctx); err != nil {
				return err
			}

			entries, err := relevantStatusEntries(ctx)
			if err != nil {
				return err
			}
			paths := stagePathsForEntries(ctx, entries)
			if len(paths) == 0 {
				return gitutil.ErrNothingToCommit
			}
			commitMessage := message
			if commitMessage == "" {
				commitMessage = defaultCommitMessageForBatch(len(entries))
			}
			if err := commitPaths(ctx, paths, commitMessage); err != nil {
				if errors.Is(err, gitutil.ErrNothingToCommit) {
					return gitutil.ErrNothingToCommit
				}
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "committed Git change: %s\n", commitMessage)
			return nil
		},
	}
	cmd.Flags().StringVarP(&message, "message", "m", "", "Git commit message")
	return cmd
}
