package cli

import (
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/jrpbuilds/keyseal/internal/gitutil"
	"github.com/jrpbuilds/keyseal/internal/repo"
	"github.com/spf13/cobra"
)

func newCommitCommand() *cobra.Command {
	var message string
	var dryRun bool

	cmd := &cobra.Command{
		Use:   "commit [logical-name...]",
		Short: "Commit current Keyseal-managed changes",
		Long: "Stage current Keyseal-managed changes and create a Git commit.\n" +
			"Only encrypted secret files plus keyseal.yaml and .sops.yaml are staged. This command never runs `git add .`.\n" +
			"Pass logical names to stage only those documents. Named commits refuse missing, unchanged, ambiguous, or invalid names before touching Git.\n" +
			"Use --dry-run to list the exact repo-relative paths that would be staged without changing the index or creating a commit.",
		Example: "  keyseal commit\n" +
			"  keyseal commit -m \"Rotate Stripe webhook secret\"\n" +
			"  keyseal commit production/app-next.env production/provisioner-next.env -m \"chore(secrets): prepare production release\"\n" +
			"  keyseal commit production/app-next.env --dry-run",
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
			named := len(args) > 0
			if named {
				entries, err = selectCommitEntriesByLogicalNames(ctx, entries, args)
				if err != nil {
					return err
				}
			}
			paths := stagePathsForEntries(ctx, entries)
			if len(paths) == 0 {
				return gitutil.ErrNothingToCommit
			}
			if dryRun {
				return writeCommitDryRun(cmd, ctx, paths)
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
			if named {
				return writeCommittedLogicalNames(cmd, ctx, paths)
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&message, "message", "m", "", "Git commit message")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "List the paths that would be staged without committing")
	return cmd
}

// selectCommitEntriesByLogicalNames restricts commit staging to the requested
// documents. Every name must resolve to exactly one changed Keyseal-managed
// status entry; otherwise the whole commit is refused before Git is touched.
func selectCommitEntriesByLogicalNames(ctx gitWorkflowContext, entries []gitutil.StatusEntry, logicalNames []string) ([]gitutil.StatusEntry, error) {
	seenNames := map[string]struct{}{}
	matched := make([]gitutil.StatusEntry, 0, len(logicalNames))
	matchedKeys := map[string]struct{}{}
	var problems []string

	for _, logical := range logicalNames {
		if err := repo.ValidateLogicalName(logical); err != nil {
			problems = append(problems, err.Error())
			continue
		}
		if _, ok := seenNames[logical]; ok {
			problems = append(problems, fmt.Sprintf("logical name %q is listed more than once", logical))
			continue
		}
		seenNames[logical] = struct{}{}
		if logicalNameIsAmbiguous(logical) {
			problems = append(problems, fmt.Sprintf("logical name %q is ambiguous", logical))
			continue
		}

		target, err := repo.LogicalNameToPath(ctx.KeysealRoot, logical, ctx.Config.Repository.EncryptedExtension)
		if err != nil {
			problems = append(problems, err.Error())
			continue
		}
		info, lstatErr := os.Lstat(target)
		switch {
		case lstatErr == nil && info.IsDir():
			problems = append(problems, fmt.Sprintf("logical name %q is ambiguous", logical))
			continue
		case lstatErr != nil && !errors.Is(lstatErr, os.ErrNotExist):
			problems = append(problems, fmt.Sprintf("inspect %s: %v", logical, lstatErr))
			continue
		}
		exists := lstatErr == nil

		pathspec, err := gitutil.Pathspec(ctx.GitRoot, target)
		if err != nil {
			problems = append(problems, err.Error())
			continue
		}
		filtered := filterStatusEntriesByRepoPath(entries, pathspec)
		switch {
		case len(filtered) > 1:
			problems = append(problems, fmt.Sprintf("logical name %q is ambiguous", logical))
		case len(filtered) == 0:
			if exists {
				problems = append(problems, fmt.Sprintf("secret %s is unchanged", logical))
			} else {
				// A deletion or rename still appears in status when the old
				// path was tracked. Absence from both status and the worktree
				// means the document was never present.
				problems = append(problems, fmt.Sprintf("secret %s not found", logical))
			}
		default:
			key := statusEntryKey(filtered[0])
			if _, ok := matchedKeys[key]; ok {
				continue
			}
			matchedKeys[key] = struct{}{}
			matched = append(matched, filtered[0])
		}
	}

	if len(problems) > 0 {
		return nil, errors.New(strings.Join(problems, "; "))
	}
	return matched, nil
}

func logicalNameIsAmbiguous(logical string) bool {
	return strings.ContainsAny(logical, "*?[")
}

func statusEntryKey(entry gitutil.StatusEntry) string {
	return entry.Code() + "\x00" + entry.Path + "\x00" + entry.OriginalPath
}

func writeCommitDryRun(cmd *cobra.Command, ctx gitWorkflowContext, paths []string) error {
	pathspecs, err := gitutil.Pathspecs(ctx.GitRoot, paths)
	if err != nil {
		return err
	}
	slices.Sort(pathspecs)
	for _, pathspec := range pathspecs {
		fmt.Fprintf(cmd.OutOrStdout(), "would stage %s\n", pathspec)
	}
	return nil
}

// writeCommittedLogicalNames lists the documents included in a named commit.
// Names are derived from encrypted paths only; the command never decrypts.
func writeCommittedLogicalNames(cmd *cobra.Command, ctx gitWorkflowContext, paths []string) error {
	names := make([]string, 0, len(paths))
	seen := map[string]struct{}{}
	for _, path := range paths {
		logical, err := repo.PathToLogicalName(ctx.KeysealRoot, path, ctx.Config.Repository.EncryptedExtension)
		if err != nil {
			continue
		}
		if _, ok := seen[logical]; ok {
			continue
		}
		seen[logical] = struct{}{}
		names = append(names, logical)
	}
	slices.Sort(names)
	for _, logical := range names {
		fmt.Fprintln(cmd.OutOrStdout(), logical)
	}
	return nil
}
