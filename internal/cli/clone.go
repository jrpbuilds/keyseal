package cli

import (
	"fmt"

	"github.com/jrpbuilds/keyseal/internal/mutate"
	"github.com/spf13/cobra"
)

func newCloneCommand() *cobra.Command {
	var force bool
	var commitConfig commitFlags

	cmd := &cobra.Command{
		Use:   "clone <source> <destination>",
		Short: "Copy an encrypted document to a new logical name",
		Long: "Decrypt <source> in memory and re-encrypt it as <destination> using the .sops.yaml creation rule for the destination path.\n" +
			"The document name is set to <destination>. The result is verified before it is written, and plaintext never touches disk.\n" +
			"An existing destination is never overwritten unless --force is set.\n" +
			"Use --commit or -m to commit only the new document. -m implies --commit.",
		Example: "  keyseal clone production/app production/app-next\n" +
			"  keyseal clone production/app production/app-next -m \"Prepare app release candidate\"",
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			m, err := prepareMutation(cmd, commitConfig)
			if err != nil {
				return err
			}
			src, err := m.target(args[0])
			if err != nil {
				return err
			}
			dst, err := m.target(args[1])
			if err != nil {
				return err
			}
			if err := mutate.Clone(m.opts, src, dst, force); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "cloned %s to %s\n", src.Logical, dst.Logical)
			return m.commitIfRequested(cmd, dst.Path, fmt.Sprintf("Clone secret %s to %s", src.Logical, dst.Logical))
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "Replace an existing destination document")
	bindCommitFlags(cmd, &commitConfig)
	return cmd
}
