package cli

import (
	"fmt"

	"github.com/jrpbuilds/keyseal/internal/buildinfo"
	"github.com/jrpbuilds/keyseal/internal/versionreq"
	"github.com/spf13/cobra"
)

func newVersionCommand() *cobra.Command {
	var short bool
	var check string

	cmd := &cobra.Command{
		Use:   "version",
		Short: "Show build version information",
		Long: "Show stamped Keyseal build metadata, or check a version constraint without loading keyseal.yaml.\n" +
			"`keyseal version --check \">=1.1.0\"` is intended for CI, Ansible, and deployment-controller bootstrap.",
		Example: "  keyseal version\n  keyseal version --short\n  keyseal version --check \">=1.1.0\"",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if check != "" && short {
				return fmt.Errorf("flags --check and --short cannot be used together")
			}
			if check != "" {
				running := buildinfo.DisplayVersion()
				if err := versionreq.Check(running, check); err != nil {
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(), "ok: %s satisfies %s\n", running, check)
				return nil
			}
			if short {
				fmt.Fprintln(cmd.OutOrStdout(), buildinfo.Short())
				return nil
			}
			fmt.Fprintln(cmd.OutOrStdout(), buildinfo.Full())
			return nil
		},
	}

	cmd.Flags().BoolVar(&short, "short", false, "Print only the version string")
	cmd.Flags().StringVar(&check, "check", "", "Check that the running binary satisfies a version constraint")
	return cmd
}
