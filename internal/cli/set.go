package cli

import (
	"bytes"
	"errors"
	"fmt"
	"os"

	"github.com/jrpbuilds/keyseal/internal/mutate"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

func newSetCommand() *cobra.Command {
	var fromStdin bool
	var fd int
	var commitConfig commitFlags

	cmd := &cobra.Command{
		Use:   "set <logical-name> <KEY> (--stdin | --fd N)",
		Short: "Set one value from stdin or a file descriptor",
		Long: "Set or replace one key in an encrypted document without opening an editor.\n" +
			"The value is read from stdin (--stdin) or an inherited file descriptor (--fd N); it is never accepted as an argument.\n" +
			"One trailing newline is removed. When stdin is a terminal, Keyseal prompts without echoing the value.\n" +
			"The document is re-encrypted and verified before it replaces the original; on failure the original is left unchanged.",
		Example: "  printf '%s' \"$STRIPE_SECRET_KEY\" | keyseal set production/app-next STRIPE_SECRET_KEY --stdin\n" +
			"  keyseal set production/app-next STRIPE_SECRET_KEY --stdin\n" +
			"  keyseal set production/app-next STRIPE_SECRET_KEY --fd 3 3< ./stripe-key.txt",
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			fromFD := cmd.Flags().Changed("fd")
			switch {
			case fromStdin && fromFD:
				return errors.New("use either --stdin or --fd, not both")
			case !fromStdin && !fromFD:
				return errors.New("provide the value with --stdin or --fd; values are never accepted as arguments")
			case fromFD && fd < 3:
				return errors.New("--fd must be 3 or higher; use --stdin for standard input")
			}

			logical, key := args[0], args[1]
			m, err := prepareMutation(cmd, commitConfig)
			if err != nil {
				return err
			}
			if err := validateKeyNames([]string{key}, m.opts.Validation); err != nil {
				return err
			}
			value, err := readSecretValue(cmd, key, fromStdin, fd)
			if err != nil {
				return err
			}
			return m.update(cmd, logical, defaultCommitMessageForSecretEdit(logical), func(doc *mutate.Document) ([]mutate.Change, error) {
				return []mutate.Change{{Key: key, Action: doc.Set(key, value)}}, nil
			})
		},
	}
	cmd.Flags().BoolVar(&fromStdin, "stdin", false, "Read the value from standard input")
	cmd.Flags().IntVar(&fd, "fd", 0, "Read the value from this inherited file descriptor (3 or higher)")
	bindCommitFlags(cmd, &commitConfig)
	return cmd
}

// readSecretValue reads one value from stdin or an inherited descriptor. A
// terminal stdin gets a no-echo prompt so the value never appears on screen
// or in shell history.
func readSecretValue(cmd *cobra.Command, key string, fromStdin bool, fd int) (string, error) {
	if !fromStdin {
		file := os.NewFile(uintptr(fd), fmt.Sprintf("fd %d", fd))
		defer file.Close()
		value, err := mutate.ReadSecret(file)
		if err != nil {
			return "", fmt.Errorf("fd %d: %w", fd, err)
		}
		return value, nil
	}

	in := cmd.InOrStdin()
	if file, ok := in.(*os.File); ok && term.IsTerminal(int(file.Fd())) {
		fmt.Fprintf(cmd.ErrOrStderr(), "Value for %s (input hidden): ", key)
		raw, err := term.ReadPassword(int(file.Fd()))
		fmt.Fprintln(cmd.ErrOrStderr())
		if err != nil {
			return "", fmt.Errorf("read hidden input: %w", err)
		}
		return mutate.ReadSecret(bytes.NewReader(raw))
	}
	return mutate.ReadSecret(in)
}
