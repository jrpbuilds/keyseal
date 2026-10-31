package cli

import (
	"github.com/jrpbuilds/keyseal/internal/doctor"
	"github.com/spf13/cobra"
)

// scopeFlags holds the mutually exclusive document selectors shared by
// doctor and verify. Exactly one family may be set: --scope (repeatable),
// --profile, or --identity-profile.
type scopeFlags struct {
	scopes          []string
	profile         string
	identityProfile string
}

func bindScopeFlags(cmd *cobra.Command, flags *scopeFlags) {
	cmd.Flags().StringArrayVar(
		&flags.scopes,
		"scope",
		nil,
		"Limit checks to logical-name globs (repeatable; exclusive with --profile and --identity-profile)",
	)
	cmd.Flags().StringVar(
		&flags.profile,
		"profile",
		"",
		"Limit checks to an access_profiles entry (exclusive with --scope and --identity-profile)",
	)
	cmd.Flags().StringVar(
		&flags.identityProfile,
		"identity-profile",
		"",
		"Limit checks to an access_profiles entry and require a matching local age identity (exclusive with --scope and --profile)",
	)
}

func (f scopeFlags) options() doctor.Options {
	return doctor.Options{
		ScopePatterns:   append([]string(nil), f.scopes...),
		Profile:         f.profile,
		IdentityProfile: f.identityProfile,
	}
}
