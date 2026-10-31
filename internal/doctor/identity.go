package doctor

import (
	"fmt"
	"io"
	"os"
	"strings"

	"filippo.io/age"
	"github.com/jrpbuilds/keyseal/internal/config"
)

const (
	ageKeyEnvVar       = "SOPS_AGE_KEY_FILE"
	ageKeyInlineEnvVar = "SOPS_AGE_KEY"
	ageKeyUnavailable  = "age key material is missing or unreadable"
)

// identityAvailability is the --identity-profile pre-check outcome.
// When available is false, doctor skips per-file decrypt for included documents.
type identityAvailability struct {
	available bool
	check     CheckResult
}

// checkIdentityAvailability loads local age identities using the same
// precedence as decrypt, then optionally matches them against the profile's
// public recipients. Parse and open errors never enter check details.
func checkIdentityAvailability(cwd string, cfg config.Config, profileName string) identityAvailability {
	profile := cfg.AccessProfiles[profileName]
	checkName := fmt.Sprintf("identity %s", profileName)

	publics, ok := loadLocalPublicRecipients(cwd, cfg)
	if !ok {
		return identityAvailability{
			available: false,
			check: CheckResult{
				Name:     checkName,
				Status:   StatusUnavailable,
				Severity: SeverityError,
				Summary:  "Age identity material is unavailable for this access profile",
				Details: []string{
					ageKeyUnavailable,
					"Included documents were not decrypted because the local identity could not be loaded.",
				},
				Remediation: []string{
					"Provide the age private key for this role via SOPS_AGE_KEY, SOPS_AGE_KEY_FILE, or sops.age_key_file, then rerun.",
				},
			},
		}
	}

	if len(profile.Recipients) == 0 {
		return identityAvailability{
			available: true,
			check: CheckResult{
				Name:     checkName,
				Status:   StatusOK,
				Severity: SeverityInformational,
				Summary:  "Age identity material is available for this access profile",
				Details: []string{
					"No recipients were configured on the access profile, so availability was based on loading local age identity material.",
				},
			},
		}
	}

	wanted := make(map[string]struct{}, len(profile.Recipients))
	for _, recipient := range profile.Recipients {
		wanted[recipient] = struct{}{}
	}
	for _, public := range publics {
		if _, match := wanted[public]; match {
			return identityAvailability{
				available: true,
				check: CheckResult{
					Name:     checkName,
					Status:   StatusOK,
					Severity: SeverityInformational,
					Summary:  "Local age identity matches a configured access-profile recipient",
				},
			}
		}
	}

	return identityAvailability{
		available: false,
		check: CheckResult{
			Name:     checkName,
			Status:   StatusUnavailable,
			Severity: SeverityError,
			Summary:  "Local age identity does not match this access profile",
			Details: []string{
				"No loaded age identity matched the public recipients listed on the access profile.",
				"Included documents were not decrypted.",
			},
			Remediation: []string{
				"Use the age key for this role, update access_profiles recipients, or omit recipients to skip this pre-check.",
			},
		},
	}
}

// loadLocalPublicRecipients resolves age identity material with decrypt
// precedence and returns only public recipient strings.
//
// Precedence matches sopsutil decrypt helpers:
//  1. non-empty SOPS_AGE_KEY (inline identity text, not a path)
//  2. non-empty SOPS_AGE_KEY_FILE
//  3. resolved sops.age_key_file
//
// Failure returns ok=false. The age library can quote private key lines in
// errors, so callers must never surface those errors.
func loadLocalPublicRecipients(cwd string, cfg config.Config) (publics []string, ok bool) {
	src, closer, err := openAgeIdentitySource(cwd, cfg)
	if err != nil {
		return nil, false
	}
	if closer != nil {
		defer closer.Close()
	}

	ids, err := age.ParseIdentities(src)
	if err != nil {
		return nil, false
	}
	publics, err = publicRecipientsFromIdentities(ids)
	if err != nil {
		return nil, false
	}
	return publics, true
}

func openAgeIdentitySource(cwd string, cfg config.Config) (io.Reader, io.Closer, error) {
	if inline := strings.TrimSpace(os.Getenv(ageKeyInlineEnvVar)); inline != "" {
		return strings.NewReader(inline), nil, nil
	}

	keyPath := strings.TrimSpace(os.Getenv(ageKeyEnvVar))
	if keyPath == "" {
		keyPath = config.ResolvePath(cwd, cfg.SOPS.AgeKeyFile)
	}
	if strings.TrimSpace(keyPath) == "" {
		return nil, nil, fmt.Errorf("age key path is empty")
	}

	f, err := os.Open(keyPath)
	if err != nil {
		return nil, nil, err
	}
	return f, f, nil
}

// publicRecipientsFromIdentities returns public recipient encodings.
// Identity.String() returns the private key and must never be called here.
func publicRecipientsFromIdentities(ids []age.Identity) ([]string, error) {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		switch v := id.(type) {
		case *age.X25519Identity:
			out = append(out, v.Recipient().String())
		case *age.HybridIdentity:
			out = append(out, v.Recipient().String())
		default:
			return nil, fmt.Errorf("unsupported identity type")
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no identities found")
	}
	return out, nil
}
