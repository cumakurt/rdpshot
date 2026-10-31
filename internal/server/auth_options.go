package server

import (
	"errors"
	"strings"

	"rdpshot/internal/model"
	"rdpshot/internal/ntlm"
)

// applyAuthOptions reads auth_mode / credential fields via get and validates
// them against opts.EnableAuth. Modes single and pth force EnableAuth on and
// require the matching secret fields.
func applyAuthOptions(opts *model.ScanOptions, get func(string) string) error {
	mode := strings.ToLower(strings.TrimSpace(get("auth_mode")))
	ccache := strings.TrimSpace(get("auth_ccache"))
	if mode == "" && ccache != "" {
		mode = model.AuthModeKerberos
	}
	switch mode {
	case "":
		mode = model.AuthModeWordlist
	case model.AuthModeWordlist, model.AuthModeSingle, model.AuthModePTH, model.AuthModeKerberos:
	default:
		return errors.New("auth_mode must be wordlist, single, pth, or kerberos")
	}

	opts.AuthMode = mode
	opts.AuthUsername = strings.TrimSpace(get("auth_username"))
	opts.AuthDomain = strings.TrimSpace(get("auth_domain"))
	opts.AuthPassword = strings.TrimSpace(get("auth_password"))
	opts.AuthNTHash = strings.TrimSpace(get("auth_nthash"))
	opts.AuthCCache = ccache

	if mode == model.AuthModeSingle || mode == model.AuthModePTH || mode == model.AuthModeKerberos {
		opts.EnableAuth = true
		// Screenshots stay under EnableScreens; single/pth/kerberos do not force them.
	}
	if !opts.EnableAuth {
		return nil
	}

	switch mode {
	case model.AuthModeSingle:
		if opts.AuthUsername == "" {
			return errors.New("auth_username is required for single-credential mode")
		}
		if opts.AuthPassword == "" {
			return errors.New("auth_password is required for single-credential mode")
		}
		opts.AuthNTHash = ""
		opts.AuthCCache = ""
	case model.AuthModePTH:
		if opts.AuthUsername == "" {
			return errors.New("auth_username is required for pass-the-hash mode")
		}
		if opts.AuthNTHash == "" {
			return errors.New("auth_nthash is required for pass-the-hash mode")
		}
		raw, err := ntlm.ParseNTHash(opts.AuthNTHash)
		if err != nil {
			return err
		}
		opts.AuthNTHash = ntlm.FormatNTHash(raw)
		opts.AuthPassword = ""
		opts.AuthCCache = ""
	case model.AuthModeKerberos:
		if opts.AuthCCache == "" {
			return errors.New("auth_ccache is required for kerberos pass-the-ticket mode")
		}
		opts.AuthPassword = ""
		opts.AuthNTHash = ""
	}
	return nil
}

// redactScan clears password/hash fields before returning a scan over the API.
func redactScan(scan model.Scan) model.Scan {
	scan.Options = scan.Options.RedactAuthSecrets()
	return scan
}

// redactScans redacts every scan in a list.
func redactScans(scans []model.Scan) []model.Scan {
	out := make([]model.Scan, len(scans))
	for i, scan := range scans {
		out[i] = redactScan(scan)
	}
	return out
}

// redactSchedule clears password/hash fields on a schedule's options.
func redactSchedule(sch model.Schedule) model.Schedule {
	sch.Options = sch.Options.RedactAuthSecrets()
	return sch
}

// redactSchedules redacts every schedule in a list.
func redactSchedules(items []model.Schedule) []model.Schedule {
	out := make([]model.Schedule, len(items))
	for i, sch := range items {
		out[i] = redactSchedule(sch)
	}
	return out
}
