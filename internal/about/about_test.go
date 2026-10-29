package about

import (
	"strings"
	"testing"
)

func TestSnapshotDefaultsVersion(t *testing.T) {
	info := Snapshot("")
	if info.Version != "dev" {
		t.Fatalf("version = %q, want dev", info.Version)
	}
	if info.Developer != Developer {
		t.Fatalf("developer = %q, want %q", info.Developer, Developer)
	}
	if !strings.Contains(info.Copyright, Developer) {
		t.Fatalf("copyright missing developer: %q", info.Copyright)
	}
}

func TestVersionBannerContainsCredits(t *testing.T) {
	banner := VersionBanner("1.2.3")
	for _, want := range []string{
		"rdpshot 1.2.3",
		Developer,
		Email,
		GitHubURL,
		LinkedInURL,
		LicenseID,
		CopyrightLine(),
	} {
		if !strings.Contains(banner, want) {
			t.Fatalf("banner missing %q:\n%s", want, banner)
		}
	}
}
