// Package about holds project identity and developer credits shared by the
// CLI, web portal and report generators.
package about

import "fmt"

const (
	// Product is the short tool name shown in UIs and reports.
	Product = "rdpshot"

	// ProductTitle is the human-facing product label.
	ProductTitle = "RDPShot"

	// Tagline summarizes the product for footers and about pages.
	Tagline = "RDP Security Audit Platform"

	// Developer is the primary author name.
	Developer = "Cuma KURT"

	// Email is the public contact address.
	Email = "cumakurt@gmail.com"

	// GitHubURL is the project repository.
	GitHubURL = "https://github.com/cumakurt/rdpshot"

	// LinkedInURL is the developer's professional profile.
	LinkedInURL = "https://www.linkedin.com/in/cuma-kurt-34414917/"

	// LicenseID is the SPDX license identifier.
	LicenseID = "GPL-3.0"

	// LicenseName is the human-readable license label.
	LicenseName = "GNU General Public License v3.0"

	// CopyrightYear is the copyright year for attributions.
	CopyrightYear = "2026"
)

// CopyrightLine returns the short copyright attribution.
func CopyrightLine() string {
	return fmt.Sprintf("Copyright (C) %s %s", CopyrightYear, Developer)
}

// ContactLine returns "Name <email>".
func ContactLine() string {
	return fmt.Sprintf("%s <%s>", Developer, Email)
}

// VersionBanner formats the multi-line identity block used by `rdpshot version`
// and serve startup banners.
func VersionBanner(version string) string {
	if version == "" {
		version = "dev"
	}
	return fmt.Sprintf(
		"%s %s\nDeveloper: %s\nEmail:     %s\nGitHub:    %s\nLinkedIn:  %s\nLicense:   %s\n%s\n",
		Product, version, Developer, Email, GitHubURL, LinkedInURL, LicenseID, CopyrightLine(),
	)
}

// Info is the structured identity payload exposed to templates and JSON APIs.
type Info struct {
	Product       string `json:"product"`
	ProductTitle  string `json:"product_title"`
	Tagline       string `json:"tagline"`
	Version       string `json:"version"`
	Developer     string `json:"developer"`
	Email         string `json:"email"`
	GitHubURL     string `json:"github_url"`
	LinkedInURL   string `json:"linkedin_url"`
	LicenseID     string `json:"license_id"`
	LicenseName   string `json:"license_name"`
	Copyright     string `json:"copyright"`
	CopyrightYear string `json:"copyright_year"`
}

// Snapshot returns identity fields for the given build version.
func Snapshot(version string) Info {
	if version == "" {
		version = "dev"
	}
	return Info{
		Product:       Product,
		ProductTitle:  ProductTitle,
		Tagline:       Tagline,
		Version:       version,
		Developer:     Developer,
		Email:         Email,
		GitHubURL:     GitHubURL,
		LinkedInURL:   LinkedInURL,
		LicenseID:     LicenseID,
		LicenseName:   LicenseName,
		Copyright:     CopyrightLine(),
		CopyrightYear: CopyrightYear,
	}
}
