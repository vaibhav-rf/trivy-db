package rapidfort

// SourcePackageAdvisory matches the per-package JSON format published in the
// upstream RapidFort security-advisories repo.
// File path: security-advisories/OS/{osName}/{package_name}.json
//
// Splitting per distro version happens in-memory inside parse() at DB-build
// time (the file bundles all versions of a package in a single JSON blob), so
// this format is what the parser consumes directly. Formerly there was a
// vuln-list-update fetcher that pre-split these into per-version files; that
// intermediate step was removed because the upstream is already parseable JSON
// in a git repo (same pattern as ghsa, bundler, node, bitnami, etc.).
type SourcePackageAdvisory struct {
	PackageName string                         `json:"package_name"`
	Advisory    map[string]map[string]CVEEntry `json:"advisory"` // distroVersion -> cveID -> CVEEntry
}

// CVEEntry holds the advisory details for a single CVE within a distro release.
type CVEEntry struct {
	CVEID       string  `json:"cve_id"`
	Title       string  `json:"title"`
	Description string  `json:"description"`
	Severity    string  `json:"severity"` // "LOW", "MEDIUM", "HIGH", "CRITICAL"
	Status      string  `json:"status"`   // "fixed" or "open"
	Events      []Event `json:"events"`
}

// Event represents a single version range — an introduced version and an optional fixed version.
// If Fixed is empty the vulnerability is still open for that introduced range.
type Event struct {
	Introduced string `json:"introduced,omitempty"`
	Fixed      string `json:"fixed,omitempty"`
	Identifier string `json:"identifier,omitempty"` // e.g. "el9", "fc39"; absent for ubuntu/alpine
}

// RapidFortCustom carries per-event metadata via types.Advisory.Custom.
// Identifiers is parallel to Advisory.VulnerableVersions — Identifiers[i]
// is the distro identifier (e.g. "el9") for VulnerableVersions[i].
// Only set when at least one event has a non-empty Identifier.
type RapidFortCustom struct {
	Identifiers []string `json:"identifiers,omitempty"`
}
