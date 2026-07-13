package rapidfort

// SourcePackageAdvisory is one per-package file from the RapidFort repo
// (OS/{osName}/{package_name}.json). One file bundles every distro version
// for a package; parse() fans it out per-version in-memory at DB-build time.
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

// Event is a version range: [Introduced, Fixed). An empty Fixed means the
// vulnerability is still open from Introduced onward.
type Event struct {
	Introduced string `json:"introduced,omitempty"`
	Fixed      string `json:"fixed,omitempty"`
	Identifier string `json:"identifier,omitempty"` // e.g. "el9", "fc39"; absent for ubuntu/alpine
}

// RapidFortCustom rides on types.Advisory.Custom to carry per-event metadata.
// Identifiers is index-parallel to types.Advisory.VulnerableVersions: for
// range i, Identifiers[i] is the distro tag (e.g. "el9") for VulnerableVersions[i].
type RapidFortCustom struct {
	Identifiers []string `json:"identifiers,omitempty"`
}
