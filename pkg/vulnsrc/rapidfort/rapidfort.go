package rapidfort

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/samber/oops"
	bolt "go.etcd.io/bbolt"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/ecosystem"
	"github.com/aquasecurity/trivy-db/pkg/log"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/utils"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/bucket"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

const rapidfortDir = "rapidfort-security-advisories"

// osSubDir is the top-level directory inside the RapidFort security-advisories
// repo that groups advisory JSON files by operating system.
const osSubDir = "OS"

var source = types.DataSource{
	ID:   vulnerability.RapidFort,
	Name: "RapidFort Security Advisories",
	URL:  "https://github.com/rapidfort/security-advisories",
}

type config struct {
	dbc    db.Operation
	logger *log.Logger
}

// VulnSrc implements the vulnsrc.VulnSrc interface and is used to build the DB.
type VulnSrc struct {
	config
}

func NewVulnSrc() VulnSrc {
	return VulnSrc{
		config: config{
			dbc:    db.Config{},
			logger: log.WithPrefix("rapidfort"),
		},
	}
}

func (vs VulnSrc) Name() types.SourceID {
	return source.ID
}

// Update reads all per-package JSON files from
// {dir}/security-advisories/OS/{os}/{pkg}.json (the raw upstream RapidFort
// advisory repo, fetched into the build cache by the Makefile) and writes
// them into the BoltDB. Splitting each source file by distro version happens
// in-memory inside parse(), not on disk.
func (vs VulnSrc) Update(dir string) error {
	rootDir := filepath.Join(dir, rapidfortDir, osSubDir)
	eb := oops.In("rapidfort").With("root_dir", rootDir)

	entries, err := vs.parse(rootDir)
	if err != nil {
		return eb.Wrap(err)
	}
	if err = vs.put(entries); err != nil {
		return eb.Wrap(err)
	}
	return nil
}

type entry struct {
	bucket   bucket.DataSourceBucket
	pkgName  string
	cveID    string
	advisory types.Advisory
	detail   types.VulnerabilityDetail
}

func (vs VulnSrc) parse(rootDir string) ([]entry, error) {
	eb := oops.In("rapidfort").With("root_dir", rootDir)
	var entries []entry

	err := utils.FileWalk(rootDir, func(r io.Reader, path string) error {
		if !strings.HasSuffix(path, ".json") {
			return nil
		}

		// Relative path: {osName}/{pkg}.json; the distro version lives inside the JSON.
		relPath, err := filepath.Rel(rootDir, path)
		if err != nil {
			return eb.With("path", path).Wrapf(err, "failed to make relative path")
		}
		parts := strings.SplitN(filepath.ToSlash(relPath), "/", 2)
		if len(parts) < 2 {
			vs.logger.Warn("Skipping file with unexpected path structure", "path", path)
			return nil
		}
		osName := ecosystem.Type(parts[0])

		var src SourcePackageAdvisory
		if err := json.NewDecoder(r).Decode(&src); err != nil {
			return eb.With("path", path).Wrapf(err, "json decode error")
		}

		// alpine feeds already hold one distribution per file. The RedHat feed
		// mixes RHEL/Fedora/rf ranges and the Ubuntu feed mixes ubuntu/rf ranges,
		// so split each into one advisory set per distribution first; all shapes
		// then convert the same way.
		sources := map[ecosystem.Type]SourcePackageAdvisory{
			osName: src,
		}
		switch osName {
		case ecosystem.RedHat:
			sources = vs.split(src, path, redhatRangeTarget)
		case ecosystem.Ubuntu:
			sources = vs.split(src, path, ubuntuRangeTarget)
		}
		for eco, s := range sources {
			entries = append(entries, toEntries(eco, s)...)
		}
		return nil
	})
	if err != nil {
		return nil, oops.Wrapf(err, "walk error")
	}
	return entries, nil
}

// toEntries converts one distribution's advisories (version -> cveID -> CVEEntry)
// into DB entries. An unsupported base OS (e.g. debian) is skipped silently:
// RapidFort owns which OSes its feed ships, so an OS this build doesn't ingest
// is expected, not something to warn about on every file.
func toEntries(osName ecosystem.Type, src SourcePackageAdvisory) []entry {
	var entries []entry
	for version, cveMap := range src.Advisory {
		b, err := newBucket(osName, version)
		if err != nil {
			// newBucket only rejects the base ecosystem (constant for this file),
			// not the version, so a failure means the whole file is unsupported.
			return nil
		}
		for cveID, cve := range cveMap {
			entries = append(entries, entry{
				bucket:   b,
				pkgName:  src.PackageName,
				cveID:    cveID,
				advisory: buildAdvisory(cve.Severity, cve.Events),
				detail:   buildVulnerabilityDetail(cve),
			})
		}
	}
	return entries
}

// rangeTargetFunc maps an event's identifier plus the file's top-level version
// key to the (ecosystem, version) of the bucket the event belongs in. Returning
// false skips the event with a warning.
type rangeTargetFunc func(identifier, fileVersion string) (ecosystem.Type, string, bool)

// split re-keys a mixed feed file into one advisory set per distribution it
// targets. rangeTarget owns the per-OS routing rules (elN/fcNN/rf for RedHat;
// ubuntu/rf for Ubuntu). Dropping the source file's top-level version key
// collapses ranges the feed replicates identically across those keys — the
// scanner picks buckets by rangeTarget's output, not by the file's key.
func (vs VulnSrc) split(src SourcePackageAdvisory, path string, rangeTarget rangeTargetFunc) map[ecosystem.Type]SourcePackageAdvisory {
	out := map[ecosystem.Type]SourcePackageAdvisory{}
	// Walk versions in stable order so the collected event order and the CVE
	// meta chosen "on first sight" below don't depend on Go's random map
	// iteration — the resulting Advisory is written to disk verbatim.
	versions := make([]string, 0, len(src.Advisory))
	for v := range src.Advisory {
		versions = append(versions, v)
	}
	sort.Strings(versions)

	for _, fileVer := range versions {
		for cveID, cve := range src.Advisory[fileVer] {
			for _, ev := range cve.Events {
				if ev.Introduced == "" && ev.Fixed == "" {
					continue
				}
				eco, targetVer, ok := rangeTarget(ev.Identifier, fileVer)
				if !ok {
					vs.logger.Warn("Skipping range with an unusable distribution identifier",
						"path", path, "cve", cveID, "identifier", ev.Identifier)
					continue
				}
				spa, ok := out[eco]
				if !ok {
					spa = SourcePackageAdvisory{
						PackageName: src.PackageName, Advisory: map[string]map[string]CVEEntry{},
					}
					out[eco] = spa
				}
				if spa.Advisory[targetVer] == nil {
					spa.Advisory[targetVer] = map[string]CVEEntry{}
				}
				// Copy the CVE meta on first sight, then collect its events.
				e, ok := spa.Advisory[targetVer][cveID]
				if !ok {
					e = cve
					e.Events = nil
				}
				// Skip identical copies the feed repeats across file-version keys.
				if !slices.Contains(e.Events, ev) {
					e.Events = append(e.Events, ev)
				}
				spa.Advisory[targetVer][cveID] = e
			}
		}
	}
	return out
}

// ubuntuRangeTarget maps an Ubuntu event's identifier to its bucket.
// "rf" → the family-level "rapidfort ubuntu" bucket (empty version) — kept
// separate from the RPM-format "rapidfort Red Hat" bucket so the dpkg
// comparator never sees an RPM range and vice versa.
// "ubuntu" / empty identifier → the versioned "rapidfort ubuntu <ver>" bucket
// (empty is accepted for backward compatibility with pre-annotation files).
func ubuntuRangeTarget(identifier, ubuntuVer string) (eco ecosystem.Type, version string, ok bool) {
	switch identifier {
	case "rf":
		return ecosystem.Ubuntu, "", true
	case "ubuntu", "":
		return ecosystem.Ubuntu, ubuntuVer, true
	}
	return "", "", false
}

// redhatRangeTarget maps a RedHat event's identifier to its bucket.
// "rf" → the family-level "rapidfort Red Hat" bucket (empty version), keeping
// RPM-format rf ranges out of the dpkg-format "rapidfort ubuntu" bucket.
// "elN" → "rapidfort Red Hat N"; "fcNN" → "rapidfort fedora NN".
// The file's top-level version key is ignored (RedHat feeds re-list the same
// fcNN/rf ranges under every RHEL major, and dedup collapses them at write time).
func redhatRangeTarget(identifier, _ string) (eco ecosystem.Type, version string, ok bool) {
	switch {
	case identifier == "rf":
		return ecosystem.RedHat, "", true
	case strings.HasPrefix(identifier, "el"):
		version = strings.TrimPrefix(identifier, "el")
		return ecosystem.RedHat, version, isVersionNumber(version)
	case strings.HasPrefix(identifier, "fc"):
		version = strings.TrimPrefix(identifier, "fc")
		return ecosystem.Fedora, version, isVersionNumber(version)
	}
	return "", "", false
}

// isVersionNumber reports whether s looks like a distro version number:
// dot-separated groups of digits, e.g. "9", "44" or "3.18". Empty, leading,
// trailing or doubled dots (e.g. "", ".", "1.", "1..2") are rejected so a
// malformed identifier can't produce a bogus bucket like "rapidfort Red Hat .".
func isVersionNumber(s string) bool {
	if s == "" {
		return false
	}
	for _, part := range strings.Split(s, ".") {
		if part == "" {
			return false
		}
		for _, r := range part {
			if r < '0' || r > '9' {
				return false
			}
		}
	}
	return true
}

func (vs VulnSrc) put(entries []entry) error {
	// Fail loudly on an empty parse — a silent no-op here would ship an empty
	// RapidFort integration if the cache is misconfigured or the feed breaks,
	// and nobody scans per-source build logs to catch it.
	if len(entries) == 0 {
		return oops.Errorf("no RapidFort advisories to save — check that the security-advisories cache is populated")
	}
	vs.logger.Info("Saving RapidFort advisories", "count", len(entries))

	return vs.dbc.BatchUpdate(func(tx *bolt.Tx) error {
		// Register the data source once per platform.
		addedDataSources := map[string]struct{}{}
		for _, e := range entries {
			// Name() concatenates the platform string, so compute it once and reuse.
			platform := e.bucket.Name()
			eb := oops.With("platform", platform).With("package", e.pkgName).With("cve", e.cveID)

			if _, ok := addedDataSources[platform]; !ok {
				if err := vs.dbc.PutDataSource(tx, platform, e.bucket.DataSource()); err != nil {
					return eb.Wrapf(err, "failed to put data source")
				}
				addedDataSources[platform] = struct{}{}
			}

			if err := vs.dbc.PutAdvisoryDetail(tx, e.cveID, e.pkgName, []string{platform}, e.advisory); err != nil {
				return eb.Wrapf(err, "failed to save advisory")
			}
			if err := vs.dbc.PutVulnerabilityDetail(tx, e.cveID, source.ID, e.detail); err != nil {
				return eb.Wrapf(err, "failed to save vulnerability detail")
			}
			if err := vs.dbc.PutVulnerabilityID(tx, e.cveID); err != nil {
				return eb.Wrapf(err, "failed to save vulnerability ID")
			}
		}
		return nil
	})
}

// buildAdvisory converts version-range events into the trivy-db Advisory format.
// Each event represents a version range: Introduced..Fixed (or open-ended if
// Fixed is empty). Buckets are homogeneous per distribution, so no per-range
// distribution metadata is stored alongside the ranges.
func buildAdvisory(severity string, events []Event) types.Advisory {
	var patched, vulnerable []string
	for _, ev := range events {
		switch {
		case ev.Fixed != "":
			patched = append(patched, ev.Fixed)
			if ev.Introduced != "" {
				// Comma-separated: each part is parsed individually by newConstraint which handles spaces.
				vulnerable = append(vulnerable, fmt.Sprintf(">= %s, < %s", ev.Introduced, ev.Fixed))
			} else {
				// Single constraint: write without space so the existing space-based splitter
				// doesn't break it into ["<", "version"].
				vulnerable = append(vulnerable, fmt.Sprintf("<%s", ev.Fixed))
			}
		case ev.Introduced != "":
			// Open vulnerability (no fix): write without space for the same reason.
			vulnerable = append(vulnerable, fmt.Sprintf(">=%s", ev.Introduced))
		}
	}

	sev := types.SeverityUnknown
	if s, err := types.NewSeverity(strings.ToUpper(severity)); err == nil {
		sev = s
	}

	// Sort for a stable on-disk DB: events for the same distribution can be
	// collected from several RHEL majors (see splitRedHat), so their source
	// order is not guaranteed. The lists are independent (no per-range
	// identifiers), so sorting each on its own is safe.
	sort.Strings(patched)
	sort.Strings(vulnerable)

	return types.Advisory{
		PatchedVersions:    patched,
		VulnerableVersions: vulnerable,
		Severity:           sev,
	}
}

// buildVulnerabilityDetail carries only prose (title, description). Severity
// stays in Advisory (per-package), not here, so FillInfo can't override
// RapidFort's curated severity with the base-OS VendorSeverity.
func buildVulnerabilityDetail(cve CVEEntry) types.VulnerabilityDetail {
	return types.VulnerabilityDetail{
		Title:       cve.Title,
		Description: cve.Description,
	}
}

// VulnSrcGetter is used by trivy (the scanner) to query advisories from the DB
// for a specific base ecosystem (e.g. ecosystem.Ubuntu, ecosystem.Alpine).
type VulnSrcGetter struct {
	baseEcosystem ecosystem.Type
	config
}

func NewVulnSrcGetter(baseEcosystem ecosystem.Type) VulnSrcGetter {
	return VulnSrcGetter{
		baseEcosystem: baseEcosystem,
		config: config{
			dbc:    db.Config{},
			logger: log.WithPrefix("rapidfort-" + string(baseEcosystem)),
		},
	}
}

// Get returns RapidFort advisories for a given package and OS version (e.g. "22.04").
func (vs VulnSrcGetter) Get(params db.GetParams) ([]types.Advisory, error) {
	eb := oops.In("rapidfort").With("base_ecosystem", vs.baseEcosystem).With("os_version", params.Release).With("package_name", params.PkgName)

	b, err := newBucket(vs.baseEcosystem, params.Release)
	if err != nil {
		return nil, eb.Wrapf(err, "failed to create a bucket name")
	}
	advs, err := vs.dbc.GetAdvisories(b.Name(), params.PkgName)
	if err != nil {
		return nil, eb.Wrapf(err, "failed to get advisories")
	}
	return advs, nil
}
