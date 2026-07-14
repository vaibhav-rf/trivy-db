package rapidfort

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/samber/lo"
	"github.com/samber/oops"
	bolt "go.etcd.io/bbolt"

	"github.com/aquasecurity/trivy-db/pkg/db"
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

		// Relative path: {osName}/{pkg}.json (rooted at security-advisories/OS/).
		// The distro version is NOT in the path — it's carried inside the JSON
		// (one source file bundles all versions for a given package), so we
		// split by version in-memory below.
		relPath, err := filepath.Rel(rootDir, path)
		if err != nil {
			return eb.With("path", path).Wrapf(err, "failed to make relative path")
		}
		parts := strings.SplitN(filepath.ToSlash(relPath), "/", 2)
		if len(parts) < 2 {
			vs.logger.Warn("Skipping file with unexpected path structure", "path", path)
			return nil
		}
		osName := parts[0]

		var src SourcePackageAdvisory
		if err := json.NewDecoder(r).Decode(&src); err != nil {
			return eb.With("path", path).Wrapf(err, "json decode error")
		}

		// The source file's shape is {version: {cveID: CVEEntry}}. We fan it
		// out here into per-(platform, cveID) entries so downstream put() can
		// write one advisory-detail per (version, package, cveID) tuple.
		for version, cveMap := range src.Advisory {
			// Real distro versions start with a digit ("9", "20.04", "3.18").
			// Skip identifier-like keys (e.g. "el4") that occasionally leak
			// into the upstream feed — otherwise they'd become bogus buckets
			// like "rapidfort Red Hat el4" that no scanner would ever match.
			if version == "" || version[0] < '0' || version[0] > '9' {
				vs.logger.Warn("Skipping advisory with invalid version key", "path", path, "version", version)
				continue
			}
			// newBucket doubles as the supported-OS gate: unsupported base
			// OSes (e.g. debian) fall through to its default case and skip.
			b, err := newBucket(osName, version)
			if err != nil {
				vs.logger.Warn("Skipping advisory for unsupported base OS", "path", path, "base_os", osName)
				return nil
			}
			for cveID, cveEntry := range cveMap {
				entries = append(entries, entry{
					bucket:   b,
					pkgName:  src.PackageName,
					cveID:    cveID,
					advisory: buildAdvisory(cveEntry),
					detail:   buildVulnerabilityDetail(cveEntry),
				})
			}
		}
		return nil
	})
	if err != nil {
		return nil, oops.Wrapf(err, "walk error")
	}
	return entries, nil
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
			// Cache the platform name: e.bucket.Name() composes it from base OS +
			// version at call time (string concat), and we reuse it four times below.
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

// buildAdvisory converts a CVEEntry's Events into the trivy-db Advisory format.
// Each event represents a version range: Introduced..Fixed (or open-ended if Fixed is empty).
func buildAdvisory(cve CVEEntry) types.Advisory {
	var patched, vulnerable, identifiers []string
	for _, ev := range cve.Events {
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
		default:
			continue
		}
		// Append even when ev.Identifier is empty so identifiers[i] stays
		// index-parallel with vulnerable[i] — the scanner pairs them by
		// index (see parseCustomIdentifiers in trivy/pkg/detector/ospkg/rapidfort).
		// The EveryBy check below drops Custom entirely when every identifier
		// is empty (ubuntu/alpine), so those empties never reach the DB.
		identifiers = append(identifiers, ev.Identifier)
	}

	severity := types.SeverityUnknown
	if sev, err := types.NewSeverity(strings.ToUpper(cve.Severity)); err == nil {
		severity = sev
	}

	adv := types.Advisory{
		PatchedVersions:    patched,
		VulnerableVersions: vulnerable,
		Severity:           severity,
	}

	// Only set Custom when at least one event carries an identifier (e.g. redhat).
	// Ubuntu/alpine events have no identifiers, so Custom stays nil for them.
	// EveryBy returns true (vacuously) on an empty slice, so no-events → no Custom.
	if !lo.EveryBy(identifiers, func(s string) bool { return s == "" }) {
		adv.Custom = RapidFortCustom{
			Identifiers: identifiers,
		}
	}

	return adv
}

// buildVulnerabilityDetail carries only title and description. Severity is
// deliberately omitted: RapidFort is a curated derivative (like root.io), so
// per-package severity lives in Advisory. Setting it here too would let
// FillInfo override the curated value with the base-OS severity via
// VendorSeverity[BaseID] when the same CVE exists in the base feed.
func buildVulnerabilityDetail(cve CVEEntry) types.VulnerabilityDetail {
	return types.VulnerabilityDetail{
		Title:       cve.Title,
		Description: cve.Description,
	}
}

// VulnSrcGetter is used by trivy (the scanner) to query advisories from the DB
// for a specific base OS (e.g. "ubuntu" or "alpine").
type VulnSrcGetter struct {
	baseOS string
	config
}

func NewVulnSrcGetter(baseOS string) VulnSrcGetter {
	return VulnSrcGetter{
		baseOS: baseOS,
		config: config{
			dbc:    db.Config{},
			logger: log.WithPrefix("rapidfort-" + baseOS),
		},
	}
}

// Get returns RapidFort advisories for a given package and OS version (e.g. "22.04").
func (vs VulnSrcGetter) Get(params db.GetParams) ([]types.Advisory, error) {
	eb := oops.In("rapidfort").With("base_os", vs.baseOS).With("os_version", params.Release).With("package_name", params.PkgName)

	b, err := newBucket(vs.baseOS, params.Release)
	if err != nil {
		return nil, eb.Wrapf(err, "failed to create a bucket name")
	}
	advs, err := vs.dbc.GetAdvisories(b.Name(), params.PkgName)
	if err != nil {
		return nil, eb.Wrapf(err, "failed to get advisories")
	}
	return advs, nil
}
