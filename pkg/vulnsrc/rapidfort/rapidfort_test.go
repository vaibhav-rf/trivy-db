package rapidfort_test

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/rapidfort"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrctest"
)

func TestVulnSrc_Update(t *testing.T) {
	tests := []struct {
		name       string
		dir        string
		wantValues []vulnsrctest.WantValues
		noBuckets  [][]string
		wantErr    string
	}{
		{
			name: "happy path",
			dir:  filepath.Join("testdata", "happy"),
			wantValues: []vulnsrctest.WantValues{
				{
					Key: []string{
						"data-source",
						"rapidfort ubuntu 20.04",
					},
					Value: types.DataSource{
						ID:     vulnerability.RapidFort,
						Name:   "RapidFort Security Advisories",
						URL:    "https://github.com/rapidfort/security-advisories",
						BaseID: "ubuntu",
					},
				},
				{
					Key: []string{
						"advisory-detail",
						"CVE-2020-8169",
						"rapidfort ubuntu 20.04",
						"curl",
					},
					Value: types.Advisory{
						PatchedVersions:    []string{"7.68.0-1ubuntu2.1"},
						VulnerableVersions: []string{">= 7.68.0, < 7.68.0-1ubuntu2.1"},
						Severity:           types.SeverityHigh,
					},
				},
				{
					// Open vulnerability: no patched version
					Key: []string{
						"advisory-detail",
						"CVE-2021-22876",
						"rapidfort ubuntu 20.04",
						"curl",
					},
					Value: types.Advisory{
						VulnerableVersions: []string{">=7.68.0"},
						Severity:           types.SeverityMedium,
					},
				},
				// vulnerability-detail entries are written by PutVulnerabilityDetail
				// (see buildVulnerabilityDetail). They carry only the title and
				// description; severity intentionally lives in Advisory instead
				// (RapidFort is a curated derivative — see comment on
				// buildVulnerabilityDetail for the rationale).
				{
					Key: []string{
						"vulnerability-detail",
						"CVE-2020-8169",
						"rapidfort",
					},
					Value: types.VulnerabilityDetail{
						Title:       "curl: partial password leak over DNS on HTTP redirect",
						Description: "curl 7.62.0 through 7.70.0 is vulnerable to an information disclosure vulnerability.",
					},
				},
				{
					Key: []string{
						"vulnerability-detail",
						"CVE-2021-22876",
						"rapidfort",
					},
					Value: types.VulnerabilityDetail{
						Title:       "curl: Automatic referer leaks credentials",
						Description: "curl does not strip off user credentials from the URL when automatically populating the Referer: HTTP request header field.",
					},
				},
				{
					Key: []string{
						"vulnerability-id",
						"CVE-2020-8169",
					},
					Value: map[string]any{},
				},
				{
					Key: []string{
						"data-source",
						"rapidfort alpine 3.18",
					},
					Value: types.DataSource{
						ID:     vulnerability.RapidFort,
						Name:   "RapidFort Security Advisories",
						URL:    "https://github.com/rapidfort/security-advisories",
						BaseID: "alpine",
					},
				},
				{
					Key: []string{
						"advisory-detail",
						"CVE-2023-5678",
						"rapidfort alpine 3.18",
						"libssl3",
					},
					Value: types.Advisory{
						PatchedVersions:    []string{"3.1.4-r1"},
						VulnerableVersions: []string{">= 3.0.0, < 3.1.4-r1"},
						Severity:           types.SeverityMedium,
					},
				},
				{
					Key: []string{
						"vulnerability-detail",
						"CVE-2023-5678",
						"rapidfort",
					},
					Value: types.VulnerabilityDetail{
						Title:       "openssl: X.400 address type confusion in X.509 GeneralName",
						Description: "There is a type confusion vulnerability relating to X.400 address processing inside an X.509 GeneralName.",
					},
				},
				{
					Key: []string{
						"vulnerability-id",
						"CVE-2023-5678",
					},
					Value: map[string]any{},
				},
				{
					Key: []string{
						"data-source",
						"rapidfort Red Hat 9",
					},
					Value: types.DataSource{
						ID:     vulnerability.RapidFort,
						Name:   "RapidFort Security Advisories",
						URL:    "https://github.com/rapidfort/security-advisories",
						BaseID: "redhat",
					},
				},
				{
					Key: []string{
						"advisory-detail",
						"CVE-2023-27536",
						"rapidfort Red Hat 9",
						"curl",
					},
					Value: types.Advisory{
						PatchedVersions:    []string{"7.76.1-26.el9_3.3", "7.76.1-26.fc39"},
						VulnerableVersions: []string{">= 7.76.1-14.el9, < 7.76.1-26.el9_3.3", ">= 7.76.1-14.fc39, < 7.76.1-26.fc39"},
						Severity:           types.SeverityMedium,
						Custom: map[string]any{
							"identifiers": []any{"el9", "fc39"},
						},
					},
				},
				{
					// Open vulnerability: no patched version
					Key: []string{
						"advisory-detail",
						"CVE-2024-99999",
						"rapidfort Red Hat 9",
						"curl",
					},
					Value: types.Advisory{
						VulnerableVersions: []string{">=7.76.1-14.el9"},
						Severity:           types.SeverityHigh,
						Custom: map[string]any{
							"identifiers": []any{"el9"},
						},
					},
				},
				{
					Key: []string{
						"vulnerability-detail",
						"CVE-2023-27536",
						"rapidfort",
					},
					Value: types.VulnerabilityDetail{
						Title:       "curl: GSS delegation too eager connection re-use",
						Description: "An authentication bypass vulnerability exists in libcurl prior to v8.0.0 where it reuses a previously established GSS-negotiate connection.",
					},
				},
				{
					Key: []string{
						"vulnerability-detail",
						"CVE-2024-99999",
						"rapidfort",
					},
					Value: types.VulnerabilityDetail{
						Title:       "curl: hypothetical unfixed vulnerability",
						Description: "A hypothetical vulnerability in curl that has not yet been fixed.",
					},
				},
				{
					Key: []string{
						"vulnerability-id",
						"CVE-2023-27536",
					},
					Value: map[string]any{},
				},
				{
					Key: []string{
						"vulnerability-id",
						"CVE-2024-99999",
					},
					Value: map[string]any{},
				},
			},
		},
		{
			// Multi-version + empty-version case: exercises the in-memory splitting
			// that this parser now owns (previously done on disk by vuln-list-update).
			// A single source file at OS/ubuntu/curl.json declares two populated
			// distro versions (20.04 and 22.04) plus one empty version (18.04).
			// The parser must fan the file out into two distinct platform buckets
			// (one per populated version) and must not crash / produce phantom
			// entries on the empty version.
			name: "multi-version file - each version becomes its own platform bucket",
			dir:  filepath.Join("testdata", "multiversion"),
			wantValues: []vulnsrctest.WantValues{
				// 20.04 platform derived from the "20.04" key inside the source file.
				{
					Key: []string{"data-source", "rapidfort ubuntu 20.04"},
					Value: types.DataSource{
						ID:     vulnerability.RapidFort,
						Name:   "RapidFort Security Advisories",
						URL:    "https://github.com/rapidfort/security-advisories",
						BaseID: "ubuntu",
					},
				},
				{
					Key: []string{
						"advisory-detail",
						"CVE-2020-8169",
						"rapidfort ubuntu 20.04",
						"curl",
					},
					Value: types.Advisory{
						PatchedVersions:    []string{"7.68.0-1ubuntu2.1"},
						VulnerableVersions: []string{">= 7.68.0, < 7.68.0-1ubuntu2.1"},
						Severity:           types.SeverityHigh,
					},
				},
				{
					// vulnerability-detail matches what PutVulnerabilityDetail writes
					// from buildVulnerabilityDetail (title + description only;
					// severity lives in Advisory for RapidFort — see rapidfort.go).
					Key: []string{
						"vulnerability-detail",
						"CVE-2020-8169",
						"rapidfort",
					},
					Value: types.VulnerabilityDetail{
						Title:       "curl: partial password leak over DNS on HTTP redirect",
						Description: "curl 7.62.0 through 7.70.0 is vulnerable to an information disclosure vulnerability.",
					},
				},
				{
					Key:   []string{"vulnerability-id", "CVE-2020-8169"},
					Value: map[string]any{},
				},
				// 22.04 platform derived from the same source file's "22.04" key.
				{
					Key: []string{"data-source", "rapidfort ubuntu 22.04"},
					Value: types.DataSource{
						ID:     vulnerability.RapidFort,
						Name:   "RapidFort Security Advisories",
						URL:    "https://github.com/rapidfort/security-advisories",
						BaseID: "ubuntu",
					},
				},
				{
					Key: []string{
						"advisory-detail",
						"CVE-2023-38039",
						"rapidfort ubuntu 22.04",
						"curl",
					},
					Value: types.Advisory{
						PatchedVersions:    []string{"7.81.0-1ubuntu1.14"},
						VulnerableVersions: []string{">= 7.81.0, < 7.81.0-1ubuntu1.14"},
						Severity:           types.SeverityMedium,
					},
				},
				{
					Key: []string{
						"vulnerability-detail",
						"CVE-2023-38039",
						"rapidfort",
					},
					Value: types.VulnerabilityDetail{
						Title:       "curl: out of heap memory issue due to missing limit on header quantity",
						Description: "When curl retrieves an HTTP response, it stores the incoming headers so that they can be accessed later via the libcurl headers API.",
					},
				},
				{
					Key:   []string{"vulnerability-id", "CVE-2023-38039"},
					Value: map[string]any{},
				},
			},
			// The empty "18.04" version bucket in the source file must not
			// produce any entries: no data-source key for that platform and,
			// since no CVE advisory-detail exists to point at it, no downstream
			// bucket carries the platform name either.
		},
		{
			// Malformed path: a JSON file at security-advisories/OS/curl.json
			// (missing the {osName}/ level) must be skipped with a warning by
			// the len(parts) < 2 guard in parse(). No buckets should be written.
			name: "malformed path - json directly under OS/ is skipped",
			dir:  filepath.Join("testdata", "malformed_path"),
			noBuckets: [][]string{
				{"advisory-detail"},
				{"vulnerability-id"},
				{"vulnerability-detail"},
				{"data-source"},
			},
		},
		{
			// Unsupported OS: RapidFort's upstream repo also publishes an
			// OS/debian/ directory, but trivy's scanner side doesn't dispatch
			// to it (see provider.go). The supportedOSes allowlist must skip
			// these advisories at DB build so we don't populate unreachable
			// buckets. Fixture is a real-shape debian advisory JSON.
			name: "unsupported OS is skipped by allowlist",
			dir:  filepath.Join("testdata", "unsupported_os"),
			noBuckets: [][]string{
				{"advisory-detail"},
				{"vulnerability-id"},
				{"vulnerability-detail"},
				{"data-source"},
			},
		},
		{
			name:    "sad path - invalid JSON",
			dir:     filepath.Join("testdata", "sad"),
			wantErr: "json decode error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vs := rapidfort.NewVulnSrc()
			vulnsrctest.TestUpdate(t, vs, vulnsrctest.TestUpdateArgs{
				Dir:        tt.dir,
				WantValues: tt.wantValues,
				NoBuckets:  tt.noBuckets,
				WantErr:    tt.wantErr,
			})
		})
	}
}

func TestVulnSrc_Get(t *testing.T) {
	tests := []struct {
		name     string
		baseOS   string
		osVer    string
		pkgName  string
		fixtures []string
		want     []types.Advisory
		wantErr  string
	}{
		{
			name:    "ubuntu advisory found",
			baseOS:  "ubuntu",
			osVer:   "20.04",
			pkgName: "curl",
			fixtures: []string{
				"testdata/fixtures/happy.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			want: []types.Advisory{
				{
					VulnerabilityID:    "CVE-2020-8169",
					VulnerableVersions: []string{">= 7.68.0, < 7.68.0-1ubuntu2.1"},
					PatchedVersions:    []string{"7.68.0-1ubuntu2.1"},
					Severity:           types.SeverityHigh,
					DataSource: &types.DataSource{
						ID:     vulnerability.RapidFort,
						Name:   "RapidFort Security Advisories",
						URL:    "https://github.com/rapidfort/security-advisories",
						BaseID: "ubuntu",
					},
				},
			},
		},
		{
			name:    "alpine advisory found",
			baseOS:  "alpine",
			osVer:   "3.18",
			pkgName: "libssl3",
			fixtures: []string{
				"testdata/fixtures/happy.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			want: []types.Advisory{
				{
					VulnerabilityID:    "CVE-2023-5678",
					VulnerableVersions: []string{">= 3.0.0, < 3.1.4-r1"},
					PatchedVersions:    []string{"3.1.4-r1"},
					Severity:           types.SeverityMedium,
					DataSource: &types.DataSource{
						ID:     vulnerability.RapidFort,
						Name:   "RapidFort Security Advisories",
						URL:    "https://github.com/rapidfort/security-advisories",
						BaseID: "alpine",
					},
				},
			},
		},
		{
			name:    "redhat advisory found",
			baseOS:  "redhat",
			osVer:   "9",
			pkgName: "curl",
			fixtures: []string{
				"testdata/fixtures/happy.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			want: []types.Advisory{
				{
					VulnerabilityID:    "CVE-2023-27536",
					VulnerableVersions: []string{">= 7.76.1-14.el9, < 7.76.1-26.el9_3.3", ">= 7.76.1-14.fc39, < 7.76.1-26.fc39"},
					PatchedVersions:    []string{"7.76.1-26.el9_3.3", "7.76.1-26.fc39"},
					Severity:           types.SeverityMedium,
					Custom: map[string]any{
						"identifiers": []any{"el9", "fc39"},
					},
					DataSource: &types.DataSource{
						ID:     vulnerability.RapidFort,
						Name:   "RapidFort Security Advisories",
						URL:    "https://github.com/rapidfort/security-advisories",
						BaseID: "redhat",
					},
				},
				{
					VulnerabilityID:    "CVE-2024-99999",
					VulnerableVersions: []string{">=7.76.1-14.el9"},
					Severity:           types.SeverityHigh,
					Custom: map[string]any{
						"identifiers": []any{"el9"},
					},
					DataSource: &types.DataSource{
						ID:     vulnerability.RapidFort,
						Name:   "RapidFort Security Advisories",
						URL:    "https://github.com/rapidfort/security-advisories",
						BaseID: "redhat",
					},
				},
			},
		},
		{
			name:    "no advisory for package",
			baseOS:  "ubuntu",
			osVer:   "22.04",
			pkgName: "curl",
			fixtures: []string{
				"testdata/fixtures/happy.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vs := rapidfort.NewVulnSrcGetter(tt.baseOS)
			vulnsrctest.TestGet(t, vs, vulnsrctest.TestGetArgs{
				Fixtures:   tt.fixtures,
				WantValues: tt.want,
				GetParams: db.GetParams{
					Release: tt.osVer,
					PkgName: tt.pkgName,
				},
				WantErr: tt.wantErr,
			})
		})
	}
}

func TestVulnSrc_Name(t *testing.T) {
	vs := rapidfort.NewVulnSrc()
	assert.Equal(t, vulnerability.RapidFort, vs.Name())
}
