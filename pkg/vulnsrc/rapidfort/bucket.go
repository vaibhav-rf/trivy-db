package rapidfort

import (
	"github.com/samber/oops"

	"github.com/aquasecurity/trivy-db/pkg/ecosystem"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/bucket"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

// rapidFortBucket wraps a base OS bucket. RapidFort advisories reuse the base
// OS naming (e.g. "ubuntu 20.04", "Red Hat 9") prefixed with "rapidfort " so
// the platform name stays consistent with the original distributions.
// RapidFort's own rebuilds ("rf") share the same base bucket type with an
// empty version, producing names like "rapidfort Red Hat" and "rapidfort
// ubuntu" — one per base OS family, so rf ranges never share a bucket across
// package formats (which would let the wrong version comparator interpret a
// range string).
type rapidFortBucket struct {
	base       bucket.Bucket
	dataSource types.DataSource
}

func (r rapidFortBucket) Name() string {
	return "rapidfort " + r.base.Name()
}

func (r rapidFortBucket) Ecosystem() ecosystem.Type {
	return r.base.Ecosystem()
}

func (r rapidFortBucket) DataSource() types.DataSource {
	return r.dataSource
}

// newBucket builds a RapidFort bucket for the given base ecosystem and version.
// An unsupported base ecosystem returns an error so the caller can skip it.
// An empty version selects the family-level bucket used for rf-only ranges
// (e.g. baseEcosystem=RedHat + version="" → "rapidfort Red Hat").
// This is the single source of truth for which base ecosystems RapidFort
// dispatches to; keep it aligned with trivy/pkg/detector/ospkg/rapidfort.
func newBucket(baseEcosystem ecosystem.Type, version string) (bucket.DataSourceBucket, error) {
	ds := source
	var base bucket.Bucket
	switch baseEcosystem {
	case ecosystem.Ubuntu:
		base, ds.BaseID = bucket.NewUbuntu(version), vulnerability.Ubuntu
	case ecosystem.Alpine:
		base, ds.BaseID = bucket.NewAlpine(version), vulnerability.Alpine
	case ecosystem.RedHat:
		base, ds.BaseID = bucket.NewRedHat(version), vulnerability.RedHat
	case ecosystem.Fedora:
		base, ds.BaseID = bucket.NewFedora(version), vulnerability.Fedora
	default:
		return nil, oops.With("base_ecosystem", baseEcosystem).Errorf("unsupported base ecosystem")
	}
	return rapidFortBucket{base: base, dataSource: ds}, nil
}
