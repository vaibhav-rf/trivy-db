package rapidfort

import (
	"github.com/samber/oops"

	"github.com/aquasecurity/trivy-db/pkg/ecosystem"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/bucket"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

// rapidFortBucket wraps a base OS bucket. RapidFort advisories reuse the base
// OS naming (e.g. "ubuntu 20.04", "Red Hat 9") prefixed with "rapidfort ",
// so the platform name stays consistent with the original distributions.
// RapidFort's own rebuilds ("rf") have no upstream distribution version. They
// still split into RedHat- and Ubuntu-flavored buckets so their ranges never
// share a bucket across package formats — that would let the wrong version
// comparator interpret a range string.
type rapidFortBucket struct {
	ecosystem  ecosystem.Type
	base       bucket.Bucket
	dataSource types.DataSource
	// rfSuffix identifies the rf bucket flavor when base is nil ("redhat" or
	// "ubuntu"). Empty for base-backed buckets (Ubuntu/Alpine/RedHat/Fedora).
	rfSuffix string
}

func (r rapidFortBucket) Name() string {
	name := "rapidfort"
	switch {
	case r.base != nil:
		name += " " + r.base.Name()
	case r.rfSuffix != "":
		name += " " + r.rfSuffix
	}
	return name
}

func (r rapidFortBucket) Ecosystem() ecosystem.Type {
	return r.ecosystem
}

func (r rapidFortBucket) DataSource() types.DataSource {
	return r.dataSource
}

// newBucket builds a RapidFort bucket for the given base ecosystem and version.
// An unsupported base ecosystem returns an error so the caller can skip it.
// This is the single source of truth for which base ecosystems RapidFort
// dispatches to; keep it aligned with trivy/pkg/detector/ospkg/rapidfort.
func newBucket(baseEcosystem ecosystem.Type, version string) (bucket.DataSourceBucket, error) {
	ds := source
	var base bucket.Bucket
	var rfSuffix string
	switch baseEcosystem {
	case ecosystem.Ubuntu:
		base, ds.BaseID = bucket.NewUbuntu(version), vulnerability.Ubuntu
	case ecosystem.Alpine:
		base, ds.BaseID = bucket.NewAlpine(version), vulnerability.Alpine
	case ecosystem.RedHat:
		base, ds.BaseID = bucket.NewRedHat(version), vulnerability.RedHat
	case ecosystem.Fedora:
		base, ds.BaseID = bucket.NewFedora(version), vulnerability.Fedora
	case ecosystem.RapidFortRedHat:
		// RapidFort's own RPM rebuilds — dpkg comparator must not see these
		// ranges, so they live in a bucket separate from the Ubuntu-flavored
		// rf bucket. Platform name: "rapidfort redhat".
		rfSuffix = "redhat"
	case ecosystem.RapidFortUbuntu:
		// RapidFort's own dpkg rebuilds — RPM comparator must not see these.
		// Platform name: "rapidfort ubuntu".
		rfSuffix = "ubuntu"
	default:
		return nil, oops.With("base_ecosystem", baseEcosystem).Errorf("unsupported base ecosystem")
	}
	return rapidFortBucket{
		ecosystem:  baseEcosystem,
		base:       base,
		dataSource: ds,
		rfSuffix:   rfSuffix,
	}, nil
}
