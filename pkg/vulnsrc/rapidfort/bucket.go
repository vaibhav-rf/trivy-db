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
type rapidFortBucket struct {
	base       bucket.Bucket
	dataSource types.DataSource
}

func (r rapidFortBucket) Name() string {
	return "rapidfort " + r.base.Name()
}

func (r rapidFortBucket) Ecosystem() ecosystem.Type {
	return ecosystem.RapidFort
}

func (r rapidFortBucket) DataSource() types.DataSource {
	return r.dataSource
}

// newBucket resolves the base OS directory name (e.g. "ubuntu", "alpine",
// "redhat") into a RapidFort bucket, including the DataSource (with BaseID)
// used when saving. An unsupported base OS results in an error so the caller
// can skip it — this is the single source of truth for which OSes RapidFort
// dispatches to; keep it aligned with trivy/pkg/detector/ospkg/rapidfort.
func newBucket(baseOS, version string) (bucket.DataSourceBucket, error) {
	ds := source
	var base bucket.Bucket
	switch baseOS {
	case "ubuntu":
		base, ds.BaseID = bucket.NewUbuntu(version), vulnerability.Ubuntu
	case "alpine":
		base, ds.BaseID = bucket.NewAlpine(version), vulnerability.Alpine
	case "redhat":
		base, ds.BaseID = bucket.NewRedHat(version), vulnerability.RedHat
	default:
		return nil, oops.With("base_os", baseOS).Errorf("unsupported base OS")
	}
	return rapidFortBucket{base: base, dataSource: ds}, nil
}
