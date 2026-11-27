package imodels

import (
	"testing"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/requirements"
	"github.com/google/osv-scalibr/purl"
)

func Test_specifierFromRequirement(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		requirement string
		comparator  string
		want        string
	}{
		{
			name:        "exact_pin",
			requirement: "django==4.2",
			comparator:  "==",
			want:        "==4.2",
		},
		{
			name:        "exact_pin_with_spaces",
			requirement: "django == 4.2",
			comparator:  "==",
			want:        "==4.2",
		},
		{
			name:        "compatible_release",
			requirement: "django~=4.2",
			comparator:  "~=",
			want:        "~=4.2",
		},
		{
			name:        "compatible_release_with_spaces",
			requirement: "django ~= 4.2",
			comparator:  "~=",
			want:        "~=4.2",
		},
		{
			name:        "greater_than_or_equal",
			requirement: "requests>=2.20.0",
			comparator:  ">=",
			want:        ">=2.20.0",
		},
		{
			name:        "less_than_or_equal",
			requirement: "urllib3<=1.26.18",
			comparator:  "<=",
			want:        "<=1.26.18",
		},
		{
			name:        "arbitrary_equality",
			requirement: "six===1.16.0",
			comparator:  "===",
			want:        "===1.16.0",
		},
		{
			name:        "extras",
			requirement: "celery[redis]>=5.0",
			comparator:  ">=",
			want:        ">=5.0",
		},
		{
			name:        "environment_marker",
			requirement: `idna~=3.4 ; python_version >= "3.8"`,
			comparator:  "~=",
			want:        "~=3.4",
		},
		{
			name:        "trailing_token",
			requirement: "foo==1.0 unexpected",
			comparator:  "==",
			want:        "==1.0",
		},
		{
			name:        "empty_requirement",
			requirement: "",
			comparator:  "==",
			want:        "",
		},
		{
			name:        "comparator_missing_from_requirement",
			requirement: "django",
			comparator:  "==",
			want:        "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := specifierFromRequirement(tt.requirement, tt.comparator)
			if got != tt.want {
				t.Errorf("specifierFromRequirement(%q, %q) = %q, want %q", tt.requirement, tt.comparator, got, tt.want)
			}
		})
	}
}

func TestPackageInfo_RequirementsVersionSpecifier(t *testing.T) {
	t.Parallel()

	pkg := func(name, version, comparator, requirement string) *extractor.Package {
		return &extractor.Package{
			Name:     name,
			Version:  version,
			PURLType: purl.TypePyPi,
			Metadata: &requirements.Metadata{
				VersionComparator: comparator,
				Requirement:       requirement,
			},
		}
	}

	tests := []struct {
		name    string
		pkg     *extractor.Package
		version string
		spec    string
	}{
		{
			name:    "exact_pin",
			pkg:     pkg("django", "4.2", "==", "django==4.2"),
			version: "4.2",
			spec:    "==4.2",
		},
		{
			name:    "compatible_release",
			pkg:     pkg("django", "4.2", "~=", "django~=4.2"),
			version: "4.2",
			spec:    "~=4.2",
		},
		{
			name:    "range_lower_bound",
			pkg:     pkg("requests", "2.20.0", ">=", "requests>=2.20.0"),
			version: "2.20.0",
			spec:    ">=2.20.0",
		},
		{
			name:    "resolved_version_keeps_original_specifier",
			pkg:     pkg("django", "4.2.16", "~=", "django~=4.2"),
			version: "4.2.16",
			spec:    "~=4.2",
		},
		{
			name:    "no_comparator",
			pkg:     pkg("bare", "", "", "bare"),
			version: "",
			spec:    "",
		},
		{
			name: "not_a_requirements_package",
			pkg: &extractor.Package{
				Name:     "left-pad",
				Version:  "1.0.0",
				PURLType: purl.TypeNPM,
			},
			version: "1.0.0",
			spec:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := PackageInfo(tt.pkg)
			if got.Version != tt.version {
				t.Errorf("PackageInfo().Version = %q, want %q", got.Version, tt.version)
			}
			if got.VersionSpecifier != tt.spec {
				t.Errorf("PackageInfo().VersionSpecifier = %q, want %q", got.VersionSpecifier, tt.spec)
			}
		})
	}
}
