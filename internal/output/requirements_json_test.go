package output_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/requirements"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scanner/v2/internal/imodels"
	"github.com/google/osv-scanner/v2/internal/output"
	"github.com/google/osv-scanner/v2/pkg/models"
)

func TestPrintJSONResults_RequirementsTxtVersionSpecifier(t *testing.T) {
	t.Parallel()

	const requirementsTxt = "" +
		"django==4.2\n" +
		"flask~=2.3\n" +
		"requests>=2.31.0\n" +
		"urllib3<=1.26.18\n" +
		"six===1.16.0\n" +
		"Werkzeug == 3.0.1\n" +
		"celery[redis]>=5.0\n" +
		"idna~=3.4 ; python_version >= \"3.8\"\n" +
		"bare\n" +
		"coverage!=3.5\n" +
		"wild==1.0.*\n"

	extr, err := requirements.New(&cpb.PluginConfig{})
	if err != nil {
		t.Fatalf("requirements.New() error: %v", err)
	}

	inv, err := extr.Extract(t.Context(), &filesystem.ScanInput{
		Path:   "requirements.txt",
		Reader: strings.NewReader(requirementsTxt),
	})
	if err != nil {
		t.Fatalf("Extract() error: %v", err)
	}

	byName := map[string]*extractor.Package{}
	for _, pkg := range inv.Packages {
		byName[pkg.Name] = pkg
	}
	mustPkg := func(name string) *extractor.Package {
		t.Helper()
		pkg, ok := byName[name]
		if !ok {
			t.Fatalf("extracted package %q not found in %v", name, inv.Packages)
		}

		return pkg
	}

	// Transitive resolution replaces the version with a concrete release and
	// keeps the original requirement metadata.
	resolved := *mustPkg("flask")
	resolved.Version = "2.3.3"
	byName["flask-resolved"] = &resolved

	byName["left-pad"] = &extractor.Package{
		Name:     "left-pad",
		Version:  "1.0.0",
		PURLType: purl.TypeNPM,
	}

	pkgs := []models.PackageVulns{
		{Package: imodels.PackageInfo(mustPkg("django"))},
		{Package: imodels.PackageInfo(mustPkg("flask"))},
		{Package: imodels.PackageInfo(mustPkg("flask-resolved"))},
		{Package: imodels.PackageInfo(mustPkg("requests"))},
		{Package: imodels.PackageInfo(mustPkg("urllib3"))},
		{Package: imodels.PackageInfo(mustPkg("six"))},
		{Package: imodels.PackageInfo(mustPkg("Werkzeug"))},
		{Package: imodels.PackageInfo(mustPkg("celery"))},
		{Package: imodels.PackageInfo(mustPkg("idna"))},
		{Package: imodels.PackageInfo(mustPkg("bare"))},
		{Package: imodels.PackageInfo(mustPkg("coverage"))},
		{Package: imodels.PackageInfo(mustPkg("wild"))},
		{Package: imodels.PackageInfo(mustPkg("left-pad"))},
	}

	results := &models.VulnerabilityResults{
		Results: []models.PackageSource{{
			Source:   models.SourceInfo{Path: "requirements.txt", Type: models.SourceTypeProjectPackage},
			Packages: pkgs,
		}},
	}

	var buf bytes.Buffer
	if err := output.PrintJSONResults(results, &buf); err != nil {
		t.Fatalf("PrintJSONResults() error: %v", err)
	}

	packages := decodePackageObjects(t, buf.Bytes())
	if len(packages) != len(pkgs) {
		t.Fatalf("decoded %d packages, want %d", len(packages), len(pkgs))
	}

	want := []struct {
		name    string
		version string
		spec    string
		present bool
	}{
		{name: "django", version: "4.2", spec: "==4.2", present: true},
		{name: "flask", version: "2.3", spec: "~=2.3", present: true},
		{name: "flask", version: "2.3.3", spec: "~=2.3", present: true},
		{name: "requests", version: "2.31.0", spec: ">=2.31.0", present: true},
		{name: "urllib3", version: "1.26.18", spec: "<=1.26.18", present: true},
		{name: "six", version: "1.16.0", spec: "===1.16.0", present: true},
		{name: "werkzeug", version: "3.0.1", spec: "==3.0.1", present: true},
		{name: "celery", version: "5.0", spec: ">=5.0", present: true},
		{name: "idna", version: "3.4", spec: "~=3.4", present: true},
		{name: "bare", version: "", present: false},
		{name: "coverage", version: "", present: false},
		{name: "wild", version: "", present: false},
		{name: "left-pad", version: "1.0.0", present: false},
	}

	for i, tt := range want {
		got := packages[i]
		if got["name"] != tt.name {
			t.Errorf("packages[%d].name = %v, want %s", i, got["name"], tt.name)
		}
		if got["version"] != tt.version {
			t.Errorf("packages[%d] %s version = %v, want %s", i, tt.name, got["version"], tt.version)
		}

		spec, ok := got["version_specifier"]
		if ok != tt.present {
			t.Errorf("packages[%d] %s version_specifier present = %v, want %v (value %v)", i, tt.name, ok, tt.present, spec)
		}
		if tt.present && spec != tt.spec {
			t.Errorf("packages[%d] %s version_specifier = %v, want %s", i, tt.name, spec, tt.spec)
		}
	}
}

func decodePackageObjects(t *testing.T, raw []byte) []map[string]any {
	t.Helper()

	var doc struct {
		Results []struct {
			Packages []struct {
				Package map[string]any `json:"package"`
			} `json:"packages"`
		} `json:"results"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("json.Unmarshal() error: %v\n%s", err, raw)
	}
	if len(doc.Results) != 1 {
		t.Fatalf("decoded %d results, want 1", len(doc.Results))
	}

	packages := make([]map[string]any, 0, len(doc.Results[0].Packages))
	for _, pkg := range doc.Results[0].Packages {
		packages = append(packages, pkg.Package)
	}

	return packages
}
