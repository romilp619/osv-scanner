// Package imodels defines internal models for osv-scanner.
package imodels

import (
	"path/filepath"
	"strings"

	"github.com/google/osv-scalibr/enricher/vulnmatch/osvutil"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/requirements"
	apkmetadata "github.com/google/osv-scalibr/extractor/filesystem/os/apk/metadata"
	dpkgmetadata "github.com/google/osv-scalibr/extractor/filesystem/os/dpkg/metadata"
	rpmmetadata "github.com/google/osv-scalibr/extractor/filesystem/os/rpm/metadata"
	"github.com/google/osv-scalibr/inventory/osvecosystem"
	"github.com/google/osv-scanner/v2/internal/cmdlogger"
	"github.com/google/osv-scanner/v2/internal/scalibrextract/language/osv/osvscannerjson"
	"github.com/google/osv-scanner/v2/internal/scalibrextract/vcs/gitrepo"
	"github.com/google/osv-scanner/v2/internal/scalibrplugin"

	scalibrosv "github.com/google/osv-scalibr/extractor/filesystem/osv"
	"github.com/google/osv-scanner/v2/pkg/models"
)

var gitExtractors = map[string]struct{}{
	gitrepo.Name: {},
}

// ParsePackage parses SCALIBR package metadata into OSV normalized package.
// This does not affect matching. It is only used for reporting and filtering.
func ParsePackage(pkg *extractor.Package) osvutil.NormalizedPackage {
	parsed := osvutil.ParsePackage(pkg)

	if metadata, ok := pkg.Metadata.(*osvscannerjson.Metadata); ok {
		newEco, err := osvecosystem.Parse(metadata.Ecosystem)
		if err != nil {
			cmdlogger.Warnf("Warning: error parsing osvscanner.json ecosystem: %s", err.Error())
		} else if !newEco.IsEmpty() {
			parsed.Ecosystem = newEco
		}
	}

	return parsed
}

func Location(pkg *extractor.Package) string {
	// Use the scan root, defaulting to / for virtual filesystems (e.g. container images)
	scanRoot := pkg.ScanRoot
	if scanRoot == "" {
		scanRoot = "/"
	}

	return filepath.Join(scanRoot, pkg.Location.PathOrEmpty())
}

func SourceType(pkg *extractor.Package) models.SourceType {
	for _, extractorName := range pkg.Plugins {
		if strings.HasPrefix(extractorName, "os/") {
			return models.SourceTypeOSPackage
		} else if _, ok := scalibrplugin.ExtractorPresets["sbom"][extractorName]; ok {
			return models.SourceTypeSBOM
		} else if _, ok := gitExtractors[extractorName]; ok {
			return models.SourceTypeGit
		} else if _, ok := scalibrplugin.ExtractorPresets["artifact"][extractorName]; ok {
			return models.SourceTypeArtifact
		} else if _, ok := scalibrplugin.ExtractorPresets["lockfile"][extractorName]; ok {
			return models.SourceTypeProjectPackage
		}
	}

	return models.SourceTypeUnknown
}

func DepGroups(pkg *extractor.Package) []string {
	if dg, ok := pkg.Metadata.(scalibrosv.DepGroups); ok {
		return dg.DepGroups()
	}

	return []string{}
}

func osPackageName(pkg *extractor.Package) string {
	if metadata, ok := pkg.Metadata.(*apkmetadata.Metadata); ok {
		return metadata.PackageName
	}
	if metadata, ok := pkg.Metadata.(*dpkgmetadata.Metadata); ok {
		return metadata.PackageName
	}
	if metadata, ok := pkg.Metadata.(*rpmmetadata.Metadata); ok {
		return metadata.PackageName
	}

	return ""
}

func PackageVulns(p *extractor.Package) models.PackageVulns {
	return models.PackageVulns{Package: PackageInfo(p), DepGroups: DepGroups(p)}
}

func PackageInfo(p *extractor.Package) models.PackageInfo {
	parsedPkg := ParsePackage(p)

	pi := models.PackageInfo{
		Name:             parsedPkg.Name,
		Version:          parsedPkg.Version,
		VersionSpecifier: versionSpecifier(p),
		Ecosystem:        parsedPkg.Ecosystem.String(),
		OSPackageName:    osPackageName(p),
		Commit:           parsedPkg.Commit,
		Deprecated:       p.Deprecated,
		Inventory:        p,
	}

	if packageURL := p.PURL(); packageURL != nil {
		pi.PURL = packageURL.String()
	}

	if p.LayerMetadata != nil {
		pi.ImageOrigin = &models.ImageOriginDetails{
			Index: p.LayerMetadata.Index,
		}
	}

	return pi
}

// versionSpecifier returns the original requirements.txt operator and version,
// such as "==4.2" or "~=4.2".
//
// Transitive resolution overwrites Package.Version with a concrete release and
// leaves Metadata.Requirement unchanged, so the specifier is taken from the
// requirement instead of the current version.
func versionSpecifier(pkg *extractor.Package) string {
	meta, ok := pkg.Metadata.(*requirements.Metadata)
	if !ok || meta.VersionComparator == "" {
		return ""
	}

	return specifierFromRequirement(meta.Requirement, meta.VersionComparator)
}

// specifierFromRequirement returns comparator plus the version that follows it
// in a requirements.txt requirement. Environment markers and trailing tokens
// are dropped, and whitespace around the version is removed.
func specifierFromRequirement(requirement, comparator string) string {
	req := strings.TrimSpace(requirement)
	if req == "" || comparator == "" {
		return ""
	}

	_, version, ok := strings.Cut(req, comparator)
	if !ok {
		return ""
	}

	version, _, _ = strings.Cut(version, ";")
	version = strings.TrimSpace(version)
	if cut := strings.IndexAny(version, " \t"); cut >= 0 {
		version = strings.TrimSpace(version[:cut])
	}
	if version == "" {
		return ""
	}

	return comparator + version
}
