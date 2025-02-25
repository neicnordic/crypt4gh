package version

import (
	"fmt"

	version "github.com/hashicorp/go-version"
)

// The version in the current branch
var Version = "1.14.0"

// If this is "" (empty string) then it means that it is a final release.
// Otherwise, this is a pre-release e.g. "dev", "beta", "rc1", etc.
var VersionMarker = ""

// PackageVersion is an instance of version.Version.
var PackageVersion *version.Version

// PackageVersion is an instance of version.Version.
const Packagename = "crypt4gh"

func init() {
	PackageVersion = version.Must(version.NewVersion(Version))
}

// String returns the complete version string, including prerelease
func String() string {
	if VersionMarker != "" {
		return fmt.Sprintf("%s-%s", Version, VersionMarker)
	}

	return Version
}
