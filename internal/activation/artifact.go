package activation

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"

	"github.com/lanej/intent/internal/cleanup"
)

// SelectedArtifact binds the executing image ID to an owner build manifest.
// A replaced mutable pathname cannot pair old image identity with new bytes.
func SelectedArtifact() (map[string]any, error) {
	image := ImageIdentity()

	result := map[string]any{"expected_identity": image, "sha256": nil}
	if image == nil {
		result["reason"] = "executing-image-is-unmanaged"
		return result, nil
	}

	executable, err := os.Executable()
	if err != nil {
		return nil, err
	}

	executable, err = filepath.EvalSymlinks(executable)
	if err != nil {
		return nil, err
	}

	manifest := executable + ".build.json"

	info, err := os.Lstat(manifest)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() > 16384 {
		result["reason"] = "selected-artifact-manifest-unavailable"
		return result, nil
	}

	file, err := os.Open(manifest) // #nosec G304 -- The native executable supplies its own adjacent bounded manifest; links are refused and the opened inode is checked.
	if err != nil {
		return nil, err
	}
	defer cleanup.Close(file)

	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		result["reason"] = "selected-artifact-manifest-changed"
		return result, nil
	}

	var record struct {
		ExpectedIdentity string `json:"expected_identity"`
		SHA256           string `json:"sha256"`
	}
	if err = json.NewDecoder(io.LimitReader(file, 16385)).Decode(&record); err != nil {
		return nil, err
	}

	if record.ExpectedIdentity != *image {
		result["reason"] = "executing-image-and-selected-manifest-differ"
		return result, nil
	}

	digest, err := selectedExecutableDigest(executable)
	if err != nil {
		return nil, err
	}

	if digest != record.SHA256 {
		result["reason"] = "selected-artifact-bytes-and-manifest-differ"
		return result, nil
	}

	result["sha256"] = digest

	return result, nil
}

func selectedExecutableDigest(path string) (string, error) { return Digest(path) }
