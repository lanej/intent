//go:build !windows

package approvalconfig

import (
	"os"
	"path/filepath"

	"github.com/lanej/intent/internal/approvaldiscovery"
)

type LifecycleProfile struct {
	Path string `json:"profile_path"`
	Profile
}

// LifecycleProfiles returns only validated existing profiles. It does not
// create configuration, prune parser records, or start an SSH connection.
func LifecycleProfiles() ([]LifecycleProfile, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}

	dir := filepath.Join(home, ".intent-ssh")

	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return []LifecycleProfile{}, nil
	}

	if err != nil {
		return nil, err
	}

	if err = approvaldiscovery.PrivateDir(dir, false); err != nil {
		return nil, err
	}

	profiles := []LifecycleProfile{}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		path := filepath.Join(dir, entry.Name(), "profile.json")
		if _, err = os.Lstat(path); os.IsNotExist(err) {
			continue
		}

		profile, profileErr := readProfile(path)
		if profileErr != nil {
			return nil, profileErr
		}

		profiles = append(profiles, LifecycleProfile{Path: path, Profile: profile})
	}

	return profiles, nil
}

func LifecycleProfileAt(path string) (LifecycleProfile, error) {
	profile, err := readProfile(path)
	return LifecycleProfile{Path: path, Profile: profile}, err
}
