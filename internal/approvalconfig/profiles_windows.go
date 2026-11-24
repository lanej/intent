//go:build windows

package approvalconfig

type LifecycleProfile struct {
	Path        string `json:"profile_path"`
	Host        string `json:"host"`
	MacID       string `json:"mac_id"`
	RemoteDir   string `json:"remote_directory"`
	Executable  string `json:"executable"`
	LocalSocket string `json:"local_socket"`
}

func LifecycleProfiles() ([]LifecycleProfile, error) {
	return nil, unsupported()
}

func LifecycleProfileAt(string) (LifecycleProfile, error) {
	return LifecycleProfile{}, unsupported()
}
