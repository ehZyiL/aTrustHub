//go:build !windows

package sangforclean

func DefaultBackupRootDir() string {
	return ""
}

func CreateBackup(plan *Plan, backupRootDir string) (*BackupManifest, error) {
	return nil, ErrUnsupported
}
