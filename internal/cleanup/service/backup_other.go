//go:build !windows

package service

func DefaultBackupRootDir() string {
	return ""
}

func CreateBackup(plan *Plan, backupRootDir string) (*BackupManifest, error) {
	return nil, ErrUnsupported
}
