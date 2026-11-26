//go:build !windows

package service

import "context"

func RestoreBackup(manifestPath string, rw *ReportWriter) error {
	return ErrUnsupported
}

func ListBackups(backupRootDir string) ([]BackupManifest, error) {
	return nil, ErrUnsupported
}

func RestoreBackupContext(ctx context.Context, manifestPath string, rw *ReportWriter) error {
	return ErrUnsupported
}
