//go:build !windows

package sangforclean

func RestoreBackup(manifestPath string, rw *ReportWriter) error {
	return ErrUnsupported
}

func ListBackups(backupRootDir string) ([]BackupManifest, error) {
	return nil, ErrUnsupported
}
