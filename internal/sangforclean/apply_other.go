//go:build !windows

package sangforclean

type ApplyOptions struct {
	Plan          *Plan
	ReportPath    string
	OnlyIDs       []string
	SkipIDs       []string
	BackupRootDir string
}

func Apply(opts ApplyOptions) (int, error) {
	return 2, ErrUnsupported
}
