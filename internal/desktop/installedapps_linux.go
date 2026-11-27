package desktop

import (
	"github.com/ehzyil/connect-hub/internal/localapps"
	"github.com/ehzyil/connect-hub/internal/model"
)

func readInstalledProgram(path string) (model.LocalApp, error) {
	return localapps.ReadDesktopProgram(path)
}
