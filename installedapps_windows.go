package main

import (
	"github.com/ehZyiL/connect-hub/internal/localapps"
	"github.com/ehZyiL/connect-hub/internal/model"
)

func readInstalledProgram(path string) (model.LocalApp, error) {
	return localapps.ReadWindowsProgram(path)
}
