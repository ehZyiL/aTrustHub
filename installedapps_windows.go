package main

import (
	"github.com/qy/easyconnect/internal/localapps"
	"github.com/qy/easyconnect/internal/model"
)

func readInstalledProgram(path string) (model.LocalApp, error) {
	return localapps.ReadWindowsProgram(path)
}
