//go:build !linux

package main

import (
	"errors"

	"github.com/qy/easyconnect/internal/model"
)

func readInstalledProgram(string) (model.LocalApp, error) {
	return model.LocalApp{}, errors.New("此平台尚未提供已安装软件的接管入口，请手动选择程序")
}
