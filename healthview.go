package main

import (
	"github.com/ehzyil/connect-hub/internal/vpn"
)

func healthProbeText(kind string, result vpn.ProbeResult) string {
	text := kind + "：未验证"
	switch result.State {
	case "ok":
		if kind == "DNS" {
			text = "DNS：网关有应答"
		} else {
			text = "TCP：已通过 VPN 建立（业务操作未验证）"
		}
	case "failed":
		text = kind + "：探测失败"
	}
	if result.State == "ok" || result.State == "failed" {
		if result.Target != "" && kind != "DNS" {
			text += " · " + result.Target
		}
		if result.Error != "" {
			text += " · " + result.Error
		}
	}
	return text
}
