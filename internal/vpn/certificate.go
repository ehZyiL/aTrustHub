package vpn

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/ehzyil/connect-hub/internal/model"
	"github.com/ehzyil/connect-hub/internal/workeripc"
)

// ProbeGatewayCertificate observes a certificate without logging in. It shares
// only the endpoint with a short-lived worker, never credentials or proxy secrets.
func ProbeGatewayCertificate(ctx context.Context, server string, port int) (*workeripc.CertificateInfo, error) {
	bin, err := workerPath()
	if err != nil {
		return nil, err
	}
	return probeGatewayCertificate(ctx, bin, server, port)
}

func probeGatewayCertificate(ctx context.Context, bin, server string, port int) (*workeripc.CertificateInfo, error) {
	if server == "" || strings.ContainsAny(server, "/?#@\\ \t\r\n") || port < 1 || port > 65535 {
		return nil, errors.New("网关地址无效")
	}
	ctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	address := net.JoinHostPort(server, strconv.Itoa(port))
	id := model.NewID()
	input, err := json.Marshal(workeripc.Message{Version: workeripc.Version, Session: id, Type: "certificate_probe", Address: address})
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, bin)
	hideWorkerCmd(cmd)
	cmd.Stdin, cmd.Stderr = bytes.NewReader(append(input, '\n')), io.Discard
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, errors.New("无法准备证书读取核心")
	}
	if err = cmd.Start(); err != nil {
		_ = stdout.Close()
		return nil, errors.New("无法启动证书读取核心，请检查安装目录")
	}
	output, readErr := io.ReadAll(io.LimitReader(stdout, workeripc.MaxMessage+1))
	if readErr != nil || len(output) > workeripc.MaxMessage {
		_ = cmd.Process.Kill()
	}
	waitErr := cmd.Wait()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if readErr != nil || len(output) > workeripc.MaxMessage {
		return nil, errors.New("证书读取核心返回的数据无效")
	}
	var reply workeripc.Message
	if json.Unmarshal(output, &reply) != nil || reply.Version != workeripc.Version || reply.Session != id || reply.Address != address {
		return nil, errors.New("证书读取核心未返回兼容应答，请同时更新主程序和 easyconnect-worker")
	}
	if reply.Type == "error" {
		return nil, errors.New("无法读取网关证书，请检查地址和网络后重试")
	}
	if waitErr != nil || reply.Type != "certificate" || reply.Error != "" || !ValidCertificateInfo(reply.Certificate) {
		return nil, errors.New("证书读取结果无效，请更新核心后重试")
	}
	return reply.Certificate, nil
}

func ValidCertificateInfo(info *workeripc.CertificateInfo) bool {
	if info == nil || len(info.Subject) > 4096 || len(info.Issuer) > 4096 || info.NotAfter <= info.NotBefore {
		return false
	}
	pin, err := hex.DecodeString(info.SHA256)
	return err == nil && len(pin) == 32 && len(info.SHA256) == 64
}

// Handles both current and older worker error wording. This only offers a
// diagnostic action; no error text grants trust or bypasses certificate checks.
func IsGatewayCertificateError(message string) bool {
	return strings.Contains(message, "网关证书")
}
