// easyconnect-check is a developer integration probe. It accepts one JSON
// configuration on stdin and exchanges challenges on the same pipe. Passwords
// must never be passed as command arguments or environment variables.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/ehzyil/connect-hub/internal/model"
	localproxy "github.com/ehzyil/connect-hub/internal/proxy"
	"github.com/ehzyil/connect-hub/internal/vpn"
	"golang.org/x/net/proxy"
)

type input struct {
	Server            string `json:"server"`
	Username          string `json:"username"`
	Password          string `json:"password"`
	CertificateSHA256 string `json:"certificateSHA256"`
	Target            string `json:"target"`
}

func main() {
	if err := run(); err != nil {
		_ = json.NewEncoder(os.Stdout).Encode(map[string]string{"type": "error", "error": err.Error()})
		os.Exit(1)
	}
}

func run() error {
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	if !scanner.Scan() {
		return errors.New("missing input")
	}
	var cfg input
	if err := json.Unmarshal(scanner.Bytes(), &cfg); err != nil {
		return errors.New("invalid input")
	}
	host, port, err := model.ParseAccessAddress(cfg.Server)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	enc := json.NewEncoder(os.Stdout)
	sess, err := vpn.NewEasyConnectConnector("")(ctx, model.AccessPoint{Server: host, Port: port, Username: cfg.Username, Protocol: model.ProtocolEasyConnect, CertificateSHA256: cfg.CertificateSHA256}, vpn.Credentials{Login: cfg.Password, Challenge: func(ctx context.Context, ch vpn.Challenge) (string, error) {
		if err := enc.Encode(map[string]any{"type": "challenge", "id": ch.ID, "kind": ch.Kind, "image": ch.Image}); err != nil {
			return "", err
		}
		answer := make(chan string, 1)
		go func() {
			if scanner.Scan() {
				answer <- scanner.Text()
			} else {
				answer <- ""
			}
		}()
		select {
		case value := <-answer:
			if value == "" {
				return "", context.Canceled
			}
			return value, nil
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}})
	cfg.Password = ""
	if err != nil {
		return err
	}
	defer sess.Close()
	p := localproxy.New(localproxy.Options{Addr: "127.0.0.1:0", Dial: sess.Dial})
	if err := p.Start(); err != nil {
		return err
	}
	defer p.Close()
	if err := enc.Encode(map[string]any{"type": "ready", "proxy": p.Addr().String(), "info": sess.Info()}); err != nil {
		return err
	}
	if cfg.Target == "" {
		return enc.Encode(map[string]string{"type": "complete", "result": "authentication only; no target configured"})
	}
	u, err := url.Parse(cfg.Target)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return errors.New("invalid test URL")
	}
	for _, scheme := range []string{"socks5", "http"} {
		transport := &http.Transport{DisableKeepAlives: true}
		defer transport.CloseIdleConnections()
		if scheme == "http" {
			pu, _ := url.Parse("http://" + p.Addr().String())
			transport.Proxy = http.ProxyURL(pu)
		} else {
			d, err := proxy.SOCKS5("tcp", p.Addr().String(), nil, &net.Dialer{Timeout: 20 * time.Second})
			if err != nil {
				return err
			}
			transport.DialContext = d.(proxy.ContextDialer).DialContext
		}
		client := &http.Client{Transport: transport, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		resp, err := client.Get(cfg.Target)
		if err != nil {
			return fmt.Errorf("%s request failed: %w", scheme, err)
		}
		n, readErr := io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		_ = resp.Body.Close()
		if readErr != nil {
			return readErr
		}
		if err := enc.Encode(map[string]any{"type": "probe", "proxy": scheme, "status": resp.StatusCode, "bytes": n}); err != nil {
			return err
		}
	}
	return enc.Encode(map[string]string{"type": "complete"})
}
