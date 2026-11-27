package relay

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"time"
)

type deviceSessionRequest struct {
	PublicKey []byte
	Signature []byte
}

func deviceProof(state *tls.ConnectionState, sid, fp string) ([]byte, error) {
	if state == nil || state.Version < tls.VersionTLS13 {
		return nil, errors.New("TLS 1.3 required")
	}
	exporter, err := state.ExportKeyingMaterial("EXPORTER-connect-hub-device-v2", nil, 32)
	if err != nil {
		return nil, err
	}
	encoded, _ := json.Marshal(struct {
		Domain, ShareID, Fingerprint string
		Exporter                     []byte
	}{"connect-hub/device-session/v2", sid, fp, exporter})
	sum := sha256.Sum256(encoded)
	return sum[:], nil
}

func (s *Server) handleDeviceSession(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Connection", "close")
	if r.Method != http.MethodPost {
		writeError(w, NewError(CodeInvalidRequest, "只支持 POST"))
		return
	}
	if !s.auth.allow(clientIP(r)) {
		writeError(w, NewError(CodeBusy, "认证请求过于频繁"))
		return
	}
	body, err := readBounded(r.Body, MaxSessionBody)
	if err != nil {
		writeError(w, err)
		return
	}
	var req deviceSessionRequest
	if decodeStrictJSON(body, &req) != nil || len(req.PublicKey) != ed25519.PublicKeySize {
		writeError(w, NewError(CodeInvalidCredentials, "设备凭据无效"))
		return
	}
	proof, err := deviceProof(r.TLS, s.shareID, s.identity.Fingerprint)
	if err != nil || !ed25519.Verify(req.PublicKey, proof, req.Signature) {
		writeError(w, NewError(CodeInvalidCredentials, "设备身份认证失败"))
		return
	}
	p := s.pairing
	// Authorization and lease creation serialize with revocation, so a late
	// successful signature cannot recreate a lease after RevokeDevice returns.
	p.mu.Lock()
	defer p.mu.Unlock()
	d := p.devices[deviceID(req.PublicKey)]
	if d.ID == "" || p.denied[d.ID] {
		writeError(w, NewError(CodeInvalidCredentials, "设备授权已撤销或尚未确认"))
		return
	}
	if err := promoteConnection(r, connectionControl); err != nil {
		writeError(w, err)
		return
	}
	snap, err := s.snapshot(r.Context())
	if err != nil {
		writeError(w, err)
		return
	}
	if err = snap.Validate(); err != nil {
		writeError(w, err)
		return
	}
	token, err := randomToken()
	if err != nil {
		writeError(w, NewError(CodeBusy, "无法生成会话凭据"))
		return
	}
	id := "device:" + d.ID
	if _, err = s.clients.create(id, d.Name, token, time.Now()); err == errReauth {
		s.clients.replace(id, d.Name, token, time.Now())
	} else if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, SessionResponse{Version: ProtocolVersion, ShareID: s.shareID, ServerInstanceID: s.instance, ClientID: id, ClientToken: token, Epoch: snap.Epoch, Revision: snap.Revision, Capabilities: snap.Capabilities, LeaseSeconds: int(s.clients.lease.Seconds()), Resources: snap.Resources})
}

// deviceSession uses one freshly pinned TLS connection. Its proof cannot be
// replayed on another HTTP connection, nor reused by an automatic retry.
func (c *Client) deviceSession(ctx context.Context) (SessionResponse, error) {
	var out SessionResponse
	seed, err := base64.RawURLEncoding.DecodeString(c.code.Token)
	if err != nil || len(seed) != ed25519.SeedSize {
		return out, NewError(CodeInvalidCredentials, "设备私钥不可用，请重新配对")
	}
	private := ed25519.NewKeyFromSeed(seed)
	raw, err := c.dial(ctx, "tcp", c.code.Address())
	if err != nil {
		return out, err
	}
	defer raw.Close()
	conn := tls.Client(raw, c.tlsConfig.Clone())
	if err = conn.HandshakeContext(ctx); err != nil {
		return out, err
	}
	state := conn.ConnectionState()
	proof, err := deviceProof(&state, c.code.ShareID, c.code.Fingerprint)
	if err != nil {
		return out, err
	}
	data, _ := json.Marshal(deviceSessionRequest{private.Public().(ed25519.PublicKey), ed25519.Sign(private, proof)})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/v2/sessions", bytes.NewReader(data))
	if err != nil {
		return out, err
	}
	c.setHeaders(req)
	req.Close = true
	deadline := time.Now().Add(ControlTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	if err = req.Write(conn); err != nil {
		return out, err
	}
	resp, err := http.ReadResponse(bufioReader(conn), req)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	body, err := readBounded(resp.Body, MaxSnapshotBytes+MaxErrorBody)
	if err != nil {
		return out, err
	}
	if resp.StatusCode != http.StatusOK {
		return out, decodeError(resp.StatusCode, body)
	}
	err = json.Unmarshal(body, &out)
	return out, err
}
