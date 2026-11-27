package relay

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/bytemare/opaque"
	"github.com/ehzyil/connect-hub/internal/relay/contract"
	"github.com/gorilla/websocket"
)

const pairExporterLabel = "EXPORTER-connect-hub-pair-v2"

type pairHello struct{ InviteID, ShareID, Fingerprint string }
type pairStart struct {
	PublicKey []byte
	Name      string
	KE1       []byte
	Signature []byte
}
type pairFrame struct {
	Sequence uint64
	Payload  []byte
	MAC      []byte
}

func opaqueConfig(binding []byte) *opaque.Configuration {
	c := opaque.DefaultConfiguration()
	c.Context = binding
	return c
}
func serverPairIdentity(sid, fp string) []byte {
	return []byte("connect-hub/pair/v2/" + sid + "/" + fp)
}
func inviteClientIdentity(id string) []byte { return []byte("invitation/" + id) }

func newInvitation(pin, sid, fp string, now time.Time) (*invitationRecord, error) {
	id, err := randomToken()
	if err != nil {
		return nil, err
	}
	cfg := opaqueConfig(nil)
	sk, pk := cfg.KeyGen()
	material := &opaque.ServerKeyMaterial{Identity: serverPairIdentity(sid, fp), PrivateKey: sk, PublicKeyBytes: pk.Encode(), OPRFGlobalSeed: cfg.GenerateOPRFSeed()}
	srv, err := cfg.Server()
	if err != nil {
		return nil, err
	}
	if err = srv.SetKeyMaterial(material); err != nil {
		return nil, err
	}
	cli, err := cfg.Client()
	if err != nil {
		return nil, err
	}
	defer cli.ClearState()
	req, err := cli.RegistrationInit([]byte(pin))
	if err != nil {
		return nil, err
	}
	resp, err := srv.RegistrationResponse(req, []byte(id), nil)
	if err != nil {
		return nil, err
	}
	rec, _, err := cli.RegistrationFinalize(resp, inviteClientIdentity(id), material.Identity)
	if err != nil {
		return nil, err
	}
	return &invitationRecord{view: contract.Invitation{ID: id, ExpiresAt: now.Add(contract.InviteLifetime), Capacity: contract.InviteCapacity}, material: material, record: &opaque.ClientRecord{CredentialIdentifier: []byte(id), ClientIdentity: inviteClientIdentity(id), RegistrationRecord: rec}}, nil
}

// All PAKE messages and approval polling stay on this one dedicated TLS 1.3
// WebSocket. No HTTP transport can silently reconnect it. RFC 9807 Context
// commits the TLS exporter, host certificate, invitation, and device key/name.
func pairingBinding(state *tls.ConnectionState, hello pairHello, start pairStart) ([]byte, error) {
	if state == nil || state.Version < tls.VersionTLS13 {
		return nil, errors.New("TLS 1.3 required")
	}
	exporter, err := state.ExportKeyingMaterial(pairExporterLabel, nil, 32)
	if err != nil {
		return nil, err
	}
	encoded, _ := json.Marshal(struct {
		Domain    string
		Hello     pairHello
		PublicKey []byte
		Name      string
		Exporter  []byte
	}{"connect-hub/pair/v2", hello, start.PublicKey, start.Name, exporter})
	sum := sha256.Sum256(encoded)
	return sum[:], nil
}

func pairMAC(key []byte, role string, sequence uint64, payload []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte("connect-hub/pair/v2/" + role + "/" + strconv.FormatUint(sequence, 10) + "/"))
	h.Write(payload)
	return h.Sum(nil)
}

func writePairFrame(ws *websocket.Conn, key []byte, role string, seq uint64, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	_ = ws.SetWriteDeadline(time.Now().Add(ControlTimeout))
	return ws.WriteJSON(pairFrame{seq, data, pairMAC(key, role, seq, data)})
}

func readPairFrame(ws *websocket.Conn, key []byte, role string, seq uint64, value any) error {
	var f pairFrame
	if err := ws.ReadJSON(&f); err != nil {
		return err
	}
	if f.Sequence != seq || !hmac.Equal(f.MAC, pairMAC(key, role, seq, f.Payload)) {
		return errors.New("pair_auth_failed: 配对消息认证失败")
	}
	return decodeStrictJSON(f.Payload, value)
}

func pairVerification(key []byte) string {
	return hex.EncodeToString(pairMAC(key, "verify", 0, nil)[:6])
}

func (s *Server) handlePairStart(w http.ResponseWriter, r *http.Request) {
	if !s.pairRate.allow(clientIP(r)) {
		http.Error(w, "pair_rate_limited", http.StatusTooManyRequests)
		return
	}
	select {
	case s.pairSlots <- struct{}{}:
	default:
		http.Error(w, "pair_busy", http.StatusTooManyRequests)
		return
	}
	handshaking := true
	defer func() {
		if handshaking {
			<-s.pairSlots
		}
	}()
	p := s.pairing
	p.mu.Lock()
	p.expireLocked()
	if !p.activeInviteLocked() || len(p.requests) >= contract.MaxPairRequests || p.pendingApply != nil {
		p.mu.Unlock()
		http.Error(w, "invite_unavailable", http.StatusGone)
		return
	}
	inv := p.invite
	p.mu.Unlock()
	extendPairHandshake(r)
	ws, err := (&websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return r.Header.Get("Origin") == "" }, HandshakeTimeout: TLSHandshakeTimeout}).Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer ws.Close()
	// Hijacked sockets are otherwise outside http.Server.Close's ownership.
	stop := context.AfterFunc(s.root, func() { _ = ws.Close() })
	defer stop()
	ws.SetReadLimit(8 << 10)
	deadline := time.Now().Add(contract.PairHandshakeLifetime)
	_ = ws.SetReadDeadline(deadline)
	_ = ws.SetWriteDeadline(deadline)
	hello := pairHello{inv.view.ID, s.shareID, s.identity.Fingerprint}
	if ws.WriteJSON(hello) != nil {
		return
	}
	var start pairStart
	if ws.ReadJSON(&start) != nil || len(start.PublicKey) != ed25519.PublicKeySize || len(start.Name) > 160 {
		return
	}
	start.Name = sanitizeClientName(start.Name)
	binding, err := pairingBinding(r.TLS, hello, start)
	if err != nil || !ed25519.Verify(start.PublicKey, binding, start.Signature) {
		return
	}
	srv, err := opaqueConfig(binding).Server()
	if err != nil {
		return
	}
	if srv.SetKeyMaterial(inv.material) != nil {
		return
	}
	ke1, err := srv.Deserialize.KE1(start.KE1)
	if err != nil {
		return
	}
	ke2, output, err := srv.GenerateKE2(ke1, inv.record)
	if err != nil {
		return
	}
	if ws.WriteJSON(ke2.Serialize()) != nil {
		return
	}
	var encoded []byte
	if ws.ReadJSON(&encoded) != nil {
		return
	}
	ke3, err := srv.Deserialize.KE3(encoded)
	if err != nil || srv.LoginFinish(ke3, output.ClientMAC) != nil {
		return
	}
	if promoteConnection(r, connectionPair) != nil {
		return
	}
	id, err := randomToken()
	if err != nil {
		return
	}
	p.mu.Lock()
	p.expireLocked()
	if p.invite != inv || !p.activeInviteLocked() || len(p.requests) >= contract.MaxPairRequests || p.pendingApply != nil {
		p.mu.Unlock()
		return
	}
	rec := &pairRecord{view: contract.PairRequest{ID: id, DeviceID: deviceID(start.PublicKey), Name: start.Name, Source: clientIP(r), Verification: pairVerification(output.SessionSecret), State: "pending", ExpiresAt: p.now().Add(contract.PairRequestLifetime)}, pub: append([]byte(nil), start.PublicKey...), key: output.SessionSecret, invite: inv}
	// A duplicate authenticated key cannot take another device's request or
	// spend another invitation slot. The fresh transcript has its own SAS.
	if p.devices[rec.view.DeviceID].ID != "" {
		rec.view.State = "approved"
	}
	p.requests[id] = rec
	p.mu.Unlock()
	// Authenticated pending channels have the separate request bound. They do
	// not occupy the smaller unauthenticated, expensive-PAKE handshake budget.
	<-s.pairSlots
	handshaking = false
	for seq := uint64(1); ; seq++ {
		p.mu.Lock()
		p.expireLocked()
		current := p.requests[id]
		view := rec.view
		if current == nil {
			view.State = "expired"
		}
		p.mu.Unlock()
		if err := writePairFrame(ws, rec.key, "server", seq, view); err != nil {
			return
		}
		_ = ws.SetReadDeadline(rec.view.ExpiresAt)
		var action string
		if readPairFrame(ws, rec.key, "client", seq, &action) != nil {
			return
		}
		if action == "ack" {
			p.mu.Lock()
			if rec.view.State == "approved" && p.devices[rec.view.DeviceID].ID != "" && p.pendingApply == nil {
				rec.view.State = "claimed"
			}
			ack := rec.view
			p.mu.Unlock()
			_ = writePairFrame(ws, rec.key, "server", seq+1, ack)
			return
		}
		if action != "poll" {
			return
		}
		// Bound work per authenticated request as well as per source/global
		// handshakes. No failed attempt cancels the invitation globally.
		select {
		case <-time.After(contract.PairPollInterval):
		case <-s.root.Done():
			return
		}
	}
}

// PairConnection owns a single PAKE channel. The private key is generated by
// the client; only its public verifier reaches the host. Approval never issues
// or reissues a plaintext credential, which makes receipt loss harmless.
type PairConnection struct {
	ws       *websocket.Conn
	key      []byte
	code     ShareCode
	view     contract.PairRequest
	sequence uint64
}

func StartPair(ctx context.Context, target contract.PairTarget, pin string) (*PairConnection, error) {
	return StartPairWithCheckpoint(ctx, target, pin, nil)
}

// The production IPC callback durably stores the private key and authenticated
// host pin BEFORE KE3 can create a request. Losing any later response or ack
// therefore leaves a credential with which the client can reclaim its grant.
func StartPairWithCheckpoint(ctx context.Context, target contract.PairTarget, pin string, checkpoint func(ShareCode) error) (*PairConnection, error) {
	if len(pin) != contract.InviteDigits {
		return nil, errors.New("invalid_pin: 请输入 8 位数字邀请码")
	}
	for _, c := range pin {
		if c < '0' || c > '9' {
			return nil, errors.New("invalid_pin: 邀请码只能包含数字")
		}
	}
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, err
	}
	var fingerprint string
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{ALPNProtocol}, InsecureSkipVerify: true, VerifyConnection: func(state tls.ConnectionState) error {
		if len(state.PeerCertificates) != 1 {
			return errors.New("pair_certificate_invalid")
		}
		sum := sha256.Sum256(state.PeerCertificates[0].Raw)
		fingerprint = hex.EncodeToString(sum[:])
		// This validates syntax, address, lifetime and usage only. Trust is
		// established below by OPAQUE with this certificate + exporter bound.
		cfg, err := ClientTLSConfig(fingerprint, target.Host)
		if err != nil {
			return err
		}
		return cfg.VerifyConnection(state)
	}}
	d := websocket.Dialer{TLSClientConfig: tlsCfg, HandshakeTimeout: TLSHandshakeTimeout, Proxy: nil}
	address := net.JoinHostPort(target.Host, strconv.Itoa(target.Port))
	ws, response, err := d.DialContext(ctx, "wss://"+address+"/v2/pair/start", nil)
	if err != nil {
		if response != nil {
			switch response.StatusCode {
			case http.StatusTooManyRequests:
				return nil, errors.New("pair_rate_limited: 配对请求过多，请稍后重试")
			case http.StatusGone:
				return nil, errors.New("invite_unavailable: 邀请码已取消、过期、耗尽或队列已满")
			}
		}
		return nil, errors.New("pair_unavailable: 无法开始配对，请检查邀请码是否有效")
	}
	stopHandshake := context.AfterFunc(ctx, func() { _ = ws.Close() })
	defer stopHandshake()
	success := false
	defer func() {
		if !success {
			ws.Close()
		}
	}()
	ws.SetReadLimit(8 << 10)
	_ = ws.SetReadDeadline(time.Now().Add(contract.PairHandshakeLifetime))
	var hello pairHello
	if err = ws.ReadJSON(&hello); err != nil {
		return nil, err
	}
	if hello.ShareID != target.ShareID || hello.Fingerprint != fingerprint {
		return nil, errors.New("pair_identity_mismatch")
	}
	state := ws.UnderlyingConn().(*tls.Conn).ConnectionState()
	start := pairStart{PublicKey: pub, Name: sanitizeClientName(target.Name)}
	binding, err := pairingBinding(&state, hello, start)
	if err != nil {
		return nil, err
	}
	start.Signature = ed25519.Sign(priv, binding)
	cli, err := opaqueConfig(binding).Client()
	if err != nil {
		return nil, err
	}
	defer cli.ClearState()
	ke1, err := cli.GenerateKE1([]byte(pin))
	if err != nil {
		return nil, err
	}
	start.KE1 = ke1.Serialize()
	if err = ws.WriteJSON(start); err != nil {
		return nil, err
	}
	var encoded []byte
	if err = ws.ReadJSON(&encoded); err != nil {
		return nil, err
	}
	ke2, err := cli.Deserialize.KE2(encoded)
	if err != nil {
		return nil, errors.New("pair_auth_failed")
	}
	ke3, key, _, err := cli.GenerateKE3(ke2, inviteClientIdentity(hello.InviteID), serverPairIdentity(hello.ShareID, hello.Fingerprint))
	if err != nil {
		return nil, errors.New("pair_auth_failed: 邀请码错误或通道身份不匹配")
	}
	code := ShareCode{Version: 2, Host: target.Host, Port: target.Port, ShareID: hello.ShareID, Fingerprint: hello.Fingerprint, Name: target.HostName, Token: base64.RawURLEncoding.EncodeToString(priv.Seed())}
	if checkpoint != nil {
		if err := checkpoint(code); err != nil {
			return nil, err
		}
	}
	if err = ws.WriteJSON(ke3.Serialize()); err != nil {
		return nil, err
	}
	var view contract.PairRequest
	if err = readPairFrame(ws, key, "server", 1, &view); err != nil {
		return nil, errors.New("pair_auth_failed: 主机未确认配对")
	}
	if view.DeviceID != deviceID(pub) || view.Verification != pairVerification(key) {
		return nil, errors.New("pair_identity_mismatch")
	}
	_ = ws.SetReadDeadline(view.ExpiresAt)
	success = true
	return &PairConnection{ws: ws, key: key, sequence: 1, view: view, code: code}, nil
}

func (p *PairConnection) View() contract.PairRequest { return p.view }
func (p *PairConnection) Code() (ShareCode, error) {
	if p.view.State != "approved" && p.view.State != "claimed" {
		return ShareCode{}, errors.New("pair_not_approved")
	}
	return p.code, nil
}
func (p *PairConnection) Poll() (contract.PairRequest, error) {
	if err := writePairFrame(p.ws, p.key, "client", p.sequence, "poll"); err != nil {
		return p.view, err
	}
	p.sequence++
	err := readPairFrame(p.ws, p.key, "server", p.sequence, &p.view)
	return p.view, err
}
func (p *PairConnection) Ack() error {
	if p.view.State != "approved" {
		return errors.New("pair_not_approved")
	}
	if err := writePairFrame(p.ws, p.key, "client", p.sequence, "ack"); err != nil {
		return err
	}
	p.sequence++
	if err := readPairFrame(p.ws, p.key, "server", p.sequence, &p.view); err != nil {
		return err
	}
	if p.view.State != "claimed" {
		return fmt.Errorf("pair_ack_failed: %s", p.view.State)
	}
	return nil
}
func (p *PairConnection) Close() error { return p.ws.Close() }
