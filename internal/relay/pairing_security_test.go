package relay

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ehzyil/connect-hub/internal/relay/contract"
	"github.com/gorilla/websocket"
)

func TestPairCheckpointPrecedesRequestAndSurvivesLostApproval(t *testing.T) {
	s, target, invite, _ := pairFixture(t)
	var stored ShareCode
	p, err := StartPairWithCheckpoint(context.Background(), target, invite.PIN, func(code ShareCode) error {
		v, err := s.PairControl(context.Background(), contract.PairCommand{Operation: "list"})
		if err != nil || len(v.Requests) != 0 {
			t.Fatal("host can approve before client checkpoint", err)
		}
		stored = code
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if _, err = s.PairControl(context.Background(), contract.PairCommand{Operation: "approve", ID: p.View().ID}); err != nil {
		t.Fatal(err)
	}
	// Lose the entire approval response, not just the acknowledgement.
	p.Close()
	c, err := NewClient(ClientOptions{Code: stored})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, _, err = c.Open(context.Background()); err != nil {
		t.Fatal("pre-confirmation checkpoint cannot reclaim durable grant", err)
	}
	if stored.String() != "" {
		t.Fatal("private device credential exported as share code")
	}
	before, _ := s.PairControl(context.Background(), contract.PairCommand{Operation: "list"})
	_, err = StartPairWithCheckpoint(context.Background(), target, invite.PIN, func(ShareCode) error {
		return errors.New("injected local credential failure")
	})
	if err == nil {
		t.Fatal("failed checkpoint continued handshake")
	}
	after, _ := s.PairControl(context.Background(), contract.PairCommand{Operation: "list"})
	if len(after.Requests) != len(before.Requests) || after.Invitation.Approved != 1 {
		t.Fatal("failed checkpoint created an approvable request")
	}
}

func TestPairDeviceProofReplayRejectedByEndpoint(t *testing.T) {
	s, target, invite, _ := pairFixture(t)
	p, _, _ := approvePair(t, s, target, invite.PIN)
	code, _ := p.Code()
	seed, _ := base64.RawURLEncoding.DecodeString(code.Token)
	private := ed25519.NewKeyFromSeed(seed)
	cfg, _ := ClientTLSConfig(s.identity.Fingerprint, target.Host)
	dial := func() *tls.Conn {
		t.Helper()
		conn, err := tls.Dial("tcp", net.JoinHostPort(target.Host, strconv.Itoa(target.Port)), cfg)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { conn.Close() })
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		return conn
	}
	first := dial()
	state := first.ConnectionState()
	proof, _ := deviceProof(&state, target.ShareID, s.identity.Fingerprint)
	data, _ := json.Marshal(deviceSessionRequest{private.Public().(ed25519.PublicKey), ed25519.Sign(private, proof)})
	post := func(conn *tls.Conn) int {
		t.Helper()
		req, _ := http.NewRequest(http.MethodPost, "https://"+code.Address()+"/v2/sessions", bytes.NewReader(data))
		req.Close = true
		if err := req.Write(conn); err != nil {
			t.Fatal(err)
		}
		resp, err := http.ReadResponse(bufioReader(conn), req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}
	if status := post(first); status != http.StatusOK {
		t.Fatal("original proof failed", status)
	}
	if status := post(dial()); status != http.StatusUnauthorized {
		t.Fatal("cross-connection replay not rejected", status)
	}
	if s.ActiveClients() != 1 {
		t.Fatal("replay changed authenticated device count")
	}
}

func TestPairMITMRelayCannotAuthenticateEvenWithRewrittenIdentity(t *testing.T) {
	s, target, invite, _ := pairFixture(t)
	identity, _ := GenerateIdentity("127.0.0.1")
	serverTLS, err := ServerTLSConfig(identity)
	if err != nil {
		t.Fatal(err)
	}
	backendTLS, _ := ClientTLSConfig(s.identity.Fingerprint, target.Host)
	forwarded := make(chan struct{}, 1)
	proxy := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		up, _, err := (&websocket.Dialer{TLSClientConfig: backendTLS}).Dial("wss://"+net.JoinHostPort(target.Host, strconv.Itoa(target.Port))+"/v2/pair/start", nil)
		if err != nil {
			return
		}
		defer up.Close()
		down, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer down.Close()
		_ = up.SetReadDeadline(time.Now().Add(3 * time.Second))
		_ = down.SetReadDeadline(time.Now().Add(3 * time.Second))
		var hello pairHello
		if up.ReadJSON(&hello) != nil {
			return
		}
		fake := hello
		fake.Fingerprint = identity.Fingerprint
		if down.WriteJSON(fake) != nil {
			return
		}
		var start pairStart
		if down.ReadJSON(&start) != nil {
			return
		}
		// The attacker substitutes a key it controls, proves possession on the
		// upstream connection, and relays the honest client's KE1/KE2 unchanged.
		// OPAQUE's transcript context must still prevent this identity splice.
		pub, priv, _ := ed25519.GenerateKey(nil)
		start.PublicKey = pub
		upState := up.UnderlyingConn().(*tls.Conn).ConnectionState()
		binding, _ := pairingBinding(&upState, hello, start)
		start.Signature = ed25519.Sign(priv, binding)
		if up.WriteJSON(start) != nil {
			return
		}
		var ke2 []byte
		if up.ReadJSON(&ke2) != nil {
			return
		}
		forwarded <- struct{}{}
		_ = down.WriteJSON(ke2)
		var ke3 []byte
		if down.ReadJSON(&ke3) == nil {
			_ = up.WriteJSON(ke3)
		}
	}))
	proxy.TLS = serverTLS
	proxy.StartTLS()
	defer proxy.Close()
	_, port, _ := net.SplitHostPort(proxy.Listener.Addr().String())
	attacked := target
	attacked.Port, _ = strconv.Atoi(port)
	if _, err := StartPair(context.Background(), attacked, invite.PIN); err == nil || !strings.Contains(err.Error(), "pair_auth_failed") {
		t.Fatal("MITM authenticated or failed before PAKE verification", err)
	}
	select {
	case <-forwarded:
	default:
		t.Fatal("test did not relay a real OPAQUE exchange")
	}
	v, _ := s.PairControl(context.Background(), contract.PairCommand{Operation: "list"})
	if len(v.Requests) != 0 || len(v.Devices) != 0 {
		t.Fatal("MITM created an approvable request")
	}
}

func TestPairPublicKeyClaimWithoutPossessionIsRejected(t *testing.T) {
	s, target, invite, _ := pairFixture(t)
	p, _, _ := approvePair(t, s, target, invite.PIN)
	code, _ := p.Code()
	seed, _ := base64.RawURLEncoding.DecodeString(code.Token)
	victim := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	cfg, _ := ClientTLSConfig(s.identity.Fingerprint, target.Host)
	ws, _, err := (&websocket.Dialer{TLSClientConfig: cfg}).Dial("wss://"+code.Address()+"/v2/pair/start", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()
	_ = ws.SetReadDeadline(time.Now().Add(3 * time.Second))
	var hello pairHello
	if ws.ReadJSON(&hello) != nil {
		t.Fatal("missing hello")
	}
	cli, _ := opaqueConfig(nil).Client()
	defer cli.ClearState()
	ke1, _ := cli.GenerateKE1([]byte(invite.PIN))
	_ = ws.WriteJSON(pairStart{PublicKey: victim, Name: "impersonator", KE1: ke1.Serialize()})
	var ke2 []byte
	if ws.ReadJSON(&ke2) == nil {
		t.Fatal("self-reported public key proceeded without proof of possession")
	}
	v, _ := s.PairControl(context.Background(), contract.PairCommand{Operation: "list"})
	if len(v.Requests) != 1 || v.Invitation.Approved != 1 {
		t.Fatal("identity spoof changed approval state")
	}
}

func TestPairAdministrationIsNotExposedToRemotePeers(t *testing.T) {
	s, target, _, _ := pairFixture(t)
	cfg, _ := ClientTLSConfig(s.identity.Fingerprint, target.Host)
	transport := &http.Transport{TLSClientConfig: cfg}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	for _, path := range []string{"/v2/pair/approve", "/v2/pair/create", "/devices", "/v2/devices/revoke"} {
		response, err := client.Post("https://"+net.JoinHostPort(target.Host, strconv.Itoa(target.Port))+path, "application/json", strings.NewReader(`{}`))
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != http.StatusNotFound {
			t.Fatal("remote admin route exists", path, response.StatusCode)
		}
	}
}
