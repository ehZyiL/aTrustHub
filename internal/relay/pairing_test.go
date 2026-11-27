package relay

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ehzyil/connect-hub/internal/relay/contract"
)

type memoryDevices struct {
	mu      sync.Mutex
	devices []contract.PairedDevice
	fail    bool
	lost    bool
	writes  int
}

func (m *memoryDevices) LoadDevices(context.Context, string) ([]contract.PairedDevice, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]contract.PairedDevice(nil), m.devices...), nil
}
func (m *memoryDevices) SaveDevices(_ context.Context, _ string, d []contract.PairedDevice) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.writes++
	if m.fail {
		return errors.New("injected storage failure")
	}
	m.devices = append([]contract.PairedDevice(nil), d...)
	if m.lost {
		m.lost = false
		return errors.New("injected response loss")
	}
	return nil
}

func addPending(t *testing.T, p *pairingState, inv *invitationRecord) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := randomToken()
	p.requests[id] = &pairRecord{view: contract.PairRequest{ID: id, DeviceID: deviceID(pub), State: "pending", ExpiresAt: p.now().Add(contract.PairRequestLifetime)}, pub: pub, invite: inv}
	return id
}

func TestPairApprovalAtomicCapacityAndIdempotence(t *testing.T) {
	store := &memoryDevices{}
	p, _ := newPairingState(context.Background(), store, "share", "fp", func(string) {})
	inv := &invitationRecord{view: contract.Invitation{Capacity: 5, ExpiresAt: time.Now().Add(time.Minute)}}
	p.invite = inv
	ids := make([]string, 16)
	for i := range ids {
		ids[i] = addPending(t, p, inv)
	}
	var successes atomic.Int64
	var wg sync.WaitGroup
	for _, id := range ids {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			if _, err := p.control(context.Background(), contract.PairCommand{Operation: "approve", ID: id}); err == nil {
				successes.Add(1)
			}
		}(id)
	}
	wg.Wait()
	if successes.Load() != 5 || len(p.devices) != 5 || inv.view.Approved != 5 {
		t.Fatalf("success=%d devices=%d used=%d", successes.Load(), len(p.devices), inv.view.Approved)
	}
	for id, r := range p.requests {
		if r.view.State == "approved" {
			for range 3 {
				if _, err := p.control(context.Background(), contract.PairCommand{Operation: "approve", ID: id}); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	if inv.view.Approved != 5 || store.writes != 5 {
		t.Fatalf("duplicate approval consumed quota: %d/%d", inv.view.Approved, store.writes)
	}
}

func TestPairPersistenceFailureAndLostResponse(t *testing.T) {
	for _, lost := range []bool{false, true} {
		t.Run(map[bool]string{false: "write-failure", true: "response-loss"}[lost], func(t *testing.T) {
			store := &memoryDevices{fail: !lost, lost: lost}
			p, _ := newPairingState(context.Background(), store, "s", "f", func(string) {})
			inv := &invitationRecord{view: contract.Invitation{Capacity: 5}}
			p.invite = inv
			id := addPending(t, p, inv)
			if _, err := p.control(context.Background(), contract.PairCommand{Operation: "approve", ID: id}); err == nil {
				t.Fatal("failed persistence returned success")
			}
			if inv.view.Approved != 0 || len(p.devices) != 0 || p.requests[id].view.State != "pending" {
				t.Fatal("failed persistence committed approval")
			}
			store.mu.Lock()
			store.fail = false
			store.mu.Unlock()
			if _, err := p.control(context.Background(), contract.PairCommand{Operation: "approve", ID: id}); err != nil {
				t.Fatal(err)
			}
			if inv.view.Approved != 1 || len(p.devices) != 1 || len(store.devices) != 1 {
				t.Fatal("reconciliation lost idempotence")
			}
		})
	}
}

func TestPairInvitationIndependentRequestAndRestart(t *testing.T) {
	store := &memoryDevices{}
	p, _ := newPairingState(context.Background(), store, "s", "f", func(string) {})
	inv := &invitationRecord{view: contract.Invitation{Capacity: 1, ExpiresAt: time.Now().Add(-time.Second)}}
	p.invite = inv
	id := addPending(t, p, inv)
	if p.activeInviteLocked() {
		t.Fatal("expired invitation accepted new pairing")
	}
	if _, err := p.control(context.Background(), contract.PairCommand{Operation: "approve", ID: id}); err != nil {
		t.Fatal(err)
	}
	other := &invitationRecord{view: contract.Invitation{Capacity: 5}}
	p.invite = other
	if inv.view.Approved != 1 || other.view.Approved != 0 {
		t.Fatal("request moved to replacement invitation")
	}
	copy, err := newPairingState(context.Background(), store, "s", "f", func(string) {})
	if err != nil {
		t.Fatal(err)
	}
	if copy.invite != nil || len(copy.requests) != 0 || len(copy.devices) != 1 {
		t.Fatal("restart did not clear only ephemeral state")
	}
	p.now = func() time.Time { return time.Now().Add(10 * time.Minute) }
	if _, err := p.control(context.Background(), contract.PairCommand{Operation: "approve", ID: id}); err == nil {
		t.Fatal("expired request accepted")
	}
}

func pairFixture(t *testing.T) (*Server, contract.PairTarget, contract.PairView, *memoryDevices) {
	t.Helper()
	identity, err := GenerateIdentity("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	echo, closeEcho := echoServer(t)
	t.Cleanup(closeEcho)
	src := newFakeSource(testSnapshot())
	src.echo = echo
	sid, _ := randomShareID()
	store := &memoryDevices{}
	s, err := StartServer(ServerOptions{Identity: identity, Source: src, ShareID: sid, Token: "legacy-token", DeviceStore: store})
	if err != nil {
		t.Fatal(err)
	}
	s.pairRate = newRateLimiter(6000, 100, 6000, 100)
	s.auth = newRateLimiter(6000, 100, 6000, 100)
	t.Cleanup(func() { _ = s.Close(context.Background()) })
	view, err := s.PairControl(context.Background(), contract.PairCommand{Operation: "create"})
	if err != nil {
		t.Fatal(err)
	}
	if len(view.PIN) != 8 || view.Invitation.Capacity != 5 {
		t.Fatal("wrong invitation defaults")
	}
	return s, contract.PairTarget{Host: "127.0.0.1", Port: s.Port(), ShareID: sid, Name: "same untrusted name"}, view, store
}

func approvePair(t *testing.T, s *Server, target contract.PairTarget, pin string) (*PairConnection, *Client, string) {
	t.Helper()
	p, err := StartPair(context.Background(), target, pin)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.Close() })
	v, err := s.PairControl(context.Background(), contract.PairCommand{Operation: "list"})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range v.Requests {
		if r.ID == p.View().ID {
			found = r.Verification == p.View().Verification && r.DeviceID == p.View().DeviceID
		}
	}
	if !found {
		t.Fatal("SAS/device mismatch")
	}
	if _, err = s.PairControl(context.Background(), contract.PairCommand{Operation: "approve", ID: p.View().ID}); err != nil {
		t.Fatal(err)
	}
	if _, err = p.Poll(); err != nil {
		t.Fatal(err)
	}
	code, err := p.Code()
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewClient(ClientOptions{Code: code})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	_, token, err := c.Open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return p, c, token
}

func TestPairEndToEndReclaimRevokeIsolationAndV1(t *testing.T) {
	s, target, invite, store := pairFixture(t)
	p1, c1, token1 := approvePair(t, s, target, invite.PIN)
	p2, c2, token2 := approvePair(t, s, target, invite.PIN)
	if p1.View().DeviceID == p2.View().DeviceID {
		t.Fatal("self-reported name became identity")
	}
	// Lost receipt/ack does not lose the client-generated credential; even a
	// fresh Client can authenticate without the PIN or PAKE session key.
	code, _ := p1.Code()
	p1.Close()
	fresh, err := NewClient(ClientOptions{Code: code})
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	for range 3 {
		if _, _, err = fresh.Open(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if s.ActiveClients() != 2 {
		t.Fatalf("reconnect inflated online devices: %d", s.ActiveClients())
	}
	_, token1, err = c1.Open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	tunnel, err := c1.Dial(context.Background(), token1, 1, testSnapshot().Revision, "10.1.2.3:443")
	if err != nil {
		t.Fatal(err)
	}
	defer tunnel.Close()
	if _, err = s.PairControl(context.Background(), contract.PairCommand{Operation: "revoke", ID: p1.View().DeviceID}); err != nil {
		t.Fatal(err)
	}
	if _, _, err = c1.Open(context.Background()); err == nil {
		t.Fatal("revoked device reauthenticated")
	}
	if _, err = c1.Status(context.Background(), token1); err == nil {
		t.Fatal("revoked lease survived")
	}
	_ = tunnel.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 1)
	if _, err = tunnel.Read(buf); err == nil {
		t.Fatal("revoked tunnel survived")
	}
	if _, err = c2.Status(context.Background(), token2); err != nil {
		t.Fatalf("other device revoked: %v", err)
	}
	if err = p2.Ack(); err != nil {
		t.Fatal(err)
	}
	if _, err = s.PairControl(context.Background(), contract.PairCommand{Operation: "cancel"}); err != nil {
		t.Fatal(err)
	}
	if _, _, err = c2.Open(context.Background()); err != nil {
		t.Fatal("cancelled invitation revoked device", err)
	}
	if len(store.devices) != 1 {
		t.Fatal("wrong durable revocation")
	}
	legacy, err := NewClient(ClientOptions{Code: ShareCode{Version: 1, Host: target.Host, Port: target.Port, ShareID: target.ShareID, Fingerprint: s.identity.Fingerprint, Token: "legacy-token"}})
	if err != nil {
		t.Fatal(err)
	}
	defer legacy.Close()
	if _, _, err = legacy.Open(context.Background()); err != nil {
		t.Fatal("v1 compatibility", err)
	}
}

func TestPairWrongCodeNoRequestAndNoSecretDisclosure(t *testing.T) {
	s, target, invite, _ := pairFixture(t)
	wrong := "00000000"
	if invite.PIN == wrong {
		wrong = "11111111"
	}
	if _, err := StartPair(context.Background(), target, wrong); err == nil {
		t.Fatal("wrong PIN authenticated")
	}
	v, _ := s.PairControl(context.Background(), contract.PairCommand{Operation: "list"})
	if len(v.Requests) != 0 || len(v.Devices) != 0 || s.ActiveClients() != 0 || s.conns.count() != 0 {
		t.Fatal("unauthenticated traffic consumed business capacity")
	}
	data, _ := json.Marshal(v)
	if strings.Contains(string(data), invite.PIN) || strings.Contains(string(data), "legacy-token") {
		t.Fatal("snapshot disclosed secret")
	}
	if p, err := StartPair(context.Background(), target, invite.PIN); err != nil {
		t.Fatal("wrong attempt invalidated invitation", err)
	} else {
		p.Close()
	}
}

func TestPairChannelBindingAndReplay(t *testing.T) {
	s, target, invite, _ := pairFixture(t)
	p, err := StartPair(context.Background(), target, invite.PIN)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	// Role separation, sequence numbers and MACs reject replay/tampering.
	mac := pairMAC(p.key, "client", 1, []byte(`"poll"`))
	if string(mac) == string(pairMAC(p.key, "server", 1, []byte(`"poll"`))) || string(mac) == string(pairMAC(p.key, "client", 2, []byte(`"poll"`))) {
		t.Fatal("MAC did not bind direction/sequence")
	}
	_ = p.ws.WriteJSON(pairFrame{Sequence: 1, Payload: []byte(`"poll"`), MAC: mac})
	var v contract.PairRequest
	if err = readPairFrame(p.ws, p.key, "server", 2, &v); err != nil {
		t.Fatal(err)
	}
	_ = p.ws.WriteJSON(pairFrame{Sequence: 1, Payload: []byte(`"poll"`), MAC: mac})
	if err = readPairFrame(p.ws, p.key, "server", 3, &v); err == nil {
		t.Fatal("replayed poll accepted")
	}
	// Two independent TLS sessions yield different exporter-bound proofs.
	var states []tls.ConnectionState
	for range 2 {
		cfg, _ := ClientTLSConfig(s.identity.Fingerprint, target.Host)
		conn, err := tls.Dial("tcp", net.JoinHostPort(target.Host, strconvPort(target.Port)), cfg)
		if err != nil {
			t.Fatal(err)
		}
		states = append(states, conn.ConnectionState())
		conn.Close()
	}
	a, _ := deviceProof(&states[0], target.ShareID, s.identity.Fingerprint)
	b, _ := deviceProof(&states[1], target.ShareID, s.identity.Fingerprint)
	if string(a) == string(b) {
		t.Fatal("proof not bound to TLS connection")
	}
}

func strconvPort(p int) string { return itoa(p) }

// Keep io linked here for the byte-stream verification helper used below.
var _ = io.EOF
