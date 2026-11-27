package relay

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ehzyil/connect-hub/internal/relay/contract"
)

type pairingPersistence struct {
	*fakePersistence
	*memoryDevices
}

func TestPairPauseRestartResumePreservesDevicesAndLegacyDisable(t *testing.T) {
	ctx := context.Background()
	persist := &pairingPersistence{newFakePersistence(), &memoryDevices{}}
	sink, nets := newFakeSink("p1"), loopbackNets()
	controller := NewController(persist, sink, nets, nil, nil)
	t.Cleanup(func() { controller.Shutdown(ctx) })
	if err := controller.Enable(ctx, EnableOptions{PointID: "p1"}); err != nil {
		t.Fatal(err)
	}
	legacy, err := controller.ShareCode()
	if err != nil {
		t.Fatal(err)
	}
	code, _ := ParseShareCode(legacy)
	invite, err := controller.PairControl(ctx, contract.PairCommand{Operation: "create"})
	if err != nil {
		t.Fatal(err)
	}
	pair, err := StartPair(ctx, contract.PairTarget{Host: code.Host, Port: code.Port, ShareID: code.ShareID, Name: "paused-device"}, invite.PIN)
	if err != nil {
		t.Fatal(err)
	}
	defer pair.Close()
	if _, err = controller.PairControl(ctx, contract.PairCommand{Operation: "approve", ID: pair.View().ID}); err != nil {
		t.Fatal(err)
	}
	if _, err = pair.Poll(); err != nil {
		t.Fatal(err)
	}
	deviceCode, _ := pair.Code()
	if err = controller.PauseSharing(ctx); err != nil {
		t.Fatal(err)
	}
	if !persist.ShareSettings().Paused || !persist.ShareSettings().Enabled {
		t.Fatal("pause destroyed share intent")
	}
	if err = controller.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	controller = NewController(persist, sink, nets, nil, nil)
	if err = controller.Restore(ctx); err != nil {
		t.Fatal(err)
	}
	if controller.server != nil || !controller.View().Paused {
		t.Fatal("paused restart opened a listener")
	}
	v, err := controller.PairControl(ctx, contract.PairCommand{Operation: "list"})
	if err != nil || len(v.Devices) != 1 || len(v.Requests) != 0 || v.Invitation != nil {
		t.Fatal("pause/restart lost grant or retained ephemeral state", err)
	}
	if err = controller.ResumeSharing(ctx); err != nil {
		t.Fatal(err)
	}
	if restored, err := controller.ShareCode(); err != nil || restored != legacy {
		t.Fatal("resume rotated legacy identity", err)
	}
	client, _ := NewClient(ClientOptions{Code: deviceCode})
	defer client.Close()
	if _, _, err = client.Open(ctx); err != nil {
		t.Fatal("resume required a new invite", err)
	}
	if err = controller.Disable(ctx); err != nil {
		t.Fatal(err)
	}
	if persist.ShareSettings().ShareID != "" || persist.secretCount() != 0 {
		t.Fatal("legacy Disable no longer destroys identity")
	}
	if _, _, err = client.Open(ctx); err == nil {
		t.Fatal("disabled share still authenticates")
	}
}

func TestPairPendingQuotaAndHandshakeQuotaAreSeparateFromBusiness(t *testing.T) {
	s, target, invite, _ := pairFixture(t)
	for range contract.MaxPairRequests {
		p, err := StartPair(context.Background(), target, invite.PIN)
		if err != nil {
			t.Fatal("pending requests consumed handshake capacity", err)
		}
		t.Cleanup(func() { p.Close() })
	}
	if _, err := StartPair(context.Background(), target, invite.PIN); err == nil {
		t.Fatal("pending request bound exceeded")
	}
	if s.ActiveClients() != 0 || s.conns.count() != 0 || len(s.pairSlots) != 0 {
		t.Fatal("pending requests consumed business or handshake quota")
	}
	legacy, _ := NewClient(ClientOptions{Code: ShareCode{Version: 1, Host: target.Host, Port: target.Port, ShareID: target.ShareID, Fingerprint: s.identity.Fingerprint, Token: "legacy-token"}})
	defer legacy.Close()
	if _, _, err := legacy.Open(context.Background()); err != nil {
		t.Fatal("pending queue prevented business authentication", err)
	}
	s.pairing.mu.Lock()
	s.pairing.now = func() time.Time { return time.Now().Add(contract.PairRequestLifetime) }
	s.pairing.mu.Unlock()
	v, _ := s.PairControl(context.Background(), contract.PairCommand{Operation: "list"})
	if len(v.Requests) != contract.MaxPairRequests || v.Requests[0].State != "expired" {
		t.Fatal("request timeout not visible")
	}
	if _, err := s.PairControl(context.Background(), contract.PairCommand{Operation: "approve", ID: v.Requests[0].ID}); err == nil || !strings.Contains(err.Error(), "request_expired") {
		t.Fatal("expired request did not report specific failure", err)
	}
}

func TestPairFailedRevokeIsIsolatedAndCannotReauthenticate(t *testing.T) {
	s, target, invite, store := pairFixture(t)
	first, a, _ := approvePair(t, s, target, invite.PIN)
	_, b, _ := approvePair(t, s, target, invite.PIN)
	store.mu.Lock()
	store.fail = true
	store.mu.Unlock()
	if _, err := s.PairControl(context.Background(), contract.PairCommand{Operation: "revoke", ID: first.View().DeviceID}); err == nil {
		t.Fatal("failed revocation persistence reported success")
	}
	if _, _, err := a.Open(context.Background()); err == nil {
		t.Fatal("failed revoke left target authorized")
	}
	if _, _, err := b.Open(context.Background()); err != nil {
		t.Fatal("failed revoke blocked another device", err)
	}
	store.mu.Lock()
	store.fail = false
	store.mu.Unlock()
	v, err := s.PairControl(context.Background(), contract.PairCommand{Operation: "list"})
	if err != nil || len(v.Devices) != 1 || v.Invitation.Approved != 2 {
		t.Fatal("revocation reconciliation changed approval quota", err)
	}
}

func TestPairSourceBackoffDoesNotExhaustGlobalBudget(t *testing.T) {
	r := newRateLimiter(contract.PairRatePerIP, contract.PairBurstPerIP, contract.PairRateGlobal, contract.PairBurstGlobal)
	now := time.Now()
	r.now = func() time.Time { return now }
	for range contract.PairBurstPerIP {
		if !r.allow("attacker") {
			t.Fatal("initial source budget missing")
		}
	}
	for range 100 {
		if r.allow("attacker") {
			t.Fatal("source backoff not enforced")
		}
	}
	if !r.allow("honest-peer") {
		t.Fatal("limited attacker consumed remaining global budget")
	}
	now = now.Add(time.Minute / contract.PairRatePerIP)
	if !r.allow("attacker") {
		t.Fatal("source did not recover after backoff")
	}
}

func TestPairInvitationOnlineAndTunnelBudgetsRemainIndependent(t *testing.T) {
	s, target, invite, _ := pairFixture(t)
	var clients []*Client
	for i := range MaxActiveClients + 1 {
		if i > 0 && i%contract.InviteCapacity == 0 {
			var err error
			invite, err = s.PairControl(context.Background(), contract.PairCommand{Operation: "create"})
			if err != nil {
				t.Fatal(err)
			}
		}
		pair, err := StartPair(context.Background(), target, invite.PIN)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { pair.Close() })
		if _, err = s.PairControl(context.Background(), contract.PairCommand{Operation: "approve", ID: pair.View().ID}); err != nil {
			t.Fatal("online limit incorrectly blocked durable approval", err)
		}
		if _, err = pair.Poll(); err != nil {
			t.Fatal(err)
		}
		code, _ := pair.Code()
		client, _ := NewClient(ClientOptions{Code: code})
		t.Cleanup(client.Close)
		clients = append(clients, client)
		_, _, err = client.Open(context.Background())
		if (i < MaxActiveClients && err != nil) || (i == MaxActiveClients && err == nil) {
			t.Fatal("online device bound not independent of approvals", i, err)
		}
	}
	v, _ := s.PairControl(context.Background(), contract.PairCommand{Operation: "list"})
	if len(v.Devices) != MaxActiveClients+1 || s.ActiveClients() != MaxActiveClients || v.Invitation.Approved != 1 || s.conns.count() != 0 {
		t.Fatal("invitation/device/business quota conflated")
	}
	// Re-authenticating an online device replaces its lease even at capacity.
	if _, _, err := clients[0].Open(context.Background()); err != nil || s.ActiveClients() != MaxActiveClients {
		t.Fatal("reconnect required an extra online slot", err)
	}
	if _, err := s.PairControl(context.Background(), contract.PairCommand{Operation: "revoke-all"}); err != nil {
		t.Fatal(err)
	}
	if s.ActiveClients() != 0 {
		t.Fatal("revoke-all retained device leases")
	}
	for _, client := range clients {
		if _, _, err := client.Open(context.Background()); err == nil {
			t.Fatal("revoke-all retained device authorization")
		}
	}
}
