package relay

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// A client that keeps making authenticated requests must keep its lease, even if
// it never calls the /v1/status heartbeat. Before this was fixed only the
// heartbeat renewed, so a client polling resources every second was dropped
// after one lease period and told to "重新认证" for no visible reason.
func TestAnyAuthenticatedRequestRenewsTheLease(t *testing.T) {
	const (
		shareToken = "share-token-for-test"
		clientTok  = "client-session-token-for-test"
		lease      = 80 * time.Millisecond
	)
	s := &Server{token: shareToken, clients: newClientRegistry(4, lease)}
	if _, err := s.clients.create("cid-1", "probe", clientTok, time.Now()); err != nil {
		t.Fatalf("create: %v", err)
	}

	auth := func() error {
		req := httptest.NewRequest(http.MethodGet, "/v1/resources", nil)
		req.Header.Set(HeaderAuthorization, "Bearer "+clientTok)
		_, err := s.authenticateClient(httptest.NewRecorder(), req)
		return err
	}

	// Six requests spaced a third of a lease apart: without renewal the session
	// dies at the second or third one.
	for i := 0; i < 6; i++ {
		time.Sleep(lease / 3)
		if err := auth(); err != nil {
			t.Fatalf("第 %d 次认证失败（会话应当被续租）：%v", i+1, err)
		}
	}

	// The lease must still expire when nothing touches it: renewal is not a
	// permanent pass.
	time.Sleep(2 * lease)
	if err := auth(); err == nil {
		t.Fatal("静默超过一个租约后仍然认证成功")
	}
}

// The share token itself is never accepted as a session token, even though it is
// the credential the client starts with.
func TestShareTokenIsNotASessionToken(t *testing.T) {
	const shareToken = "share-token-for-test"
	s := &Server{token: shareToken, clients: newClientRegistry(4, time.Minute)}
	req := httptest.NewRequest(http.MethodGet, "/v1/resources", nil)
	req.Header.Set(HeaderAuthorization, "Bearer "+shareToken)
	if _, err := s.authenticateClient(httptest.NewRecorder(), req); err == nil {
		t.Fatal("分享口令被当作客户端会话接受了")
	}
}
