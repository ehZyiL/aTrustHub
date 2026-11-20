package vpn

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/qy/easyconnect/internal/workeripc"
	"github.com/things-go/go-socks5"
	"github.com/things-go/go-socks5/statute"
)

func TestWorkerUDPRequiresAuthorizedReadyAndPreservesDatagrams(t *testing.T) {
	for _, reportedRoute := range []string{"vpn", "direct", ""} {
		t.Run("report="+reportedRoute, func(t *testing.T) {
			ln, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			s := &processSession{done: make(chan struct{}), stopping: make(chan struct{}), outgoing: make(chan workerWrite, 2)}
			defer close(s.done)
			ready := workeripc.Message{Address: "127.0.0.1:1", VPNAddress: ln.Addr().String(), Capabilities: []string{"strict_vpn", "flow_prepare", "flow_cancel"}, FlowReporting: true}
			if err := s.configureReady(ready, "fixture-password"); err != nil {
				t.Fatal(err)
			}
			if _, err := s.DialVPN(context.Background(), "udp", "a.io:9"); !errors.Is(err, ErrStrictUDPUnavailable) {
				t.Fatalf("old worker: %v", err)
			}
			ready.Capabilities = append(ready.Capabilities, workeripc.StrictUDP)
			if err := s.configureReady(ready, "fixture-password"); err != nil {
				t.Fatal(err)
			}
			f := s.flows.Load()
			go func() {
				for {
					select {
					case req := <-s.outgoing:
						if req.message.Type == "flow_prepare" {
							f.deliverReady(workeripc.Message{RequestID: req.message.RequestID})
						}
						req.result <- nil
					case <-s.done:
						return
					}
				}
			}()
			server := socks5.NewServer(
				socks5.WithAuthMethods([]socks5.Authenticator{socks5.UserPassAuthenticator{Credentials: testFlowCredentials{"fixture-password"}}}),
				socks5.WithRule(&socks5.PermitCommand{EnableAssociate: true}),
				socks5.WithAssociateHandle(func(_ context.Context, w io.Writer, req *socks5.Request) error {
					if !req.DestAddr.IP.Equal(net.IPv4(127, 0, 0, 1)) || req.DestAddr.Port == 0 {
						return errors.New("invalid local UDP source")
					}
					relay, err := net.DialUDP("udp4", &net.UDPAddr{IP: req.DestAddr.IP}, &net.UDPAddr{IP: req.DestAddr.IP, Port: req.DestAddr.Port})
					if err != nil {
						return err
					}
					defer relay.Close()
					_ = relay.SetDeadline(time.Now().Add(2 * time.Second))
					if err := socks5.SendReply(w, statute.RepSuccess, relay.LocalAddr()); err != nil {
						return err
					}
					var buf [512]byte
					n, err := relay.Read(buf[:])
					if err != nil {
						return err
					}
					target, marker, err := workeripc.DecodeUDPFrame(buf[:n])
					if err != nil || target != "a.io:9" || len(marker) != 1 || marker[0] != 0 {
						return errors.New("missing local authorization marker")
					}
					if reportedRoute != "" {
						f.deliver(workeripc.Message{RequestID: testFlowID(req), Flow: &workeripc.FlowResult{Target: target, Route: reportedRoute}})
					}
					if _, err := w.Write([]byte{0}); err != nil {
						return err
					}
					if reportedRoute == "vpn" {
						for range 2 {
							n, err = relay.Read(buf[:])
							if err != nil {
								return err
							}
							if _, err = relay.Write(buf[:n]); err != nil {
								return err
							}
						}
					}
					_, _ = req.Reader.Read(buf[:1])
					return nil
				}),
			)
			go func() { _ = server.Serve(ln) }()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			conn, err := s.DialVPN(ctx, "udp4", "a.io:9")
			cancel()
			if reportedRoute != "vpn" {
				if err == nil {
					_ = conn.Close()
					t.Fatal("uncorroborated relay became a VPN path")
				}
				if len(f.udpSlots) != 0 {
					t.Fatal("failed association leaked a slot")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(time.Second))
			for _, want := range []string{"", "the next datagram"} {
				if n, err := conn.Write([]byte(want)); err != nil || n != len(want) {
					t.Fatalf("write %d %v", n, err)
				}
				var data [64]byte
				n, err := conn.Read(data[:])
				if err != nil || string(data[:n]) != want {
					t.Fatalf("datagram %q, %v", data[:n], err)
				}
			}
			_ = conn.Close()
			if len(f.udpSlots) != 0 {
				t.Fatal("closed association leaked a slot")
			}
		})
	}
}
