package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/egoist/mygo/ui"
	"github.com/ehZyiL/connect-hub/internal/model"
	"github.com/ehZyiL/connect-hub/internal/vpn"
	"github.com/ehZyiL/connect-hub/internal/workeripc"
)

func certificateFixture() certificateProbeDraft {
	return certificateProbeDraft{open: true, confirmed: true, pointID: "vpn", server: "vpn.test", port: 443, info: &workeripc.CertificateInfo{SHA256: strings.Repeat("a", 64), NotBefore: 1, NotAfter: 2}}
}

func TestCertificateEditorConfirmationDoesNotSaveUntilEditorSaved(t *testing.T) {
	a := testApp(t)
	a.openNewEditor()
	a.editor.name, a.editor.address = "测试网关", "https://vpn.test"
	a.editor.username, a.editor.cred = "test", "test-password"
	a.editor.socksPort = "0"
	d := certificateFixture()
	d.pointID, d.editorToken, d.confirmed = "", a.editor.certificateToken, false
	a.certificateProbe = d
	tt := ui.NewTester(a.view, 1120, 800)
	if err := tt.Click("信任并填入"); err != nil {
		t.Fatal(err)
	}
	if a.editor.certificateSHA256 != "" || !a.certificateProbe.open {
		t.Fatal("unchecked trust button changed the draft")
	}
	if err := tt.Click("我已核实网关来源，信任此证书"); err != nil {
		t.Fatal(err)
	}
	if err := tt.Click("信任并填入"); err != nil {
		t.Fatal(err)
	}
	if a.certificateProbe.open || !a.editor.open || a.editor.certificateSHA256 != d.info.SHA256 {
		t.Fatal("confirmation did not return the pin to the open editor", a.certificateProbe.err)
	}
	if len(a.store.Config().Points) != 0 {
		t.Fatal("certificate confirmation unexpectedly saved the editor")
	}
	a.saveEditor()
	if a.editor.err != "" {
		t.Fatal(a.editor.err)
	}
	if p := a.store.Config().Points[0]; p.CertificateSHA256 != d.info.SHA256 {
		t.Fatal("saving editor lost the confirmed pin")
	}
}

func TestCertificateCancelDiscardsLateReplyAndPreservesEditor(t *testing.T) {
	a := testApp(t)
	a.openNewEditor()
	a.editor.address = "https://vpn.test"
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	replies := make(chan certificateProbeReply, 1)
	d := certificateFixture()
	d.pointID, d.editorToken = "", a.editor.certificateToken
	d.running, d.confirmed, d.info = true, false, nil
	d.cancel, d.replies = cancel, replies
	a.certificateProbe = d
	tt := ui.NewTester(a.view, 1120, 800)
	tt.Key(0, ui.KeyEscape)
	if a.certificateProbe.open || !a.editor.open || ctx.Err() == nil {
		t.Fatal("closing the certificate dialog did not cancel its probe or closed the editor")
	}
	replies <- certificateProbeReply{info: certificateFixture().info}
	tt.Frame()
	if a.editor.certificateSHA256 != "" || len(a.store.Config().Points) != 0 {
		t.Fatal("late certificate response established trust")
	}
}

func TestCertificateSaveFailureRestoresPreviousTrust(t *testing.T) {
	a := testApp(t)
	a.openNewEditor()
	a.editor.address, a.editor.username, a.editor.cred = "https://vpn.test", "test", "test-password"
	a.editor.socksPort = "0"
	a.editor.certificateSHA256 = strings.Repeat("b", 64)
	a.saveEditor()
	if a.editor.err != "" {
		t.Fatal(a.editor.err)
	}
	p := a.store.Config().Points[0]
	d := certificateFixture()
	d.pointID, d.previousPin = p.ID, p.CertificateSHA256
	a.certificateProbe = d
	configPath := filepath.Join(a.dir, "config.json")
	if err := os.Remove(configPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(configPath, 0700); err != nil {
		t.Fatal(err)
	}
	a.acceptGatewayCertificate()
	if !a.certificateProbe.open || !strings.Contains(a.certificateProbe.err, "保存证书失败") {
		t.Fatal("save failure was not reported")
	}
	if got := a.store.Config().Points[0].CertificateSHA256; got != p.CertificateSHA256 {
		t.Fatal("failed save changed in-memory trust")
	}
	if v, _ := a.mgr.View(p.ID); v.State == vpn.StateConnecting || v.State == vpn.StateOnline {
		t.Fatal("failed certificate save started a connection")
	}
}

func TestCertificateTrustRequiresApprovalAndUnchangedEndpoint(t *testing.T) {
	for _, scenario := range []string{"accept", "unconfirmed", "closed", "running", "bad-result", "host", "port", "pin", "protocol", "missing"} {
		t.Run(scenario, func(t *testing.T) {
			d := certificateFixture()
			p := model.AccessPoint{ID: "vpn", Protocol: model.ProtocolEasyConnect, Server: "vpn.test", Port: 443}
			switch scenario {
			case "unconfirmed":
				d.confirmed = false
			case "closed":
				d.open = false
			case "running":
				d.running = true
			case "bad-result":
				d.info.SHA256 = "invalid"
			case "host":
				p.Server = "other.test"
			case "port":
				p.Port = 8443
			case "pin":
				p.CertificateSHA256 = strings.Repeat("b", 64)
			case "protocol":
				p.Protocol = model.ProtocolATrust
			case "missing":
				p.ID = "removed"
			}
			before := p.CertificateSHA256
			cfg := model.Config{Points: []model.AccessPoint{p}}
			err := d.applyToConfig(&cfg)
			if scenario == "accept" {
				if err != nil || cfg.Points[0].CertificateSHA256 != d.info.SHA256 {
					t.Fatal("approval not applied", err)
				}
			} else if err == nil || cfg.Points[0].CertificateSHA256 != before {
				t.Fatalf("unapproved/stale result changed trust: %v", err)
			}
		})
	}
}

func TestCertificateChangeRequiresFreshApproval(t *testing.T) {
	d := certificateFixture()
	d.previousPin = strings.Repeat("b", 64)
	d.confirmed = false
	cfg := model.Config{Points: []model.AccessPoint{{ID: "vpn", Protocol: model.ProtocolEasyConnect, Server: "vpn.test", Port: 443, CertificateSHA256: d.previousPin}}}
	if !d.changed() {
		t.Fatal("certificate rotation not identified")
	}
	if err := d.applyToConfig(&cfg); err == nil || cfg.Points[0].CertificateSHA256 != d.previousPin {
		t.Fatal("rotation silently trusted")
	}
	d.confirmed = true
	if err := d.applyToConfig(&cfg); err != nil || cfg.Points[0].CertificateSHA256 != d.info.SHA256 {
		t.Fatal("explicit rotation confirmation failed", err)
	}
}

func TestCertificateEditorRejectsStaleDraftAndAddressChanges(t *testing.T) {
	d := certificateFixture()
	d.pointID, d.editorToken = "", "editor-one"
	editor := editorDraft{open: true, protocol: "EasyConnect", address: "https://vpn.test", certificateToken: "editor-two"}
	if err := d.applyToEditor(&editor); err == nil || editor.certificateSHA256 != "" {
		t.Fatal("old dialog updated a new draft")
	}
	editor.certificateToken = "editor-one"
	if err := d.applyToEditor(&editor); err != nil {
		t.Fatal(err)
	}
	if err := editor.checkCertificateAddress("vpn.test", 443); err != nil {
		t.Fatal(err)
	}
	if err := editor.checkCertificateAddress("other.test", 443); err == nil {
		t.Fatal("approved pin followed an edited hostname")
	}
	if err := editor.checkCertificateAddress("vpn.test", 8443); err == nil {
		t.Fatal("approved pin followed an edited port")
	}
	editor.certificateSHA256 = ""
	if err := editor.checkCertificateAddress("other.test", 443); err != nil {
		t.Fatal("cleared pin blocked endpoint edit")
	}
}
