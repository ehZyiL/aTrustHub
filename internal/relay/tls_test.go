package relay

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"
)

// handmadeIdentity builds a certificate with the given properties so the
// negative verification paths can be exercised without waiting a year.
func handmadeIdentity(t *testing.T, ips []net.IP, usage []x509.ExtKeyUsage, notBefore, notAfter time.Time) *Identity {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(42),
		Subject:               pkix.Name{CommonName: "test"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           usage,
		BasicConstraintsValid: true,
		IPAddresses:           ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(der)
	if _, err := tls.X509KeyPair(probeCert(t, der), probeKey(t, key)); err != nil {
		t.Fatal(err)
	}
	return &Identity{LeafDER: der, Fingerprint: hex.EncodeToString(sum[:])}
}

func probeCert(t *testing.T, der []byte) []byte {
	t.Helper()
	out := pemEncode("CERTIFICATE", der)
	return out
}

func probeKey(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pemEncode("EC PRIVATE KEY", der)
}

// storedIdentityWithSANs builds a stored identity record whose certificate
// carries exactly the given IP SANs, so the decode boundary can be exercised
// with records this program would never generate itself.
func storedIdentityWithSANs(t *testing.T, ips []net.IP) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(7),
		Subject:               pkix.Name{CommonName: "test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(identityRecord{
		Cert: string(pemEncode("CERTIFICATE", der)),
		Key:  string(pemEncode("EC PRIVATE KEY", keyDER)),
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(payload)
}

// The identity record is the only thing that says which network a restored share
// belongs to. Decoding it without exactly one IPv4 address would leave Address
// empty, and StartServer turns an empty address into a 0.0.0.0 bind: the share
// would listen on every adapter instead of the chosen one. Refusing the record is
// the only fail-closed answer.
func TestDecodeIdentityRequiresOneBoundAddress(t *testing.T) {
	decoded, err := DecodeIdentity(storedIdentityWithSANs(t, []net.IP{net.ParseIP("192.168.1.5")}))
	if err != nil {
		t.Fatalf("单一地址的身份应当可解码：%v", err)
	}
	if decoded.Address != "192.168.1.5" {
		t.Fatalf("address = %q, want 192.168.1.5", decoded.Address)
	}
	for _, tc := range []struct {
		name string
		ips  []net.IP
	}{
		{"没有地址", nil},
		{"两个地址", []net.IP{net.ParseIP("192.168.1.5"), net.ParseIP("192.168.1.6")}},
		{"只有 IPv6", []net.IP{net.ParseIP("fd00::1")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := DecodeIdentity(storedIdentityWithSANs(t, tc.ips)); err == nil {
				t.Fatal("没有唯一 IPv4 地址的身份应当被拒绝，否则会退化成 0.0.0.0 监听")
			}
		})
	}
}

func TestIdentityGenerateAndDecode(t *testing.T) {
	id, err := GenerateIdentity("192.168.1.50")
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	if len(id.Fingerprint) != 64 {
		t.Fatalf("fingerprint = %q", id.Fingerprint)
	}
	leaf, err := x509.ParseCertificate(id.LeafDER)
	if err != nil {
		t.Fatal(err)
	}
	if err := leaf.VerifyHostname("192.168.1.50"); err != nil {
		t.Fatalf("certificate does not cover the bound address: %v", err)
	}
	stored, err := EncodeIdentity(id)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeIdentity(stored)
	if err != nil {
		t.Fatalf("DecodeIdentity: %v", err)
	}
	if decoded.Fingerprint != id.Fingerprint {
		t.Fatalf("fingerprint drift: %s != %s", decoded.Fingerprint, id.Fingerprint)
	}
	// The stored record holds only cert and key, so the address has to come back
	// from the certificate. Without it a restored share binds 0.0.0.0 (all
	// interfaces) and the controller's address-change guard can never fire.
	if decoded.Address != "192.168.1.50" {
		t.Fatalf("decoded address = %q, want 192.168.1.50", decoded.Address)
	}
	if err := VerifyIdentityRecord(decoded, "192.168.1.50"); err != nil {
		t.Fatalf("VerifyIdentityRecord: %v", err)
	}
	if err := VerifyIdentityRecord(decoded, "192.168.1.51"); err == nil {
		t.Fatal("address change must invalidate the record")
	}
}

func TestClientTLSConfigPinsFingerprint(t *testing.T) {
	id, err := GenerateIdentity("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := ClientTLSConfig(id.Fingerprint, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(id.LeafDER)
	state := tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}
	if err := cfg.VerifyConnection(state); err != nil {
		t.Fatalf("correct pin rejected: %v", err)
	}

	wrong := id.Fingerprint
	wrong = "00" + wrong[2:]
	wrongCfg, err := ClientTLSConfig(wrong, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if err := wrongCfg.VerifyConnection(state); err == nil {
		t.Fatal("wrong fingerprint must be rejected")
	}
}

func TestClientTLSConfigRejectsBadCertificates(t *testing.T) {
	now := time.Now()
	ip := []net.IP{net.ParseIP("192.168.1.50")}
	serverAuth := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	clientAuth := []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}

	check := func(t *testing.T, id *Identity, host string) error {
		t.Helper()
		cfg, err := ClientTLSConfig(id.Fingerprint, host)
		if err != nil {
			t.Fatal(err)
		}
		leaf, err := x509.ParseCertificate(id.LeafDER)
		if err != nil {
			t.Fatal(err)
		}
		return cfg.VerifyConnection(tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}})
	}

	t.Run("expired", func(t *testing.T) {
		id := handmadeIdentity(t, ip, serverAuth, now.Add(-48*time.Hour), now.Add(-24*time.Hour))
		if err := check(t, id, "192.168.1.50"); err == nil {
			t.Fatal("expired certificate accepted")
		}
	})
	t.Run("not yet valid", func(t *testing.T) {
		id := handmadeIdentity(t, ip, serverAuth, now.Add(24*time.Hour), now.Add(48*time.Hour))
		if err := check(t, id, "192.168.1.50"); err == nil {
			t.Fatal("future certificate accepted")
		}
	})
	t.Run("wrong purpose", func(t *testing.T) {
		id := handmadeIdentity(t, ip, clientAuth, now.Add(-time.Hour), now.Add(time.Hour))
		if err := check(t, id, "192.168.1.50"); err == nil {
			t.Fatal("clientAuth certificate accepted as server")
		}
	})
	t.Run("wrong address", func(t *testing.T) {
		id := handmadeIdentity(t, ip, serverAuth, now.Add(-time.Hour), now.Add(time.Hour))
		if err := check(t, id, "192.168.1.99"); err == nil {
			t.Fatal("certificate for another address accepted")
		}
	})
	t.Run("no peer certificate", func(t *testing.T) {
		id := handmadeIdentity(t, ip, serverAuth, now.Add(-time.Hour), now.Add(time.Hour))
		cfg, err := ClientTLSConfig(id.Fingerprint, "192.168.1.50")
		if err != nil {
			t.Fatal(err)
		}
		if err := cfg.VerifyConnection(tls.ConnectionState{}); err == nil {
			t.Fatal("missing peer certificate accepted")
		}
	})
}

func TestFingerprintIsLowerHexOfLeafDER(t *testing.T) {
	id, err := GenerateIdentity("10.0.0.3")
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(id.LeafDER)
	if id.Fingerprint != hex.EncodeToString(sum[:]) {
		t.Fatal("fingerprint is not the SHA-256 of the leaf DER")
	}
	for _, r := range id.Fingerprint {
		if r >= 'A' && r <= 'F' {
			t.Fatal("fingerprint must be lowercase")
		}
	}
}

func TestServerTLSConfigMinimumVersion(t *testing.T) {
	id, err := GenerateIdentity("10.0.0.3")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := ServerTLSConfig(id)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MinVersion != tls.VersionTLS13 {
		t.Fatalf("MinVersion = %x, want TLS 1.3", cfg.MinVersion)
	}
	if len(cfg.NextProtos) != 1 || cfg.NextProtos[0] != "http/1.1" {
		t.Fatalf("ALPN = %v", cfg.NextProtos)
	}
}

func pemEncode(kind string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: der})
}
