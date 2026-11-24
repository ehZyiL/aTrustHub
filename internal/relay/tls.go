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
	"errors"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"
)

// Identity is one share's TLS identity: a self-signed leaf certificate for the
// bound LAN address plus its private key. It is persisted in the secret store and
// reused across restarts until the user switches the share off.
type Identity struct {
	CertPEM     []byte
	KeyPEM      []byte
	LeafDER     []byte
	Fingerprint string
	NotBefore   time.Time
	NotAfter    time.Time
	Address     string
}

// identityRecord is the JSON shape kept in the secret store. It is JSON rather
// than concatenated PEM so the boundary between certificate and key can never be
// guessed wrong.
type identityRecord struct {
	Cert string `json:"cert"`
	Key  string `json:"key"`
}

// IdentitySecretKey is the secret-store key of a share's identity. It is
// separate from the share token so revoking a share can drop both together.
func IdentitySecretKey(shareID string) string { return "lan-share:" + shareID + ":identity" }

// FirmwareCertificateLifetime is the technical certificate lifetime of v1. It is
// a suggested value to be validated on real deployments, not a measured result.
func identityLifetime() time.Duration { return CertificateLifetime }

// GenerateIdentity creates a self-signed serverAuth leaf for ip. Randomness
// failure aborts: a share must never fall back to a weak key.
func GenerateIdentity(ip string) (*Identity, error) {
	parsed := net.ParseIP(ip)
	if parsed == nil || parsed.To4() == nil {
		return nil, fmt.Errorf("分享监听地址必须是 IPv4：%q", ip)
	}
	ip = parsed.To4().String()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("生成分享证书密钥失败：%w", err)
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, fmt.Errorf("生成分享证书序列号失败：%w", err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "connect-hub lan share", Organization: []string{"connect-hub"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(identityLifetime()),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{parsed.To4()},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("签发分享证书失败：%w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("编码分享证书密钥失败：%w", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(der)
	return &Identity{
		CertPEM:     pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		KeyPEM:      pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
		LeafDER:     der,
		Fingerprint: hex.EncodeToString(sum[:]),
		NotBefore:   leaf.NotBefore,
		NotAfter:    leaf.NotAfter,
		Address:     ip,
	}, nil
}

// EncodeIdentity serializes an identity for the secret store. The private key
// never enters the configuration JSON.
func EncodeIdentity(id *Identity) (string, error) {
	if id == nil {
		return "", errors.New("分享身份缺失")
	}
	if len(id.CertPEM) == 0 || len(id.KeyPEM) == 0 {
		return "", errors.New("分享身份不完整")
	}
	payload, err := json.Marshal(identityRecord{Cert: string(id.CertPEM), Key: string(id.KeyPEM)})
	if err != nil {
		return "", err
	}
	return string(payload), nil
}

// DecodeIdentity parses a stored identity and recomputes the fingerprint, so a
// tampered record is caught instead of trusted.
func DecodeIdentity(stored string) (*Identity, error) {
	var record identityRecord
	if err := json.Unmarshal([]byte(stored), &record); err != nil {
		return nil, errors.New("分享身份格式无效")
	}
	if record.Cert == "" || record.Key == "" {
		return nil, errors.New("分享身份格式无效")
	}
	pair, err := tls.X509KeyPair([]byte(record.Cert), []byte(record.Key))
	if err != nil {
		return nil, fmt.Errorf("分享身份无法解析：%w", err)
	}
	if len(pair.Certificate) == 0 {
		return nil, errors.New("分享身份缺少证书")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(leaf.Raw)
	return &Identity{
		CertPEM:     []byte(record.Cert),
		KeyPEM:      []byte(record.Key),
		LeafDER:     leaf.Raw,
		Fingerprint: hex.EncodeToString(sum[:]),
		NotBefore:   leaf.NotBefore,
		NotAfter:    leaf.NotAfter,
	}, nil
}

// ServerTLSConfig builds the sharing host's TLS configuration: TLS 1.3 or newer,
// ALPN http/1.1 only, and exactly the persisted leaf.
func ServerTLSConfig(id *Identity) (*tls.Config, error) {
	if id == nil {
		return nil, errors.New("分享身份缺失")
	}
	pair, err := tls.X509KeyPair(id.CertPEM, id.KeyPEM)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{pair},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{ALPNProtocol},
	}, nil
}

// ClientTLSConfig pins one leaf certificate. The certificate is self-signed, so
// the standard chain cannot vouch for it; InsecureSkipVerify disables that chain
// check and VerifyConnection installs the complete replacement:
//
//  1. leaf DER SHA-256 equals the fingerprint from the share code,
//  2. the certificate is currently valid,
//  3. its key usage allows server authentication,
//  4. it covers the address actually dialed.
//
// No code path leaves a bare InsecureSkipVerify without these checks.
func ClientTLSConfig(fingerprint, expectedHost string) (*tls.Config, error) {
	want, err := hex.DecodeString(strings.ToLower(strings.TrimSpace(fingerprint)))
	if err != nil || len(want) != sha256.Size {
		return nil, errors.New("分享证书指纹格式无效")
	}
	host := strings.TrimSpace(expectedHost)
	return &tls.Config{
		MinVersion:         tls.VersionTLS13,
		NextProtos:         []string{ALPNProtocol},
		InsecureSkipVerify: true, // replaced by VerifyConnection below
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 {
				return errors.New("分享主机没有提供证书")
			}
			leaf := state.PeerCertificates[0]
			if len(state.PeerCertificates) > 1 {
				return errors.New("分享主机提供了多余的证书链")
			}
			sum := sha256.Sum256(leaf.Raw)
			if !equalBytes(sum[:], want) {
				return fmt.Errorf("分享主机证书指纹不匹配（收到 %s）", hex.EncodeToString(sum[:]))
			}
			now := time.Now()
			if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
				return fmt.Errorf("分享主机证书不在有效期内（%s 至 %s）", leaf.NotBefore.Format(time.RFC3339), leaf.NotAfter.Format(time.RFC3339))
			}
			serverAuth := false
			for _, usage := range leaf.ExtKeyUsage {
				if usage == x509.ExtKeyUsageServerAuth || usage == x509.ExtKeyUsageAny {
					serverAuth = true
					break
				}
			}
			if !serverAuth {
				return errors.New("分享主机证书不能用于服务器身份验证")
			}
			if host != "" {
				if err := leaf.VerifyHostname(host); err != nil {
					return fmt.Errorf("分享主机证书不包含地址 %s：%w", host, err)
				}
			}
			return nil
		},
	}, nil
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

// VerifyIdentityRecord checks that a persisted identity still describes the
// address it is used for and has not expired. Expiry is a Blocked reason, not an
// excuse to silently mint a new certificate: the share code in circulation pins
// the old one.
func VerifyIdentityRecord(id *Identity, address string) error {
	if id == nil {
		return errors.New("分享身份缺失")
	}
	if id.Fingerprint == "" || len(id.Fingerprint) != 64 {
		return errors.New("分享身份指纹缺失")
	}
	leaf, err := x509.ParseCertificate(id.LeafDER)
	if err != nil {
		return errors.New("分享身份证书无法解析")
	}
	if address != "" && leaf.VerifyHostname(address) != nil {
		return fmt.Errorf("分享身份证书不包含当前地址 %s", address)
	}
	if time.Now().After(leaf.NotAfter) {
		return fmt.Errorf("分享证书已于 %s 到期，请更换分享口令", leaf.NotAfter.Format("2006-01-02"))
	}
	return nil
}
