package discovery

import (
	"net"
	"strings"

	"github.com/miekg/dns"
)

// RecordKind is one DNS record type this feature uses.
type RecordKind string

const (
	KindPTR RecordKind = "PTR"
	KindSRV RecordKind = "SRV"
	KindTXT RecordKind = "TXT"
	KindA   RecordKind = "A"
)

// Record is one received record, already attributed to the interface it arrived
// on. TTL 0 is a goodbye: the sender withdrew the record.
type Record struct {
	Kind      RecordKind
	Instance  string
	Host      string
	Port      int
	TXT       []string
	IPv4      string
	TTL       uint32
	Interface string
}

// Gone reports whether the record is a goodbye.
func (r Record) Gone() bool { return r.TTL == 0 }

// mdnsAddr is the reserved multicast group and port of multicast DNS.
const (
	mdnsGroup = "224.0.0.251:5353"
	mdnsPort  = 5353
)

// cacheFlush marks a unique record so receivers replace instead of gathering
// duplicates (RFC 6762 section 10.2).
const cacheFlush = 0x8000

// announcementMessage builds a multicast DNS response for one share. Unique
// records (SRV, TXT, A) carry the cache-flush bit; PTR does not, because
// several hosts legitimately share the query name.
//
// goodbye turns every record into a TTL-0 withdrawal, which is how a stopped
// share disappears from colleagues' lists without waiting for the TTL.
func announcementMessage(a Announcement, goodbye bool) *dns.Msg {
	msg := new(dns.Msg)
	msg.Response = true
	msg.Authoritative = true
	msg.RecursionAvailable = false
	instance := InstanceName(a.ShareID)
	host := HostLabel(a.ShareID)

	hostTTL := uint32(TTLHost.Seconds())
	otherTTL := uint32(TTLOther.Seconds())
	uniqueTTL := hostTTL
	if goodbye {
		hostTTL, otherTTL, uniqueTTL = 0, 0, 0
	}

	ptr := &dns.PTR{
		Hdr: dns.RR_Header{Name: ServiceType, Rrtype: dns.TypePTR,
			Class: dns.ClassINET, Ttl: otherTTL},
		Ptr: instance,
	}
	srv := &dns.SRV{
		Hdr: dns.RR_Header{Name: instance, Rrtype: dns.TypeSRV,
			Class: dns.ClassINET | cacheFlush, Ttl: uniqueTTL},
		Priority: 0,
		Weight:   0,
		Port:     uint16(a.Port),
		Target:   host,
	}
	txt := &dns.TXT{
		Hdr: dns.RR_Header{Name: instance, Rrtype: dns.TypeTXT,
			Class: dns.ClassINET | cacheFlush, Ttl: otherTTL},
		Txt: BuildTXT(a),
	}
	arec := &dns.A{
		Hdr: dns.RR_Header{Name: host, Rrtype: dns.TypeA,
			Class: dns.ClassINET | cacheFlush, Ttl: uniqueTTL},
		A: net.ParseIP(a.Address).To4(),
	}
	msg.Answer = []dns.RR{ptr}
	msg.Extra = []dns.RR{srv, txt, arec}
	return msg
}

// browseQuery asks for every instance of the service.
func browseQuery() *dns.Msg {
	msg := new(dns.Msg)
	msg.Id = 0
	msg.RecursionDesired = false
	msg.Question = []dns.Question{{
		Name:   ServiceType,
		Qtype:  dns.TypePTR,
		Qclass: dns.ClassINET,
	}}
	return msg
}

// instanceQuery asks for the records a cached PTR may be missing, which happens
// when a responder answers without additional records.
func instanceQuery(instance string) *dns.Msg {
	msg := new(dns.Msg)
	msg.Id = 0
	msg.RecursionDesired = false
	for _, qtype := range []uint16{dns.TypeSRV, dns.TypeTXT} {
		msg.Question = append(msg.Question, dns.Question{
			Name: instance, Qtype: qtype, Qclass: dns.ClassINET,
		})
	}
	return msg
}

// parseRecords converts a received message into records bound to iface. It
// ignores anything that is not part of this feature: other service types, other
// record types, malformed addresses and non-IPv4 traffic.
func parseRecords(msg *dns.Msg, iface string) []Record {
	if msg == nil || !msg.Response {
		return nil
	}
	seen := make(map[string]bool)
	var out []Record
	add := func(r Record) {
		k := string(r.Kind) + "|" + r.Instance + "|" + r.Host + "|" + r.IPv4
		if seen[k] {
			return
		}
		seen[k] = true
		out = append(out, r)
	}
	for _, rr := range append(append([]dns.RR{}, msg.Answer...), msg.Extra...) {
		if rr == nil || rr.Header() == nil {
			continue
		}
		hdr := rr.Header()
		// The cache-flush bit lives in the class field; strip it before use.
		if hdr.Class&^cacheFlush != dns.ClassINET {
			continue
		}
		switch rec := rr.(type) {
		case *dns.PTR:
			if !strings.EqualFold(strings.TrimSuffix(hdr.Name, "."), strings.TrimSuffix(ServiceType, ".")) {
				continue
			}
			if !IsInstance(rec.Ptr) {
				continue
			}
			add(Record{Kind: KindPTR, Instance: rec.Ptr, TTL: hdr.Ttl, Interface: iface})
		case *dns.SRV:
			if !IsInstance(hdr.Name) {
				continue
			}
			add(Record{Kind: KindSRV, Instance: hdr.Name, Host: rec.Target,
				Port: int(rec.Port), TTL: hdr.Ttl, Interface: iface})
		case *dns.TXT:
			if !IsInstance(hdr.Name) {
				continue
			}
			add(Record{Kind: KindTXT, Instance: hdr.Name, TXT: rec.Txt,
				TTL: hdr.Ttl, Interface: iface})
		case *dns.A:
			ip := rec.A.To4()
			if ip == nil {
				continue
			}
			add(Record{Kind: KindA, Host: hdr.Name, IPv4: ip.String(),
				TTL: hdr.Ttl, Interface: iface})
		}
	}
	return out
}
