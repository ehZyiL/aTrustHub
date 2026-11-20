package splitdns

import (
	"context"
	"errors"
	"github.com/miekg/dns"
	"strings"
	"sync"
	"time"
)

type Identity struct {
	GatewayID     string
	Generation    int
	Version, Mode string
}
type cacheKey struct {
	Identity
	Name        string
	Type, Class uint16
	RD, CD      bool
}
type cachedAnswer struct {
	message *dns.Msg
	at      time.Time
	ttl     uint32
}

// Cache never stores mapped answers, which need publication confirmation.
type Cache struct {
	mu      sync.Mutex
	entries map[cacheKey]cachedAnswer
}

func (c *Cache) Exchange(ctx context.Context, id Identity, packet []byte, current func() bool, exchange ExchangeFunc) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	q := new(dns.Msg)
	if len(packet) > 65535 || q.Unpack(packet) != nil || q.Response || q.Opcode != dns.OpcodeQuery || len(q.Question) != 1 {
		return nil, errors.New("无效 DNS 请求")
	}
	if current == nil || !current() {
		return nil, errors.New("DNS 会话已变化")
	}
	question := q.Question[0]
	key := cacheKey{id, strings.ToLower(question.Name), question.Qtype, question.Qclass, q.RecursionDesired, q.CheckingDisabled}
	cacheable := id.Mode == "raw" && len(q.Extra) == 0 && len(q.Answer) == 0 && len(q.Ns) == 0
	started := time.Now()
	if cacheable {
		c.mu.Lock()
		entry, found := c.entries[key]
		c.mu.Unlock()
		if elapsed := uint32(time.Since(entry.at) / time.Second); found && elapsed < entry.ttl {
			m := entry.message.Copy()
			m.Id = q.Id
			m.Question = append([]dns.Question(nil), q.Question...)
			for _, section := range [][]dns.RR{m.Answer, m.Ns, m.Extra} {
				for _, rr := range section {
					if rr.Header().Rrtype != dns.TypeOPT {
						if rr.Header().Ttl > elapsed {
							rr.Header().Ttl -= elapsed
						} else {
							rr.Header().Ttl = 0
						}
					}
				}
			}
			if !current() {
				return nil, errors.New("DNS 会话已变化")
			}
			return m.Pack()
		}
	}
	response, err := exchange(ctx, packet)
	if err != nil {
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	if !current() {
		return nil, errors.New("DNS 会话已变化")
	}
	m := new(dns.Msg)
	if len(response) > 65535 || m.Unpack(response) != nil || !m.Response || m.Id != q.Id || m.Opcode != q.Opcode || len(m.Question) != 1 || !strings.EqualFold(m.Question[0].Name, question.Name) || m.Question[0].Qclass != question.Qclass || m.Question[0].Qtype != question.Qtype {
		return nil, errors.New("DNS 应答与查询不匹配")
	}
	// Preserve negative RCODEs; do not cache failures or infer negative TTLs.
	if cacheable && m.Rcode == dns.RcodeSuccess && !m.Truncated && len(m.Answer) > 0 {
		ttl := uint32(300)
		for _, section := range [][]dns.RR{m.Answer, m.Ns, m.Extra} {
			for _, rr := range section {
				if rr.Header().Rrtype != dns.TypeOPT && rr.Header().Ttl < ttl {
					ttl = rr.Header().Ttl
				}
			}
		}
		if ttl > 0 {
			c.mu.Lock()
			if c.entries == nil {
				c.entries = make(map[cacheKey]cachedAnswer)
			}
			for k, e := range c.entries {
				if time.Since(e.at) >= time.Duration(e.ttl)*time.Second {
					delete(c.entries, k)
				}
			}
			if len(c.entries) >= 256 {
				for k := range c.entries {
					delete(c.entries, k)
					break
				}
			}
			c.entries[key] = cachedAnswer{m.Copy(), started, ttl}
			c.mu.Unlock()
		}
	}
	return response, nil
}
