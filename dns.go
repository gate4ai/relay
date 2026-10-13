// SPDX-License-Identifier: FSL-1.1-ALv2

package relay

import (
	"net"
	"strings"

	"github.com/miekg/dns"
)

// DNS — авторитетный DNS зоны relay: A/AAAA для relay и всех устройств
// (<id>.relay.gate4.ai → адрес relay), TXT _acme-challenge.<id> для DNS-01.
type DNS struct {
	Zone  string // relay.gate4.ai
	IPv4  net.IP
	IPv6  net.IP
	Store *Store
	TTL   uint32
}

// ServeDNS отвечает на запросы.
func (d *DNS) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true
	zone := dns.Fqdn(strings.ToLower(d.Zone))
	ttl := d.TTL
	if ttl == 0 {
		ttl = 60
	}
	for _, q := range r.Question {
		name := strings.ToLower(q.Name)
		if name != zone && !strings.HasSuffix(name, "."+zone) {
			m.Rcode = dns.RcodeRefused
			continue
		}
		hdr := dns.RR_Header{Name: q.Name, Class: dns.ClassINET, Ttl: ttl}
		switch q.Qtype {
		case dns.TypeA:
			if d.IPv4 != nil && !strings.HasPrefix(name, "_acme-challenge.") {
				hdr.Rrtype = dns.TypeA
				m.Answer = append(m.Answer, &dns.A{Hdr: hdr, A: d.IPv4})
			}
		case dns.TypeAAAA:
			if d.IPv6 != nil && !strings.HasPrefix(name, "_acme-challenge.") {
				hdr.Rrtype = dns.TypeAAAA
				m.Answer = append(m.Answer, &dns.AAAA{Hdr: hdr, AAAA: d.IPv6})
			}
		case dns.TypeTXT:
			hdr.Rrtype = dns.TypeTXT
			hdr.Ttl = 10
			for _, v := range d.Store.TXT(name) {
				m.Answer = append(m.Answer, &dns.TXT{Hdr: hdr, Txt: []string{v}})
			}
		case dns.TypeSOA:
			hdr.Rrtype = dns.TypeSOA
			m.Answer = append(m.Answer, &dns.SOA{Hdr: hdr, Ns: "ns1." + zone, Mbox: "hostmaster." + zone, Serial: 1, Refresh: 3600, Retry: 600, Expire: 86400, Minttl: 60})
		case dns.TypeCAA:
			hdr.Rrtype = dns.TypeCAA
			m.Answer = append(m.Answer, &dns.CAA{Hdr: hdr, Flag: 0, Tag: "issue", Value: "letsencrypt.org"})
		}
	}
	_ = w.WriteMsg(m)
}

// ListenDNS запускает UDP и TCP сервер DNS на addr.
func ListenDNS(addr string, h *DNS) (*dns.Server, *dns.Server, error) {
	udp := &dns.Server{Addr: addr, Net: "udp", Handler: h}
	tcp := &dns.Server{Addr: addr, Net: "tcp", Handler: h}
	errc := make(chan error, 2)
	udp.NotifyStartedFunc = func() { errc <- nil }
	tcp.NotifyStartedFunc = func() { errc <- nil }
	go func() {
		if err := udp.ListenAndServe(); err != nil {
			errc <- err
		}
	}()
	go func() {
		if err := tcp.ListenAndServe(); err != nil {
			errc <- err
		}
	}()
	for i := 0; i < 2; i++ {
		if err := <-errc; err != nil {
			return nil, nil, err
		}
	}
	return udp, tcp, nil
}
