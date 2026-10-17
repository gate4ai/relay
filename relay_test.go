// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/hashicorp/yamux"
	"github.com/miekg/dns"
)

// Сквозные тесты с настоящим клиентом устройства — в ядре
// (github.com/gate4ai/gate4ai/internal/relayclient). Здесь — сервер по протоколу
// из docs/protocol.md с минимальным устройством на WebSocket + yamux.

type env struct {
	srv    *Server
	client *http.Client
	dial   func(ctx context.Context, network, addr string) (net.Conn, error)
	pool   *x509.CertPool
}

func start(t *testing.T) *env {
	t.Helper()
	cert, leaf, err := SelfSigned("relay.test")
	if err != nil {
		t.Fatal(err)
	}
	st, _ := OpenStore("")
	s := NewServer("relay.test", &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"http/1.1"}}, st)
	s.HoldFor = 200 * time.Millisecond
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go s.Serve(l)
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	dial := func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", l.Addr().String())
	}
	return &env{srv: s, dial: dial, pool: pool, client: &http.Client{Timeout: 3 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "relay.test"}, DialContext: dial}}}
}

func (e *env) register(t *testing.T) (id, tok string) {
	t.Helper()
	resp, err := e.client.Post("https://relay.test/api/devices", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var v struct{ DeviceID, Token, Host string }
	var raw map[string]string
	_ = json.NewDecoder(resp.Body).Decode(&raw)
	v.DeviceID, v.Token, v.Host = raw["device_id"], raw["token"], raw["host"]
	if len(v.DeviceID) != 16 || v.Host != v.DeviceID+".relay.test" || v.Token == "" {
		t.Fatal(raw)
	}
	return v.DeviceID, v.Token
}

func (e *env) call(t *testing.T, method, path, id, tok string, body any) int {
	t.Helper()
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest(method, "https://relay.test"+path, bytes.NewReader(b))
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("X-Gate4ai-Device", id)
	resp, err := e.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

// device — минимальное устройство: туннель и TLS-сервер с собственным сертификатом.
func (e *env) device(t *testing.T, ctx context.Context, id, tok string) *x509.CertPool {
	t.Helper()
	h := http.Header{}
	h.Set("Authorization", "Bearer "+tok)
	h.Set("X-Gate4ai-Device", id)
	ws, _, err := websocket.Dial(ctx, "wss://relay.test/tunnel", &websocket.DialOptions{HTTPHeader: h, HTTPClient: e.client})
	if err != nil {
		t.Fatal(err)
	}
	ws.SetReadLimit(-1)
	cfg := yamux.DefaultConfig()
	cfg.LogOutput = io.Discard
	sess, err := yamux.Server(websocket.NetConn(ctx, ws, websocket.MessageBinary), cfg)
	if err != nil {
		t.Fatal(err)
	}
	cert, leaf, _ := SelfSigned(id + ".relay.test")
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "device "+r.Host) })}
	go srv.Serve(tls.NewListener(sess, &tls.Config{Certificates: []tls.Certificate{cert}}))
	go func() { <-ctx.Done(); sess.Close() }()
	for i := 0; i < 200 && !e.srv.Online(id); i++ {
		time.Sleep(10 * time.Millisecond)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return pool
}

func (e *env) agentGet(id string, pool *x509.CertPool) (string, *x509.Certificate, error) {
	c := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{DialContext: e.dial, DisableKeepAlives: true,
		TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: id + ".relay.test"}}}
	resp, err := c.Get("https://" + id + ".relay.test/x")
	if err != nil {
		return "", nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b), resp.TLS.PeerCertificates[0], nil
}

func TestPassthroughAndAuth(t *testing.T) {
	e := start(t)
	id, tok := e.register(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pool := e.device(t, ctx, id, tok)
	body, peer, err := e.agentGet(id, pool)
	if err != nil || !strings.HasPrefix(body, "device ") {
		t.Fatal(body, err)
	}
	if peer.Subject.CommonName != id+".relay.test" {
		t.Fatal("relay terminated TLS:", peer.Subject)
	}
	e.srv.Disconnect(id)
	time.Sleep(50 * time.Millisecond)
	if e.srv.Online(id) {
		t.Fatal("still online after Disconnect")
	}
	if _, _, err := e.agentGet(id, pool); err == nil {
		t.Fatal("offline device answered")
	}
	if _, _, err := e.agentGet("unknown000000000", pool); err == nil {
		t.Fatal("unknown device answered")
	}
	if code := e.call(t, "POST", "/api/witness", id, "dev_wrong", map[string]any{"seq": 1, "head": strings.Repeat("a", 64)}); code != 401 {
		t.Fatal("wrong token:", code)
	}
}

func TestWitnessMonotonic(t *testing.T) {
	e := start(t)
	id, tok := e.register(t)
	head := strings.Repeat("ab", 32)
	if code := e.call(t, "POST", "/api/witness", id, tok, map[string]any{"seq": 10, "head": head, "ts": time.Now(), "sig": "00"}); code != 200 {
		t.Fatal(code)
	}
	if code := e.call(t, "POST", "/api/witness", id, tok, map[string]any{"seq": 5, "head": head}); code != 409 {
		t.Fatal("rewound log accepted:", code)
	}
	if code := e.call(t, "POST", "/api/witness", id, tok, map[string]any{"seq": 11, "head": "short"}); code != 400 {
		t.Fatal("bad head accepted:", code)
	}
	if cps := e.srv.Store.Checkpoints(id); len(cps) != 1 || cps[0].Seq != 10 {
		t.Fatal(cps)
	}
}

func TestACMETXTAndDNS(t *testing.T) {
	e := start(t)
	id, tok := e.register(t)
	if code := e.call(t, "POST", "/api/acme/txt", id, tok, map[string]string{"name": "_acme-challenge.victim.relay.test", "value": "x"}); code != 403 {
		t.Fatal("device set TXT for another name:", code)
	}
	if code := e.call(t, "POST", "/api/acme/txt", id, tok, map[string]string{"name": "_acme-challenge." + id + ".relay.test.", "value": "tok-1"}); code != 200 {
		t.Fatal(code)
	}
	udp, tcp, err := ListenDNS("127.0.0.1:0", &DNS{Zone: "relay.test", IPv4: net.ParseIP("203.0.113.7"), Store: e.srv.Store})
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Shutdown()
	defer tcp.Shutdown()
	q := func(name string, typ uint16) *dns.Msg {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(name), typ)
		r, _, err := new(dns.Client).Exchange(m, udp.PacketConn.LocalAddr().String())
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	if r := q("_acme-challenge."+id+".relay.test", dns.TypeTXT); len(r.Answer) != 1 || r.Answer[0].(*dns.TXT).Txt[0] != "tok-1" || !r.Authoritative {
		t.Fatal(r)
	}
	if r := q(id+".relay.test", dns.TypeA); len(r.Answer) != 1 || r.Answer[0].(*dns.A).A.String() != "203.0.113.7" {
		t.Fatal(r)
	}
	if r := q("example.com", dns.TypeA); r.Rcode != dns.RcodeRefused {
		t.Fatal("open resolver")
	}
	e.call(t, "DELETE", "/api/acme/txt", id, tok, map[string]string{"name": "_acme-challenge." + id + ".relay.test", "value": "tok-1"})
	if r := q("_acme-challenge."+id+".relay.test", dns.TypeTXT); len(r.Answer) != 0 {
		t.Fatal("TXT not deleted")
	}
}

func TestRegistrationClosed(t *testing.T) {
	e := start(t)
	e.srv.AllowReg = false
	resp, err := e.client.Post("https://relay.test/api/devices", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatal(resp.Status)
	}
}

func TestPeekSNI(t *testing.T) {
	a, b := net.Pipe()
	go func() {
		c := tls.Client(a, &tls.Config{ServerName: "abc.relay.test", InsecureSkipVerify: true})
		c.Handshake()
	}()
	sni, prefix, err := PeekSNI(b)
	if err != nil || sni != "abc.relay.test" || len(prefix) < 50 || prefix[0] != 0x16 {
		t.Fatal(sni, len(prefix), err)
	}
}

// TestRoute: стороннее имя пробрасывается на бэкенд без расшифровки — клиент
// видит сертификат бэкенда, а не relay.
func TestRoute(t *testing.T) {
	e := start(t)
	cert, leaf, _ := SelfSigned("site.test")
	bl, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { bl.Close() })
	go http.Serve(bl, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "site "+r.Host) }))
	if err := e.srv.AddRoute("Site.Test.", bl.Addr().String()); err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	get := func(host string, pool *x509.CertPool) (string, *x509.Certificate, error) {
		c := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{DialContext: e.dial, DisableKeepAlives: true,
			TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: host}}}
		resp, err := c.Get("https://" + host + "/")
		if err != nil {
			return "", nil, err
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return string(b), resp.TLS.PeerCertificates[0], nil
	}
	body, peer, err := get("site.test", pool)
	if err != nil || body != "site site.test" || !peer.Equal(leaf) {
		t.Fatal(body, err)
	}
	if _, _, err := get("other.test", pool); err == nil {
		t.Fatal("unknown SNI must be reset")
	}
	// Relay API остаётся на своём имени.
	if resp, err := e.client.Get("https://relay.test/api/health"); err != nil || resp.StatusCode != 200 {
		t.Fatal(resp, err)
	}
	for _, h := range []string{"relay.test", "abc.relay.test", ""} {
		if e.srv.AddRoute(h, "127.0.0.1:1") == nil {
			t.Fatalf("route %q must be rejected", h)
		}
	}
	if e.srv.AddRoute("x.test", "no-port") == nil {
		t.Fatal("bad backend address must be rejected")
	}
	// Бэкенд недоступен — соединение сбрасывается.
	bl.Close()
	if _, _, err := get("site.test", pool); err == nil {
		t.Fatal("expected failure with backend down")
	}
}
