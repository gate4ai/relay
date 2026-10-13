// SPDX-License-Identifier: FSL-1.1-ALv2

package relay

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/hashicorp/yamux"
)

// Server — relay.
type Server struct {
	Domain   string      // relay.gate4.ai: устройства — <id>.relay.gate4.ai
	TLS      *tls.Config // сертификат самого relay (для туннеля и API)
	Store    *Store
	Log      *slog.Logger
	HoldFor  time.Duration // сколько держать входящее при офлайн-устройстве (~30 с)
	AllowReg bool          // открытая регистрация устройств

	mu       sync.Mutex
	sessions map[string]*yamux.Session
	waiters  map[string][]chan struct{}
}

// NewServer создаёт relay.
func NewServer(domain string, tlsCfg *tls.Config, st *Store) *Server {
	return &Server{Domain: strings.ToLower(domain), TLS: tlsCfg, Store: st, Log: slog.Default(), HoldFor: 30 * time.Second,
		AllowReg: true, sessions: map[string]*yamux.Session{}, waiters: map[string][]chan struct{}{}}
}

// DeviceHost — публичное имя устройства.
func (s *Server) DeviceHost(id string) string { return id + "." + s.Domain }

// Serve принимает TCP-соединения (порт 443).
func (s *Server) Serve(l net.Listener) error {
	api := &http.Server{Handler: s.apiHandler(), ReadHeaderTimeout: 10 * time.Second}
	apiConns := newChanListener(l.Addr())
	go api.Serve(tls.NewListener(apiConns, s.TLS))
	defer api.Close()
	for {
		c, err := l.Accept()
		if err != nil {
			return err
		}
		go s.handle(c, apiConns)
	}
}

func (s *Server) handle(c net.Conn, api *chanListener) {
	sni, prefix, err := PeekSNI(c)
	if err != nil {
		c.Close()
		return
	}
	sni = strings.ToLower(sni)
	if sni == s.Domain {
		api.push(WithPrefix(c, prefix))
		return
	}
	id, ok := strings.CutSuffix(sni, "."+s.Domain)
	if !ok || id == "" || strings.Contains(id, ".") {
		c.Close()
		return
	}
	if !s.Store.Exists(id) {
		c.Close()
		return
	}
	sess := s.waitSession(id)
	if sess == nil {
		c.Close() // устройство офлайн: очереди нет, агент повторит позже
		return
	}
	st, err := sess.Open()
	if err != nil {
		c.Close()
		return
	}
	// Passthrough: relay не расшифровывает трафик.
	go func() { _, _ = st.Write(prefix); _, _ = io.Copy(st, c); st.Close() }()
	_, _ = io.Copy(c, st)
	c.Close()
}

// SetHoldFor меняет время удержания входящих соединений офлайн-устройства.
func (s *Server) SetHoldFor(d time.Duration) {
	s.mu.Lock()
	s.HoldFor = d
	s.mu.Unlock()
}

func (s *Server) waitSession(id string) *yamux.Session {
	s.mu.Lock()
	deadline := time.Now().Add(s.HoldFor)
	s.mu.Unlock()
	for {
		s.mu.Lock()
		sess := s.sessions[id]
		if sess != nil && sess.IsClosed() {
			delete(s.sessions, id)
			sess = nil
		}
		if sess != nil {
			s.mu.Unlock()
			return sess
		}
		wait := time.Until(deadline)
		if wait <= 0 {
			s.mu.Unlock()
			return nil
		}
		ch := make(chan struct{})
		s.waiters[id] = append(s.waiters[id], ch)
		s.mu.Unlock()
		select {
		case <-ch:
		case <-time.After(wait):
		}
	}
}

// Online — подключено ли устройство.
func (s *Server) Online(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess := s.sessions[id]
	return sess != nil && !sess.IsClosed()
}

// Disconnect обрывает туннель устройства (администрирование и тесты);
// устройство переподключится само.
func (s *Server) Disconnect(id string) {
	s.mu.Lock()
	sess := s.sessions[id]
	s.mu.Unlock()
	if sess != nil {
		sess.Close()
	}
}

func deviceAuth(r *http.Request) (string, string) {
	id := r.Header.Get("X-Gate4ai-Device")
	tok, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	return id, tok
}

func (s *Server) apiHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/devices", func(w http.ResponseWriter, r *http.Request) {
		if !s.AllowReg {
			http.Error(w, "registration closed", 403)
			return
		}
		id, tok, err := s.Store.Register()
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		writeJSON(w, map[string]string{"device_id": id, "token": tok, "host": s.DeviceHost(id)})
	})
	mux.HandleFunc("GET /tunnel", func(w http.ResponseWriter, r *http.Request) {
		id, tok := deviceAuth(r)
		if !s.Store.Auth(id, tok) {
			http.Error(w, "unauthorized", 401)
			return
		}
		ws, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		ws.SetReadLimit(-1)
		conn := websocket.NetConn(context.Background(), ws, websocket.MessageBinary)
		cfg := yamux.DefaultConfig()
		cfg.LogOutput = io.Discard
		cfg.KeepAliveInterval = 15 * time.Second
		sess, err := yamux.Client(conn, cfg)
		if err != nil {
			conn.Close()
			return
		}
		s.mu.Lock()
		if old := s.sessions[id]; old != nil {
			old.Close()
		}
		s.sessions[id] = sess
		for _, ch := range s.waiters[id] {
			close(ch)
		}
		delete(s.waiters, id)
		s.mu.Unlock()
		s.Log.Info("device connected", "device", id)
		<-sess.CloseChan()
		s.Log.Info("device disconnected", "device", id)
	})
	// ACME DNS-01: устройство ставит TXT только для своего имени.
	mux.HandleFunc("POST /api/acme/txt", func(w http.ResponseWriter, r *http.Request) { s.txt(w, r, true) })
	mux.HandleFunc("DELETE /api/acme/txt", func(w http.ResponseWriter, r *http.Request) { s.txt(w, r, false) })
	mux.HandleFunc("POST /api/witness", func(w http.ResponseWriter, r *http.Request) {
		id, tok := deviceAuth(r)
		if !s.Store.Auth(id, tok) {
			http.Error(w, "unauthorized", 401)
			return
		}
		var cp WitnessedCheckpoint
		if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&cp); err != nil || len(cp.Head) != 64 {
			http.Error(w, "bad checkpoint", 400)
			return
		}
		cp.ReceivedAt = time.Now().UTC()
		if err := s.Store.AddCheckpoint(id, cp); err != nil {
			http.Error(w, err.Error(), 409)
			return
		}
		writeJSON(w, map[string]any{"ok": true})
	})
	mux.HandleFunc("GET /api/witness/{id}", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, s.Store.Checkpoints(r.PathValue("id")))
	})
	mux.HandleFunc("GET /api/health", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, map[string]bool{"ok": true}) })
	return mux
}

func (s *Server) txt(w http.ResponseWriter, r *http.Request, set bool) {
	id, tok := deviceAuth(r)
	if !s.Store.Auth(id, tok) {
		http.Error(w, "unauthorized", 401)
		return
	}
	var req struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	want := "_acme-challenge." + s.DeviceHost(id)
	if strings.ToLower(strings.TrimSuffix(req.Name, ".")) != want {
		http.Error(w, "a device may only set "+want, 403)
		return
	}
	var err error
	if set {
		err = s.Store.SetTXT(want, req.Value)
	} else {
		err = s.Store.DelTXT(want, req.Value)
	}
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// chanListener — net.Listener из канала соединений.
type chanListener struct {
	ch     chan net.Conn
	addr   net.Addr
	once   sync.Once
	closed chan struct{}
}

func newChanListener(a net.Addr) *chanListener {
	return &chanListener{ch: make(chan net.Conn), addr: a, closed: make(chan struct{})}
}

func (l *chanListener) push(c net.Conn) {
	select {
	case l.ch <- c:
	case <-l.closed:
		c.Close()
	}
}

func (l *chanListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ch:
		return c, nil
	case <-l.closed:
		return nil, errors.New("listener closed")
	}
}

func (l *chanListener) Close() error   { l.once.Do(func() { close(l.closed) }); return nil }
func (l *chanListener) Addr() net.Addr { return l.addr }
