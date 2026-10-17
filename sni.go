// SPDX-License-Identifier: AGPL-3.0-only

// Package relay — собственный relay gate4.ai: устройство держит исходящее
// соединение WebSocket поверх TLS:443 с мультиплексором yamux; входящие TLS-
// соединения облачных агентов relay пробрасывает по SNI без расшифровки
// (TLS-passthrough), сертификат выпускается на устройство (ACME DNS-01).
// Relay также свидетель чекпоинтов журнала (видит только хэши).
package relay

import (
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"time"
)

var errSNIDone = errors.New("sni captured")

// recordingConn — только чтение, всё прочитанное сохраняется для повтора.
type recordingConn struct {
	r   io.Reader
	buf bytes.Buffer
}

func (c *recordingConn) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.buf.Write(p[:n])
	return n, err
}
func (c *recordingConn) Write(p []byte) (int, error)      { return 0, io.ErrClosedPipe }
func (c *recordingConn) Close() error                     { return nil }
func (c *recordingConn) LocalAddr() net.Addr              { return nil }
func (c *recordingConn) RemoteAddr() net.Addr             { return nil }
func (c *recordingConn) SetDeadline(time.Time) error      { return nil }
func (c *recordingConn) SetReadDeadline(time.Time) error  { return nil }
func (c *recordingConn) SetWriteDeadline(time.Time) error { return nil }

// PeekSNI читает ClientHello и возвращает SNI и прочитанные байты (их нужно
// отдать получателю первыми). Relay видит только ClientHello.
func PeekSNI(conn net.Conn) (string, []byte, error) {
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	defer conn.SetReadDeadline(time.Time{})
	rc := &recordingConn{r: io.LimitReader(conn, 64<<10)}
	var sni string
	err := tls.Server(rc, &tls.Config{GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
		sni = h.ServerName
		return nil, errSNIDone
	}}).Handshake()
	if sni == "" {
		if err == nil || errors.Is(err, errSNIDone) {
			err = errors.New("no SNI in ClientHello")
		}
		return "", rc.buf.Bytes(), err
	}
	return sni, rc.buf.Bytes(), nil
}

// prefixConn — соединение, отдающее сначала prefix.
type prefixConn struct {
	net.Conn
	r io.Reader
}

func (c *prefixConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// WithPrefix возвращает conn, который сначала отдаёт prefix.
func WithPrefix(conn net.Conn, prefix []byte) net.Conn {
	return &prefixConn{Conn: conn, r: io.MultiReader(bytes.NewReader(prefix), conn)}
}
