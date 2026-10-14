// SPDX-License-Identifier: FSL-1.1-ALv2

// Команда gate4ai-relay — relay gate4.ai: публичный адрес устройств
// (<device-id>.<domain>), TLS-passthrough по SNI, туннели WebSocket + yamux,
// авторитетный DNS зоны для ACME DNS-01, свидетель чекпоинтов. Тот же бинарник
// для hosted и self-hosted. --route пробрасывает сторонние имена (сайт) на
// локальный бэкенд по SNI, тоже без расшифровки.
package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"

	"github.com/gate4ai/relay"
)

// version — версия сборки (-ldflags "-X main.version=…").
var version = "dev"

func main() {
	domain := flag.String("domain", "relay.gate4.ai", "relay domain; devices are <id>.<domain>")
	listen := flag.String("listen", ":443", "TCP address for TLS (tunnels, API, device traffic)")
	dnsAddr := flag.String("dns", "", "address of the authoritative DNS server for the zone, e.g. :53 (empty — off)")
	ipv4 := flag.String("ipv4", "", "public IPv4 of the relay (A records)")
	ipv6 := flag.String("ipv6", "", "public IPv6 of the relay (AAAA records)")
	certFile := flag.String("cert", "", "TLS certificate of the relay domain (PEM)")
	keyFile := flag.String("key", "", "TLS key (PEM)")
	selfSigned := flag.Bool("self-signed", false, "development: self-signed certificate for the relay domain")
	stateFile := flag.String("state", "relay-state.json", "state file (devices, TXT records, witnessed checkpoints)")
	openReg := flag.Bool("open-registration", true, "allow new devices to register")
	var routes routeFlags
	flag.Var(&routes, "route", "pass TLS for another name to a backend by SNI, without decrypting: host=addr, e.g. gate4.ai=127.0.0.1:8443 (repeatable)")
	showVersion := flag.Bool("version", false, "")
	flag.Parse()
	if *showVersion {
		fmt.Println("gate4ai-relay", version)
		return
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if err := run(log, *domain, *listen, *dnsAddr, *ipv4, *ipv6, *certFile, *keyFile, *selfSigned, *stateFile, *openReg, routes); err != nil {
		log.Error("relay", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger, domain, listen, dnsAddr, ipv4, ipv6, certFile, keyFile string, selfSigned bool, stateFile string, openReg bool, routes []string) error {
	var cert tls.Certificate
	var err error
	switch {
	case certFile != "":
		cert, err = tls.LoadX509KeyPair(certFile, keyFile)
	case selfSigned:
		cert, _, err = relay.SelfSigned(domain)
	default:
		return fmt.Errorf("pass --cert/--key for %s (or --self-signed for development)", domain)
	}
	if err != nil {
		return err
	}
	st, err := relay.OpenStore(stateFile)
	if err != nil {
		return err
	}
	if dnsAddr != "" {
		h := &relay.DNS{Zone: domain, IPv4: net.ParseIP(ipv4), IPv6: net.ParseIP(ipv6), Store: st}
		if _, _, err := relay.ListenDNS(dnsAddr, h); err != nil {
			return fmt.Errorf("dns: %w", err)
		}
		log.Info("dns listening", "addr", dnsAddr, "zone", domain)
	}
	s := relay.NewServer(domain, &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"http/1.1"}}, st)
	s.Log, s.AllowReg = log, openReg
	for _, r := range routes {
		host, addr, _ := strings.Cut(r, "=")
		if err := s.AddRoute(host, addr); err != nil {
			return err
		}
		log.Info("route", "host", host, "backend", addr)
	}
	l, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	log.Info("relay listening", "addr", listen, "domain", domain)
	return s.Serve(l)
}

// routeFlags — повторяемый флаг --route host=addr.
type routeFlags []string

func (r *routeFlags) String() string     { return strings.Join(*r, ",") }
func (r *routeFlags) Set(v string) error { *r = append(*r, v); return nil }
