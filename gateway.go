package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Microsoft/go-winio"
)

type upstream struct {
	scheme, addr, user, pass string
}

type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufferedConn) Read(p []byte) (int, error) { return b.r.Read(p) }

func (u *upstream) dial(ctx context.Context, host string, port int) (net.Conn, error) {
	d := net.Dialer{Timeout: 15 * time.Second}
	raw, err := d.DialContext(ctx, "tcp4", u.addr)
	if err != nil {
		return nil, fmt.Errorf("proxy unreachable: %w", err)
	}
	raw.SetDeadline(time.Now().Add(30 * time.Second))
	var c net.Conn = raw
	if u.scheme == "http" {
		c, err = u.httpConnect(raw, host, port)
	} else {
		err = u.socksConnect(raw, host, port)
	}
	if err != nil {
		raw.Close()
		return nil, err
	}
	raw.SetDeadline(time.Time{})
	return c, nil
}

func (u *upstream) socksConnect(c net.Conn, host string, port int) error {
	hello := []byte{5, 1, 0}
	if u.user != "" {
		hello = []byte{5, 2, 0, 2}
	}
	if _, err := c.Write(hello); err != nil {
		return err
	}
	var r [2]byte
	if _, err := io.ReadFull(c, r[:]); err != nil {
		return err
	}
	if r[0] != 5 {
		return errors.New("proxy does not speak socks5")
	}
	switch r[1] {
	case 0:
	case 2:
		if len(u.user) > 255 || len(u.pass) > 255 {
			return errors.New("proxy credentials are too long")
		}
		req := append([]byte{1, byte(len(u.user))}, u.user...)
		req = append(append(req, byte(len(u.pass))), u.pass...)
		if _, err := c.Write(req); err != nil {
			return err
		}
		if _, err := io.ReadFull(c, r[:]); err != nil {
			return err
		}
		if r[1] != 0 {
			return errors.New("proxy rejected the credentials")
		}
	default:
		return errors.New("proxy offers no usable auth method")
	}
	req := []byte{5, 1, 0}
	if ip, err := netip.ParseAddr(host); err == nil && ip.Is4() {
		a := ip.As4()
		req = append(append(req, 1), a[:]...)
	} else {
		if len(host) > 255 {
			return errors.New("host name is too long")
		}
		req = append(append(req, 3, byte(len(host))), host...)
	}
	req = binary.BigEndian.AppendUint16(req, uint16(port))
	if _, err := c.Write(req); err != nil {
		return err
	}
	var h [4]byte
	if _, err := io.ReadFull(c, h[:]); err != nil {
		return err
	}
	if h[1] != 0 {
		return fmt.Errorf("proxy refused the connection (socks code %d)", h[1])
	}
	n := 0
	switch h[3] {
	case 1:
		n = 4
	case 4:
		n = 16
	case 3:
		var l [1]byte
		if _, err := io.ReadFull(c, l[:]); err != nil {
			return err
		}
		n = int(l[0])
	default:
		return errors.New("bad socks reply")
	}
	_, err := io.CopyN(io.Discard, c, int64(n+2))
	return err
}

func (u *upstream) httpConnect(c net.Conn, host string, port int) (net.Conn, error) {
	target := net.JoinHostPort(host, strconv.Itoa(port))
	req := "CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n"
	if u.user != "" {
		req += "Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(u.user+":"+u.pass)) + "\r\n"
	}
	if _, err := io.WriteString(c, req+"\r\n"); err != nil {
		return nil, err
	}
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("proxy refused the connection (http %d)", resp.StatusCode)
	}
	return &bufferedConn{Conn: c, r: br}, nil
}

var (
	errGateClosed = errors.New("gate is closed")
	errTarget     = errors.New("target is not allowed")
	reserved      = func() []netip.Prefix {
		var out []netip.Prefix
		for _, p := range []string{
			"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
			"192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15",
			"198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
		} {
			out = append(out, netip.MustParsePrefix(p))
		}
		return out
	}()
)

func checkTarget(host string, port int) error {
	h := strings.TrimSuffix(strings.ToLower(host), ".")
	if port < 1 || port > 65535 {
		return fmt.Errorf("%w: bad port", errTarget)
	}
	if h == "" || h == "localhost" || strings.HasSuffix(h, ".localhost") {
		return fmt.Errorf("%w: local name", errTarget)
	}
	ip, err := netip.ParseAddr(h)
	if err != nil {
		return nil
	}
	if !ip.Is4() {
		return fmt.Errorf("%w: ipv6 is blocked", errTarget)
	}
	for _, p := range reserved {
		if p.Contains(ip) {
			return fmt.Errorf("%w: %s is not a public address", errTarget, ip)
		}
	}
	return nil
}

func splitTarget(hostport string, def int) (string, int, error) {
	host, p, err := net.SplitHostPort(hostport)
	if err != nil {
		return strings.Trim(hostport, "[]"), def, nil
	}
	port, err := strconv.Atoi(p)
	if err != nil {
		return "", 0, fmt.Errorf("%w: bad port", errTarget)
	}
	return host, port, nil
}

type route struct {
	host  string
	port  int
	until time.Time
}

type dnsEntry struct {
	ips   []netip.Addr
	until time.Time
}

type gateway struct {
	ctl    *controller
	ln     net.Listener
	broken bool
	mu     sync.Mutex
	conns  map[net.Conn]struct{}
	routes map[uint16]route
	dns    map[string]dnsEntry
	names  map[netip.Addr]string
	doh    *http.Client
}

func newGateway(ctl *controller, port int) (*gateway, error) {
	ln, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		return nil, err
	}
	g := &gateway{ctl: ctl, ln: ln, conns: map[net.Conn]struct{}{}, routes: map[uint16]route{}, dns: map[string]dnsEntry{}, names: map[netip.Addr]string{}}
	g.doh = &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) { return g.open("1.1.1.1", 443) },
	}}
	return g, nil
}

func (g *gateway) serveRoutes(sid string) error {
	ln, err := winio.ListenPipe(routePipe, &winio.PipeConfig{SecurityDescriptor: "D:P(A;;GA;;;SY)(A;;GRGW;;;" + sid + ")", MessageMode: true})
	if err != nil {
		return err
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go g.route(c)
		}
	}()
	return nil
}

func (g *gateway) route(c net.Conn) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(15 * time.Second))
	buf := make([]byte, 512)
	n, err := c.Read(buf)
	if err != nil || n < 2 {
		return
	}
	switch buf[0] {
	case 'C':
		if n != 9 {
			return
		}
		ip, port := netip.AddrFrom4([4]byte(buf[3:7])), int(binary.BigEndian.Uint16(buf[7:9]))
		if g.refuses(ip, port) {
			c.Write([]byte{1})
			return
		}
		host := ip.String()
		g.mu.Lock()
		if name, ok := g.names[ip]; ok {
			host = name
		}
		now := time.Now()
		for p, r := range g.routes {
			if now.After(r.until) {
				delete(g.routes, p)
			}
		}
		g.routes[binary.BigEndian.Uint16(buf[1:3])] = route{host, port, now.Add(30 * time.Second)}
		g.mu.Unlock()
		c.Write([]byte{0})
	case 'R':
		ips, err := g.resolve(strings.TrimSuffix(strings.ToLower(string(buf[1:n])), "."))
		if err != nil {
			c.Write([]byte{0})
			return
		}
		out := []byte{byte(len(ips))}
		for _, ip := range ips {
			a := ip.As4()
			out = append(out, a[:]...)
		}
		c.Write(out)
	}
}

func (g *gateway) refuses(ip netip.Addr, port int) bool {
	up := g.ctl.upstreamIfOpen()
	if up == nil || checkTarget(ip.String(), port) != nil {
		return true
	}
	a, err := netip.ParseAddrPort(up.addr)
	return err == nil && a == netip.AddrPortFrom(ip, uint16(port))
}

func (g *gateway) resolve(name string) ([]netip.Addr, error) {
	if err := checkTarget(name, 443); err != nil {
		return nil, err
	}
	g.mu.Lock()
	e, ok := g.dns[name]
	g.mu.Unlock()
	if ok && time.Now().Before(e.until) {
		return e.ips, nil
	}
	req, err := http.NewRequest(http.MethodGet, "https://1.1.1.1/dns-query?type=A&name="+name, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-json")
	resp, err := g.doh.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var r struct {
		Status int
		Answer []struct {
			Type int
			TTL  int
			Data string
		}
	}
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return nil, err
	}
	ttl := 300
	var ips []netip.Addr
	for _, a := range r.Answer {
		ip, err := netip.ParseAddr(a.Data)
		if a.Type != 1 || err != nil || !ip.Is4() || checkTarget(ip.String(), 443) != nil || len(ips) == 16 {
			continue
		}
		ips = append(ips, ip)
		ttl = min(ttl, max(a.TTL, 30))
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("%s: no address", name)
	}
	g.mu.Lock()
	g.dns[name] = dnsEntry{ips, time.Now().Add(time.Duration(ttl) * time.Second)}
	for _, ip := range ips {
		g.names[ip] = name
	}
	g.mu.Unlock()
	return ips, nil
}

func (g *gateway) take(addr net.Addr) (route, bool) {
	a, ok := addr.(*net.TCPAddr)
	if !ok {
		return route{}, false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	r, ok := g.routes[uint16(a.Port)]
	delete(g.routes, uint16(a.Port))
	return r, ok && time.Now().Before(r.until)
}

func (g *gateway) serve() {
	go func() {
		for range time.Tick(time.Second) {
			if !g.ctl.allowed() {
				g.closeAll()
			}
		}
	}()
	for {
		c, err := g.ln.Accept()
		if err != nil {
			return
		}
		go g.handle(c)
	}
}

func (g *gateway) closeAll() {
	g.mu.Lock()
	defer g.mu.Unlock()
	for c := range g.conns {
		c.Close()
	}
}

func (g *gateway) handle(c net.Conn) {
	g.mu.Lock()
	g.conns[c] = struct{}{}
	g.mu.Unlock()
	defer func() {
		c.Close()
		g.mu.Lock()
		delete(g.conns, c)
		g.mu.Unlock()
	}()
	br := bufio.NewReader(c)
	if r, ok := g.take(c.RemoteAddr()); ok {
		up, err := g.open(r.host, r.port)
		if err != nil {
			return
		}
		pipe(c, br, up)
		return
	}
	c.SetReadDeadline(time.Now().Add(30 * time.Second))
	first, err := br.Peek(1)
	if err != nil {
		return
	}
	if first[0] == 5 {
		g.socks(c, br)
	} else {
		g.http(c, br)
	}
}

func (g *gateway) open(host string, port int) (net.Conn, error) {
	if err := checkTarget(host, port); err != nil {
		return nil, err
	}
	up := g.ctl.upstreamIfOpen()
	if up == nil {
		return nil, errGateClosed
	}
	if g.broken {
		down := *up
		down.addr = "127.0.0.1:1"
		up = &down
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return up.dial(ctx, host, port)
}

func (g *gateway) socks(c net.Conn, br *bufio.Reader) {
	var h [2]byte
	if _, err := io.ReadFull(br, h[:]); err != nil {
		return
	}
	if _, err := io.CopyN(io.Discard, br, int64(h[1])); err != nil {
		return
	}
	c.Write([]byte{5, 0})
	var q [4]byte
	if _, err := io.ReadFull(br, q[:]); err != nil {
		return
	}
	reply := func(code byte) { c.Write([]byte{5, code, 0, 1, 0, 0, 0, 0, 0, 0}) }
	if q[1] != 1 {
		reply(7)
		return
	}
	var host string
	switch q[3] {
	case 1:
		var a [4]byte
		if _, err := io.ReadFull(br, a[:]); err != nil {
			return
		}
		host = netip.AddrFrom4(a).String()
	case 3:
		var l [1]byte
		if _, err := io.ReadFull(br, l[:]); err != nil {
			return
		}
		name := make([]byte, l[0])
		if _, err := io.ReadFull(br, name); err != nil {
			return
		}
		host = string(name)
	default:
		reply(8)
		return
	}
	var p [2]byte
	if _, err := io.ReadFull(br, p[:]); err != nil {
		return
	}
	up, err := g.open(host, int(binary.BigEndian.Uint16(p[:])))
	switch {
	case errors.Is(err, errTarget), errors.Is(err, errGateClosed):
		reply(2)
		return
	case err != nil:
		reply(5)
		return
	}
	reply(0)
	pipe(c, br, up)
}

func (g *gateway) http(c net.Conn, br *bufio.Reader) {
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	fail := func(err error) {
		code := http.StatusBadGateway
		switch {
		case errors.Is(err, errTarget):
			code = http.StatusForbidden
		case errors.Is(err, errGateClosed):
			code = http.StatusServiceUnavailable
		}
		msg := "airlock: " + err.Error() + "\n"
		fmt.Fprintf(c, "HTTP/1.1 %d %s\r\nContent-Type: text/plain\r\nConnection: close\r\nContent-Length: %d\r\n\r\n%s", code, http.StatusText(code), len(msg), msg)
	}
	if req.Method == http.MethodConnect {
		host, port, err := splitTarget(req.Host, 443)
		if err != nil {
			fail(err)
			return
		}
		up, err := g.open(host, port)
		if err != nil {
			fail(err)
			return
		}
		io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\n")
		pipe(c, br, up)
		return
	}
	if req.URL.Scheme != "http" || req.URL.Host == "" {
		fail(fmt.Errorf("%w: only http:// and CONNECT are proxied", errTarget))
		return
	}
	host, port, err := splitTarget(req.URL.Host, 80)
	if err != nil {
		fail(err)
		return
	}
	up, err := g.open(host, port)
	if err != nil {
		fail(err)
		return
	}
	defer up.Close()
	req.RequestURI = ""
	req.Header.Del("Proxy-Connection")
	req.Header.Del("Proxy-Authorization")
	req.Close = true
	c.SetReadDeadline(time.Time{})
	if err := req.Write(up); err != nil {
		return
	}
	io.Copy(c, up)
}

func pipe(c net.Conn, br *bufio.Reader, up net.Conn) {
	defer up.Close()
	c.SetReadDeadline(time.Time{})
	done := make(chan struct{}, 2)
	go func() {
		io.Copy(up, br)
		closeWrite(up)
		done <- struct{}{}
	}()
	go func() {
		io.Copy(c, up)
		closeWrite(c)
		done <- struct{}{}
	}()
	<-done
	<-done
}

func closeWrite(c net.Conn) {
	if h, ok := c.(interface{ CloseWrite() error }); ok {
		h.CloseWrite()
		return
	}
	c.Close()
}
