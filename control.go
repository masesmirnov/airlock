package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	leaseDuration = 90 * time.Second
	checkInterval = 30 * time.Second
)

type Status struct {
	Open        bool     `json:"open"`
	Reason      string   `json:"reason,omitempty"`
	LeaseUntil  string   `json:"lease_until,omitempty"`
	LastCheck   string   `json:"last_check,omitempty"`
	Checks      int      `json:"checks"`
	ExitIP      string   `json:"exit_ip,omitempty"`
	ExitCountry string   `json:"exit_country,omitempty"`
	RuleCountry string   `json:"rule_country"`
	RuleIP      string   `json:"rule_ip,omitempty"`
	Proxy       string   `json:"proxy"`
	TZ          string   `json:"tz"`
	Lang        string   `json:"lang"`
	Port        int      `json:"port"`
	Shared      []string `json:"shared"`
	Private     []string `json:"private"`
	Browser     string   `json:"browser"`
	SystemTZ    bool     `json:"system_tz"`
}

type controller struct {
	mu         sync.Mutex
	cfg        *Config
	up         *upstream
	open       bool
	reason     string
	leaseUntil time.Time
	lastCheck  time.Time
	checks     int
	pinnedIP   string
	exitIP     string
	exitLoc    string
	paused     bool
	latched    bool
	onClose    func()
	kick       chan struct{}
}

func newController(cfg *Config, up *upstream) *controller {
	return &controller{cfg: cfg, up: up, reason: "starting", kick: make(chan struct{}, 1)}
}

func (c *controller) run() {
	t := time.NewTicker(checkInterval)
	for {
		c.check()
		select {
		case <-t.C:
		case <-c.kick:
		}
	}
}

func (c *controller) wake() {
	select {
	case c.kick <- struct{}{}:
	default:
	}
}

func (c *controller) allowed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.open && time.Now().Before(c.leaseUntil)
}

func (c *controller) upstreamIfOpen() *upstream {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.open && time.Now().Before(c.leaseUntil) {
		return c.up
	}
	return nil
}

func (c *controller) shut(reason string) {
	c.open = false
	c.reason = reason
	if c.onClose != nil {
		go c.onClose()
	}
}

func (c *controller) check() {
	c.mu.Lock()
	cfg, up, held := c.cfg, c.up, c.paused || c.latched
	c.mu.Unlock()
	if held {
		return
	}
	if err := cfg.ready(); err != nil || up == nil {
		c.mu.Lock()
		if err == nil {
			err = errors.New("proxy is not set")
		}
		c.shut("not configured: " + err.Error())
		c.mu.Unlock()
		return
	}
	ip, loc, err := probeExit(up)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cfg != cfg || c.paused || c.latched {
		return
	}
	now := time.Now()
	c.lastCheck = now
	c.checks++
	if err != nil {
		c.reason = "exit check failed: " + err.Error()
		if !now.Before(c.leaseUntil) {
			c.shut(c.reason)
		}
		return
	}
	c.exitIP, c.exitLoc = ip, loc
	switch {
	case loc == "":
		c.shut("exit country could not be determined")
	case !strings.EqualFold(loc, cfg.Country):
		c.shut(fmt.Sprintf("exit country %s does not match the rule %s", loc, cfg.Country))
	case cfg.IP != "" && ip != cfg.IP:
		c.shut(fmt.Sprintf("exit address %s does not match the rule %s", ip, cfg.IP))
	case c.pinnedIP != "" && ip != c.pinnedIP:
		c.latched = true
		c.shut(fmt.Sprintf("exit address changed from %s to %s, run: airlock reopen", c.pinnedIP, ip))
	default:
		c.pinnedIP = ip
		c.open = true
		c.reason = ""
		c.leaseUntil = now.Add(leaseDuration)
	}
}

func (c *controller) reload(cfg *Config, up *upstream) {
	c.mu.Lock()
	c.cfg, c.up = cfg, up
	c.pinnedIP, c.latched = "", false
	c.shut("configuration changed, checking")
	c.mu.Unlock()
	c.wake()
}

func (c *controller) pause() {
	c.mu.Lock()
	c.paused = true
	c.shut("paused by the owner")
	c.mu.Unlock()
}

func (c *controller) reopen() {
	c.mu.Lock()
	c.paused, c.latched, c.pinnedIP = false, false, ""
	c.mu.Unlock()
	c.wake()
}

func (c *controller) status() Status {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := Status{
		Open:        c.open && time.Now().Before(c.leaseUntil),
		Reason:      c.reason,
		Checks:      c.checks,
		ExitIP:      c.exitIP,
		ExitCountry: c.exitLoc,
		RuleCountry: c.cfg.Country,
		RuleIP:      c.cfg.IP,
		Proxy:       c.cfg.Proxy,
		TZ:          c.cfg.TZ,
		Lang:        c.cfg.Lang,
		Port:        c.cfg.Port,
		Shared:      c.cfg.Shared,
		Private:     c.cfg.Private,
		Browser:     c.cfg.Browser,
		SystemTZ:    c.cfg.SystemTZ,
	}
	if c.open && !s.Open {
		s.Reason = "lease expired: " + c.reason
	}
	if !c.leaseUntil.IsZero() {
		s.LeaseUntil = c.leaseUntil.Format(time.RFC3339)
	}
	if !c.lastCheck.IsZero() {
		s.LastCheck = c.lastCheck.Format(time.RFC3339)
	}
	return s
}

func getter(up *upstream) func(string) ([]byte, error) {
	client := &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			DisableKeepAlives: true,
			DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
				host, p, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, err
				}
				port, err := strconv.Atoi(p)
				if err != nil {
					return nil, err
				}
				return up.dial(ctx, host, port)
			},
		},
	}
	return func(url string) ([]byte, error) {
		resp, err := client.Get(url)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("%s answered %d", url, resp.StatusCode)
		}
		return io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	}
}

func probeZone(up *upstream) string {
	body, err := getter(up)("https://ipinfo.io/json")
	if err != nil {
		return ""
	}
	var v struct {
		Timezone string `json:"timezone"`
	}
	json.Unmarshal(body, &v)
	return v.Timezone
}

func probeExit(up *upstream) (ip, loc string, err error) {
	get := getter(up)
	body, err := get("https://www.cloudflare.com/cdn-cgi/trace")
	if err == nil {
		ip, loc = parseTrace(string(body))
		if ip != "" && loc != "" {
			return ip, loc, nil
		}
	}
	first := err
	body, err = get("https://ipinfo.io/json")
	if err != nil {
		if first != nil {
			err = first
		}
		return "", "", err
	}
	var v struct {
		IP      string `json:"ip"`
		Country string `json:"country"`
	}
	if err := json.Unmarshal(body, &v); err != nil || v.IP == "" {
		return "", "", errors.New("exit address service gave no address")
	}
	return v.IP, strings.ToUpper(v.Country), nil
}

func parseTrace(body string) (ip, loc string) {
	for _, line := range strings.Split(body, "\n") {
		k, v, _ := strings.Cut(strings.TrimSpace(line), "=")
		switch k {
		case "ip":
			ip = v
		case "loc":
			if v != "XX" && v != "T1" {
				loc = strings.ToUpper(v)
			}
		}
	}
	return ip, loc
}
