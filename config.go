package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	appName     = "airlock"
	accountName = "Claude"
	pipePath    = `\\.\pipe\airlock-control`
	routePipe   = `\\.\pipe\airlock-route`
	defaultPort = 47631
	accountFile = "account.bin"
	authFile    = "proxy-auth.bin"
)

type Config struct {
	Proxy    string   `json:"proxy"`
	Country  string   `json:"country"`
	IP       string   `json:"ip,omitempty"`
	TZ       string   `json:"tz"`
	Lang     string   `json:"lang"`
	Shared   []string `json:"shared"`
	Private  []string `json:"private"`
	Browser  string   `json:"browser"`
	Port     int      `json:"port"`
	OwnerSID string   `json:"owner_sid"`
	UserSID  string   `json:"user_sid"`
	SystemTZ bool     `json:"system_tz,omitempty"`
	HostZone string   `json:"host_zone,omitempty"`
}

type proxyAuth struct {
	User string `json:"user"`
	Pass string `json:"pass"`
}

func programDir() string { return filepath.Join(os.Getenv("ProgramFiles"), appName) }
func dataDir() string    { return filepath.Join(os.Getenv("ProgramData"), appName) }
func helperPath() string { return filepath.Join(programDir(), appName+"w.exe") }
func hookPath() string   { return filepath.Join(programDir(), appName+"hook.dll") }

func loadConfig() (*Config, error) {
	b, err := os.ReadFile(filepath.Join(dataDir(), "config.json"))
	if err != nil {
		return nil, err
	}
	c := &Config{}
	if err := json.Unmarshal(b, c); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Config) save() error {
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dataDir(), "config.json"), b, 0o600)
}

func (c *Config) ready() error {
	switch {
	case c.Proxy == "":
		return errors.New("proxy is not set")
	case c.Country == "":
		return errors.New("exit country rule is not set")
	case c.TZ == "":
		return errors.New("time zone is not set")
	case c.Lang == "":
		return errors.New("language is not set")
	}
	_, _, err := parseProxy(c.Proxy)
	return err
}

func parseProxy(raw string) (scheme, addr string, err error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", "", fmt.Errorf("bad proxy url: %w", err)
	}
	switch u.Scheme {
	case "socks5", "socks5h":
		scheme = "socks5"
	case "http":
		scheme = "http"
	default:
		return "", "", errors.New("proxy scheme must be socks5 or http")
	}
	if u.User != nil {
		return "", "", errors.New("keep the login out of the proxy url, enter it with: airlock proxy")
	}
	if u.Hostname() == "" || u.Port() == "" {
		return "", "", errors.New("proxy url needs host and port")
	}
	return scheme, u.Host, nil
}

func loadUpstream(c *Config) (*upstream, error) {
	scheme, addr, err := parseProxy(c.Proxy)
	if err != nil {
		return nil, err
	}
	up := &upstream{scheme: scheme, addr: addr}
	b, err := readSecret(authFile)
	if errors.Is(err, os.ErrNotExist) {
		return up, nil
	}
	if err != nil {
		return nil, err
	}
	var a proxyAuth
	if err := json.Unmarshal(b, &a); err != nil {
		return nil, err
	}
	up.user, up.pass = a.User, a.Pass
	return up, nil
}

func writeSecret(name string, data []byte) error {
	in := windows.DataBlob{Size: uint32(len(data)), Data: &data[0]}
	var out windows.DataBlob
	if err := windows.CryptProtectData(&in, nil, nil, 0, nil, windows.CRYPTPROTECT_LOCAL_MACHINE|windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return os.WriteFile(filepath.Join(dataDir(), name), bytes.Clone(unsafe.Slice(out.Data, out.Size)), 0o600)
}

func readSecret(name string) ([]byte, error) {
	enc, err := os.ReadFile(filepath.Join(dataDir(), name))
	if err != nil {
		return nil, err
	}
	if len(enc) == 0 {
		return nil, errors.New(name + " is empty")
	}
	in := windows.DataBlob{Size: uint32(len(enc)), Data: &enc[0]}
	var out windows.DataBlob
	if err := windows.CryptUnprotectData(&in, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return bytes.Clone(unsafe.Slice(out.Data, out.Size)), nil
}
