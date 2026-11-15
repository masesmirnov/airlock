package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
	"golang.org/x/term"
)

func call(req request) (*response, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := winio.DialPipeAccessImpLevel(ctx, pipePath, windows.GENERIC_READ|windows.GENERIC_WRITE, winio.PipeImpLevelIdentification)
	if err != nil {
		return nil, fmt.Errorf("service is not reachable: %w", err)
	}
	defer c.Close()
	if err := json.NewEncoder(c).Encode(req); err != nil {
		return nil, err
	}
	var resp response
	if err := json.NewDecoder(bufio.NewReader(c)).Decode(&resp); err != nil {
		return nil, err
	}
	if resp.Error != "" {
		return &resp, errors.New(resp.Error)
	}
	return &resp, nil
}

func sandboxRun(req request) (*response, error) {
	sid, _, _, err := windows.LookupSID("", accountName)
	if err != nil {
		return nil, fmt.Errorf("sandbox account is missing, run: airlock install (%w)", err)
	}
	if err := grantDesktop(sid); err != nil {
		return nil, err
	}
	req.Cmd = "run"
	return call(req)
}

func cmdRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	wait := fs.Bool("wait", false, "wait for the program and return its exit code")
	hidden := fs.Bool("hidden", false, "start without a window")
	if err := fs.Parse(args); err != nil {
		return err
	}
	args = fs.Args()
	if len(args) == 0 {
		return errors.New("usage: airlock run [-wait] [-hidden] [--] <command> [args...]")
	}
	if !strings.ContainsAny(args[0], `\/`) {
		if p, err := exec.LookPath(args[0]); err == nil {
			args[0] = p
		}
	}
	resp, err := sandboxRun(request{Line: windows.ComposeCommandLine(args), Wait: *wait, Hidden: *hidden, Hook: true})
	if err != nil {
		return err
	}
	if *wait {
		if resp.Exit != 0 {
			os.Exit(int(resp.Exit))
		}
		return nil
	}
	fmt.Printf("started pid %d\n", resp.PID)
	return nil
}

func cmdBrowser(args []string) error {
	_, err := sandboxRun(request{Line: windows.ComposeCommandLine(append([]string{helperPath(), "browser-host"}, args...)), Hidden: true})
	return err
}

func cmdSimple(cmd string) error {
	resp, err := call(request{Cmd: cmd})
	if err != nil {
		return err
	}
	printStatus(resp.Status)
	return nil
}

func cmdLog() error {
	resp, err := call(request{Cmd: "log"})
	if err != nil {
		return err
	}
	for _, line := range resp.Log {
		fmt.Println(line)
	}
	return nil
}

func printStatus(s *Status) {
	state := "OPEN"
	if !s.Open {
		state = "CLOSED"
	}
	fmt.Printf("gate:        %s\n", state)
	if s.Reason != "" {
		fmt.Printf("reason:      %s\n", s.Reason)
	}
	fmt.Printf("exit:        %s %s\n", s.ExitIP, s.ExitCountry)
	fmt.Printf("rule:        country %s", s.RuleCountry)
	if s.RuleIP != "" {
		fmt.Printf(", address %s", s.RuleIP)
	}
	fmt.Printf("\nlease until: %s\nlast check:  %s\n", s.LeaseUntil, s.LastCheck)
	fmt.Printf("proxy:       %s\ntime zone:   %s\nlanguage:    %s\nshared:      %s\n", s.Proxy, s.TZ, s.Lang, strings.Join(s.Shared, ", "))
}

func cmdKill() error {
	resp, err := call(request{Cmd: "kill"})
	if err != nil {
		return err
	}
	fmt.Printf("stopped %d sandbox programs\n", resp.Count)
	return nil
}

func elevate() error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	dir, err := os.Getwd()
	if err != nil {
		return err
	}
	line := windows.ComposeCommandLine(append(os.Args[1:], holdFlag))
	if err := windows.ShellExecute(0, u16("runas"), u16(self), u16(line), u16(dir), windows.SW_SHOWNORMAL); err != nil {
		return fmt.Errorf("administrator rights were not granted: %w", err)
	}
	fmt.Println("continuing in the administrator window")
	return nil
}

func elevateWait(args ...string) (bool, error) {
	self, err := os.Executable()
	if err != nil {
		return false, err
	}
	info := struct {
		size, mask            uint32
		hwnd                  uintptr
		verb, file, args, dir *uint16
		show                  int32
		app, ids              uintptr
		class                 *uint16
		classKey              uintptr
		hotKey                uint32
		icon                  uintptr
		process               windows.Handle
	}{mask: 0x40, verb: u16("runas"), file: u16(self), args: u16(windows.ComposeCommandLine(args)), show: windows.SW_HIDE}
	info.size = uint32(unsafe.Sizeof(info))
	if r, _, err := shell32.NewProc("ShellExecuteExW").Call(uintptr(unsafe.Pointer(&info))); r == 0 {
		if errors.Is(err, windows.ERROR_CANCELLED) {
			return false, nil
		}
		return false, fmt.Errorf("administrator rights were not granted: %w", err)
	}
	defer windows.CloseHandle(info.process)
	windows.WaitForSingleObject(info.process, windows.INFINITE)
	var code uint32
	windows.GetExitCodeProcess(info.process, &code)
	return code == 0, nil
}

func setFlags(cfg *Config, args []string) error {
	fs := flag.NewFlagSet(os.Args[1], flag.ContinueOnError)
	fs.StringVar(&cfg.Proxy, "proxy", cfg.Proxy, "socks5://host:port or http://host:port")
	fs.StringVar(&cfg.Country, "country", cfg.Country, "required exit country, ISO code")
	fs.StringVar(&cfg.IP, "ip", cfg.IP, "required exit address, optional")
	fs.StringVar(&cfg.TZ, "tz", cfg.TZ, "IANA time zone, for example America/New_York")
	fs.StringVar(&cfg.Lang, "lang", cfg.Lang, "language tag, for example en-US")
	fs.BoolVar(&cfg.SystemTZ, "windows-tz", cfg.SystemTZ, "switch the Windows time zone to the zone of the exit while the service runs")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg.Country = strings.ToUpper(cfg.Country)
	if cfg.Proxy != "" {
		if _, _, err := parseProxy(cfg.Proxy); err != nil {
			return err
		}
	}
	if _, err := time.LoadLocation(cfg.TZ); cfg.TZ != "" && err != nil {
		return fmt.Errorf("unknown time zone %q", cfg.TZ)
	}
	return nil
}

func cmdSet(args []string) error {
	cfg, err := loadConfig()
	if err != nil {
		return fmt.Errorf("not installed: %w", err)
	}
	if err := setFlags(cfg, args); err != nil {
		return err
	}
	if err := cfg.save(); err != nil {
		return err
	}
	return cmdSimple("reload")
}

func cmdProxy() error {
	cfg, err := loadConfig()
	if err != nil {
		return fmt.Errorf("not installed: %w", err)
	}
	auth, err := askProxy(cfg)
	if err != nil || auth == nil {
		return err
	}
	if err := saveAuth(auth); err != nil {
		return err
	}
	if err := cfg.save(); err != nil {
		return err
	}
	return cmdSimple("reload")
}

func saveAuth(a *proxyAuth) error {
	if a.User == "" {
		if err := os.Remove(filepath.Join(dataDir(), authFile)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	b, err := json.Marshal(a)
	if err != nil {
		return err
	}
	return writeSecret(authFile, b)
}

func askProxy(cfg *Config) (*proxyAuth, error) {
	fmt.Print("paste the proxy as ip:port:user:password and press Enter (input stays hidden): ")
	raw, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return nil, err
	}
	line := strings.TrimSpace(string(raw))
	if line == "" {
		fmt.Println("no proxy given, the gate stays closed until you run: airlock proxy")
		return nil, nil
	}
	auth, err := resolveProxy(cfg, line, func(format string, a ...any) { fmt.Printf(format+"\n", a...) })
	if err != nil {
		return nil, err
	}
	if cfg.TZ == "" {
		fmt.Print("time zone of the exit was not detected, type it (for example America/New_York): ")
		zone, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil {
			return nil, err
		}
		cfg.TZ = strings.TrimSpace(zone)
	}
	if _, err := time.LoadLocation(cfg.TZ); cfg.TZ == "" || err != nil {
		return nil, fmt.Errorf("unknown time zone %q", cfg.TZ)
	}
	fmt.Printf("saved: exit country %s, time zone %s, language %s (change with: airlock set)\n", cfg.Country, cfg.TZ, cfg.Lang)
	return auth, nil
}

func resolveProxy(cfg *Config, line string, say func(string, ...any)) (*proxyAuth, error) {
	schemes := []string{"socks5", "http"}
	for _, s := range schemes {
		if rest, ok := strings.CutPrefix(line, s+"://"); ok {
			line, schemes = rest, []string{s}
			break
		}
	}
	parts := strings.SplitN(line, ":", 4)
	if len(parts) != 2 && len(parts) != 4 {
		return nil, errors.New("expected ip:port or ip:port:user:password")
	}
	if port, err := strconv.Atoi(parts[1]); err != nil || port < 1 || port > 65535 {
		return nil, errors.New("the second field must be the port number")
	}
	addr := net.JoinHostPort(parts[0], parts[1])
	auth := &proxyAuth{}
	if len(parts) == 4 {
		auth.User, auth.Pass = parts[2], parts[3]
	}
	say("proxy %s, login %q, password of %d characters", addr, auth.User, len(auth.Pass))
	var err error
	for _, scheme := range schemes {
		up := &upstream{scheme: scheme, addr: addr, user: auth.User, pass: auth.Pass}
		ip, loc, perr := probeExit(up)
		if perr != nil {
			say("as %s it does not work: %v", scheme, perr)
			err = perr
			continue
		}
		say("works as %s, exit %s, country %s", scheme, ip, loc)
		cfg.Proxy, cfg.Country, cfg.IP = scheme+"://"+addr, loc, ""
		if zone := probeZone(up); zone != "" {
			cfg.TZ = zone
		}
		if cfg.Lang == "" {
			cfg.Lang = "en-US"
		}
		return auth, nil
	}
	return nil, fmt.Errorf("the proxy did not work as socks5 or http: %w", err)
}
