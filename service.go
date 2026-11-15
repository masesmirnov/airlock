package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
)

var (
	procPipeSession = kernel32.NewProc("GetNamedPipeClientSessionId")
	procProcessIDs  = windows.NewLazySystemDLL("psapi.dll").NewProc("EnumProcesses")
	procAllocEx     = kernel32.NewProc("VirtualAllocEx")
	procRemote      = kernel32.NewProc("CreateRemoteThread")
	procLoadLibrary = kernel32.NewProc("LoadLibraryW")
	procThreadExit  = kernel32.NewProc("GetExitCodeThread")
)

type request struct {
	Cmd     string `json:"cmd"`
	Line    string `json:"line,omitempty"`
	Dir     string `json:"dir,omitempty"`
	Hidden  bool   `json:"hidden,omitempty"`
	Wait    bool   `json:"wait,omitempty"`
	Timeout int    `json:"timeout,omitempty"`
	Hook    bool   `json:"hook,omitempty"`
}

type proc struct {
	PID  uint32 `json:"pid"`
	Path string `json:"path"`
}

type response struct {
	Error  string   `json:"error,omitempty"`
	PID    uint32   `json:"pid,omitempty"`
	Exit   uint32   `json:"exit,omitempty"`
	Count  int      `json:"count"`
	Status *Status  `json:"status,omitempty"`
	Log    []string `json:"log,omitempty"`
	Procs  []proc   `json:"procs,omitempty"`
}

type server struct {
	mu    sync.Mutex
	cfg   *Config
	ctl   *controller
	sid   *windows.SID
	token windows.Token
	hive  registry.Key
}

var recent struct {
	sync.Mutex
	lines []string
}

func logf(format string, args ...any) {
	line := fmt.Sprintf(format, args...)
	log.Print(line)
	recent.Lock()
	recent.lines = append(recent.lines, time.Now().Format("15:04:05 ")+line)
	if len(recent.lines) > 80 {
		recent.lines = recent.lines[len(recent.lines)-80:]
	}
	recent.Unlock()
}

func cmdService() error {
	f, err := os.OpenFile(filepath.Join(dataDir(), appName+".log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err == nil {
		log.SetOutput(f)
	}
	return svc.Run(appName, &server{})
}

func (s *server) Execute(_ []string, r <-chan svc.ChangeRequest, st chan<- svc.Status) (bool, uint32) {
	st <- svc.Status{State: svc.StartPending}
	if err := s.start(); err != nil {
		logf("start: %v", err)
		return true, 1
	}
	st <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for c := range r {
		switch c.Cmd {
		case svc.Interrogate:
			st <- c.CurrentStatus
		case svc.Stop, svc.Shutdown:
			st <- svc.Status{State: svc.StopPending}
			s.mu.Lock()
			cfg := *s.cfg
			s.mu.Unlock()
			applyZone(&cfg, false)
			return false, 0
		}
	}
	return false, 0
}

func (s *server) start() error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	sid, err := windows.StringToSid(cfg.UserSID)
	if err != nil {
		return err
	}
	if err := enablePrivileges("SeAssignPrimaryTokenPrivilege", "SeIncreaseQuotaPrivilege", "SeTcbPrivilege"); err != nil {
		return err
	}
	if s.token, s.hive, err = logonSandbox(); err != nil {
		return err
	}
	if err := provisionHive(s.hive, cfg); err != nil {
		return err
	}
	applyZone(cfg, cfg.SystemTZ)
	up, err := loadUpstream(cfg)
	if err != nil {
		logf("proxy: %v", err)
	}
	s.cfg, s.sid = cfg, sid
	s.ctl = newController(cfg, up)
	gw, err := newGateway(s.ctl, cfg.Port)
	if err != nil {
		return err
	}
	s.ctl.onClose = gw.closeAll
	check, err := newGateway(s.ctl, cfg.Port+1)
	if err != nil {
		return err
	}
	check.broken = true
	if err := gw.serveRoutes(cfg.UserSID); err != nil {
		return err
	}
	if _, err := startNetguard(sid, cfg.Port); err != nil {
		return err
	}
	ln, err := winio.ListenPipe(pipePath, &winio.PipeConfig{SecurityDescriptor: "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;" + cfg.OwnerSID + ")"})
	if err != nil {
		return err
	}
	go gw.serve()
	go check.serve()
	go s.ctl.run()
	go s.listen(ln)
	go s.applyLanguage(cfg.Lang)
	go s.guardClaude()
	logf("started, gateway on 127.0.0.1:%d", cfg.Port)
	return nil
}

func (s *server) guardClaude() {
	self := windows.GetCurrentProcessId()
	seen := map[uint32]bool{}
	for range time.Tick(250 * time.Millisecond) {
		snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
		if err != nil {
			continue
		}
		parent := map[uint32]uint32{}
		e := windows.ProcessEntry32{Size: uint32(unsafe.Sizeof(windows.ProcessEntry32{}))}
		for err = windows.Process32First(snap, &e); err == nil; err = windows.Process32Next(snap, &e) {
			if strings.EqualFold(windows.UTF16ToString(e.ExeFile[:]), "claude.exe") {
				parent[e.ProcessID] = e.ParentProcessID
			}
		}
		windows.CloseHandle(snap)
		for pid := range seen {
			if _, ok := parent[pid]; !ok {
				delete(seen, pid)
			}
		}
		for pid, ppid := range parent {
			if seen[pid] {
				continue
			}
			if !ownedBy(pid, s.sid) {
				seen[pid] = true
				continue
			}
			on, err := hooked(pid)
			if err != nil {
				continue
			}
			seen[pid] = true
			if parentOn, _ := hooked(ppid); !on && ppid != self && !parentOn {
				s.rehook(pid)
			}
		}
	}
}

func hooked(pid uint32) (bool, error) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPMODULE|windows.TH32CS_SNAPMODULE32, pid)
	if err != nil {
		return false, err
	}
	defer windows.CloseHandle(snap)
	m := windows.ModuleEntry32{Size: uint32(unsafe.Sizeof(windows.ModuleEntry32{}))}
	for err = windows.Module32First(snap, &m); err == nil; err = windows.Module32Next(snap, &m) {
		switch strings.ToLower(windows.UTF16ToString(m.Module[:])) {
		case "airlockhook.dll", "airlockicmp.dll":
			return true, nil
		}
	}
	return false, nil
}

func (s *server) rehook(pid uint32) {
	h, err := windows.OpenProcess(windows.PROCESS_TERMINATE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return
	}
	defer windows.CloseHandle(h)
	buf := make([]byte, 64<<10)
	line := ""
	if windows.NtQueryInformationProcess(h, windows.ProcessCommandLineInformation, unsafe.Pointer(&buf[0]), uint32(len(buf)), nil) == nil {
		line = (*windows.NTUnicodeString)(unsafe.Pointer(&buf[0])).String()
	}
	path := make([]uint16, windows.MAX_LONG_PATH)
	n := uint32(len(path))
	windows.QueryFullProcessImageName(h, 0, &path[0], &n)
	image := windows.UTF16ToString(path[:n])
	var session uint32
	windows.ProcessIdToSessionId(pid, &session)
	windows.TerminateProcess(h, 1)
	logf("stopped %s started without the hook", image)
	if line == "" || strings.Contains(line, "--type=") || !strings.Contains(strings.ToLower(image), `\anthropicclaude\`) {
		return
	}
	if _, _, err := s.launch(session, request{Line: line, Hook: true}); err != nil {
		logf("restart with the hook: %v", err)
	}
}

func (s *server) listen(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			logf("pipe: %v", err)
			return
		}
		go s.serve(c)
	}
}

func (s *server) serve(c net.Conn) {
	defer c.Close()
	var req request
	if err := json.NewDecoder(bufio.NewReader(c)).Decode(&req); err != nil {
		return
	}
	var resp response
	switch req.Cmd {
	case "status":
	case "pause":
		s.ctl.pause()
	case "reopen":
		s.ctl.reopen()
	case "reload":
		if err := s.reload(); err != nil {
			resp.Error = err.Error()
		}
	case "log":
		recent.Lock()
		resp.Log = slices.Clone(recent.lines)
		recent.Unlock()
	case "kill":
		resp.Count = s.kill()
	case "list":
		resp.Procs = s.procs()
	case "reset":
		if err := s.reset(); err != nil {
			resp.Error = err.Error()
		}
	case "proxy":
		if err := s.setProxy(req.Line); err != nil {
			resp.Error = err.Error()
		}
	case "run":
		var session uint32
		if f, ok := c.(interface{ Fd() uintptr }); ok {
			procPipeSession.Call(f.Fd(), uintptr(unsafe.Pointer(&session)))
		}
		if session == 0 {
			resp.Error = "caller has no interactive session"
			break
		}
		pid, exit, err := s.launch(session, req)
		if err != nil {
			resp.Error = err.Error()
		}
		resp.PID, resp.Exit = pid, exit
	default:
		resp.Error = "unknown command"
	}
	st := s.ctl.status()
	resp.Status = &st
	json.NewEncoder(c).Encode(resp)
}

func (s *server) setProxy(line string) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	auth, err := resolveProxy(cfg, strings.TrimSpace(line), func(string, ...any) {})
	if err != nil {
		return err
	}
	if _, err := time.LoadLocation(cfg.TZ); cfg.TZ == "" || err != nil {
		return errors.New("time zone of the exit was not detected, set it with: airlock set -tz")
	}
	if err := saveAuth(auth); err != nil {
		return err
	}
	if err := cfg.save(); err != nil {
		return err
	}
	logf("proxy changed, exit country %s", cfg.Country)
	if err := s.reload(); err != nil {
		return err
	}
	s.kill()
	return nil
}

func (s *server) reload() error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	if err := provisionHive(s.hive, cfg); err != nil {
		return err
	}
	applyZone(cfg, cfg.SystemTZ)
	up, err := loadUpstream(cfg)
	if err != nil {
		logf("proxy: %v", err)
	}
	s.mu.Lock()
	changed := cfg.Lang != s.cfg.Lang
	s.cfg = cfg
	s.mu.Unlock()
	s.ctl.reload(cfg, up)
	if changed {
		go s.applyLanguage(cfg.Lang)
	}
	return nil
}

func (s *server) reset() error {
	s.kill()
	for i := 0; len(s.procs()) > 0; i++ {
		if i == 20 {
			return errors.New("sandbox processes did not stop")
		}
		time.Sleep(500 * time.Millisecond)
	}
	profile, err := s.token.GetUserProfileDirectory()
	if err != nil {
		return err
	}
	entries, err := os.ReadDir(profile)
	if err != nil {
		return err
	}
	for _, e := range entries {
		os.RemoveAll(filepath.Join(profile, e.Name()))
	}
	filepath.WalkDir(filepath.Join(filepath.Dir(profile), "Default"), func(path string, d fs.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(filepath.Join(filepath.Dir(profile), "Default"), path)
		return os.MkdirAll(filepath.Join(profile, rel), 0o755)
	})
	if err := registry.DeleteKey(s.hive, `Software\Airlock`); err != nil {
		return err
	}
	s.mu.Lock()
	cfg := s.cfg
	s.mu.Unlock()
	if err := provisionHive(s.hive, cfg); err != nil {
		return err
	}
	logf("sandbox reset to a new computer")
	return nil
}

func (s *server) applyLanguage(lang string) {
	if lang == "" {
		return
	}
	ps := filepath.Join(os.Getenv("SystemRoot"), `System32\WindowsPowerShell\v1.0\powershell.exe`)
	pack := fmt.Sprintf("if (-not (Get-InstalledLanguage -Language '%s')) { Install-Language -Language '%s' | Out-Null; 'installed' }", lang, lang)
	out, err := exec.Command(ps, "-NoProfile", "-NonInteractive", "-Command", pack).CombinedOutput()
	logf("language pack %s: %v %s", lang, err, strings.TrimSpace(string(out)))
	s.mu.Lock()
	list := ownerInput(s.cfg.OwnerSID)
	s.mu.Unlock()
	if list == "" {
		list = fmt.Sprintf("Set-WinUserLanguageList -LanguageList '%s' -Force", lang)
	}
	script := fmt.Sprintf("Set-Culture -CultureInfo '%s'; %s; Set-WinUILanguageOverride -Language '%s'", lang, list, lang)
	line := windows.ComposeCommandLine([]string{ps, "-NoProfile", "-NonInteractive", "-Command", script})
	_, exit, err := s.launch(0, request{Line: line, Hidden: true, Wait: true, Timeout: 120})
	logf("language %s: exit %d, error %v", lang, exit, err)
}

func ownerInput(owner string) string {
	base := owner + `\Control Panel\International\User Profile`
	k, err := registry.OpenKey(registry.USERS, base, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer k.Close()
	langs, _, err := k.GetStringsValue("Languages")
	if err != nil {
		return ""
	}
	parts := []string{"$l = Get-WinUserLanguageList", "$l.Clear()"}
	for _, lang := range langs {
		sk, err := registry.OpenKey(registry.USERS, base+`\`+lang, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		names, _ := sk.ReadValueNames(0)
		sk.Close()
		var tips []string
		for _, n := range names {
			if strings.Contains(n, ":") {
				tips = append(tips, "'"+n+"'")
			}
		}
		i := len(parts) - 2
		parts = append(parts, fmt.Sprintf("$l.Add('%s'); $l[%d].InputMethodTips.Clear(); @(%s) | ForEach-Object { $l[%d].InputMethodTips.Add($_) }", lang, i, strings.Join(tips, ","), i))
	}
	if len(parts) == 2 {
		return ""
	}
	return strings.Join(append(parts, "Set-WinUserLanguageList $l -Force"), "; ")
}

func (s *server) procs() []proc {
	pids := make([]uint32, 1<<15)
	var size uint32
	if r, _, _ := procProcessIDs.Call(uintptr(unsafe.Pointer(&pids[0])), uintptr(len(pids)*4), uintptr(unsafe.Pointer(&size))); r == 0 {
		return nil
	}
	var list []proc
	for _, pid := range pids[:size/4] {
		if pid == 0 || !ownedBy(pid, s.sid) {
			continue
		}
		p := proc{PID: pid}
		if h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid); err == nil {
			path := make([]uint16, windows.MAX_LONG_PATH)
			n := uint32(len(path))
			if windows.QueryFullProcessImageName(h, 0, &path[0], &n) == nil {
				p.Path = windows.UTF16ToString(path[:n])
			}
			windows.CloseHandle(h)
		}
		list = append(list, p)
	}
	return list
}

func (s *server) kill() int {
	stopped := 0
	for _, p := range s.procs() {
		h, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, p.PID)
		if err != nil {
			continue
		}
		if windows.TerminateProcess(h, 1) == nil {
			stopped++
		}
		windows.CloseHandle(h)
	}
	logf("stopped %d sandbox processes", stopped)
	return stopped
}

func (s *server) launch(session uint32, req request) (pid, exit uint32, err error) {
	if req.Line == "" {
		return 0, 0, errors.New("empty command line")
	}
	var tok windows.Token
	if err := windows.DuplicateTokenEx(s.token, windows.TOKEN_ALL_ACCESS, nil, windows.SecurityImpersonation, windows.TokenPrimary, &tok); err != nil {
		return 0, 0, fmt.Errorf("duplicate token: %w", err)
	}
	defer tok.Close()
	desktop := ""
	if session != 0 {
		if err := windows.SetTokenInformation(tok, windows.TokenSessionId, (*byte)(unsafe.Pointer(&session)), 4); err != nil {
			return 0, 0, fmt.Errorf("token session: %w", err)
		}
		desktop = `winsta0\default`
	}
	var env *uint16
	if err := windows.CreateEnvironmentBlock(&env, tok, false); err != nil {
		return 0, 0, fmt.Errorf("environment: %w", err)
	}
	defer windows.DestroyEnvironmentBlock(env)
	block, err := s.ownName(env)
	if err != nil {
		return 0, 0, err
	}
	s.mu.Lock()
	dir := req.Dir
	if dir == "" && len(s.cfg.Shared) > 0 {
		dir = s.cfg.Shared[0]
	}
	s.mu.Unlock()
	var cwd *uint16
	if dir != "" {
		cwd = u16(dir)
	}
	si := windows.StartupInfo{Desktop: u16(desktop)}
	si.Cb = uint32(unsafe.Sizeof(si))
	flags := uint32(windows.CREATE_UNICODE_ENVIRONMENT | windows.CREATE_NEW_CONSOLE)
	if req.Hidden {
		flags = windows.CREATE_UNICODE_ENVIRONMENT | windows.CREATE_NO_WINDOW
		si.Flags = windows.STARTF_USESHOWWINDOW
	}
	if req.Hook {
		flags |= windows.CREATE_SUSPENDED
		req.Line = squirrelApp(req.Line)
	}
	var pi windows.ProcessInformation
	if err := windows.CreateProcessAsUser(tok, nil, u16(req.Line), nil, nil, false, flags, &block[0], cwd, &si, &pi); err != nil {
		return 0, 0, fmt.Errorf("start %s: %w", req.Line, err)
	}
	defer windows.CloseHandle(pi.Process)
	defer windows.CloseHandle(pi.Thread)
	if req.Hook {
		if err := inject(pi.Process, hookPath()); err != nil {
			windows.TerminateProcess(pi.Process, 1)
			return 0, 0, fmt.Errorf("hook %s: %w", req.Line, err)
		}
		windows.ResumeThread(pi.Thread)
	}
	if !req.Wait {
		return pi.ProcessId, 0, nil
	}
	timeout := uint32(windows.INFINITE)
	if req.Timeout > 0 {
		timeout = uint32(req.Timeout) * 1000
	}
	if ev, _ := windows.WaitForSingleObject(pi.Process, timeout); ev != windows.WAIT_OBJECT_0 {
		windows.TerminateProcess(pi.Process, 1)
		return pi.ProcessId, 0, errors.New("timed out")
	}
	windows.GetExitCodeProcess(pi.Process, &exit)
	return pi.ProcessId, exit, nil
}

func (s *server) ownName(env *uint16) ([]uint16, error) {
	k, err := registry.OpenKey(s.hive, `Software\Airlock`, registry.QUERY_VALUE)
	if err != nil {
		return nil, fmt.Errorf("sandbox identity: %w", err)
	}
	name, _, err := k.GetStringValue("ComputerName")
	k.Close()
	if err != nil {
		return nil, fmt.Errorf("sandbox identity: %w", err)
	}
	own := map[string]string{"COMPUTERNAME": name, "USERDOMAIN": name, "USERDOMAIN_ROAMINGPROFILE": name, "LOGONSERVER": `\\` + name}
	var block []uint16
	for p := unsafe.Pointer(env); *(*uint16)(p) != 0; {
		v := windows.UTF16PtrToString((*uint16)(p))
		p = unsafe.Add(p, (len(windows.StringToUTF16(v)))*2)
		if key, _, ok := strings.Cut(v, "="); ok && own[strings.ToUpper(key)] != "" {
			v = key + "=" + own[strings.ToUpper(key)]
		}
		block = append(block, windows.StringToUTF16(v)...)
	}
	return append(block, 0), nil
}

func squirrelApp(line string) string {
	args, err := windows.DecomposeCommandLine(line)
	if err != nil || len(args) == 0 {
		return line
	}
	apps, _ := filepath.Glob(filepath.Join(filepath.Dir(args[0]), "app-*", filepath.Base(args[0])))
	var newest time.Time
	for _, app := range apps {
		if fi, err := os.Stat(app); err == nil && fi.ModTime().After(newest) {
			args[0], newest = app, fi.ModTime()
		}
	}
	return windows.ComposeCommandLine(args)
}

func inject(process windows.Handle, dll string) error {
	path, err := windows.UTF16FromString(dll)
	if err != nil {
		return err
	}
	size := uintptr(len(path) * 2)
	mem, _, err := procAllocEx.Call(uintptr(process), 0, size, windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if mem == 0 {
		return fmt.Errorf("allocate: %w", err)
	}
	if err := windows.WriteProcessMemory(process, mem, (*byte)(unsafe.Pointer(&path[0])), size, nil); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	t, _, err := procRemote.Call(uintptr(process), 0, 0, procLoadLibrary.Addr(), mem, 0, 0)
	if t == 0 {
		return fmt.Errorf("remote thread: %w", err)
	}
	defer windows.CloseHandle(windows.Handle(t))
	if ev, _ := windows.WaitForSingleObject(windows.Handle(t), 15000); ev != windows.WAIT_OBJECT_0 {
		return errors.New("did not load in time")
	}
	var code uint32
	if r, _, _ := procThreadExit.Call(t, uintptr(unsafe.Pointer(&code))); r == 0 || code == 0 {
		return errors.New("did not load")
	}
	return nil
}
