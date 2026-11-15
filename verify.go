package main

import (
	"crypto/rand"
	_ "embed"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

//go:embed probe.ps1
var probeScript []byte

type probeResult struct {
	GatePublic   string `json:"gate_public"`
	GatePrivate  string `json:"gate_private"`
	GateLoopback string `json:"gate_loopback"`
	GateIPv6     string `json:"gate_ipv6"`
	GateUDP      int    `json:"gate_udp"`
	DirectTCP4   string `json:"direct_tcp4"`
	DirectTCP6   string `json:"direct_tcp6"`
	DirectDNSTCP string `json:"direct_dns_tcp"`
	DirectUDP    string `json:"direct_udp"`
	DirectUDP6   string `json:"direct_udp6"`
	DirectDoT    string `json:"direct_dot"`
	DirectMeta   string `json:"direct_meta"`
	Multicast    string `json:"multicast"`
	Broadcast    string `json:"broadcast"`
	ICMP         bool   `json:"icmp"`
	DirectProxy  string `json:"direct_proxy"`
	DNSSystem    string `json:"dns_system"`
	CurlIP       string `json:"curl_ip"`
	DoH          string `json:"doh"`
	FailIP       string `json:"fail_ip"`
	FailDoH      string `json:"fail_doh"`
	FailGate     string `json:"fail_gate"`
	EnvTZ        string `json:"env_tz"`
	EnvProxy     string `json:"env_proxy"`
	Culture      string `json:"culture"`
	UICulture    string `json:"ui_culture"`
	WinAPITZ     string `json:"winapi_tz"`
	ProcOffset   int    `json:"process_offset"`
	SysOffset    int    `json:"system_offset"`
	Node         string `json:"node"`
	User         string `json:"user"`
	Profile      string `json:"profile"`
	SharedRead   bool   `json:"shared_read"`
	OwnerProfile bool   `json:"owner_profile"`
	ClosedRoots  string `json:"closed_roots"`
	Pipe         string `json:"pipe"`
	DataDir      bool   `json:"data_dir"`
	SCStop       int    `json:"sc_stop"`
	Hooked       bool   `json:"hooked"`
	BITS         string `json:"bits"`
	ShellStart   string `json:"shell_start"`
	Browser      string `json:"browser"`
	BrowserFail  string `json:"browser_fail"`

	Identity identity `json:"identity"`

	Geo          string `json:"geo"`
	SystemLocale string `json:"system_locale"`
}

type identity struct {
	MachineGUID    string `json:"machine_guid"`
	MachineGUIDReg string `json:"machine_guid_reg"`
	Names          string `json:"names"`
	Account        string `json:"account"`
	ProductID      string `json:"product_id"`
	InstallDate    string `json:"install_date"`
	SusID          string `json:"sus_id"`
	HWProfile      string `json:"hw_profile"`
	SQMID          string `json:"sqm_id"`
	Model          string `json:"model"`
	Volume         string `json:"volume"`
	VolumeCmd      string `json:"volume_cmd"`
	Disk           string `json:"disk"`
	SMBIOS         string `json:"smbios"`
	Boot           int64  `json:"boot"`
	WMI            string `json:"wmi"`
	MACs           string `json:"macs"`
	IpconfigMACs   string `json:"ipconfig_macs"`
	BSSID          string `json:"bssid"`
	ARP            int    `json:"arp"`

	ClaudeDevice string `json:"claude_device"`
}

func hostIdentity() identity {
	reg := func(path, name string) string {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE)
		if err != nil {
			return ""
		}
		defer k.Close()
		if s, _, err := k.GetStringValue(name); err == nil {
			return s
		}
		if n, _, err := k.GetIntegerValue(name); err == nil {
			return fmt.Sprint(n)
		}
		return ""
	}
	cv, bios := `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, `HARDWARE\DESCRIPTION\System\BIOS`
	id := identity{
		MachineGUID: reg(`SOFTWARE\Microsoft\Cryptography`, "MachineGuid"),
		ProductID:   reg(cv, "ProductId"),
		InstallDate: reg(cv, "InstallDate"),
		SusID:       reg(`SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate`, "SusClientId"),
		HWProfile:   reg(`SYSTEM\CurrentControlSet\Control\IDConfigDB\Hardware Profiles\0001`, "HwProfileGuid"),
		SQMID:       reg(`SOFTWARE\Microsoft\SQMClient`, "MachineId"),
		Model:       reg(bios, "SystemManufacturer") + " " + reg(bios, "SystemProductName"),
	}
	id.Names, _ = os.Hostname()
	tick, _, _ := kernel32.NewProc("GetTickCount64").Call()
	id.Boot = time.Now().Unix() - int64(tick/1000)
	if b, err := os.ReadFile(filepath.Join(os.Getenv("APPDATA"), "Claude", "ant-did")); err == nil {
		if d, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b))); err == nil {
			id.ClaudeDevice = strings.TrimSpace(string(d))
		}
	}
	var serial uint32
	if windows.GetVolumeInformation(u16(`C:\`), nil, 0, &serial, nil, nil, nil, 0) == nil {
		id.Volume = fmt.Sprintf("%08X", serial)
	}
	if h, err := windows.CreateFile(u16(`\\.\PhysicalDrive0`), 0, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, 0, 0); err == nil {
		out := make([]byte, 1024)
		var n uint32
		if windows.DeviceIoControl(h, 0x2D1400, &make([]byte, 12)[0], 12, &out[0], uint32(len(out)), &n, nil) == nil {
			if off := binary.LittleEndian.Uint32(out[24:]); off > 0 && off < n {
				end := off
				for end < n && out[end] != 0 {
					end++
				}
				id.Disk = strings.TrimSpace(string(out[off:end]))
			}
		}
		windows.CloseHandle(h)
	}
	var macs []string
	if ifaces, err := net.Interfaces(); err == nil {
		for _, i := range ifaces {
			if len(i.HardwareAddr) > 0 {
				macs = append(macs, strings.ToUpper(hex.EncodeToString(i.HardwareAddr)))
			}
		}
	}
	id.MACs = strings.Join(macs, ";")
	id.SMBIOS = smbiosIDs()
	cmd := exec.Command(filepath.Join(os.Getenv("SystemRoot"), `System32\netsh.exe`), "wlan", "show", "interfaces")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
	if out, err := cmd.Output(); err == nil {
		if m := regexp.MustCompile(`BSSID\s*:\s*(\S+)`).FindSubmatch(out); m != nil {
			id.BSSID = string(m[1])
		}
	}
	return id
}

func smbiosIDs() string {
	get := kernel32.NewProc("GetSystemFirmwareTable")
	n, _, _ := get.Call(0x52534D42, 0, 0, 0)
	if n == 0 {
		return ""
	}
	b := make([]byte, n)
	n, _, _ = get.Call(0x52534D42, 0, uintptr(unsafe.Pointer(&b[0])), n)
	b = b[:n]
	var uuid, sys, board string
	for i := 8; i+4 <= len(b); {
		typ, l := b[i], int(b[i+1])
		s := i + l
		if l < 4 || s+1 >= len(b) {
			break
		}
		e := s
		for e+1 < len(b) && (b[e] != 0 || b[e+1] != 0) {
			e++
		}
		strs := strings.Split(string(b[s:e]), "\x00")
		str := func(k byte) string {
			if k == 0 || int(k) > len(strs) {
				return ""
			}
			return strings.TrimSpace(strs[k-1])
		}
		if typ == 1 && l >= 0x18 {
			uuid, sys = strings.ToUpper(hex.EncodeToString(b[i+8:i+24])), str(b[i+7])
		}
		if typ == 2 && l > 7 {
			board = str(b[i+7])
		}
		if typ == 127 {
			break
		}
		i = e + 2
	}
	return uuid + ";" + sys + ";" + board
}

func identityLeaks(in, host identity) []string {
	var leaks []string
	same := func(label, a, b string) {
		a, b = strings.Trim(a, "{} "), strings.Trim(b, "{} ")
		if a != "" && strings.EqualFold(a, b) && !slices.Contains(leaks, label) {
			leaks = append(leaks, label)
		}
	}
	same("MachineGuid", in.MachineGUID, host.MachineGUID)
	same("MachineGuid", in.MachineGUIDReg, host.MachineGUID)
	for _, n := range strings.Split(in.Names, ";") {
		same("имя компьютера", n, host.Names)
	}
	for _, a := range strings.Split(in.Account, ";") {
		domain, _, _ := strings.Cut(a, `\`)
		same("имя компьютера в учётке", domain, host.Names)
	}
	same("ProductId", in.ProductID, host.ProductID)
	same("дата установки Windows", in.InstallDate, host.InstallDate)
	same("SusClientId", in.SusID, host.SusID)
	same("HwProfileGuid", in.HWProfile, host.HWProfile)
	same("SQM MachineId", in.SQMID, host.SQMID)
	same("серийник тома", in.Volume, host.Volume)
	same("серийник тома", in.VolumeCmd, host.Volume)
	same("серийник диска", in.Disk, host.Disk)
	same("ID устройства Claude", in.ClaudeDevice, host.ClaudeDevice)
	same("BSSID Wi-Fi", in.BSSID, host.BSSID)
	if d := in.Boot - host.Boot; d > -600 && d < 600 {
		leaks = append(leaks, "время загрузки")
	}
	in6, host6 := strings.Split(in.SMBIOS, ";"), strings.Split(host.SMBIOS, ";")
	for i := range min(len(in6), len(host6)) {
		if !strings.Contains(in6[i], " ") {
			same("SMBIOS", in6[i], host6[i])
		}
	}
	for _, m := range strings.Split(in.MACs+";"+in.IpconfigMACs, ";") {
		for _, h := range strings.Split(host.MACs, ";") {
			if len(m) == 12 && strings.Trim(m, "0") != "" {
				same("MAC", m, h)
			}
		}
	}
	return leaks
}

func identityCheck(in identity) (bool, string) {
	leaks := identityLeaks(in, hostIdentity())
	ok := len(leaks) == 0 && in.MachineGUID != "" && strings.EqualFold(in.MachineGUID, in.MachineGUIDReg) && in.Names != "" && !strings.Contains(in.Names, ";") &&
		in.Volume != "" && in.MACs != "" && !strings.HasPrefix(in.SMBIOS, ";") && in.SMBIOS != "" && in.Boot != 0 && in.WMI == "blocked" && in.ARP == 0
	return ok, fmt.Sprintf("ID устройства Claude %q, MachineGuid %s (через reg.exe %s), имя %s, учётка %s, модель %s, том %s, диск %q, SMBIOS %q, WMI %s, записей ARP %d; совпадений с этим компьютером: %q",
		in.ClaudeDevice, in.MachineGUID, in.MachineGUIDReg, in.Names, in.Account, in.Model, in.Volume, in.Disk, in.SMBIOS, in.WMI, in.ARP, strings.Join(leaks, ", "))
}

type browserResult struct {
	Error  string   `json:"error"`
	TZ     string   `json:"tz"`
	Offset int      `json:"offset"`
	Lang   string   `json:"lang"`
	Body   string   `json:"body"`
	ICE    []string `json:"ice"`

	Fonts     []string `json:"fonts"`
	Webdriver bool     `json:"webdriver"`
}

func lockProbe(st *Status) (func(), error) {
	if len(st.Shared) == 0 {
		return nil, errors.New("no shared folder is configured")
	}
	dir := filepath.Join(st.Shared[0], ".airlock")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	name := u16(filepath.Join(dir, "lock"))
	for i := 0; ; i++ {
		h, err := windows.CreateFile(name, windows.GENERIC_WRITE|windows.DELETE, 0, nil, windows.OPEN_ALWAYS, windows.FILE_FLAG_DELETE_ON_CLOSE, 0)
		if err == nil {
			return func() { windows.CloseHandle(h) }, nil
		}
		if err != windows.ERROR_SHARING_VIOLATION && err != windows.ERROR_ACCESS_DENIED || i == 600 {
			return nil, fmt.Errorf("another check is still running: %w", err)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func runProbe(st *Status, mode string) (*probeResult, error) {
	if len(st.Shared) == 0 {
		return nil, errors.New("no shared folder is configured")
	}
	dir := filepath.Join(st.Shared[0], ".airlock")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	script, out := filepath.Join(dir, "probe.ps1"), filepath.Join(dir, "probe.json")
	if err := os.WriteFile(script, probeScript, 0o644); err != nil {
		return nil, err
	}
	os.Remove(out)
	token := make([]byte, 16)
	rand.Read(token)
	if err := os.WriteFile(filepath.Join(dir, "token.txt"), []byte(hex.EncodeToString(token)), 0o644); err != nil {
		return nil, err
	}
	_, upstream, _ := parseProxy(st.Proxy)
	ps := filepath.Join(os.Getenv("SystemRoot"), `System32\WindowsPowerShell\v1.0\powershell.exe`)
	args := []string{ps, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", script,
		"-Port", fmt.Sprint(st.Port), "-Out", out, "-OwnerProfile", os.Getenv("USERPROFILE"), "-DataDir", dataDir(),
		"-Shared", strings.Join(st.Shared, ";"), "-Helper", helperPath(),
		"-Proxy", upstream, "-Token", hex.EncodeToString(token)}
	if mode != "" {
		args = append(args, mode)
	}
	if _, err := sandboxRun(request{Line: windows.ComposeCommandLine(args), Hidden: true, Wait: true, Timeout: 300, Hook: true}); err != nil {
		return nil, fmt.Errorf("probe did not run inside the sandbox: %w", err)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		return nil, fmt.Errorf("probe left no result in the shared folder: %w", err)
	}
	p := &probeResult{}
	return p, json.Unmarshal(b, p)
}

type check struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
}

func cmdVerify() error {
	fmt.Println("probing from inside the sandbox, about a minute...")
	rows, err := runChecks()
	if err != nil {
		return err
	}
	failed := 0
	for _, r := range rows {
		mark := "PASS"
		if !r.OK {
			mark = "FAIL"
			failed++
		}
		fmt.Printf("%s  %-38s %s\n", mark, r.Name, r.Detail)
	}
	if failed > 0 {
		return fmt.Errorf("%d of %d checks failed", failed, len(rows))
	}
	return nil
}

func runChecks() ([]check, error) {
	resp, err := call(request{Cmd: "status"})
	if err != nil {
		return nil, err
	}
	st := resp.Status
	unlock, err := lockProbe(st)
	if err != nil {
		return nil, err
	}
	defer unlock()
	started := time.Now()
	p, err := runProbe(st, "")
	if err != nil {
		return nil, err
	}
	var b browserResult
	json.Unmarshal([]byte(p.Browser), &b)
	browserIP, _ := parseTrace(b.Body)

	time.Sleep(time.Until(started.Add(checkInterval + 5*time.Second)))
	resp, err = call(request{Cmd: "status"})
	if err != nil {
		return nil, err
	}
	later := resp.Status

	if _, err := call(request{Cmd: "pause"}); err != nil {
		return nil, err
	}
	closed, closedErr := runProbe(st, "-Quick")
	if _, err := call(request{Cmd: "reopen"}); err != nil {
		return nil, err
	}
	if closedErr != nil {
		return nil, closedErr
	}

	blocked := func(v ...string) bool {
		for _, s := range v {
			if s != "blocked" {
				return false
			}
		}
		return true
	}
	udp4 := udpControl("udp4", "8.8.8.8:53").closed(p.DirectUDP)
	bitsQuiet := p.BITS != "" && p.BITS != "Transferred" && p.BITS != "Transferring"
	ruleOK := st.Open && strings.EqualFold(st.ExitCountry, st.RuleCountry) && (st.RuleIP == "" || st.RuleIP == st.ExitIP)
	zone, _ := windowsZone(st.TZ)
	geo, _ := geoID(st.RuleCountry)
	rows := []check{
		{"1  only TCP to public IPv4 leaves", p.GatePublic == "200" && p.GatePrivate == "403" && p.GateLoopback == "403" && p.GateIPv6 == "403" && blocked(p.DirectMeta, p.DirectProxy),
			fmt.Sprintf("via gate: public %s, private %s, loopback %s, ipv6 %s; direct link-local %s, upstream %s", p.GatePublic, p.GatePrivate, p.GateLoopback, p.GateIPv6, p.DirectMeta, p.DirectProxy)},
		{"2  all traffic goes through the proxy", p.CurlIP != "" && p.CurlIP == st.ExitIP && p.DirectTCP4 == "open" && bitsQuiet,
			fmt.Sprintf("terminal exit %s, service exit %s, direct %s, BITS %s", p.CurlIP, st.ExitIP, p.DirectTCP4, p.BITS)},
		{"3  DNS only through the proxy", p.DNSSystem == "resolved" && udp4 && p.CurlIP != "",
			fmt.Sprintf("system resolver %s, direct UDP 53 %s, direct TCP 53 %s", p.DNSSystem, p.DirectUDP, p.DirectDNSTCP)},
		{"4  system time zone and language", p.EnvTZ == st.TZ && (p.Node == "" || p.Node == st.TZ) && strings.EqualFold(p.Culture, st.Lang) && strings.EqualFold(p.UICulture, st.Lang) && (!st.SystemTZ || p.WinAPITZ == zone) && p.Geo == geo && strings.EqualFold(p.SystemLocale, st.Lang),
			fmt.Sprintf("TZ %s, node %q, culture %s, UI %s, Windows zone %s, region %s, system locale %s", p.EnvTZ, p.Node, p.Culture, p.UICulture, p.WinAPITZ, p.Geo, p.SystemLocale)},
		{"5  browser time zone, language, fingerprint", b.TZ == st.TZ && strings.EqualFold(b.Lang, st.Lang) && len(b.Fonts) == 0 && b.Body != "" && !b.Webdriver,
			fmt.Sprintf("tz %s, language %s, Chinese fonts %q, webdriver %v %s", b.TZ, b.Lang, b.Fonts, b.Webdriver, b.Error)},
		{"6  owner files are open", p.OwnerProfile && p.ClosedRoots == "",
			fmt.Sprintf("owner profile writable: %v, closed folders: %q, runs as %s", p.OwnerProfile, p.ClosedRoots, p.User)},
		{"7  no access to the controls", p.Pipe == "UnauthorizedAccessException" && !p.DataDir && p.SCStop != 0,
			fmt.Sprintf("control pipe %s, data folder readable: %v, stop service exit %d", p.Pipe, p.DataDir, p.SCStop)},
		{"8  closed gate means no internet", closed.GatePublic != "200" && blocked(closed.DirectTCP4),
			fmt.Sprintf("with the gate closed: via gate %s, direct %s", closed.GatePublic, closed.DirectTCP4)},
		{"9  UDP is blocked", udp4 && p.GateUDP == 7,
			fmt.Sprintf("direct %s, closed against a host control: %v, socks UDP associate reply %d", p.DirectUDP, udp4, p.GateUDP)},
		{"10 IPv6 is blocked", blocked(p.DirectTCP6) && p.GateIPv6 == "403",
			fmt.Sprintf("direct %s, via gate %s", p.DirectTCP6, p.GateIPv6)},
		{"11 same exit address everywhere", ruleOK && st.ExitIP != "" && p.CurlIP == st.ExitIP && browserIP == st.ExitIP,
			fmt.Sprintf("host %s, terminal %s, browser %s, rule %s %s", st.ExitIP, p.CurlIP, browserIP, st.RuleCountry, st.RuleIP)},
		{"12 own browser, links open in it", p.Hooked && p.ShellStart == "ok" && b.Body != "" && strings.HasPrefix(strings.ToLower(p.Profile), `c:\users\`+strings.ToLower(accountName)),
			fmt.Sprintf("link hook loaded: %v, start through the shell %s, profile %s", p.Hooked, p.ShellStart, p.Profile)},
		{"13 90 s lease renewed every 30 s", later.Checks > st.Checks && later.LeaseUntil > st.LeaseUntil,
			fmt.Sprintf("checks %d -> %d, lease %s -> %s", st.Checks, later.Checks, st.LeaseUntil, later.LeaseUntil)},
		{"14 exit rule is enforced", ruleOK,
			fmt.Sprintf("open %v, exit country %s, rule %s %s %s", st.Open, st.ExitCountry, st.RuleCountry, st.RuleIP, st.Reason)},
		{"15 proxy is invisible", !p.DataDir && p.EnvProxy == "",
			fmt.Sprintf("data folder readable: %v, proxy settings seen by the app: %q", p.DataDir, p.EnvProxy)},
	}
	idOK, idText := identityCheck(p.Identity)
	return append(rows, check{"16 own machine identity", idOK, idText}), nil
}

var reasonTexts = []struct {
	pattern *regexp.Regexp
	text    string
}{
	{regexp.MustCompile(`^starting$`), "служба запускается"},
	{regexp.MustCompile(`^not configured.*$`), "прокси не задан"},
	{regexp.MustCompile(`^configuration changed.*$`), "проверяется новый прокси"},
	{regexp.MustCompile(`^paused by the owner$`), "приостановлено"},
	{regexp.MustCompile(`^exit country could not be determined$`), "не удалось определить страну выхода"},
	{regexp.MustCompile(`^exit country (\S+) does not match the rule (\S+)$`), "страна выхода $1 не совпадает с правилом $2"},
	{regexp.MustCompile(`^exit address (\S+) does not match the rule (\S+)$`), "адрес выхода $1 не совпадает с правилом $2"},
	{regexp.MustCompile(`^exit address changed from (\S+) to (\S+),.*$`), "адрес выхода сменился с $1 на $2"},
	{regexp.MustCompile(`^exit check failed.*$`), "прокси не отвечает"},
}

func reasonText(reason string) string {
	reason = strings.TrimPrefix(reason, "lease expired: ")
	for _, r := range reasonTexts {
		if r.pattern.MatchString(reason) {
			return r.pattern.ReplaceAllString(reason, r.text)
		}
	}
	return reason
}

func liveChecks(st *Status) []check {
	if st == nil {
		return []check{{"Служба оболочки отвечает", false, "служба не запущена, нужна установка: airlock install"}}
	}
	if !st.Open {
		return []check{{"Прокси на связи", false, reasonText(st.Reason)}}
	}
	return nil
}

type udpProbe struct {
	routed, answered bool
}

func udpControl(network, addr string) udpProbe {
	q := []byte{0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1}
	c, err := net.Dial(network, addr)
	if err != nil {
		return udpProbe{}
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Write(q); err != nil {
		return udpProbe{routed: true}
	}
	_, err = c.Read(make([]byte, 512))
	return udpProbe{routed: true, answered: err == nil}
}

func (h udpProbe) closed(sandbox string) bool {
	return sandbox == "blocked" || sandbox == "unreachable" || !h.routed || h.answered && sandbox == "silent"
}

func (h udpProbe) String() string {
	switch {
	case !h.routed:
		return "нет маршрута"
	case h.answered:
		return "ответил"
	}
	return "без ответа"
}

func hostPing() bool {
	cmd := exec.Command(filepath.Join(os.Getenv("SystemRoot"), `System32\ping.exe`), "-n", "1", "-w", "2000", "1.1.1.1")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
	out, _ := cmd.Output()
	return strings.Contains(string(out), "TTL=")
}

func sandboxPeers(pids map[uint32]bool) []string {
	var peers []string
	for _, t := range []struct{ family, row, addr, size, port, state, pid uintptr }{{windows.AF_INET, 24, 12, 4, 16, 0, 20}, {windows.AF_INET6, 56, 24, 16, 44, 48, 52}} {
		size := uint32(1 << 16)
		var buf []byte
		for {
			buf = make([]byte, size)
			r, _, _ := procTcpTable.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0, t.family, 5, 0)
			if r == 0 {
				break
			}
			if r != uintptr(windows.ERROR_INSUFFICIENT_BUFFER) {
				return peers
			}
		}
		n := *(*uint32)(unsafe.Pointer(&buf[0]))
		for i := uintptr(0); i < uintptr(n); i++ {
			row := buf[4+i*t.row:]
			if *(*uint32)(unsafe.Pointer(&row[t.state])) != 5 || !pids[*(*uint32)(unsafe.Pointer(&row[t.pid]))] {
				continue
			}
			ip, _ := netip.AddrFromSlice(row[t.addr : t.addr+t.size])
			if !ip.Unmap().IsLoopback() {
				peers = append(peers, netip.AddrPortFrom(ip.Unmap(), uint16(row[t.port])<<8|uint16(row[t.port+1])).String())
			}
		}
	}
	return peers
}

var launchNames = [...]string{
	"Наружу только через шлюз",
	"Терминал выходит через прокси",
	"DNS только через прокси",
	"Часовой пояс и язык системы",
	"Часовой пояс и язык браузера",
	"Твои файлы доступны",
	"Управление и прокси недоступны",
	"Без прокси связи нет",
	"UDP закрыт",
	"IPv6 закрыт",
	"Выход соответствует правилу",
	"Свой ID компьютера",
}

func launchChecks(st *Status) ([]check, identity) {
	unlock, err := lockProbe(st)
	if err != nil {
		return []check{{"Проверка изнутри песочницы", false, err.Error()}}, identity{}
	}
	defer unlock()
	var host4, host6 udpProbe
	v6net, pinged := false, false
	control := make(chan struct{})
	go func() {
		host4, host6 = udpControl("udp4", "8.8.8.8:53"), udpControl("udp6", "[2001:4860:4860::8888]:53")
		if c, err := net.DialTimeout("tcp6", "[2606:4700:4700::1111]:443", 3*time.Second); err == nil {
			c.Close()
			v6net = true
		}
		pinged = hostPing()
		close(control)
	}()
	peers := map[string]bool{}
	stop, sampled := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(sampled)
		for {
			if resp, _ := call(request{Cmd: "list"}); resp != nil {
				pids := map[uint32]bool{}
				for _, pr := range resp.Procs {
					pids[pr.PID] = true
				}
				for _, peer := range sandboxPeers(pids) {
					peers[peer] = true
				}
			}
			select {
			case <-stop:
				return
			case <-time.After(500 * time.Millisecond):
			}
		}
	}()
	p, err := runProbe(st, "-Launch")
	close(stop)
	<-sampled
	<-control
	if err != nil {
		return []check{{"Проверка изнутри песочницы", false, err.Error()}}, identity{}
	}
	var b, down browserResult
	json.Unmarshal([]byte(p.Browser), &b)
	json.Unmarshal([]byte(p.BrowserFail), &down)
	browserIP, _ := parseTrace(b.Body)
	udp4, udp6 := host4.closed(p.DirectUDP), host6.closed(p.DirectUDP6) || !v6net
	word := func(s string) string {
		switch s {
		case "blocked":
			return "отклонено"
		case "unreachable":
			return "нет маршрута"
		case "silent":
			return "без ответа"
		case "answered":
			return "ответил"
		case "failed":
			return "нет ответа"
		case "open", "resolved":
			return "ОТКРЫТО"
		}
		return s
	}
	refused := func(s string, host udpProbe) string {
		return fmt.Sprintf("из песочницы %s, с этого компьютера %s", word(s), host)
	}
	reply := func(ok bool) string {
		if ok {
			return "ОТВЕЧАЕТ"
		}
		return "нет ответа"
	}
	udp6Text := refused(p.DirectUDP6, host6)
	if !v6net {
		udp6Text = "у этого компьютера нет выхода в IPv6"
	}
	zone, _ := windowsZone(st.TZ)
	want := 0
	if loc, err := time.LoadLocation(st.TZ); err == nil {
		_, off := time.Now().In(loc).Zone()
		want = off / 60
	}
	var system, browser []string
	if zone == "" || p.WinAPITZ != zone || p.EnvTZ != st.TZ {
		system = append(system, fmt.Sprintf("пояс %s вместо %s", p.WinAPITZ, zone))
	}
	if p.ProcOffset != want || p.SysOffset != want {
		system = append(system, fmt.Sprintf("смещение %+d мин вместо %+d", p.ProcOffset, want))
	}
	if !strings.EqualFold(p.Culture, st.Lang) || !strings.EqualFold(p.UICulture, st.Lang) {
		system = append(system, fmt.Sprintf("язык %s, интерфейс %s вместо %s", p.Culture, p.UICulture, st.Lang))
	}
	if geo, _ := geoID(st.RuleCountry); p.Geo != geo {
		system = append(system, fmt.Sprintf("регион %s вместо %s", p.Geo, geo))
	}
	if !strings.EqualFold(p.SystemLocale, st.Lang) {
		system = append(system, fmt.Sprintf("язык системы %s вместо %s", p.SystemLocale, st.Lang))
	}
	if b.TZ != st.TZ || -b.Offset != want {
		browser = append(browser, fmt.Sprintf("пояс %s вместо %s", b.TZ, st.TZ))
	}
	if !strings.EqualFold(b.Lang, st.Lang) {
		browser = append(browser, fmt.Sprintf("язык %s вместо %s", b.Lang, st.Lang))
	}
	if len(b.Fonts) > 0 {
		browser = append(browser, "китайские шрифты "+strings.Join(b.Fonts, ", "))
	}
	if b.Webdriver {
		browser = append(browser, "браузер помечен как управляемый программой")
	}
	if b.Error != "" {
		browser = append(browser, b.Error)
	}
	var leaked []string
	for _, a := range b.ICE {
		if net.ParseIP(a) != nil {
			leaked = append(leaked, a)
		}
	}
	ruleOK := st.Open && st.ExitCountry != "" && strings.EqualFold(st.ExitCountry, st.RuleCountry) && (st.RuleIP == "" || st.RuleIP == st.ExitIP)
	rule := st.RuleCountry
	if st.RuleIP != "" {
		rule += ", " + st.RuleIP
	}
	idOK, idText := identityCheck(p.Identity)
	return []check{
		{launchNames[0], p.DirectTCP4 == "open" && p.GatePrivate == "403" && p.GateLoopback == "403" && len(leaked) == 0 && !p.ICMP && len(peers) == 0,
			fmt.Sprintf("соединение с 1.1.1.1: %s; шлюз в локальную сеть: %s, на этот компьютер: %s; WebRTC в браузере: %q; ping из песочницы: %s, с этого компьютера: %s; соединения песочницы мимо шлюза: %q", word(p.DirectTCP4), p.GatePrivate, p.GateLoopback, strings.Join(leaked, ", "), reply(p.ICMP), reply(pinged), strings.Join(slices.Sorted(maps.Keys(peers)), ", "))},
		{launchNames[1], p.CurlIP != "" && p.CurlIP == st.ExitIP && p.EnvProxy == "",
			fmt.Sprintf("из терминала %q, у службы %q, настройки прокси у Claude: %q", p.CurlIP, st.ExitIP, p.EnvProxy)},
		{launchNames[2], p.DoH == "answered" && udp4 && p.DNSSystem == "resolved",
			fmt.Sprintf("DoH через прокси: %s; напрямую UDP 53: %s, TCP 53: %s, DoT 853: %s; системный DNS у Claude: %s", word(p.DoH), refused(p.DirectUDP, host4), word(p.DirectDNSTCP), word(p.DirectDoT), word(p.DNSSystem))},
		{launchNames[3], len(system) == 0, strings.Join(system, ", ")},
		{launchNames[4], len(browser) == 0, strings.Join(browser, ", ")},
		{launchNames[5], p.SharedRead && p.OwnerProfile && p.ClosedRoots == "",
			fmt.Sprintf("общая папка читается: %v, запись в твой профиль: %v, закрытые папки: %q", p.SharedRead, p.OwnerProfile, p.ClosedRoots)},
		{launchNames[6], p.Pipe == "UnauthorizedAccessException" && !p.DataDir && p.SCStop != 0 && p.DirectMeta != "open" && p.DirectProxy == "blocked" && !strings.Contains(p.EnvProxy, "@"),
			fmt.Sprintf("канал управления: %s, папка службы читается: %v, остановка службы: код %d, адрес метаданных: %s, прокси напрямую: %s", p.Pipe, p.DataDir, p.SCStop, word(p.DirectMeta), word(p.DirectProxy))},
		{launchNames[7], p.FailIP == "" && p.FailDoH != "answered" && p.FailGate == "502" && down.Body == "" && down.Error != "",
			fmt.Sprintf("при обрыве прокси: терминал %q, DoH %s, шлюз %s, браузер %q", p.FailIP, word(p.FailDoH), p.FailGate, down.Error)},
		{launchNames[8], udp4 && p.GateUDP == 7 && p.Multicast == "blocked" && p.Broadcast == "blocked",
			fmt.Sprintf("напрямую: %s; UDP через шлюз: код %d; групповой: %s, широковещательный: %s", refused(p.DirectUDP, host4), p.GateUDP, word(p.Multicast), word(p.Broadcast))},
		{launchNames[9], (p.DirectTCP6 == "blocked" || p.DirectTCP6 == "unreachable") && udp6 && p.GateIPv6 == "403",
			fmt.Sprintf("TCP: %s, UDP: %s, через шлюз: %s", word(p.DirectTCP6), udp6Text, p.GateIPv6)},
		{launchNames[10], ruleOK && p.CurlIP == st.ExitIP && browserIP == st.ExitIP,
			fmt.Sprintf("служба %s %s, терминал %s, браузер %s, правило %s", st.ExitCountry, st.ExitIP, p.CurlIP, browserIP, rule)},
		{launchNames[11], idOK, idText},
	}, p.Identity
}
