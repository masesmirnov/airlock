package main

import (
	_ "embed"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/jchv/go-webview2/pkg/edge"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

//go:embed panel.html
var panelHTML string

//go:embed setup.ps1
var setupScript []byte

const (
	panelTitle = "Airlock"
	panelClass = "airlock-panel"
	panelWidth = 380
	panelStyle = 0x00CA0000

	msgTray   = 0x8001
	msgQueue  = 0x8002
	msgClaude = 0x8003

	menuClaude = 1
	menuWindow = 2
	menuStop   = 3
	menuQuit   = 4
	menuRemove = 5
)

var (
	shell32           = windows.NewLazySystemDLL("shell32.dll")
	procNotifyIcon    = shell32.NewProc("Shell_NotifyIconW")
	procDwmAttribute  = windows.NewLazySystemDLL("dwmapi.dll").NewProc("DwmSetWindowAttribute")
	procRegisterClass = user32.NewProc("RegisterClassExW")
	procCreateWindow  = user32.NewProc("CreateWindowExW")
	procDestroyWindow = user32.NewProc("DestroyWindow")
	procDefWindowProc = user32.NewProc("DefWindowProcW")
	procGetMessage    = user32.NewProc("GetMessageW")
	procTranslate     = user32.NewProc("TranslateMessage")
	procDispatch      = user32.NewProc("DispatchMessageW")
	procPostMessage   = user32.NewProc("PostMessageW")
	procPostQuit      = user32.NewProc("PostQuitMessage")
	procRegisterMsg   = user32.NewProc("RegisterWindowMessageW")
	procLoadImage     = user32.NewProc("LoadImageW")
	procMetrics       = user32.NewProc("GetSystemMetrics")
	procLoadCursor    = user32.NewProc("LoadCursorW")
	procCreateMenu    = user32.NewProc("CreatePopupMenu")
	procAppendMenu    = user32.NewProc("AppendMenuW")
	procDefaultItem   = user32.NewProc("SetMenuDefaultItem")
	procTrackMenu     = user32.NewProc("TrackPopupMenu")
	procDestroyMenu   = user32.NewProc("DestroyMenu")
	procCursorPos     = user32.NewProc("GetCursorPos")
	procWorkArea      = user32.NewProc("SystemParametersInfoW")
	procReleaseMouse  = user32.NewProc("ReleaseCapture")
	procSendMessage   = user32.NewProc("SendMessageW")
	procSetWindowPos  = user32.NewProc("SetWindowPos")
	procSetForeground = user32.NewProc("SetForegroundWindow")
	procShowWindow    = user32.NewProc("ShowWindow")
	procIsIconic      = user32.NewProc("IsIconic")
	procGetWindow     = user32.NewProc("GetWindow")
	procFindWindow    = user32.NewProc("FindWindowW")
	procDpiContext    = user32.NewProc("SetProcessDpiAwarenessContext")
	procDpiForWindow  = user32.NewProc("GetDpiForWindow")
)

type windowClass struct {
	size       uint32
	style      uint32
	proc       uintptr
	clsExtra   int32
	wndExtra   int32
	instance   windows.Handle
	icon       windows.Handle
	cursor     windows.Handle
	background windows.Handle
	menuName   *uint16
	className  *uint16
	iconSmall  windows.Handle
}

type windowMessage struct {
	hwnd    windows.HWND
	message uint32
	wParam  uintptr
	lParam  uintptr
	time    uint32
	x, y    int32
}

type notifyIcon struct {
	size        uint32
	hwnd        windows.HWND
	id          uint32
	flags       uint32
	message     uint32
	icon        windows.Handle
	tip         [128]uint16
	state       uint32
	stateMask   uint32
	info        [256]uint16
	version     uint32
	infoTitle   [64]uint16
	infoFlags   uint32
	guid        windows.GUID
	balloonIcon windows.Handle
}

type panelView struct {
	Status     *Status `json:"status"`
	Busy       bool    `json:"busy"`
	ProxyError string  `json:"proxy_error,omitempty"`
	AppError   string  `json:"app_error,omitempty"`
	Installing bool    `json:"installing"`
	Checking   bool    `json:"checking"`
	Checks     []check `json:"checks"`
	Live       int     `json:"live"`
	CheckedAt  string  `json:"checked_at,omitempty"`
	IDs        []idRow `json:"ids"`
	Resetting  bool    `json:"resetting"`
	ResetError string  `json:"reset_error,omitempty"`
}

type idRow struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type panel struct {
	hwnd    windows.HWND
	web     *edge.Chromium
	icons   [2]windows.Handle
	taskbar uint32
	reveal  bool
	mu      sync.Mutex
	queue   []func()
	view    panelView
	sent    string
	probe   []check
	probed  time.Time
	running bool
}

var windowSearch struct {
	sync.Mutex
	pids  map[uint32]bool
	found windows.HWND
}

var windowVisitor = sync.OnceValue(func() uintptr {
	return windows.NewCallback(func(h windows.HWND, _ uintptr) uintptr {
		var pid uint32
		windows.GetWindowThreadProcessId(h, &pid)
		if owner, _, _ := procGetWindow.Call(uintptr(h), 4); !windowSearch.pids[pid] || owner != 0 || !windows.IsWindowVisible(h) {
			return 1
		}
		windowSearch.found = h
		return 0
	})
})

func topWindow(pids map[uint32]bool) windows.HWND {
	windowSearch.Lock()
	defer windowSearch.Unlock()
	windowSearch.pids, windowSearch.found = pids, 0
	windows.EnumWindows(windowVisitor(), nil)
	return windowSearch.found
}

func raise(h windows.HWND) {
	if iconic, _, _ := procIsIconic.Call(uintptr(h)); iconic != 0 {
		procShowWindow.Call(uintptr(h), windows.SW_RESTORE)
	}
	procSetForeground.Call(uintptr(h))
}

func message(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func claudePath() string {
	return filepath.Join(os.Getenv("SystemDrive")+`\`, "Users", accountName, `AppData\Local\AnthropicClaude\claude.exe`)
}

func darkTheme() bool {
	k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Themes\Personalize`, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	light, _, err := k.GetIntegerValue("AppsUseLightTheme")
	return err == nil && light == 0
}

func cmdPanel() error {
	runtime.LockOSThread()
	class := u16(panelClass)
	if _, err := windows.CreateMutex(nil, false, u16(`Local\airlock-panel`)); err == windows.ERROR_ALREADY_EXISTS {
		if h, _, _ := procFindWindow.Call(uintptr(unsafe.Pointer(class)), 0); h != 0 {
			procPostMessage.Call(h, msgClaude, 0, 0)
		}
		return nil
	}
	procDpiContext.Call(^uintptr(3))
	if uxtheme, err := windows.LoadLibrary("uxtheme.dll"); err == nil {
		if allowDark, err := windows.GetProcAddressByOrdinal(uxtheme, 135); err == nil {
			syscall.SyscallN(allowDark, 1)
		}
	}
	var instance windows.Handle
	if err := windows.GetModuleHandleEx(0, nil, &instance); err != nil {
		return err
	}
	p := &panel{}
	small, _, _ := procMetrics.Call(49)
	for i, name := range []string{"APP", "STOP"} {
		icon, _, _ := procLoadImage.Call(uintptr(instance), uintptr(unsafe.Pointer(u16(name))), 1, small, small, 0)
		p.icons[i] = windows.Handle(icon)
	}
	large, _, _ := procLoadImage.Call(uintptr(instance), uintptr(unsafe.Pointer(u16("APP"))), 1, 0, 0, 0x8040)
	cursor, _, _ := procLoadCursor.Call(0, 32512)
	wc := windowClass{proc: windows.NewCallback(p.handle), instance: instance, icon: windows.Handle(large), iconSmall: p.icons[0], cursor: windows.Handle(cursor), className: class}
	wc.size = uint32(unsafe.Sizeof(wc))
	if atom, _, err := procRegisterClass.Call(uintptr(unsafe.Pointer(&wc))); atom == 0 {
		return err
	}
	hwnd, _, err := procCreateWindow.Call(0, uintptr(unsafe.Pointer(class)), uintptr(unsafe.Pointer(u16(panelTitle))), panelStyle, 0, 0, panelWidth, 400, 0, 0, uintptr(instance), 0)
	if hwnd == 0 {
		return err
	}
	p.hwnd = windows.HWND(hwnd)
	if darkTheme() {
		on := uint32(1)
		procDwmAttribute.Call(hwnd, 20, uintptr(unsafe.Pointer(&on)), 4)
	}
	created, _, _ := procRegisterMsg.Call(uintptr(unsafe.Pointer(u16("TaskbarCreated"))))
	p.taskbar = uint32(created)
	p.tray(0)
	go p.poll()
	go p.claude()
	var m windowMessage
	for {
		if r, _, _ := procGetMessage.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0); int32(r) <= 0 {
			return nil
		}
		procTranslate.Call(uintptr(unsafe.Pointer(&m)))
		procDispatch.Call(uintptr(unsafe.Pointer(&m)))
	}
}

func (p *panel) tray(action uintptr) {
	p.mu.Lock()
	st, tip := p.view.Status, panelTitle+": служба не отвечает"
	p.mu.Unlock()
	icon := p.icons[1]
	if st != nil {
		tip = panelTitle + ": интернет закрыт"
		if st.Open {
			icon, tip = p.icons[0], panelTitle+": интернет открыт, "+st.ExitCountry
		}
	}
	data := notifyIcon{hwnd: p.hwnd, id: 1, flags: 7, message: msgTray, icon: icon}
	data.size = uint32(unsafe.Sizeof(data))
	copy(data.tip[:len(data.tip)-1], windows.StringToUTF16(tip))
	procNotifyIcon.Call(action, uintptr(unsafe.Pointer(&data)))
}

func (p *panel) handle(hwnd, msg, wp, lp uintptr) uintptr {
	switch uint32(msg) {
	case msgTray:
		switch lp {
		case 0x203:
			go p.claude()
		case 0x205:
			p.menu()
		}
	case msgClaude:
		go p.claude()
	case msgQueue:
		p.mu.Lock()
		queue := p.queue
		p.queue = nil
		p.mu.Unlock()
		for _, f := range queue {
			f()
		}
	case 0x111:
		switch wp & 0xffff {
		case menuClaude:
			go p.claude()
		case menuWindow:
			p.open()
		case menuStop:
			go call(request{Cmd: "kill"})
		case menuQuit:
			call(request{Cmd: "kill"})
			procDestroyWindow.Call(hwnd)
		case menuRemove:
			if r, _ := windows.MessageBox(windows.HWND(hwnd), u16("Удалить Airlock вместе с песочницей и всем, что в ней установлено?"), u16(panelTitle), windows.MB_YESNO|windows.MB_ICONWARNING); r == 6 {
				go func() {
					if ok, _ := elevateWait("uninstall"); ok {
						p.post(func() { procDestroyWindow.Call(hwnd) })
					}
				}()
			}
		}
	case 0x83:
		if wp == 0 {
			r, _, _ := procDefWindowProc.Call(hwnd, msg, wp, lp)
			return r
		}
	case 0x5:
		if p.web != nil {
			p.web.Resize()
		}
	case 0x6:
		if p.web != nil && wp&0xffff != 0 {
			p.web.Focus()
		}
	case 0x10:
		p.reveal = false
		procShowWindow.Call(hwnd, windows.SW_HIDE)
		if p.web != nil {
			p.web.Hide()
		}
	case 0x2:
		p.tray(2)
		procPostQuit.Call(0)
	case p.taskbar:
		p.tray(0)
	default:
		r, _, _ := procDefWindowProc.Call(hwnd, msg, wp, lp)
		return r
	}
	return 0
}

func (p *panel) post(f func()) {
	p.mu.Lock()
	p.queue = append(p.queue, f)
	p.mu.Unlock()
	procPostMessage.Call(uintptr(p.hwnd), msgQueue, 0, 0)
}

func (p *panel) menu() {
	menu, _, _ := procCreateMenu.Call()
	for _, item := range []struct {
		id   uintptr
		text string
	}{{menuClaude, "Открыть Claude"}, {menuWindow, "Статус и прокси"}, {menuStop, "Закрыть всё в песочнице"}, {0, ""}, {menuRemove, "Удалить Airlock"}, {menuQuit, "Выход"}} {
		flags := uintptr(0)
		if item.id == 0 {
			flags = 0x800
		}
		procAppendMenu.Call(menu, flags, item.id, uintptr(unsafe.Pointer(u16(item.text))))
	}
	procDefaultItem.Call(menu, menuClaude, 0)
	var at struct{ x, y int32 }
	procCursorPos.Call(uintptr(unsafe.Pointer(&at)))
	procSetForeground.Call(uintptr(p.hwnd))
	procTrackMenu.Call(menu, 0x2, uintptr(at.x), uintptr(at.y), 0, uintptr(p.hwnd), 0)
	procPostMessage.Call(uintptr(p.hwnd), 0, 0, 0)
	procDestroyMenu.Call(menu)
}

func (p *panel) reopen() {
	p.web.Eval("window.reset && reset()")
	procShowWindow.Call(uintptr(p.hwnd), windows.SW_SHOWNORMAL)
	p.web.Show()
	p.web.Resize()
	procSetForeground.Call(uintptr(p.hwnd))
}

func (p *panel) open() {
	go func() {
		p.mu.Lock()
		stale := time.Since(p.probed) > 15*time.Second
		p.mu.Unlock()
		if stale {
			p.verify()
		}
	}()
	p.show()
}

func (p *panel) show() {
	if p.web != nil {
		p.reopen()
		return
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return
	}
	if darkTheme() {
		os.Setenv("WEBVIEW2_DEFAULT_BACKGROUND_COLOR", "FF1F2023")
	}
	web := edge.NewChromium()
	web.MessageCallback = p.receive
	web.DataPath = filepath.Join(dir, appName, "webview")
	if !web.Embed(uintptr(p.hwnd)) {
		windows.MessageBox(p.hwnd, u16("Окно не открылось: не найден Microsoft Edge WebView2."), u16(panelTitle), windows.MB_ICONERROR)
		return
	}
	if settings, err := web.GetSettings(); err == nil {
		settings.PutAreDefaultContextMenusEnabled(false)
		settings.PutAreDevToolsEnabled(false)
	}
	p.web, p.reveal = web, true
	web.Resize()
	web.NavigateToString(panelHTML)
}

func (p *panel) receive(raw string) {
	var m struct{ Name, Arg string }
	if json.Unmarshal([]byte(raw), &m) != nil {
		return
	}
	switch m.Name {
	case "ready":
		p.mu.Lock()
		p.sent = ""
		p.mu.Unlock()
		p.update(func(*panelView) {})
	case "fit":
		height, _ := strconv.Atoi(m.Arg)
		p.fit(height)
	case "drag":
		procReleaseMouse.Call()
		procSendMessage.Call(uintptr(p.hwnd), 0xA1, 2, 0)
	case "minimize":
		procShowWindow.Call(uintptr(p.hwnd), windows.SW_MINIMIZE)
	case "close":
		procPostMessage.Call(uintptr(p.hwnd), 0x10, 0, 0)
	default:
		go p.act(m.Name, m.Arg)
	}
}

func (p *panel) fit(height int) {
	dpi, _, _ := procDpiForWindow.Call(uintptr(p.hwnd))
	if dpi == 0 {
		dpi = 96
	}
	var area struct{ left, top, right, bottom int32 }
	procWorkArea.Call(0x30, 0, uintptr(unsafe.Pointer(&area)), 0)
	margin := int32(12 * dpi / 96)
	w, h := int32(panelWidth*dpi/96), min(int32(uintptr(height)*dpi/96), area.bottom-area.top-2*margin)
	procSetWindowPos.Call(uintptr(p.hwnd), 0, uintptr(area.right-margin-w), uintptr(area.bottom-margin-h), uintptr(w), uintptr(h), 0x14)
	if p.reveal {
		p.reveal = false
		p.reopen()
	}
}

func (p *panel) update(change func(*panelView)) {
	p.mu.Lock()
	change(&p.view)
	b, _ := json.Marshal(p.view)
	fresh := string(b) != p.sent
	p.sent = string(b)
	p.mu.Unlock()
	if fresh {
		p.post(func() {
			p.tray(1)
			if p.web != nil {
				p.web.Eval("window.render && render(" + string(b) + ")")
			}
		})
	}
}

func (p *panel) poll() {
	for ; ; time.Sleep(time.Second) {
		resp, _ := call(request{Cmd: "status"})
		p.update(func(v *panelView) { p.merge(v, resp) })
		p.mu.Lock()
		empty := resp != nil && resp.Status.Open && !p.probed.IsZero() && p.probe == nil
		p.mu.Unlock()
		if empty {
			go p.verify()
		}
	}
}

func (p *panel) merge(v *panelView, resp *response) {
	if resp == nil {
		v.Status, v.Checks, v.Live = nil, liveChecks(nil), 1
		return
	}
	live := liveChecks(resp.Status)
	v.Status, v.Checks, v.Live = resp.Status, append(live, p.probe...), len(live)
}

func (p *panel) verify() (passed, ran bool) {
	p.mu.Lock()
	if p.running {
		p.mu.Unlock()
		return false, false
	}
	p.running = true
	p.mu.Unlock()
	resp, _ := call(request{Cmd: "status"})
	p.update(func(v *panelView) {
		p.probe = nil
		for _, name := range launchNames {
			p.probe = append(p.probe, check{Name: name})
		}
		p.merge(v, resp)
		v.Checking = true
	})
	var rows []check
	var id identity
	if resp != nil && resp.Status.Open {
		rows, id = launchChecks(resp.Status)
	}
	p.update(func(v *panelView) {
		p.running, p.probe, p.probed = false, rows, time.Now()
		v.IDs = idRows(id)
		p.merge(v, resp)
		v.Checking, v.CheckedAt = false, p.probed.Format("15:04")
		passed = len(rows) > 0
		for _, c := range v.Checks {
			passed = passed && c.OK
		}
	})
	return passed, true
}

func (p *panel) act(name, arg string) {
	switch name {
	case "proxy":
		p.update(func(v *panelView) { v.Busy, v.ProxyError = true, "" })
		_, err := call(request{Cmd: "proxy", Line: arg})
		p.update(func(v *panelView) { v.Busy, v.ProxyError = false, message(err) })
		if err == nil {
			time.Sleep(3 * time.Second)
			p.claude()
		}
	case "verify":
		if resp, _ := call(request{Cmd: "status"}); resp != nil && !resp.Status.Open {
			call(request{Cmd: "reopen"})
			time.Sleep(3 * time.Second)
		}
		p.verify()
	case "reset":
		if r, _ := windows.MessageBox(p.hwnd, u16("Песочница станет новым компьютером: сменятся все ID, а Claude в ней удалится вместе со входом и данными. Браузер песочницы тоже начнёт с чистого профиля."), u16(panelTitle), windows.MB_OKCANCEL|windows.MB_ICONWARNING); r != 1 {
			return
		}
		p.update(func(v *panelView) { v.Resetting, v.ResetError, v.IDs, v.AppError = true, "", nil, "" })
		_, err := call(request{Cmd: "reset"})
		p.update(func(v *panelView) { v.Resetting, v.ResetError = false, message(err) })
		p.verify()
	}
}

func idRows(id identity) []idRow {
	name, _, _ := strings.Cut(id.Names, ";")
	board, _, _ := strings.Cut(id.SMBIOS, ";")
	if b, err := hex.DecodeString(board); err == nil && len(b) == 16 {
		g := windows.GUID{Data1: binary.LittleEndian.Uint32(b), Data2: binary.LittleEndian.Uint16(b[4:]), Data3: binary.LittleEndian.Uint16(b[6:]), Data4: [8]byte(b[8:])}
		board = strings.Trim(g.String(), "{}")
	}
	var macs []string
	for _, m := range strings.Split(id.MACs, ";") {
		if len(m) != 12 {
			continue
		}
		m = m[0:2] + ":" + m[2:4] + ":" + m[4:6] + ":" + m[6:8] + ":" + m[8:10] + ":" + m[10:12]
		if !slices.Contains(macs, m) {
			macs = append(macs, m)
		}
	}
	var rows []idRow
	for _, r := range []idRow{{"Имя компьютера", name}, {"ID устройства Claude", id.ClaudeDevice}, {"MachineGuid", id.MachineGUID}, {"UUID платы", board}, {"Серийный номер диска", id.Disk}, {"MAC-адреса", strings.Join(macs, "\n")}, {"Код продукта Windows", id.ProductID}} {
		if r.Value != "" {
			rows = append(rows, r)
		}
	}
	return rows
}

func (p *panel) claude() {
	if h, _ := p.window(); h != 0 {
		raise(h)
		return
	}
	if resp, _ := call(request{Cmd: "list"}); resp != nil && slices.ContainsFunc(resp.Procs, func(pr proc) bool { return strings.EqualFold(filepath.Base(pr.Path), "claude.exe") }) {
		sandboxRun(request{Line: windows.ComposeCommandLine([]string{claudePath()}), Hook: true})
		for i := 0; i < 20; i++ {
			time.Sleep(150 * time.Millisecond)
			if h, _ := p.window(); h != 0 {
				raise(h)
				break
			}
		}
		return
	}
	for i := 0; i < 30; i++ {
		if resp, _ := call(request{Cmd: "status"}); resp == nil || resp.Status.Reason != "starting" {
			break
		}
		time.Sleep(time.Second)
	}
	shown := !windows.IsWindowVisible(p.hwnd)
	if shown {
		p.post(p.show)
	}
	passed, ran := p.verify()
	if !ran {
		return
	}
	if passed {
		if shown {
			time.Sleep(1500 * time.Millisecond)
			procPostMessage.Call(uintptr(p.hwnd), 0x10, 0, 0)
		}
		err := p.launch()
		p.update(func(v *panelView) { v.AppError = message(err) })
		if err == nil {
			return
		}
	}
	p.post(p.open)
}

func (p *panel) window() (windows.HWND, error) {
	resp, err := call(request{Cmd: "list"})
	if resp == nil {
		return 0, err
	}
	pids := map[uint32]bool{}
	for _, pr := range resp.Procs {
		if !strings.EqualFold(pr.Path, resp.Status.Browser) {
			pids[pr.PID] = true
		}
	}
	return topWindow(pids), nil
}

func (p *panel) installClaude(st *Status) error {
	cmd := filepath.Join(os.Getenv("SystemRoot"), `System32\cmd.exe`)
	resp, err := sandboxRun(request{Line: `"` + cmd + `" /d /c if exist "%LOCALAPPDATA%\AnthropicClaude\claude.exe" (exit 0) else (exit 1)`, Hidden: true, Wait: true, Timeout: 30})
	if err != nil || resp.Exit == 0 {
		return err
	}
	if len(st.Shared) == 0 {
		return errors.New("no shared folder is configured")
	}
	script := filepath.Join(st.Shared[0], ".airlock", "setup.ps1")
	if err := os.MkdirAll(filepath.Dir(script), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(script, setupScript, 0o644); err != nil {
		return err
	}
	p.update(func(v *panelView) { v.Installing = true })
	p.post(p.open)
	defer p.update(func(v *panelView) { v.Installing = false })
	ps := filepath.Join(os.Getenv("SystemRoot"), `System32\WindowsPowerShell\v1.0\powershell.exe`)
	resp, err = sandboxRun(request{Line: windows.ComposeCommandLine([]string{ps, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", script}), Hidden: true, Wait: true, Timeout: 1800, Hook: true})
	if err == nil && resp.Exit != 0 {
		err = fmt.Errorf("Claude installer exit code %d", resp.Exit)
	}
	return err
}

func (p *panel) launch() error {
	resp, err := call(request{Cmd: "status"})
	if err != nil {
		return err
	}
	if err := p.installClaude(resp.Status); err != nil {
		return err
	}
	if _, err := sandboxRun(request{Line: windows.ComposeCommandLine([]string{claudePath()}), Hook: true}); err != nil {
		return err
	}
	for i := 0; i < 60; i++ {
		time.Sleep(250 * time.Millisecond)
		if h, _ := p.window(); h != 0 {
			raise(h)
			break
		}
	}
	return nil
}
