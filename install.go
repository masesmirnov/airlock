package main

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

//go:embed hook/airlockhook.dll
var hookDLL []byte

const fontsKey = `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts`

var (
	chineseFont    = regexp.MustCompile(`(?i)YaHei|JhengHei|SimSun|SimHei|KaiTi|FangSong|DengXian|MingLiU|Yi Baiti`)
	procRemoveFont = windows.NewLazySystemDLL("gdi32.dll").NewProc("RemoveFontResourceW")
)

func stopService(m *mgr.Mgr) (*mgr.Service, error) {
	call(request{Cmd: "kill"})
	s, err := m.OpenService(appName)
	if err != nil {
		return nil, nil
	}
	st, err := s.Control(svc.Stop)
	for i := 0; err == nil && st.State != svc.Stopped && i < 60; i++ {
		time.Sleep(500 * time.Millisecond)
		st, err = s.Query()
	}
	return s, nil
}

func shortcutPath() string {
	return filepath.Join(os.Getenv("ProgramData"), `Microsoft\Windows\Start Menu\Programs`, panelTitle+".lnk")
}

func findBrowser() string {
	for _, p := range []string{
		filepath.Join(os.Getenv("ProgramFiles"), `Google\Chrome\Application\chrome.exe`),
		filepath.Join(os.Getenv("ProgramFiles(x86)"), `Google\Chrome\Application\chrome.exe`),
		filepath.Join(os.Getenv("ProgramFiles(x86)"), `Microsoft\Edge\Application\msedge.exe`),
		filepath.Join(os.Getenv("ProgramFiles"), `Microsoft\Edge\Application\msedge.exe`),
	} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

func powershell(script string) *exec.Cmd {
	cmd := exec.Command(filepath.Join(os.Getenv("SystemRoot"), `System32\WindowsPowerShell\v1.0\powershell.exe`), "-NoProfile", "-NonInteractive", "-Command", script)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
	return cmd
}

func wmiAccess(sid string, deny bool) error {
	script := fmt.Sprintf(`$ErrorActionPreference = 'Stop'
$sid = New-Object Security.Principal.SecurityIdentifier '%s'
$sd = New-Object Security.AccessControl.RawSecurityDescriptor ([byte[]](Invoke-CimMethod -Namespace root -ClassName __SystemSecurity -MethodName GetSD).SD), 0
for ($i = $sd.DiscretionaryAcl.Count - 1; $i -ge 0; $i--) { if ($sd.DiscretionaryAcl[$i].SecurityIdentifier -eq $sid) { $sd.DiscretionaryAcl.RemoveAce($i) } }
if ($%t) { $sd.DiscretionaryAcl.InsertAce(0, (New-Object Security.AccessControl.CommonAce 'ContainerInherit', 'AccessDenied', 0x3F, $sid, $false, $null)) }
$b = New-Object byte[] $sd.BinaryLength
$sd.GetBinaryForm($b, 0)
$r = Invoke-CimMethod -Namespace root -ClassName __SystemSecurity -MethodName SetSD -Arguments @{ SD = $b }
if ($r.ReturnValue) { throw "SetSD $($r.ReturnValue)" }`, sid, deny)
	if out, err := powershell(script).CombinedOutput(); err != nil {
		return fmt.Errorf("%w: %s", err, bytes.TrimSpace(out))
	}
	return nil
}

func smbQuic(on bool) error {
	if out, err := powershell(fmt.Sprintf("Set-SmbClientConfiguration -EnableSMBQUIC $%t -Force", on)).CombinedOutput(); err != nil {
		return fmt.Errorf("%w: %s", err, bytes.TrimSpace(out))
	}
	return nil
}

func moveFile(from, to string) error {
	h, err := windows.CreateFile(u16(from), windows.DELETE|windows.SYNCHRONIZE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err == windows.ERROR_SHARING_VIOLATION {
		return windows.MoveFileEx(u16(from), u16(to), windows.MOVEFILE_DELAY_UNTIL_REBOOT)
	}
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	name := windows.StringToUTF16(`\??\` + to)
	info := make([]byte, 20+2*len(name))
	binary.LittleEndian.PutUint32(info[16:], uint32(2*(len(name)-1)))
	for i, c := range name {
		binary.LittleEndian.PutUint16(info[20+2*i:], c)
	}
	return windows.SetFileInformationByHandle(h, windows.FileRenameInfo, &info[0], uint32(len(info)))
}

func hideChineseFonts() error {
	if err := enablePrivileges("SeBackupPrivilege", "SeRestorePrivilege"); err != nil {
		return err
	}
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, fontsKey, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	names, err := k.ReadValueNames(0)
	if err != nil {
		return err
	}
	backup := filepath.Join(dataDir(), "fonts")
	if err := os.MkdirAll(backup, 0o700); err != nil {
		return err
	}
	list := filepath.Join(backup, "fonts.json")
	saved := map[string]string{}
	if b, err := os.ReadFile(list); err == nil {
		json.Unmarshal(b, &saved)
	}
	for _, name := range names {
		if !chineseFont.MatchString(name) {
			continue
		}
		file, _, err := k.GetStringValue(name)
		if err != nil {
			return err
		}
		src := filepath.Join(os.Getenv("SystemRoot"), "Fonts", file)
		procRemoveFont.Call(uintptr(unsafe.Pointer(u16(src))))
		if err := moveFile(src, filepath.Join(backup, file)); err != nil && err != windows.ERROR_FILE_NOT_FOUND {
			return fmt.Errorf("%s: %w", file, err)
		}
		saved[name] = file
		b, _ := json.Marshal(saved)
		if err := os.WriteFile(list, b, 0o600); err != nil {
			return err
		}
		if err := k.DeleteValue(name); err != nil {
			return err
		}
	}
	procPostMessage.Call(0xFFFF, 0x1D, 0, 0)
	return nil
}

func restoreChineseFonts() error {
	backup := filepath.Join(dataDir(), "fonts")
	b, err := os.ReadFile(filepath.Join(backup, "fonts.json"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var saved map[string]string
	if err := json.Unmarshal(b, &saved); err != nil {
		return err
	}
	if err := enablePrivileges("SeBackupPrivilege", "SeRestorePrivilege"); err != nil {
		return err
	}
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, fontsKey, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	for name, file := range saved {
		if err := moveFile(filepath.Join(backup, file), filepath.Join(os.Getenv("SystemRoot"), "Fonts", file)); err != nil && err != windows.ERROR_FILE_NOT_FOUND {
			return fmt.Errorf("%s: %w", file, err)
		}
		if err := k.SetStringValue(name, file); err != nil {
			return err
		}
	}
	procPostMessage.Call(0xFFFF, 0x1D, 0, 0)
	return nil
}

func cmdInstall(args []string) error {
	cfg, err := loadConfig()
	if err != nil {
		cfg = &Config{Port: defaultPort, Shared: []string{`C:\Sandbox\shared`}}
	}
	if err := setFlags(cfg, args); err != nil {
		return err
	}
	var auth *proxyAuth
	if cfg.Proxy == "" && console() {
		if auth, err = askProxy(cfg); err != nil {
			return err
		}
	}
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	service, err := stopService(m)
	if err != nil {
		return err
	}

	self, err := os.Executable()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(programDir(), 0o755); err != nil {
		return err
	}
	target := filepath.Join(programDir(), appName+".exe")
	if !sameFile(self, target) {
		if h, _, _ := procFindWindow.Call(uintptr(unsafe.Pointer(u16(panelClass))), 0); h != 0 {
			procPostMessage.Call(h, 0x111, menuQuit, 0)
			for i := 0; i < 40 && h != 0; i++ {
				time.Sleep(250 * time.Millisecond)
				h, _, _ = procFindWindow.Call(uintptr(unsafe.Pointer(u16(panelClass))), 0)
			}
			time.Sleep(500 * time.Millisecond)
		}
		image, err := os.ReadFile(self)
		if err != nil {
			return err
		}
		pe := binary.LittleEndian.Uint32(image[0x3c:]) + 24 + 68
		for name, subsystem := range map[string]uint16{appName + ".exe": 3, appName + "w.exe": 2} {
			binary.LittleEndian.PutUint16(image[pe:], subsystem)
			if err := os.WriteFile(filepath.Join(programDir(), name), image, 0o755); err != nil {
				return err
			}
		}
	}
	for _, dll := range []string{hookPath(), filepath.Join(programDir(), appName+"icmp.dll")} {
		if err := os.WriteFile(dll, hookDLL, 0o644); err != nil {
			return err
		}
	}
	script := fmt.Sprintf("$s = (New-Object -ComObject WScript.Shell).CreateShortcut('%s'); $s.TargetPath = '%s'; $s.Save()", shortcutPath(), helperPath())
	if err := powershell(script).Run(); err != nil {
		fmt.Println("warning: start menu shortcut:", err)
	}
	if err := os.MkdirAll(dataDir(), 0o700); err != nil {
		return err
	}
	if err := lockDataDir(dataDir()); err != nil {
		return err
	}

	if cfg.Browser == "" {
		cfg.Browser = findBrowser()
	}
	if auth != nil {
		if err := saveAuth(auth); err != nil {
			return err
		}
	}
	owner, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	cfg.OwnerSID = owner.User.Sid.String()

	fmt.Println("account", accountName)
	sid, err := ensureAccount()
	if err != nil {
		return err
	}
	if cfg.UserSID != sid.String() {
		cfg.Private = nil
	}
	cfg.UserSID = sid.String()

	for _, dir := range cfg.Shared {
		fmt.Println("shared folder", dir)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
		if err := grantPath(dir, sid); err != nil {
			return err
		}
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	for _, dir := range append(personalRoots(cfg.Shared), home) {
		if slices.Contains(cfg.Private, dir) {
			continue
		}
		cfg.Private = append(cfg.Private, dir)
		start := time.Now()
		fmt.Printf("opening %s for the sandbox account... ", dir)
		if err := grantPath(dir, sid); err != nil {
			fmt.Println("warning:", err)
			continue
		}
		fmt.Println(time.Since(start).Round(time.Second))
	}
	fmt.Println("closing your Claude account files")
	if err := denyOwnerAccount(home, sid); err != nil {
		return fmt.Errorf("Claude account files: %w", err)
	}

	fmt.Println("network filters")
	if err := installFilters(sid, cfg.Port); err != nil {
		return fmt.Errorf("network filters: %w", err)
	}
	if err := wmiAccess(cfg.UserSID, true); err != nil {
		return fmt.Errorf("close WMI: %w", err)
	}
	if err := smbQuic(false); err != nil {
		return fmt.Errorf("SMB over QUIC: %w", err)
	}
	fmt.Println("Chinese fonts")
	if err := hideChineseFonts(); err != nil {
		return fmt.Errorf("Chinese fonts: %w", err)
	}
	if err := cfg.save(); err != nil {
		return err
	}

	fmt.Println("service")
	if service == nil {
		service, err = m.CreateService(appName, target, mgr.Config{
			DisplayName: "Airlock sandbox gate",
			Description: "Proxy-only gate and launcher for the airlock sandbox account.",
			StartType:   mgr.StartAutomatic,
		}, "service")
		if err != nil {
			return err
		}
	}
	defer service.Close()
	if err := service.Start(); err != nil {
		return fmt.Errorf("start service: %w", err)
	}
	fmt.Println("installed")
	return nil
}

func sameFile(a, b string) bool {
	x, err := os.Stat(a)
	if err != nil {
		return false
	}
	y, err := os.Stat(b)
	return err == nil && os.SameFile(x, y)
}

func cmdUninstall() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	if s, _ := stopService(m); s != nil {
		s.Delete()
		s.Close()
	}
	os.Remove(shortcutPath())
	if err := removeFilters(); err != nil {
		fmt.Println("warning: network filters:", err)
	}
	cfg, err := loadConfig()
	if err != nil {
		return errors.Join(errors.New("config is missing, folder permissions were left as they are"), removeAccount(""))
	}
	if err := wmiAccess(cfg.UserSID, false); err != nil {
		fmt.Println("warning: WMI access:", err)
	}
	if err := smbQuic(true); err != nil {
		fmt.Println("warning: SMB over QUIC:", err)
	}
	if err := restoreChineseFonts(); err != nil {
		return fmt.Errorf("Chinese fonts: %w", err)
	}
	if sid, err := windows.StringToSid(cfg.UserSID); err == nil {
		home, _ := os.UserHomeDir()
		for _, dir := range ownerAccount(home) {
			if err := revokePath(dir, sid); err != nil {
				fmt.Println("warning:", err)
			}
		}
		for _, dir := range append(cfg.Private, cfg.Shared...) {
			fmt.Println("restoring permissions on", dir)
			if err := revokePath(dir, sid); err != nil {
				fmt.Println("warning:", err)
			}
		}
	}
	if err := removeAccount(cfg.UserSID); err != nil {
		return err
	}
	os.RemoveAll(dataDir())
	os.RemoveAll(programDir())
	if left, err := os.ReadDir(programDir()); err == nil {
		for _, e := range left {
			windows.MoveFileEx(u16(filepath.Join(programDir(), e.Name())), nil, windows.MOVEFILE_DELAY_UNTIL_REBOOT)
		}
		windows.MoveFileEx(u16(programDir()), nil, windows.MOVEFILE_DELAY_UNTIL_REBOOT)
	}
	fmt.Println("uninstalled")
	return nil
}

func cmdSetup() error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	a, _ := os.ReadFile(self)
	b, _ := os.ReadFile(helperPath())
	if _, err := call(request{Cmd: "status"}); err != nil || !bytes.Equal(a, b) {
		if ok, err := elevateWait("install"); err != nil || !ok {
			return err
		}
	}
	return exec.Command(helperPath()).Start()
}
