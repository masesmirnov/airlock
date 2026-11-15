package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

var (
	netapi32  = windows.NewLazySystemDLL("netapi32.dll")
	advapi32  = windows.NewLazySystemDLL("advapi32.dll")
	userenv   = windows.NewLazySystemDLL("userenv.dll")
	user32    = windows.NewLazySystemDLL("user32.dll")
	kernel32  = windows.NewLazySystemDLL("kernel32.dll")
	iphlpapi  = windows.NewLazySystemDLL("iphlpapi.dll")
	procAdd   = netapi32.NewProc("NetUserAdd")
	procDel   = netapi32.NewProc("NetUserDel")
	procSet   = netapi32.NewProc("NetUserSetInfo")
	procGroup = netapi32.NewProc("NetLocalGroupAddMembers")
	procLogon = advapi32.NewProc("LogonUserW")
	procLoad  = userenv.NewProc("LoadUserProfileW")
	procDrop  = userenv.NewProc("DeleteProfileW")
)

const (
	nerrUserExists  = 2224
	nerrUserMissing = 2221
)

type userInfo1 struct {
	name        *uint16
	password    *uint16
	passwordAge uint32
	priv        uint32
	homeDir     *uint16
	comment     *uint16
	flags       uint32
	scriptPath  *uint16
}

type profileInfo struct {
	size        uint32
	flags       uint32
	userName    *uint16
	profilePath *uint16
	defaultPath *uint16
	serverName  *uint16
	policyPath  *uint16
	profile     windows.Handle
}

func u16(s string) *uint16 {
	p, err := windows.UTF16PtrFromString(s)
	if err != nil {
		panic(err)
	}
	return p
}

func newPassword() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "Aa1!" + base64.RawURLEncoding.EncodeToString(b), nil
}

func ensureAccount() (*windows.SID, error) {
	if _, err := readSecret(accountFile); err == nil {
		if sid, _, _, err := windows.LookupSID("", accountName); err == nil {
			return sid, nil
		}
	}
	password, err := newPassword()
	if err != nil {
		return nil, err
	}
	info := userInfo1{
		name:     u16(accountName),
		password: u16(password),
		priv:     1,
		comment:  u16("airlock sandbox account"),
		flags:    0x1 | 0x40 | 0x10000,
	}
	switch r, _, _ := procAdd.Call(0, 1, uintptr(unsafe.Pointer(&info)), 0); r {
	case 0:
	case nerrUserExists:
		pw := struct{ password *uint16 }{info.password}
		if r, _, _ := procSet.Call(0, uintptr(unsafe.Pointer(info.name)), 1003, uintptr(unsafe.Pointer(&pw)), 0); r != 0 {
			return nil, fmt.Errorf("reset password of %s: %w", accountName, syscall.Errno(r))
		}
	default:
		return nil, fmt.Errorf("create account %s: %w", accountName, syscall.Errno(r))
	}
	if err := writeSecret(accountFile, []byte(password)); err != nil {
		return nil, err
	}
	sid, _, _, err := windows.LookupSID("", accountName)
	if err != nil {
		return nil, err
	}
	users, err := windows.CreateWellKnownSid(windows.WinBuiltinUsersSid)
	if err != nil {
		return nil, err
	}
	group, _, _, err := users.LookupAccount("")
	if err != nil {
		return nil, err
	}
	member := struct{ sid *windows.SID }{sid}
	if r, _, _ := procGroup.Call(0, uintptr(unsafe.Pointer(u16(group))), 0, uintptr(unsafe.Pointer(&member)), 1); r != 0 && r != uintptr(windows.ERROR_MEMBER_IN_ALIAS) {
		return nil, fmt.Errorf("add %s to %s: %w", accountName, group, syscall.Errno(r))
	}
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList`, registry.SET_VALUE)
	if err != nil {
		return nil, err
	}
	defer k.Close()
	return sid, k.SetDWordValue(accountName, 0)
}

func removeAccount(sid string) error {
	if sid != "" {
		procDrop.Call(uintptr(unsafe.Pointer(u16(sid))), 0, 0)
	}
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList`, registry.SET_VALUE); err == nil {
		k.DeleteValue(accountName)
		k.Close()
	}
	if r, _, _ := procDel.Call(0, uintptr(unsafe.Pointer(u16(accountName)))); r != 0 && r != nerrUserMissing {
		return fmt.Errorf("delete account %s: %w", accountName, syscall.Errno(r))
	}
	return nil
}

func logonSandbox() (windows.Token, registry.Key, error) {
	password, err := readSecret(accountFile)
	if err != nil {
		return 0, 0, err
	}
	var tok windows.Token
	if r, _, e := procLogon.Call(uintptr(unsafe.Pointer(u16(accountName))), uintptr(unsafe.Pointer(u16("."))), uintptr(unsafe.Pointer(u16(string(password)))), 2, 0, uintptr(unsafe.Pointer(&tok))); r == 0 {
		return 0, 0, fmt.Errorf("log on %s: %w", accountName, e)
	}
	info := profileInfo{flags: 1, userName: u16(accountName)}
	info.size = uint32(unsafe.Sizeof(info))
	if r, _, e := procLoad.Call(uintptr(tok), uintptr(unsafe.Pointer(&info))); r == 0 {
		tok.Close()
		return 0, 0, fmt.Errorf("load profile of %s: %w", accountName, e)
	}
	return tok, registry.Key(info.profile), nil
}

func setValues(root registry.Key, path string, values map[string]any) error {
	k, _, err := registry.CreateKey(root, path, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	defer k.Close()
	for name, v := range values {
		switch v := v.(type) {
		case string:
			err = k.SetStringValue(name, v)
		case uint32:
			err = k.SetDWordValue(name, v)
		case []string:
			err = k.SetStringsValue(name, v)
		case []byte:
			err = k.SetBinaryValue(name, v)
		}
		if err != nil {
			return fmt.Errorf("%s\\%s: %w", path, name, err)
		}
	}
	return nil
}

func connectionBlob(proxy string) []byte {
	b := binary.LittleEndian.AppendUint32(nil, 0x46)
	b = binary.LittleEndian.AppendUint32(b, 1)
	b = binary.LittleEndian.AppendUint32(b, 3)
	b = binary.LittleEndian.AppendUint32(b, uint32(len(proxy)))
	b = append(b, proxy...)
	b = binary.LittleEndian.AppendUint32(b, 0)
	b = binary.LittleEndian.AppendUint32(b, 0)
	return append(b, make([]byte, 32)...)
}

func randomGUID() string {
	b := make([]byte, 16)
	rand.Read(b)
	b[6], b[8] = b[6]&0x0f|0x40, b[8]&0x3f|0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

func ensureIdentity(hive registry.Key) error {
	k, _, err := registry.CreateKey(hive, `Software\Airlock`, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	if name, _, err := k.GetStringValue("ComputerName"); err == nil && name != "" {
		return nil
	}
	b := make([]byte, 16)
	rand.Read(b)
	const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	name := []byte("DESKTOP-")
	for _, c := range b[:7] {
		name = append(name, chars[int(c)%len(chars)])
	}
	n := binary.LittleEndian.Uint64(b[8:])
	values := map[string]any{
		"MachineGuid":   randomGUID(),
		"SusClientId":   randomGUID(),
		"HwProfileGuid": "{" + randomGUID() + "}",
		"SqmMachineId":  "{" + strings.ToUpper(randomGUID()) + "}",
		"ProductId":     fmt.Sprintf("%05d-%05d-%05d-AA%03d", n%100000, n/1e5%100000, n/1e10%100000, n/1e15%1000),
		"InstallDate":   uint32(time.Now().Add(-time.Duration(30+n%300) * 24 * time.Hour).Unix()),
		"Seed":          binary.LittleEndian.Uint32(b[12:]) | 1,
	}
	if err := setValues(hive, `Software\Airlock`, values); err != nil {
		return err
	}
	return k.SetStringValue("ComputerName", string(name))
}

func geoID(country string) (string, error) {
	buf := make([]uint16, 16)
	if r, _, e := kernel32.NewProc("GetGeoInfoEx").Call(uintptr(unsafe.Pointer(u16(country))), 18, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf))); r == 0 {
		return "", fmt.Errorf("region of %s: %w", country, e)
	}
	return windows.UTF16ToString(buf), nil
}

func provisionHive(hive registry.Key, cfg *Config) error {
	if err := ensureIdentity(hive); err != nil {
		return err
	}
	if err := setValues(hive, `Software\Airlock`, map[string]any{"Gate": uint32(cfg.Port)}); err != nil {
		return err
	}
	env := map[string]any{
		"TZ":              cfg.TZ,
		"LANG":            strings.ReplaceAll(cfg.Lang, "-", "_") + ".UTF-8",
		"AIRLOCK_LANG":    cfg.Lang,
		"AIRLOCK_BROWSER": cfg.Browser,
		"BROWSER":         helperPath(),
	}
	if err := setValues(hive, "Environment", env); err != nil {
		return err
	}
	local := "127.0.0.1:" + strconv.Itoa(cfg.Port)
	inet := `Software\Microsoft\Windows\CurrentVersion\Internet Settings`
	if err := setValues(hive, inet, map[string]any{"ProxyEnable": uint32(1), "ProxyServer": local, "AutoDetect": uint32(0)}); err != nil {
		return err
	}
	blob := connectionBlob(local)
	if err := setValues(hive, inet+`\Connections`, map[string]any{"DefaultConnectionSettings": blob, "SavedLegacySettings": blob}); err != nil {
		return err
	}
	geo, err := geoID(cfg.Country)
	if err != nil {
		return err
	}
	if err := setValues(hive, `Control Panel\International\Geo`, map[string]any{"Nation": geo, "Name": cfg.Country}); err != nil {
		return err
	}
	for _, policies := range []string{`Software\Policies\Google\Chrome`, `Software\Policies\Microsoft\Edge`} {
		if err := setValues(hive, policies, map[string]any{"CommandLineFlagSecurityWarningsEnabled": uint32(0)}); err != nil {
			return err
		}
	}
	if cfg.Lang != "" {
		if err := setValues(hive, `Control Panel\Desktop`, map[string]any{"PreferredUILanguages": []string{cfg.Lang}}); err != nil {
			return err
		}
	}
	return nil
}

func enablePrivileges(names ...string) error {
	var tok windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &tok); err != nil {
		return err
	}
	defer tok.Close()
	for _, name := range names {
		tp := windows.Tokenprivileges{PrivilegeCount: 1}
		tp.Privileges[0].Attributes = windows.SE_PRIVILEGE_ENABLED
		if err := windows.LookupPrivilegeValue(nil, u16(name), &tp.Privileges[0].Luid); err != nil {
			return err
		}
		if err := windows.AdjustTokenPrivileges(tok, false, &tp, 0, nil, nil); err != nil {
			return errors.Join(errors.New(name), err)
		}
	}
	return nil
}
