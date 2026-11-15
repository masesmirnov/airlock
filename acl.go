package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	procOpenWinsta   = user32.NewProc("OpenWindowStationW")
	procCloseWinsta  = user32.NewProc("CloseWindowStation")
	procOpenDesktop  = user32.NewProc("OpenDesktopW")
	procCloseDesktop = user32.NewProc("CloseDesktop")
	procOpenObjects  = windows.NewLazySystemDLL("ntdll.dll").NewProc("NtOpenDirectoryObject")
	procDeleteAce    = advapi32.NewProc("DeleteAce")
)

const (
	fileModify    = 0x1301BF
	fileAll       = 0x1F01FF
	winstaAccess  = 0x2037F
	desktopAcces  = 0x200CF
	objectsAccess = 0x2000F
	readWriteDAC  = windows.READ_CONTROL | windows.WRITE_DAC
)

func entry(sid *windows.SID, mode windows.ACCESS_MODE, mask uint32, inherit uint32) windows.EXPLICIT_ACCESS {
	return windows.EXPLICIT_ACCESS{
		AccessPermissions: windows.ACCESS_MASK(mask),
		AccessMode:        mode,
		Inheritance:       inherit,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_USER,
			TrusteeValue: windows.TrusteeValueFromSID(sid),
		},
	}
}

func editPath(path string, e windows.EXPLICIT_ACCESS) error {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	old, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{e}, old)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

func grantPath(path string, sid *windows.SID) error {
	return editPath(path, entry(sid, windows.GRANT_ACCESS, fileModify, windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT))
}

func ownerAccount(home string) []string {
	paths, _ := filepath.Glob(filepath.Join(home, ".claude*"))
	var dirs []string
	for _, p := range append(paths, filepath.Join(home, "AppData")) {
		if fi, err := os.Lstat(p); err == nil && fi.IsDir() && fi.Mode()&os.ModeSymlink == 0 {
			dirs = append(dirs, p)
		}
	}
	return dirs
}

func denyOwnerAccount(home string, sid *windows.SID) error {
	if err := denyOnce(home, sid, windows.SUB_OBJECTS_ONLY_INHERIT|windows.INHERIT_NO_PROPAGATE|windows.INHERIT_ONLY); err != nil {
		return err
	}
	for _, dir := range ownerAccount(home) {
		if err := denyOnce(dir, sid, windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT); err != nil {
			return err
		}
	}
	return nil
}

func denyOnce(path string, sid *windows.SID, inherit uint32) error {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	acl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	for i := 0; acl != nil && i < int(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(acl, uint32(i), &ace) == nil && ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE && ace.Header.AceFlags&windows.INHERITED_ACE == 0 && (*windows.SID)(unsafe.Pointer(&ace.SidStart)).Equals(sid) {
			return nil
		}
	}
	return editPath(path, entry(sid, windows.DENY_ACCESS, fileAll, inherit))
}

func revokePath(path string, sid *windows.SID) error {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil {
		return err
	}
	for i := int(acl.AceCount) - 1; i >= 0; i-- {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(acl, uint32(i), &ace) != nil || ace.Header.AceType > windows.ACCESS_DENIED_ACE_TYPE || ace.Header.AceFlags&windows.INHERITED_ACE != 0 {
			continue
		}
		if (*windows.SID)(unsafe.Pointer(&ace.SidStart)).Equals(sid) {
			procDeleteAce.Call(uintptr(unsafe.Pointer(acl)), uintptr(i))
		}
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

func lockDataDir(path string) error {
	sd, err := windows.SecurityDescriptorFromString("D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
	if err != nil {
		return err
	}
	acl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
}

func fixedRoots() []string {
	var roots []string
	mask, _ := windows.GetLogicalDrives()
	for i := 0; i < 26; i++ {
		root := string(rune('A'+i)) + `:\`
		if mask&(1<<i) != 0 && windows.GetDriveType(u16(root)) == windows.DRIVE_FIXED {
			roots = append(roots, root)
		}
	}
	return roots
}

func personalRoots(shared []string) []string {
	system := map[string]bool{}
	for _, n := range []string{"windows", "program files", "program files (x86)", "programdata", "users", "$recycle.bin", "system volume information", "recovery", "perflogs", "$winreagent", "config.msi"} {
		system[n] = true
	}
	var out []string
	for _, root := range fixedRoots() {
		entries, err := os.ReadDir(root)
		if err != nil {
			continue
		}
	next:
		for _, e := range entries {
			if !e.IsDir() || e.Type()&os.ModeSymlink != 0 || e.Type()&os.ModeIrregular != 0 || system[strings.ToLower(e.Name())] {
				continue
			}
			dir := filepath.Join(root, e.Name())
			for _, s := range shared {
				if strings.HasPrefix(strings.ToLower(s)+`\`, strings.ToLower(dir)+`\`) {
					continue next
				}
			}
			out = append(out, dir)
		}
	}
	return out
}

func grantHandle(h windows.Handle, kind windows.SE_OBJECT_TYPE, sid *windows.SID, mask uint32) error {
	sd, err := windows.GetSecurityInfo(h, kind, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	old, _, err := sd.DACL()
	if err != nil {
		return err
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{entry(sid, windows.SET_ACCESS, mask, windows.NO_INHERITANCE)}, old)
	if err != nil {
		return err
	}
	return windows.SetSecurityInfo(h, kind, windows.DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
}

func grantDesktop(sid *windows.SID) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	ws, _, e := procOpenWinsta.Call(uintptr(unsafe.Pointer(u16("WinSta0"))), 0, readWriteDAC)
	if ws == 0 {
		return fmt.Errorf("open window station: %w", e)
	}
	defer procCloseWinsta.Call(ws)
	if err := grantHandle(windows.Handle(ws), windows.SE_WINDOW_OBJECT, sid, winstaAccess); err != nil {
		return fmt.Errorf("window station access: %w", err)
	}
	dk, _, e := procOpenDesktop.Call(uintptr(unsafe.Pointer(u16("Default"))), 0, 0, readWriteDAC)
	if dk == 0 {
		return fmt.Errorf("open desktop: %w", e)
	}
	defer procCloseDesktop.Call(dk)
	if err := grantHandle(windows.Handle(dk), windows.SE_WINDOW_OBJECT, sid, desktopAcces); err != nil {
		return fmt.Errorf("desktop access: %w", err)
	}
	var session uint32
	if err := windows.ProcessIdToSessionId(windows.GetCurrentProcessId(), &session); err != nil {
		return err
	}
	if session == 0 {
		return nil
	}
	name, err := windows.NewNTUnicodeString(fmt.Sprintf(`\Sessions\%d\BaseNamedObjects`, session))
	if err != nil {
		return err
	}
	oa := windows.OBJECT_ATTRIBUTES{ObjectName: name}
	oa.Length = uint32(unsafe.Sizeof(oa))
	var objects windows.Handle
	if r, _, _ := procOpenObjects.Call(uintptr(unsafe.Pointer(&objects)), readWriteDAC, uintptr(unsafe.Pointer(&oa))); r != 0 {
		return fmt.Errorf("open session objects: %w", windows.NTStatus(r))
	}
	defer windows.CloseHandle(objects)
	if err := grantHandle(objects, windows.SE_KERNEL_OBJECT, sid, objectsAccess); err != nil {
		return fmt.Errorf("session objects access: %w", err)
	}
	return nil
}
