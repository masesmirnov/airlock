package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

var procWindowsZone = windows.NewLazySystemDLL("icu.dll").NewProc("ucal_getWindowsTimeZoneID")

func windowsZone(iana string) (string, error) {
	id, err := windows.UTF16FromString(iana)
	if err != nil {
		return "", err
	}
	name := make([]uint16, 128)
	var status int32
	n, _, _ := procWindowsZone.Call(uintptr(unsafe.Pointer(&id[0])), uintptr(len(id)-1), uintptr(unsafe.Pointer(&name[0])), uintptr(len(name)), uintptr(unsafe.Pointer(&status)))
	if status > 0 || int32(n) <= 0 {
		return "", fmt.Errorf("Windows has no time zone for %q", iana)
	}
	return windows.UTF16ToString(name[:n]), nil
}

func tzutil(args ...string) (string, error) {
	out, err := exec.Command(filepath.Join(os.Getenv("SystemRoot"), "System32", "tzutil.exe"), args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func applyZone(cfg *Config, on bool) {
	current, err := tzutil("/g")
	if err != nil {
		logf("time zone: %v", err)
		return
	}
	want, saved := cfg.HostZone, ""
	if on {
		if want, err = windowsZone(cfg.TZ); err != nil {
			logf("time zone: %v", err)
			return
		}
		if saved = cfg.HostZone; saved == "" {
			saved = current
		}
	}
	if want != "" && want != current {
		if out, err := tzutil("/s", want); err != nil {
			logf("time zone %s: %v %s", want, err, out)
			return
		}
		logf("Windows time zone changed from %s to %s", current, want)
	}
	if cfg.HostZone != saved {
		cfg.HostZone = saved
		if err := cfg.save(); err != nil {
			logf("time zone: %v", err)
		}
	}
}
