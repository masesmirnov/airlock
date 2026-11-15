package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	_ "time/tzdata"

	"golang.org/x/sys/windows"
)

const usage = `airlock runs a program under a separate Windows account whose only way out is a checked proxy

  airlock panel                          window with the proxy field and the program buttons
  airlock run [-wait] [-hidden] [--] <command> [args...]
                                         start a program inside the sandbox
  airlock browser [url]                  open the sandbox browser
  airlock status                         gate state, exit address, lease
  airlock pause                          close the gate
  airlock reopen                         check the exit again and open the gate
  airlock kill                           stop every program running inside the sandbox
  airlock verify                         test the sandbox from the inside
  airlock log                            recent service messages

these ask for administrator rights:
  airlock install                        create the account, filters and service, then ask for the proxy
  airlock proxy                          paste a new proxy as ip:port:user:password
  airlock set [-country US] [-ip 1.2.3.4] [-tz America/New_York] [-lang en-US] [-proxy socks5://host:port]
              [-windows-tz]              also switch the Windows time zone to the zone of the exit
  airlock uninstall
`

const holdFlag = "--hold"

var hold bool

func admin(run func() error) error {
	if !windows.GetCurrentProcessToken().IsElevated() {
		return elevate()
	}
	return run()
}

func console() bool {
	h, _ := windows.GetStdHandle(windows.STD_ERROR_HANDLE)
	return h != 0 && h != windows.InvalidHandle
}

func main() {
	if len(os.Args) < 2 {
		self, _ := os.Executable()
		switch {
		case strings.EqualFold(filepath.Base(self), filepath.Base(helperPath())):
			os.Args = append(os.Args, "panel")
		case console():
			fmt.Print(usage)
			os.Exit(2)
		default:
			os.Args = append(os.Args, "setup")
		}
	}
	if strings.HasPrefix(os.Args[1], "http://") || strings.HasPrefix(os.Args[1], "https://") {
		os.Args = append([]string{os.Args[0], "browser-host"}, os.Args[1:]...)
	}
	var err error
	args := os.Args[2:]
	if n := len(args); n > 0 && args[n-1] == holdFlag {
		args, hold = args[:n-1], true
	}
	switch os.Args[1] {
	case "install":
		err = admin(func() error { return cmdInstall(args) })
	case "uninstall":
		err = admin(cmdUninstall)
	case "set":
		err = admin(func() error { return cmdSet(args) })
	case "proxy":
		err = admin(cmdProxy)
	case "run":
		err = cmdRun(args)
	case "browser":
		err = cmdBrowser(args)
	case "status", "pause", "reopen":
		err = cmdSimple(os.Args[1])
	case "log":
		err = cmdLog()
	case "kill":
		err = cmdKill()
	case "verify":
		err = cmdVerify()
	case "service":
		err = cmdService()
	case "browser-host":
		err = cmdBrowserHost(args)
	case "panel":
		err = cmdPanel()
	case "setup":
		err = cmdSetup()
	default:
		fmt.Print(usage)
		os.Exit(2)
	}
	if err != nil && console() {
		fmt.Fprintln(os.Stderr, "airlock:", err)
	} else if err != nil {
		windows.MessageBox(0, u16(err.Error()), u16(panelTitle), windows.MB_ICONERROR)
	}
	if hold {
		fmt.Print("press Enter to close")
		fmt.Scanln()
	}
	if err != nil {
		os.Exit(1)
	}
}
