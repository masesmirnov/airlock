package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const probeExpr = `(async()=>{const ice=[];try{const pc=new RTCPeerConnection({iceServers:[{urls:"stun:stun.l.google.com:19302"}]});pc.createDataChannel("x");pc.onicecandidate=e=>{if(e.candidate&&e.candidate.address)ice.push(e.candidate.address)};await pc.setLocalDescription(await pc.createOffer());await new Promise(r=>{setTimeout(r,3000);pc.onicegatheringstatechange=()=>{if(pc.iceGatheringState==="complete")r()}});pc.close()}catch(e){ice.push("error "+e)}return JSON.stringify({tz:Intl.DateTimeFormat().resolvedOptions().timeZone,offset:new Date().getTimezoneOffset(),lang:navigator.language,langs:navigator.languages,fonts:(()=>{const c=document.createElement("canvas").getContext("2d"),g=["monospace","sans-serif","serif"],w=f=>{c.font="72px "+f;return c.measureText("mmmmmmmmmmlli").width},b=g.map(w);return["Microsoft YaHei","Microsoft YaHei UI","SimSun","NSimSun","SimHei","KaiTi","FangSong","DengXian","Microsoft JhengHei","MingLiU","PMingLiU","PingFang SC","MiSans","HarmonyOS Sans","OPPO Sans"].filter(f=>g.some((x,i)=>w('"'+f+'",'+x)!==b[i]))})(),webdriver:navigator.webdriver,body:document.body?document.body.innerText:"",ice})})()`

type cdpMessage struct {
	ID        int             `json:"id,omitempty"`
	Method    string          `json:"method,omitempty"`
	Params    json.RawMessage `json:"params,omitempty"`
	SessionID string          `json:"sessionId,omitempty"`
	Result    json.RawMessage `json:"result,omitempty"`
	Error     json.RawMessage `json:"error,omitempty"`
}

type cdp struct {
	w  *os.File
	id int
}

func (c *cdp) send(session, method string, params any) int {
	c.id++
	m := map[string]any{"id": c.id, "method": method}
	if params != nil {
		m["params"] = params
	}
	if session != "" {
		m["sessionId"] = session
	}
	b, _ := json.Marshal(m)
	c.w.Write(append(b, 0))
	return c.id
}

func cmdBrowserHost(args []string) error {
	exe, tz, lang := os.Getenv("AIRLOCK_BROWSER"), os.Getenv("TZ"), os.Getenv("AIRLOCK_LANG")
	if exe == "" {
		return errors.New("AIRLOCK_BROWSER is not set, this command runs inside the sandbox")
	}
	probe, proxy, target := "", "", "chrome://newtab/"
	switch {
	case (len(args) == 2 || len(args) == 3) && args[0] == "--probe":
		probe, target = args[1], "https://www.cloudflare.com/cdn-cgi/trace"
		if len(args) == 3 {
			proxy = args[2]
		}
	case len(args) > 0:
		target = args[0]
	}
	profile := filepath.Join(os.Getenv("LOCALAPPDATA"), appName, "browser")
	if probe != "" {
		profile += "-probe"
		if proxy != "" {
			profile += "-proxy"
		}
		entries, _ := os.ReadDir(profile)
		for _, e := range entries {
			if e.Name() != "Local State" {
				os.RemoveAll(filepath.Join(profile, e.Name()))
			}
		}
	} else if _, err := windows.CreateMutex(nil, false, u16(`Local\airlock-browser`)); err == windows.ERROR_ALREADY_EXISTS {
		return exec.Command(exe, "--user-data-dir="+profile, target).Start()
	}
	if k, _, err := registry.CreateKey(registry.CURRENT_USER, `Software\Microsoft\DirectX\UserGpuPreferences`, registry.SET_VALUE); err == nil {
		k.SetStringValue(exe, "GpuPreference=1;")
		k.Close()
	}
	if k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Airlock`, registry.QUERY_VALUE); err == nil {
		if gate, _, err := k.GetIntegerValue("Gate"); err == nil && proxy == "" {
			proxy = "127.0.0.1:" + strconv.FormatUint(gate, 10)
		}
		k.Close()
	}
	toBrowser, w, err := os.Pipe()
	if err != nil {
		return err
	}
	r, fromBrowser, err := os.Pipe()
	if err != nil {
		return err
	}
	in, out := windows.Handle(toBrowser.Fd()), windows.Handle(fromBrowser.Fd())
	for _, h := range []windows.Handle{in, out} {
		if err := windows.SetHandleInformation(h, windows.HANDLE_FLAG_INHERIT, windows.HANDLE_FLAG_INHERIT); err != nil {
			return err
		}
	}
	flags := []string{
		"--user-data-dir=" + profile,
		"--remote-debugging-pipe",
		fmt.Sprintf("--remote-debugging-io-pipes=%d,%d", in, out),
		"--disable-blink-features=AutomationControlled",
		"--no-first-run",
		"--no-default-browser-check",
	}
	if lang != "" {
		flags = append(flags, "--lang="+lang)
	}
	if probe != "" {
		flags = append(flags, "--headless=new", "--disable-gpu")
	}
	if proxy != "" {
		flags = append(flags, "--proxy-server="+proxy)
	}
	cmd := exec.Command(exe, append(flags, "about:blank")...)
	cmd.SysProcAttr = &syscall.SysProcAttr{AdditionalInheritedHandles: []syscall.Handle{syscall.Handle(in), syscall.Handle(out)}}
	if err := cmd.Start(); err != nil {
		return err
	}
	toBrowser.Close()
	fromBrowser.Close()
	if probe != "" {
		time.AfterFunc(90*time.Second, func() {
			cmd.Process.Kill()
			r.Close()
		})
	}

	c := &cdp{w: w}
	attach := map[string]any{"autoAttach": true, "waitForDebuggerOnStart": true, "flatten": true}
	c.send("", "Target.setAutoAttach", attach)
	var first string
	navigate, evaluate := 0, 0
	result := []byte(`{"error":"browser closed before the page loaded"}`)
	br := bufio.NewReaderSize(r, 1<<20)
	for {
		raw, err := br.ReadBytes(0)
		if err != nil {
			break
		}
		var m cdpMessage
		if json.Unmarshal(raw[:len(raw)-1], &m) != nil {
			continue
		}
		switch {
		case m.Method == "Target.attachedToTarget":
			var p struct {
				SessionID  string `json:"sessionId"`
				TargetInfo struct {
					Type string `json:"type"`
				} `json:"targetInfo"`
			}
			json.Unmarshal(m.Params, &p)
			if p.TargetInfo.Type == "page" || p.TargetInfo.Type == "iframe" {
				if tz != "" {
					c.send(p.SessionID, "Emulation.setTimezoneOverride", map[string]string{"timezoneId": tz})
				}
				c.send(p.SessionID, "Target.setAutoAttach", attach)
			}
			c.send(p.SessionID, "Runtime.runIfWaitingForDebugger", nil)
			if first == "" && p.TargetInfo.Type == "page" {
				first = p.SessionID
				if probe != "" {
					c.send(first, "Page.enable", nil)
				}
				navigate = c.send(first, "Page.navigate", map[string]string{"url": target})
			}
		case probe == "":
		case m.ID == navigate && m.ID != 0:
			var p struct {
				ErrorText string `json:"errorText"`
			}
			json.Unmarshal(m.Result, &p)
			if p.ErrorText != "" || m.Error != nil {
				result, _ = json.Marshal(map[string]string{"error": p.ErrorText + string(m.Error)})
				c.send("", "Browser.close", nil)
			}
			navigate = -1
		case m.Method == "Page.loadEventFired" && m.SessionID == first && navigate == -1 && evaluate == 0:
			evaluate = c.send(first, "Runtime.evaluate", map[string]any{"expression": probeExpr, "returnByValue": true, "awaitPromise": true})
		case m.ID == evaluate && m.ID != 0:
			var p struct {
				Result struct {
					Value string `json:"value"`
				} `json:"result"`
			}
			json.Unmarshal(m.Result, &p)
			if p.Result.Value != "" {
				result = []byte(p.Result.Value)
			}
			c.send("", "Browser.close", nil)
		}
	}
	cmd.Wait()
	if probe != "" {
		return os.WriteFile(probe, result, 0o644)
	}
	return nil
}
