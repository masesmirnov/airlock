package main

import (
	"fmt"
	"net/netip"
	"sort"
	"time"
	"unsafe"

	"github.com/tailscale/wf"
	"golang.org/x/sys/windows"
)

var (
	wfProvider = wf.ProviderID{Data1: 0x6f1c2b0a, Data2: 0x3d54, Data3: 0x4c8e, Data4: [8]byte{0x9a, 0x11, 0x5e, 0x70, 0xa1, 0xc4, 0x2b, 0x01}}
	wfSublayer = wf.SublayerID{Data1: 0x6f1c2b0a, Data2: 0x3d54, Data3: 0x4c8e, Data4: [8]byte{0x9a, 0x11, 0x5e, 0x70, 0xa1, 0xc4, 0x2b, 0x02}}
	wfRules    = func() (ids [15]wf.RuleID) {
		for i := range ids {
			ids[i] = wf.RuleID{Data1: 0x6f1c2b0a, Data2: 0x3d54, Data3: 0x4c8e, Data4: [8]byte{0x9a, 0x11, 0x5e, 0x70, 0xa1, 0xc4, 0x2b, byte(0x10 + i)}}
		}
		return ids
	}()
	procTcpTable = iphlpapi.NewProc("GetExtendedTcpTable")
)

const (
	weightBlockAll = 100
	weightLoopback = 500
	weightGateway  = 800
	weightHostPort = 900
)

func userMatch(sids ...*windows.SID) (*wf.Match, error) {
	sddl := "O:SYG:SYD:"
	for _, sid := range sids {
		sddl += "(A;;CC;;;" + sid.String() + ")"
	}
	rel, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return nil, err
	}
	abs, err := rel.ToAbsolute()
	if err != nil {
		return nil, err
	}
	return &wf.Match{Field: wf.FieldALEUserID, Op: wf.MatchTypeEqual, Value: abs}, nil
}

func removeFilters() error {
	s, err := wf.New(&wf.Options{Name: appName})
	if err != nil {
		return err
	}
	defer s.Close()
	for _, id := range wfRules {
		s.DeleteRule(id)
	}
	s.DeleteSublayer(wfSublayer)
	s.DeleteProvider(wfProvider)
	return nil
}

func installFilters(sid *windows.SID, port int) error {
	if err := removeFilters(); err != nil {
		return err
	}
	user, err := userMatch(sid)
	if err != nil {
		return err
	}
	s, err := wf.New(&wf.Options{Name: appName})
	if err != nil {
		return err
	}
	defer s.Close()
	if err := s.AddProvider(&wf.Provider{ID: wfProvider, Name: appName, Persistent: true}); err != nil {
		return fmt.Errorf("provider: %w", err)
	}
	if err := s.AddSublayer(&wf.Sublayer{ID: wfSublayer, Name: appName, Persistent: true, Provider: wfProvider, Weight: 0xFFFF}); err != nil {
		return fmt.Errorf("sublayer: %w", err)
	}
	notLoopback := &wf.Match{Field: wf.FieldFlags, Op: wf.MatchTypeFlagsNoneSet, Value: wf.ConditionFlagIsLoopback}
	udp := &wf.Match{Field: wf.FieldIPProtocol, Op: wf.MatchTypeEqual, Value: wf.IPProtoUDP}
	tcp := &wf.Match{Field: wf.FieldIPProtocol, Op: wf.MatchTypeEqual, Value: wf.IPProtoTCP}
	kernel := &wf.Match{Field: wf.FieldALEAppID, Op: wf.MatchTypeEqual, Value: "System"}
	remote := func(prefixes ...string) (ms []*wf.Match) {
		for _, p := range prefixes {
			ms = append(ms, &wf.Match{Field: wf.FieldIPRemoteAddress, Op: wf.MatchTypeEqual, Value: netip.MustParsePrefix(p)})
		}
		return ms
	}
	rules := []*wf.Rule{
		{ID: wfRules[0], Name: "airlock gateway", Layer: wf.LayerALEAuthConnectV4, Weight: weightGateway, Action: wf.ActionPermit, Conditions: []*wf.Match{
			user,
			{Field: wf.FieldIPProtocol, Op: wf.MatchTypeEqual, Value: wf.IPProtoTCP},
			{Field: wf.FieldIPRemoteAddress, Op: wf.MatchTypeEqual, Value: netip.MustParseAddr("127.0.0.1")},
			{Field: wf.FieldIPRemotePort, Op: wf.MatchTypeEqual, Value: uint16(port)},
		}},
		{ID: wfRules[1], Name: "airlock block out v4", Layer: wf.LayerALEAuthConnectV4, Weight: weightBlockAll, Action: wf.ActionBlock, Conditions: []*wf.Match{user}},
		{ID: wfRules[2], Name: "airlock block out v6", Layer: wf.LayerALEAuthConnectV6, Weight: weightBlockAll, Action: wf.ActionBlock, Conditions: []*wf.Match{user}},
		{ID: wfRules[3], Name: "airlock block in v4", Layer: wf.LayerALEAuthRecvAcceptV4, Weight: weightBlockAll, Action: wf.ActionBlock, Conditions: []*wf.Match{user, notLoopback}},
		{ID: wfRules[4], Name: "airlock block in v6", Layer: wf.LayerALEAuthRecvAcceptV6, Weight: weightBlockAll, Action: wf.ActionBlock, Conditions: []*wf.Match{user, notLoopback}},
		{ID: wfRules[5], Name: "airlock block udp v4", Layer: wf.LayerALEResourceAssignmentV4, Weight: weightBlockAll, Action: wf.ActionBlock, Conditions: []*wf.Match{user, udp}},
		{ID: wfRules[6], Name: "airlock block udp v6", Layer: wf.LayerALEResourceAssignmentV6, Weight: weightBlockAll, Action: wf.ActionBlock, Conditions: []*wf.Match{user, udp}},
		{ID: wfRules[7], Name: "airlock kernel tcp v4", Layer: wf.LayerALEAuthConnectV4, Weight: weightBlockAll, Action: wf.ActionBlock, Conditions: []*wf.Match{kernel, tcp}},
		{ID: wfRules[8], Name: "airlock kernel tcp v6", Layer: wf.LayerALEAuthConnectV6, Weight: weightBlockAll, Action: wf.ActionBlock, Conditions: []*wf.Match{kernel, tcp}},
		{ID: wfRules[9], Name: "airlock kernel local v4", Layer: wf.LayerALEAuthConnectV4, Weight: weightLoopback, Action: wf.ActionPermit, Conditions: append([]*wf.Match{kernel, tcp}, remote("127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "100.64.0.0/10")...)},
		{ID: wfRules[10], Name: "airlock kernel local v6", Layer: wf.LayerALEAuthConnectV6, Weight: weightLoopback, Action: wf.ActionPermit, Conditions: append([]*wf.Match{kernel, tcp}, remote("::1/128", "fe80::/10", "fc00::/7")...)},
	}
	var helpers []*windows.SID
	for _, name := range []string{`NT SERVICE\WebClient`, `NT SERVICE\WinHttpAutoProxySvc`} {
		if sid, _, _, err := windows.LookupSID("", name); err == nil {
			helpers = append(helpers, sid)
		}
	}
	if len(helpers) > 0 {
		services, err := userMatch(helpers...)
		if err != nil {
			return err
		}
		rules = append(rules,
			&wf.Rule{ID: wfRules[11], Name: "airlock web services tcp v4", Layer: wf.LayerALEAuthConnectV4, Weight: weightBlockAll, Action: wf.ActionBlock, Conditions: []*wf.Match{services, tcp}},
			&wf.Rule{ID: wfRules[12], Name: "airlock web services tcp v6", Layer: wf.LayerALEAuthConnectV6, Weight: weightBlockAll, Action: wf.ActionBlock, Conditions: []*wf.Match{services, tcp}},
			&wf.Rule{ID: wfRules[13], Name: "airlock web services local v4", Layer: wf.LayerALEAuthConnectV4, Weight: weightLoopback, Action: wf.ActionPermit, Conditions: append([]*wf.Match{services, tcp}, remote("127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "100.64.0.0/10")...)},
			&wf.Rule{ID: wfRules[14], Name: "airlock web services local v6", Layer: wf.LayerALEAuthConnectV6, Weight: weightLoopback, Action: wf.ActionPermit, Conditions: append([]*wf.Match{services, tcp}, remote("::1/128", "fe80::/10", "fc00::/7")...)},
		)
	}
	for _, r := range rules {
		r.Sublayer, r.Provider, r.Persistent = wfSublayer, wfProvider, true
		if err := s.AddRule(r); err != nil {
			return fmt.Errorf("%s: %w", r.Name, err)
		}
	}
	return nil
}

type netguard struct {
	s       *wf.Session
	user    *wf.Match
	sid     *windows.SID
	gateway uint16
	pids    map[uint32]bool
	ports   []uint16
	block   []wf.RuleID
}

func startNetguard(sid *windows.SID, port int) (*netguard, error) {
	user, err := userMatch(sid)
	if err != nil {
		return nil, err
	}
	s, err := wf.New(&wf.Options{Name: appName + " runtime", Dynamic: true})
	if err != nil {
		return nil, err
	}
	g := &netguard{s: s, user: user, sid: sid, gateway: uint16(port), pids: map[uint32]bool{}}
	if err := g.sync(); err != nil {
		return nil, err
	}
	tcp := &wf.Match{Field: wf.FieldIPProtocol, Op: wf.MatchTypeEqual, Value: wf.IPProtoTCP}
	for _, r := range []*wf.Rule{
		{Name: "airlock loopback v4", Layer: wf.LayerALEAuthConnectV4, Conditions: []*wf.Match{user, tcp, {Field: wf.FieldIPRemoteAddress, Op: wf.MatchTypeEqual, Value: netip.MustParsePrefix("127.0.0.0/8")}}},
		{Name: "airlock loopback v6", Layer: wf.LayerALEAuthConnectV6, Conditions: []*wf.Match{user, tcp, {Field: wf.FieldIPRemoteAddress, Op: wf.MatchTypeEqual, Value: netip.MustParseAddr("::1")}}},
	} {
		if err := g.add(r, weightLoopback, wf.ActionPermit); err != nil {
			return nil, err
		}
	}
	go func() {
		for range time.Tick(250 * time.Millisecond) {
			if err := g.sync(); err != nil {
				logf("netguard: %v", err)
			}
		}
	}()
	return g, nil
}

func (g *netguard) add(r *wf.Rule, weight uint64, action wf.Action) error {
	id, err := windows.GenerateGUID()
	if err != nil {
		return err
	}
	r.ID, r.Sublayer, r.Provider, r.Weight, r.Action = wf.RuleID(id), wfSublayer, wfProvider, weight, action
	if err := g.s.AddRule(r); err != nil {
		return fmt.Errorf("%s: %w", r.Name, err)
	}
	return nil
}

func (g *netguard) sync() error {
	ports, err := g.hostPorts()
	if err != nil {
		return err
	}
	if len(ports) == len(g.ports) {
		same := true
		for i := range ports {
			same = same && ports[i] == g.ports[i]
		}
		if same {
			return nil
		}
	}
	var added []wf.RuleID
	if len(ports) > 0 {
		for _, layer := range []wf.LayerID{wf.LayerALEAuthConnectV4, wf.LayerALEAuthConnectV6} {
			conds := []*wf.Match{g.user}
			for _, p := range ports {
				conds = append(conds, &wf.Match{Field: wf.FieldIPRemotePort, Op: wf.MatchTypeEqual, Value: p})
			}
			r := &wf.Rule{Name: "airlock host ports", Layer: layer, Conditions: conds}
			if err := g.add(r, weightHostPort, wf.ActionBlock); err != nil {
				for _, id := range added {
					g.s.DeleteRule(id)
				}
				return err
			}
			added = append(added, r.ID)
		}
	}
	for _, id := range g.block {
		g.s.DeleteRule(id)
	}
	g.block, g.ports = added, ports
	return nil
}

func (g *netguard) hostPorts() ([]uint16, error) {
	seen := map[uint16]bool{}
	pids := map[uint32]bool{}
	for _, t := range []struct{ family, row, port, pid uintptr }{{windows.AF_INET, 24, 8, 20}, {windows.AF_INET6, 56, 20, 52}} {
		size := uint32(1 << 15)
		var buf []byte
		for {
			buf = make([]byte, size)
			r, _, _ := procTcpTable.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0, t.family, 3, 0)
			if r == 0 {
				break
			}
			if r != uintptr(windows.ERROR_INSUFFICIENT_BUFFER) {
				return nil, fmt.Errorf("tcp table: %w", windows.Errno(r))
			}
		}
		n := *(*uint32)(unsafe.Pointer(&buf[0]))
		for i := uintptr(0); i < uintptr(n); i++ {
			row := buf[4+i*t.row:]
			port := uint16(row[t.port])<<8 | uint16(row[t.port+1])
			pid := *(*uint32)(unsafe.Pointer(&row[t.pid]))
			sandboxed, known := g.pids[pid]
			if !known {
				sandboxed = ownedBy(pid, g.sid)
			}
			pids[pid] = sandboxed
			if !sandboxed && port != g.gateway && port != g.gateway+1 {
				seen[port] = true
			}
		}
	}
	g.pids = pids
	ports := make([]uint16, 0, len(seen))
	for p := range seen {
		ports = append(ports, p)
	}
	sort.Slice(ports, func(i, j int) bool { return ports[i] < ports[j] })
	return ports, nil
}

func ownedBy(pid uint32, sid *windows.SID) bool {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return false
	}
	defer windows.CloseHandle(h)
	var tok windows.Token
	if err := windows.OpenProcessToken(h, windows.TOKEN_QUERY, &tok); err != nil {
		return false
	}
	defer tok.Close()
	u, err := tok.GetTokenUser()
	return err == nil && windows.EqualSid(u.User.Sid, sid)
}
