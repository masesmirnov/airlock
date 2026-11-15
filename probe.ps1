param([int]$Port, [string]$Out, [string]$OwnerProfile, [string]$DataDir, [string]$Shared, [string]$Helper, [string]$Proxy, [string]$Token, [switch]$Quick, [switch]$Launch)
$ErrorActionPreference = 'Continue'
$r = [ordered]@{}
$v4 = [Net.Sockets.AddressFamily]::InterNetwork
$v6 = [Net.Sockets.AddressFamily]::InterNetworkV6
$curl = "$env:SystemRoot\System32\curl.exe"
$failProxy = "http://127.0.0.1:$($Port + 1)"

function Reason($e) {
  while ($e.InnerException) { $e = $e.InnerException }
  if ($e -isnot [Net.Sockets.SocketException]) { return $e.GetType().Name }
  switch ("$($e.SocketErrorCode)") {
    'AccessDenied' { 'blocked' }
    'InvalidArgument' { 'blocked' }
    'NetworkUnreachable' { 'unreachable' }
    'HostUnreachable' { 'unreachable' }
    'TimedOut' { 'silent' }
    default { "$_" }
  }
}

function Tcp($family, $address, $port) {
  $c = New-Object Net.Sockets.TcpClient($family)
  try {
    if ($c.ConnectAsync($address, $port).Wait(4000)) { 'open' } else { 'silent' }
  } catch { Reason $_.Exception } finally { $c.Close() }
}

function Udp($family, $address, $port) {
  $u = New-Object Net.Sockets.UdpClient($family)
  try {
    $u.Client.ReceiveTimeout = 3000
    [byte[]]$q = [byte[]](0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7) + [Text.Encoding]::ASCII.GetBytes('example') + [byte[]](3) + [Text.Encoding]::ASCII.GetBytes('com') + [byte[]](0, 0, 1, 0, 1)
    [void]$u.Send($q, $q.Length, $address, $port)
    $any = if ($family -eq $v6) { [Net.IPAddress]::IPv6Any } else { [Net.IPAddress]::Any }
    $ep = New-Object Net.IPEndPoint($any, 0)
    [void]$u.Receive([ref]$ep)
    'open'
  } catch { Reason $_.Exception } finally { $u.Close() }
}

function Connect($target, $port = $Port) {
  try {
    $c = New-Object Net.Sockets.TcpClient
    $c.Connect('127.0.0.1', $port)
    $s = $c.GetStream()
    $s.ReadTimeout = 40000
    $q = [Text.Encoding]::ASCII.GetBytes("CONNECT $target HTTP/1.1`r`nHost: $target`r`n`r`n")
    $s.Write($q, 0, $q.Length)
    $b = New-Object byte[] 12
    $n = 0
    while ($n -lt 12) { $k = $s.Read($b, $n, 12 - $n); if ($k -le 0) { break }; $n += $k }
    $c.Close()
    if ($n -eq 12) { [Text.Encoding]::ASCII.GetString($b, 9, 3) } else { 'none' }
  } catch { 'none' }
}

function Socks([byte]$command) {
  try {
    $c = New-Object Net.Sockets.TcpClient
    $c.Connect('127.0.0.1', $Port)
    $s = $c.GetStream()
    $s.ReadTimeout = 40000
    $b = New-Object byte[] 16
    $s.Write([byte[]](5, 1, 0), 0, 3)
    [void]$s.Read($b, 0, 2)
    $s.Write([byte[]](5, $command, 0, 1, 1, 1, 1, 1, 0, 53), 0, 10)
    $n = $s.Read($b, 0, 10)
    $c.Close()
    if ($n -ge 2) { [int]$b[1] } else { -1 }
  } catch { -1 }
}

function TraceIP($via) {
  $a = @('-s', '--max-time', '40')
  if ($via) { $a += '-x', $via }
  $t = (& $curl @a https://www.cloudflare.com/cdn-cgi/trace 2>$null | Out-String)
  if ($t -match '(?m)^ip=(.+)$') { $Matches[1].Trim() } else { '' }
}

function Doh($via) {
  $a = @('-s', '--max-time', '20', '-H', 'accept: application/dns-json')
  if ($via) { $a += '-x', $via }
  $j = (& $curl @a 'https://cloudflare-dns.com/dns-query?name=example.com&type=A' 2>$null | Out-String)
  if ($j -match '"Status"\s*:\s*0' -and $j -match '"Answer"') { 'answered' } else { 'failed' }
}

function Browser($file, $via) {
  Remove-Item $file -ErrorAction SilentlyContinue
  $si = New-Object Diagnostics.ProcessStartInfo($Helper, "browser-host --probe `"$file`" $via")
  $si.UseShellExecute = $false
  [Diagnostics.Process]::Start($si)
}

function Cast($address, $port) {
  $u = New-Object Net.Sockets.UdpClient
  try {
    $u.EnableBroadcast = $true
    $x = [Text.Encoding]::ASCII.GetBytes('airlock-probe')
    [void]$u.Send($x, $x.Length, $address, $port)
    'sent'
  } catch { Reason $_.Exception } finally { $u.Close() }
}

function Bssid {
  if ((& "$env:SystemRoot\System32\netsh.exe" wlan show interfaces | Out-String) -match 'BSSID\s*:\s*(\S+)') { $Matches[1] } else { '' }
}

function CanList($path) {
  try { [void][IO.Directory]::GetFileSystemEntries($path); $true } catch { $false }
}

$r.gate_public = Connect '1.1.1.1:443'
$r.direct_tcp4 = Tcp $v4 '1.1.1.1' 443

if (-not $Quick) {
  $dir = Split-Path $Out
  $bf = Join-Path $dir 'browser.json'
  $ff = Join-Path $dir 'browser-fail.json'
  $browsers = @((Browser $bf ''), (Browser $ff $failProxy))

  $r.direct_tcp6 = Tcp $v6 '2606:4700:4700::1111' 443
  $r.direct_dns_tcp = Tcp $v4 '8.8.8.8' 53
  $r.direct_dot = Tcp $v4 '1.1.1.1' 853
  $r.direct_udp = Udp $v4 '8.8.8.8' 53
  $r.direct_udp6 = Udp $v6 '2001:4860:4860::8888' 53
  $r.direct_meta = Tcp $v4 '169.254.169.254' 80
  $r.multicast = Cast '239.255.77.77' 47777
  $r.broadcast = Cast '255.255.255.255' 47778
  $r.icmp = (& "$env:SystemRoot\System32\ping.exe" -n 1 -w 2000 1.1.1.1 | Out-String) -match 'TTL='
  $i = $Proxy.LastIndexOf(':')
  $r.direct_proxy = if ($i -gt 0) { Tcp $v4 $Proxy.Substring(0, $i).Trim('[]') ([int]$Proxy.Substring($i + 1)) } else { 'none' }
  $r.gate_private = Connect '10.0.0.1:80'
  $r.gate_loopback = Connect '127.0.0.1:80'
  $r.gate_ipv6 = Connect '[2606:4700:4700::1111]:443'
  $r.gate_udp = Socks 3
  $r.dns_system = try { [void][Net.Dns]::GetHostAddresses('www.cloudflare.com'); 'resolved' } catch { 'blocked' }

  $r.curl_ip = TraceIP ''
  $r.doh = Doh ''
  $r.fail_ip = TraceIP $failProxy
  $r.fail_doh = Doh $failProxy
  $r.fail_gate = Connect '1.1.1.1:443' ($Port + 1)

  $r.env_tz = "$env:TZ"
  $inet = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction SilentlyContinue
  Add-Type -TypeDefinition @'
using System; using System.Runtime.InteropServices;
public static class IEProxy {
  [StructLayout(LayoutKind.Sequential)] struct Config { public bool AutoDetect; public IntPtr AutoConfigUrl, Proxy, Bypass; }
  [DllImport("winhttp.dll")] static extern bool WinHttpGetIEProxyConfigForCurrentUser(ref Config c);
  public static string Get() { Config c = new Config(); return WinHttpGetIEProxyConfigForCurrentUser(ref c) && c.Proxy != IntPtr.Zero ? Marshal.PtrToStringUni(c.Proxy) : ""; }
}
'@
  $sys = [Net.WebRequest]::GetSystemWebProxy().GetProxy('https://example.com/')
  $r.env_proxy = (@(Get-ChildItem env: | Where-Object Name -match 'proxy' | ForEach-Object { "$($_.Name)=$($_.Value)" }) + @(if ($inet.ProxyEnable) { "ProxyServer=$($inet.ProxyServer)" }) + @(if ($w = [IEProxy]::Get()) { "WinHTTP=$w" }) + @(if ($sys.Host -ne 'example.com') { ".NET=$sys" })) -join ';'
  $r.culture = (Get-Culture).Name
  $r.ui_culture = (Get-UICulture).Name
  $r.winapi_tz = [TimeZoneInfo]::Local.Id
  $r.geo = "$((Get-WinHomeLocation).GeoId)"
  $r.system_locale = (Get-WinSystemLocale).Name
  $r.process_offset = [int][DateTimeOffset]::Now.Offset.TotalMinutes
  $r.system_offset = [int][TimeZoneInfo]::FindSystemTimeZoneById([TimeZoneInfo]::Local.Id).GetUtcOffset([DateTime]::UtcNow).TotalMinutes
  $r.node = ''
  if (-not $Launch -and (Get-Command node -ErrorAction SilentlyContinue)) {
    $r.node = (& node -p "Intl.DateTimeFormat().resolvedOptions().timeZone" 2>$null | Out-String).Trim()
  }
  $r.user = [Security.Principal.WindowsIdentity]::GetCurrent().Name
  $r.profile = "$env:USERPROFILE"

  $r.shared_read = try { $Token -ne '' -and [IO.File]::ReadAllText((Join-Path $dir 'token.txt')).Trim() -eq $Token } catch { $false }
  $r.owner_profile = try { $d = Join-Path $OwnerProfile ".airlock-$PID"; [void][IO.Directory]::CreateDirectory($d); [IO.File]::WriteAllText((Join-Path $d 'x'), 'x'); [IO.Directory]::Delete($d, $true); $true } catch { $false }
  $system = 'Windows', 'Program Files', 'Program Files (x86)', 'ProgramData', 'Users', '$Recycle.Bin', 'Documents and Settings', 'System Volume Information', 'Recovery', 'PerfLogs', '$WinREAgent', 'Config.Msi'
  $closed = @()
  foreach ($d in [IO.DriveInfo]::GetDrives()) {
    if ($d.DriveType -ne 'Fixed') { continue }
    foreach ($e in [IO.Directory]::GetDirectories($d.RootDirectory.FullName)) {
      if ($system -contains [IO.Path]::GetFileName($e)) { continue }
      $skip = $false
      foreach ($s in $Shared -split ';') { if ("$s\".StartsWith("$e\", [StringComparison]::OrdinalIgnoreCase)) { $skip = $true } }
      if (-not $skip -and -not (CanList $e)) { $closed += $e }
    }
  }
  $r.closed_roots = $closed -join ';'

  $r.pipe = try {
    $p = New-Object IO.Pipes.NamedPipeClientStream('.', 'airlock-control', [IO.Pipes.PipeDirection]::InOut)
    $p.Connect(2000)
    $p.Close()
    'open'
  } catch {
    $e = $_.Exception
    while ($e.InnerException) { $e = $e.InnerException }
    $e.GetType().Name
  }
  Add-Type -TypeDefinition @'
using System; using System.Runtime.InteropServices; using System.Text;
public static class Ident {
  [DllImport("kernel32.dll", CharSet = CharSet.Unicode)] static extern bool GetVolumeInformationW(string root, StringBuilder name, int nameSize, out uint serial, out uint maxLen, out uint flags, StringBuilder fs, int fsSize);
  [DllImport("kernel32.dll")] public static extern ulong GetTickCount64();
  [DllImport("kernel32.dll")] static extern uint GetSystemFirmwareTable(uint provider, uint id, IntPtr buf, uint size);
  [DllImport("kernel32.dll", CharSet = CharSet.Unicode)] static extern IntPtr CreateFileW(string name, uint access, uint share, IntPtr sa, uint disposition, uint flags, IntPtr template);
  [DllImport("kernel32.dll")] static extern bool DeviceIoControl(IntPtr dev, uint code, byte[] inBuf, int inSize, byte[] outBuf, int outSize, out int ret, IntPtr ov);
  [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
  public static string Volume(string root) { uint s, m, f; return GetVolumeInformationW(root, null, 0, out s, out m, out f, null, 0) ? s.ToString("X8") : ""; }
  public static string Smbios() {
    uint n = GetSystemFirmwareTable(0x52534D42, 0, IntPtr.Zero, 0);
    if (n == 0) return "";
    IntPtr p = Marshal.AllocHGlobal((int)n);
    try {
      byte[] b = new byte[GetSystemFirmwareTable(0x52534D42, 0, p, n)];
      Marshal.Copy(p, b, 0, b.Length);
      string uuid = "", sys = "", board = "";
      for (int i = 8; i + 4 <= b.Length; ) {
        int type = b[i], len = b[i + 1], s = i + len, e = s;
        if (len < 4 || s + 1 >= b.Length) break;
        while (e + 1 < b.Length && (b[e] != 0 || b[e + 1] != 0)) e++;
        string[] strs = Encoding.ASCII.GetString(b, s, e - s).Split('\0');
        Func<int, string> str = k => k > 0 && k <= strs.Length ? strs[k - 1].Trim() : "";
        if (type == 1 && len >= 0x18) { uuid = BitConverter.ToString(b, i + 8, 16).Replace("-", ""); sys = str(b[i + 7]); }
        if (type == 2 && len > 7) board = str(b[i + 7]);
        if (type == 127) break;
        i = e + 2;
      }
      return uuid + ";" + sys + ";" + board;
    } finally { Marshal.FreeHGlobal(p); }
  }
  public static string Disk() {
    IntPtr h = CreateFileW(@"\\.\PhysicalDrive0", 0, 3, IntPtr.Zero, 3, 0, IntPtr.Zero);
    if (h == new IntPtr(-1)) return "";
    try {
      byte[] o = new byte[1024]; int n;
      if (!DeviceIoControl(h, 0x2D1400, new byte[12], 12, o, o.Length, out n, IntPtr.Zero)) return "";
      int off = BitConverter.ToInt32(o, 24), e = off;
      if (off <= 0 || off >= n) return "";
      while (e < n && o[e] != 0) e++;
      return Encoding.ASCII.GetString(o, off, e - off).Trim();
    } finally { CloseHandle(h); }
  }
}
'@
  $cv = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
  $vol = (cmd.exe /c vol C: | Out-String) -replace '(?s).*\s([0-9A-F]{4})-([0-9A-F]{4}).*', '$1$2'
  $r.identity = [ordered]@{
    machine_guid = [Microsoft.Win32.Registry]::GetValue('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography', 'MachineGuid', '')
    machine_guid_reg = ((& "$env:SystemRoot\System32\reg.exe" query 'HKLM\SOFTWARE\Microsoft\Cryptography' /v MachineGuid | Out-String) -split 'REG_SZ')[-1].Trim()
    names = (@([Environment]::MachineName, [Net.Dns]::GetHostName(), $env:COMPUTERNAME, $env:USERDOMAIN, (& "$env:SystemRoot\System32\hostname.exe" | Out-String).Trim()) | Select-Object -Unique) -join ';'
    account = "$([Security.Principal.WindowsIdentity]::GetCurrent().Name);$((& "$env:SystemRoot\System32\whoami.exe" | Out-String).Trim())"
    product_id =[Microsoft.Win32.Registry]::GetValue($cv, 'ProductId', '')
    install_date = "$([Microsoft.Win32.Registry]::GetValue($cv, 'InstallDate', ''))"
    owner = [Microsoft.Win32.Registry]::GetValue($cv, 'RegisteredOwner', '')
    sus_id = [Microsoft.Win32.Registry]::GetValue('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate', 'SusClientId', '')
    hw_profile = [Microsoft.Win32.Registry]::GetValue('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\IDConfigDB\Hardware Profiles\0001', 'HwProfileGuid', '')
    sqm_id = [Microsoft.Win32.Registry]::GetValue('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SQMClient', 'MachineId', '')
    model = "$([Microsoft.Win32.Registry]::GetValue('HKEY_LOCAL_MACHINE\HARDWARE\DESCRIPTION\System\BIOS', 'SystemManufacturer', '')) $([Microsoft.Win32.Registry]::GetValue('HKEY_LOCAL_MACHINE\HARDWARE\DESCRIPTION\System\BIOS', 'SystemProductName', ''))"
    volume = [Ident]::Volume('C:\')
    volume_cmd = $vol.Trim()
    disk = [Ident]::Disk()
    smbios = [Ident]::Smbios()
    boot = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() - [long]([Ident]::GetTickCount64() / 1000)
    wmi = $(try { "$((Get-CimInstance Win32_ComputerSystemProduct -ErrorAction Stop).UUID)" } catch { 'blocked' })
    macs = ([Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces() | ForEach-Object { "$($_.GetPhysicalAddress())" } | Where-Object { $_ }) -join ';'
    ipconfig_macs = ([regex]::Matches((& "$env:SystemRoot\System32\ipconfig.exe" /all | Out-String), '([0-9A-F]{2}-){5}[0-9A-F]{2}') | ForEach-Object { $_.Value -replace '-', '' }) -join ';'
    bssid = Bssid
    claude_device = $(try { [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String((Get-Content "$env:APPDATA\Claude\ant-did" -Raw -ErrorAction Stop))).Trim() } catch { '' })
    arp = [regex]::Matches((& "$env:SystemRoot\System32\arp.exe" -a | Out-String), '([0-9a-f]{2}-){5}[0-9a-f]{2}').Count
  }

  $r.data_dir = CanList $DataDir
  & "$env:SystemRoot\System32\sc.exe" stop airlock *> $null
  $r.sc_stop = $LASTEXITCODE

  if (-not $Launch) {
    $r.hooked = [bool](Get-Process -Id $PID).Modules.Where({ $_.ModuleName -eq 'airlockhook.dll' }).Count

    $r.bits = try {
      Import-Module BitsTransfer -ErrorAction Stop
      $j = Start-BitsTransfer -Source 'http://www.msftconnecttest.com/connecttest.txt' -Destination (Join-Path $env:TEMP 'airlock-bits.txt') -ProxyUsage NoProxy -Asynchronous -ErrorAction Stop
      $state = ''
      for ($i = 0; $i -lt 16; $i++) {
        Start-Sleep -Milliseconds 500
        $state = "$($j.JobState)"
        if ($state -eq 'Transferred' -or $state -eq 'Error') { break }
      }
      Remove-BitsTransfer $j -ErrorAction SilentlyContinue
      $state
    } catch { 'blocked' }

    $r.shell_start = try {
      $p = Start-Process -FilePath "$env:SystemRoot\System32\cmd.exe" -ArgumentList '/c exit' -WindowStyle Hidden -PassThru -ErrorAction Stop
      [void]$p.WaitForExit(8000)
      'ok'
    } catch { 'failed' }
  }

  foreach ($b in $browsers) { if (-not $b.WaitForExit(120000)) { $b.Kill() } }
  $r.browser = if (Test-Path $bf) { [IO.File]::ReadAllText($bf) } else { '' }
  $r.browser_fail = if (Test-Path $ff) { [IO.File]::ReadAllText($ff) } else { '' }
}

[IO.File]::WriteAllText($Out, ($r | ConvertTo-Json -Depth 4))
