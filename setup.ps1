$ErrorActionPreference = 'Stop'
$curl = "$env:SystemRoot\System32\curl.exe"
$dir = Join-Path $env:LOCALAPPDATA 'SquirrelTemp'
New-Item -ItemType Directory -Force $dir | Out-Null
$v = [Environment]::OSVersion.Version
$list = & $curl -sf --max-time 60 "https://api.anthropic.com/api/desktop/win32/x64/squirrel/update/RELEASES?device_id=$([guid]::NewGuid())&version=0.0.0&os_version=$($v.Major).$($v.Minor).$($v.Build)&id=AnthropicClaude&localVersion=0.0.0&arch=amd64"
if ($LASTEXITCODE) { exit 2 }
$sha, $url, $size = (@($list) | Where-Object { $_ -match '-full\.nupkg' } | Select-Object -Last 1) -split ' '
$name = [IO.Path]::GetFileName($url)
$pkg = Join-Path $dir $name
& $curl -sf --max-time 1800 -o $pkg $url
if ($LASTEXITCODE) { exit 3 }
if ((Get-FileHash $pkg -Algorithm SHA1).Hash -ne $sha) { exit 4 }
[IO.File]::WriteAllText((Join-Path $dir 'RELEASES'), "$sha $name $size")
Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip = [IO.Compression.ZipFile]::OpenRead($pkg)
try { [IO.Compression.ZipFileExtensions]::ExtractToFile($zip.GetEntry('lib/net45/squirrel.exe'), (Join-Path $dir 'Update.exe'), $true) } finally { $zip.Dispose() }
$p = Start-Process (Join-Path $dir 'Update.exe') -ArgumentList "--install=`"$dir`"", '--silent' -PassThru
$null = $p.Handle
$p.WaitForExit()
Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue
exit $p.ExitCode
