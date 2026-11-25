# Shared, side-effect-free discovery and bounded protocol probes (Windows PowerShell 5.1+).
Set-StrictMode -Version 2
# A WinPS child of pwsh may inherit only PowerShell 7 module directories.
# Restore the native module search entry inside this process, never in registry.
if ($PSVersionTable.PSEdition -eq 'Desktop') {
    $codexNativeModules=[IO.Path]::Combine($env:SystemRoot,'System32\WindowsPowerShell\v1.0\Modules')
    if (([string]$env:PSModulePath -split ';') -notcontains $codexNativeModules) { $env:PSModulePath=$codexNativeModules+';'+$env:PSModulePath }
}
function Test-ProxyFile([string]$Path) { return ($Path -and (Test-Path -LiteralPath $Path -PathType Leaf)) }
function Get-CodexCliCandidates {
    $native='vendor\x86_64-pc-windows-msvc\bin\codex.exe'
    $modules=New-Object 'System.Collections.Generic.List[string]'
    if ($env:APPDATA) { $modules.Add((Join-Path $env:APPDATA 'npm\node_modules')) }
    if ($env:LOCALAPPDATA) {
        $modules.Add((Join-Path $env:LOCALAPPDATA 'pnpm\global\5\node_modules'))
        $store=Join-Path $env:LOCALAPPDATA 'pnpm\global\5\node_modules\.pnpm'
        if (Test-Path -LiteralPath $store) { Get-ChildItem -LiteralPath $store -Directory -Filter '@openai+codex*' -ErrorAction SilentlyContinue | ForEach-Object { $modules.Add((Join-Path $_.FullName 'node_modules')) } }
    }
    if ($env:BUN_INSTALL) { $modules.Add((Join-Path $env:BUN_INSTALL 'install\global\node_modules')) }
    $pnpmRoots=@()
    if ($env:LOCALAPPDATA) {$pnpmRoots+=(Join-Path $env:LOCALAPPDATA 'pnpm\global')}
    if ($env:PNPM_HOME) {$pnpmRoots+=(Join-Path $env:PNPM_HOME 'global')}
    foreach ($pnpmRoot in $pnpmRoots) {
        if (Test-Path -LiteralPath $pnpmRoot) {
            Get-ChildItem -LiteralPath $pnpmRoot -Directory -ErrorAction SilentlyContinue | ForEach-Object {
                $folder=Join-Path $_.FullName 'node_modules';$modules.Add($folder);$store=Join-Path $folder '.pnpm'
                if (Test-Path -LiteralPath $store) { Get-ChildItem -LiteralPath $store -Directory -Filter '@openai+codex*' -ErrorAction SilentlyContinue | ForEach-Object {$modules.Add((Join-Path $_.FullName 'node_modules'))} }
            }
        }
    }
    if ($env:USERPROFILE) { $modules.Add((Join-Path $env:USERPROFILE '.bun\install\global\node_modules')) }
    if ($env:CODEX_PROXY_TARGET_EXE) { $env:CODEX_PROXY_TARGET_EXE }
    foreach ($folder in $modules) {
        Join-Path $folder ('@openai\codex\node_modules\@openai\codex-win32-x64\'+$native)
        Join-Path $folder ('@openai\codex\'+$native)
        Join-Path $folder ('@openai\codex-win32-x64\'+$native)
    }
    foreach ($folder in ($env:PATH -split ';')) { if ($folder) { Join-Path ($folder.Trim('"')) 'codex.exe' } }
    if ($env:LOCALAPPDATA) { Join-Path $env:LOCALAPPDATA 'codex\codex.exe' }
}
function Find-CodexCli {
    if ($env:CODEX_PROXY_TARGET_EXE) { if (Test-ProxyFile $env:CODEX_PROXY_TARGET_EXE) {return $env:CODEX_PROXY_TARGET_EXE};return $null }
    Get-CodexCliCandidates | Where-Object { Test-ProxyFile $_ } | Select-Object -Unique -First 1
}
function Get-CodexDesktopCandidates {
    if ($env:LOCALAPPDATA) { Join-Path $env:LOCALAPPDATA 'Microsoft\WindowsApps\chatgpt-desktop.exe' }
    if (Get-Command Get-AppxPackage -ErrorAction SilentlyContinue) {
        try { Get-AppxPackage -Name OpenAI.Codex -ErrorAction Stop | ForEach-Object { Join-Path $_.InstallLocation 'app\ChatGPT.exe'; Join-Path $_.InstallLocation 'app\Codex.exe' } } catch { Write-Verbose $_.Exception.Message }
    }
    if ($env:LOCALAPPDATA) { Join-Path $env:LOCALAPPDATA 'Programs\Codex\Codex.exe'; Join-Path $env:LOCALAPPDATA 'Programs\Codex\ChatGPT.exe' }
}
function Get-ProxyConfigPath([string]$Directory) {
    $candidates=@()
    if ($env:CODEX_PROXY_CONFIG) { $candidates+=$env:CODEX_PROXY_CONFIG }
    if ($Directory) { $candidates+=(Join-Path $Directory 'config.json') }
    if ($Directory) {
        $locator=Join-Path $Directory 'codex-proxy.config-path'
        if (Test-ProxyFile $locator) {
            try {
                $located=[IO.File]::ReadAllLines($locator,[Text.Encoding]::UTF8) | Select-Object -First 1
                if ($located -and [IO.Path]::IsPathRooted($located)) { $candidates+=$located }
            } catch { Write-Verbose 'Invalid CLI config locator ignored.' }
        }
    }
    if ($env:LOCALAPPDATA) { $candidates+=(Join-Path $env:LOCALAPPDATA 'codex-proxy\config.json') }
    $candidates | Where-Object { Test-ProxyFile $_ } | Select-Object -First 1
}
function Get-ProxyHints {
    foreach ($name in @('ALL_PROXY','HTTPS_PROXY','HTTP_PROXY')) {
        $value=[Environment]::GetEnvironmentVariable($name)
        if ($value) {
            try { $uri=[Uri]$value; if ($uri.Host -and $uri.Port -gt 0) { [pscustomobject]@{ Host=$uri.Host; Port=$uri.Port; Type=$(if ($uri.Scheme -match 'socks') {'socks5'} else {'http'}); Source=$name } } } catch { }
        }
    }
    try {
        $settings=Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction Stop
        if ($settings.ProxyEnable -and $settings.ProxyServer) {
            foreach ($part in ($settings.ProxyServer -split ';')) {
                $entry=$part -replace '^[^=]+=',''
                try { $uri=[Uri]('http://'+$entry); if ($uri.Host -and $uri.Port -gt 0) { [pscustomobject]@{Host=$uri.Host;Port=$uri.Port;Type='http';Source='system'} } } catch { }
            }
        }
    } catch { }
    foreach ($port in @(7897,7890,10808,10809,2080)) { [pscustomobject]@{Host='127.0.0.1';Port=$port;Type='auto';Source='local scan'} }
}
function New-ProxyTcp([string]$HostName,[int]$Port,[int]$Timeout=1000) {
    $client=New-Object Net.Sockets.TcpClient
    try {
        $operation=$client.BeginConnect($HostName,$Port,$null,$null)
        try { if (-not $operation.AsyncWaitHandle.WaitOne($Timeout)) { throw 'TCP timeout' }; $client.EndConnect($operation) } finally { $operation.AsyncWaitHandle.Close() }
        $client.ReceiveTimeout=$Timeout; $client.SendTimeout=$Timeout; return $client
    } catch { $client.Close(); throw }
}
function Read-ProxyBytes($Stream,[int]$Count) {
    $buffer=New-Object byte[] $Count; $offset=0
    while ($offset -lt $Count) { $read=$Stream.Read($buffer,$offset,$Count-$offset); if ($read -le 0) { throw 'Proxy closed the connection' }; $offset+=$read }
    return ,$buffer
}
function Test-ProxyProtocol([string]$HostName,[int]$Port,[int]$Timeout=800) {
    $tcp=$null
    try { $tcp=New-ProxyTcp $HostName $Port $Timeout; $stream=$tcp.GetStream(); $hello=[byte[]]@(5,2,0,2);$stream.Write($hello,0,$hello.Length); $response=Read-ProxyBytes $stream 2
        if ($response[0] -eq 5 -and $response[1] -in @(0,2,255)) { return [pscustomobject]@{Host=$HostName;Port=$Port;Type='socks5';AuthRequired=($response[1] -eq 2);Status='protocol detected'} }
    } catch { } finally { if ($tcp) { $tcp.Close() } }
    $tcp=$null
    try { $tcp=New-ProxyTcp $HostName $Port $Timeout; $stream=$tcp.GetStream();$request=[Text.Encoding]::ASCII.GetBytes("CONNECT example.invalid:443 HTTP/1.1`r`nHost: example.invalid:443`r`n`r`n");$stream.Write($request,0,$request.Length)
        $response=Read-ProxyBytes $stream 5
        if ([Text.Encoding]::ASCII.GetString($response) -eq 'HTTP/') { return [pscustomobject]@{Host=$HostName;Port=$Port;Type='http';AuthRequired=$null;Status='protocol detected (not an upstream connectivity test)'} }
    } catch { } finally { if ($tcp) { $tcp.Close() } }
    return $null
}
function Find-LocalProxy {
    $seen=@{}
    foreach ($hint in Get-ProxyHints) { $key=$hint.Host+':'+$hint.Port;if ($seen.ContainsKey($key)) { continue };$seen[$key]=$true
        $result=Test-ProxyProtocol $hint.Host $hint.Port
        if ($result) { return $result }
    }
}
function Get-CodexProcessState {
    Get-Process -Name ChatGPT,codex -ErrorAction SilentlyContinue | ForEach-Object {
        $process=$_
        $loaded=$false; $moduleState='not loaded';$image=''
        try { $image=$process.Path; $loaded=@($process.Modules | Where-Object ModuleName -EQ 'codex_proxy.dll').Count -gt 0 } catch { $moduleState='cannot inspect' }
        if ($loaded) { $moduleState='loaded' }
        $ready=$false; $event=$null; $mutex=$null
        try { $event=[Threading.EventWaitHandle]::OpenExisting('Local\CodexProxy_Ready_'+$process.Id);$mutex=[Threading.Mutex]::OpenExisting('Local\CodexProxy_Hooks_'+$process.Id);$ready=$event.WaitOne(0) } catch { } finally { if ($event) {$event.Dispose()};if ($mutex) {$mutex.Dispose()} }
        [pscustomobject]@{Pid=$process.Id;Name=$process.ProcessName;Image=$image;Module=$moduleState;Ready=$ready}
    }
}
function Write-ProxyJson([string]$Path,$Value) {
    $text=$Value | ConvertTo-Json -Depth 50
    [IO.File]::WriteAllText($Path,$text+"`n",(New-Object Text.UTF8Encoding $false))
}
