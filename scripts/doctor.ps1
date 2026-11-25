[CmdletBinding()]
param(
    [ValidateSet('Check','Install','Repair','Uninstall')][string]$Action='Check',
    [string]$SourceDir,
    [string]$Destination,
    [string]$CliExe,
    [string]$ShortcutRoot,
    [string]$ProxyHost,
    [ValidateRange(0,65535)][int]$ProxyPort=0,
    [ValidateSet('auto','socks5','http')][string]$ProxyType='auto',
    [switch]$SkipCliShim,
    [switch]$Yes,
    [switch]$Purge,
    [switch]$TestOpenAI,
    [switch]$TestChatGPT
)
$ErrorActionPreference='Stop'
# A WinPS child of pwsh may inherit only PowerShell 7 module directories.
# Restore the native module search entry inside this process, never in registry.
if ($PSVersionTable.PSEdition -eq 'Desktop') {
    $codexNativeModules=[IO.Path]::Combine($env:SystemRoot,'System32\WindowsPowerShell\v1.0\Modules')
    if (([string]$env:PSModulePath -split ';') -notcontains $codexNativeModules) { $env:PSModulePath=$codexNativeModules+';'+$env:PSModulePath }
}
. (Join-Path $PSScriptRoot 'ProxyTools.ps1')
if (-not $Destination) { $Destination=Join-Path $env:LOCALAPPDATA 'codex-proxy' }
$installRoot=[IO.Path]::GetFullPath($Destination).TrimEnd('\')
$manifestPath=Join-Path $installRoot 'install-manifest.json'
if ($installRoot -eq [IO.Path]::GetPathRoot($installRoot).TrimEnd('\') -or $installRoot -eq $env:USERPROFILE -or $installRoot -eq $env:LOCALAPPDATA) { throw 'Unsafe installation directory' }
function Hash-File([string]$Path) {
    # Avoid edition-dependent autoload of the Get-FileHash script function when
    # Windows PowerShell is launched through a non-PowerShell child of pwsh.
    $stream=[IO.File]::OpenRead($Path);$algorithm=[Security.Cryptography.SHA256]::Create()
    try { return [BitConverter]::ToString($algorithm.ComputeHash($stream)).Replace('-','') }
    finally { $algorithm.Dispose();$stream.Dispose() }
}
function Find-Source {
    $candidates=@()
    if ($SourceDir) { $candidates+=$SourceDir }
    $candidates+=@((Split-Path $PSScriptRoot -Parent),(Join-Path (Split-Path $PSScriptRoot -Parent) 'output\codex-proxy-win-x64'))
    foreach ($candidate in $candidates) { if ((Test-ProxyFile (Join-Path $candidate 'CodexDesktopLauncher.exe')) -and (Test-ProxyFile (Join-Path $candidate 'codex_proxy.dll'))) { return [IO.Path]::GetFullPath($candidate) } }
    throw 'Portable package not found. Extract codex-proxy-win-x64.zip, or pass -SourceDir.'
}
function Confirm-Change([string]$Message) { if ($Yes) { return $true }; return ((Read-Host ($Message+' [y/N]')) -match '^(y|yes)$') }
function Load-Manifest {
    if (-not (Test-ProxyFile $manifestPath)) { return $null }
    $value=Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($value.Product -ne 'Codex-Proxy' -or [IO.Path]::GetFullPath($value.Root).TrimEnd('\') -ne $installRoot) { throw 'Installation ownership record does not match this directory' }
    return $value
}
function Deploy-File([string]$Source,[string]$Target,$Record,[bool]$External=$false) {
    $targetAbsolute=[IO.Path]::GetFullPath($Target)
    if (-not $External -and -not $targetAbsolute.StartsWith($installRoot+'\',[StringComparison]::OrdinalIgnoreCase)) { throw 'Deployment target escaped installation directory' }
    if ($External -and [IO.Path]::GetFileName($Target) -notin @('tdh.dll','codex_proxy.dll','codex-proxy.config-path')) { throw 'Unexpected external shim filename' }
    $parent=Split-Path $Target -Parent;[IO.Directory]::CreateDirectory($parent) | Out-Null
    $hash=Hash-File $Source
    $existing=@($Record.Files | Where-Object Path -EQ $targetAbsolute | Select-Object -First 1)
    $backup=$null
    if ($existing.Count) { $backup=$existing[0].Backup }
    elseif (Test-ProxyFile $Target) {
        if ((Hash-File $Target) -ne $hash) {
            $backup=Join-Path $installRoot ('backups\'+[Guid]::NewGuid().ToString('N')+'-'+[IO.Path]::GetFileName($Target))
            [IO.Directory]::CreateDirectory((Split-Path $backup -Parent)) | Out-Null
            Copy-Item -LiteralPath $Target -Destination $backup
        }
    }
    if ([IO.Path]::GetFullPath($Source) -ne $targetAbsolute -and (-not (Test-ProxyFile $Target) -or (Hash-File $Target) -ne $hash)) {
        $temporary=$Target+'.codex-proxy-new'
        Copy-Item -LiteralPath $Source -Destination $temporary -Force
        try { Move-Item -LiteralPath $temporary -Destination $Target -Force } catch { Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue;throw 'A deployed file is locked. Close applications using the proxy, then run Repair.' }
    }
    $Record.Files=@($Record.Files | Where-Object Path -NE $targetAbsolute)+@([pscustomobject]@{Path=$targetAbsolute;Hash=$hash;Backup=$backup;External=$External})
    Write-ProxyJson $manifestPath $Record
}
function Test-Upstream($Config,[string]$TargetHost='api.openai.com',[string]$RequestPath='/v1/models') {
    if (-not $Config -or $Config.proxy.port -le 0) { Write-Host 'No enabled proxy configuration for the upstream test.';return }
    $client=$null;$tls=$null
    try {
        $client=New-ProxyTcp $Config.proxy.host $Config.proxy.port 5000;$stream=$client.GetStream()
        $user='';$password=''
        if ($Config.proxy.PSObject.Properties['username']) {$user=[string]$Config.proxy.username}
        if ($Config.proxy.PSObject.Properties['password']) {$password=[string]$Config.proxy.password}
        if ($Config.proxy.type -eq 'socks5') {
            $hello=[byte[]]@(5,2,0,2);$stream.Write($hello,0,$hello.Length);$reply=Read-ProxyBytes $stream 2
            if ($reply[0] -ne 5) { throw 'Invalid SOCKS5 version' }
            if ($reply[1] -eq 2) {
                $u=[Text.Encoding]::UTF8.GetBytes($user);$p=[Text.Encoding]::UTF8.GetBytes($password)
                if (-not $u.Length -or $u.Length -gt 255 -or $p.Length -gt 255) { throw 'SOCKS5 credentials missing/too long' }
                $auth=[byte[]](@(1,$u.Length)+$u+@($p.Length)+$p);$stream.Write($auth,0,$auth.Length);$reply=Read-ProxyBytes $stream 2
                if ($reply[0] -ne 1 -or $reply[1] -ne 0) { throw 'SOCKS5 authentication failed' }
            } elseif ($reply[1] -ne 0) { throw 'SOCKS5 method rejected' }
            $name=[Text.Encoding]::ASCII.GetBytes($TargetHost);$request=[byte[]](@(5,1,0,3,$name.Length)+$name+@(1,187));$stream.Write($request,0,$request.Length)
            $reply=Read-ProxyBytes $stream 4;if ($reply[0] -ne 5 -or $reply[1] -ne 0) { throw 'SOCKS5 tunnel rejected' }
            if ($reply[3] -eq 1) {$null=Read-ProxyBytes $stream 6} elseif ($reply[3] -eq 4) {$null=Read-ProxyBytes $stream 18} elseif ($reply[3] -eq 3) {$length=(Read-ProxyBytes $stream 1)[0];$null=Read-ProxyBytes $stream ($length+2)} else {throw 'Invalid SOCKS5 address'}
        } else {
            $authorization='';if ($user -or $password) { $authorization='Proxy-Authorization: Basic '+[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($user+':'+$password))+"`r`n" }
            $request=[Text.Encoding]::ASCII.GetBytes("CONNECT ${TargetHost}:443 HTTP/1.1`r`nHost: ${TargetHost}:443`r`n"+$authorization+"`r`n");$stream.Write($request,0,$request.Length)
            $header='';while (-not $header.EndsWith("`r`n`r`n")) { if ($header.Length -gt 65536) {throw 'Proxy header too long'};$header+=[char](Read-ProxyBytes $stream 1)[0] }
            if ($header -notmatch '^HTTP/1\.[01] 2\d\d ') { throw 'HTTP CONNECT rejected (check credentials/type)' }
        }
        $tls=New-Object Net.Security.SslStream($stream,$false)
        $tls.ReadTimeout=5000;$tls.WriteTimeout=5000;$tls.AuthenticateAsClient($TargetHost)
        $request=[Text.Encoding]::ASCII.GetBytes("GET $RequestPath HTTP/1.1`r`nHost: $TargetHost`r`nConnection: close`r`n`r`n");$tls.Write($request,0,$request.Length)
        $status='';while (-not $status.EndsWith("`r`n") -and $status.Length -lt 256) { $status+=[char](Read-ProxyBytes $tls 1)[0] }
        Write-Host ($TargetHost+' TLS verified; '+$status.Trim()+'. 401/403 indicates an HTTP response, not account/model availability.')
    } catch { Write-Warning ('Upstream test failed: '+$_.Exception.Message) } finally { if ($tls) {$tls.Dispose()};if ($client) {$client.Close()} }
}
if ($Action -eq 'Check') {
    Write-Host 'Codex-Proxy read-only check / 只读体检'
    Write-Host ('Installation: '+$installRoot+'; present='+(Test-Path -LiteralPath $installRoot))
    $desktop=@(Get-CodexDesktopCandidates | Where-Object { Test-ProxyFile $_ } | Select-Object -Unique)
    Write-Host ('Desktop: '+($desktop -join '; '))
    $native=if ($CliExe) {$CliExe} else {Find-CodexCli};Write-Host ('CLI: '+$native)
    if ($native) { foreach ($name in @('tdh.dll','codex_proxy.dll','codex-proxy.config-path')) { Write-Host ($name+': '+(Test-ProxyFile (Join-Path (Split-Path $native -Parent) $name))) } }
    if ($native -and (Test-ProxyFile (Join-Path (Split-Path $native -Parent) 'config.json'))) { Write-Warning ('CLI-local config.json takes priority: '+(Join-Path (Split-Path $native -Parent) 'config.json')) }
    if ($native) { Write-Host ('CLI effective config: '+(Get-ProxyConfigPath (Split-Path $native -Parent))) }
    Get-CodexProcessState | Format-Table -AutoSize | Out-Host
    $config=$null;$path=Get-ProxyConfigPath $installRoot
    if ($path) {
        try {
            $config=Get-Content -LiteralPath $path -Raw -Encoding UTF8 | ConvertFrom-Json
            if (($config.proxy.port -isnot [int] -and $config.proxy.port -isnot [long]) -or $config.proxy.port -lt 0 -or $config.proxy.port -gt 65535 -or $config.proxy.type -notin @('http','socks5') -or [string]::IsNullOrWhiteSpace($config.proxy.host)) {throw 'Invalid proxy fields'}
            Write-Host ('Config: '+$path+'; proxy='+$config.proxy.type+'://'+$config.proxy.host+':'+$config.proxy.port)
        } catch { $config=$null;Write-Warning 'Configuration is invalid or missing required proxy fields.' }
    }
    if ($config -and $config.proxy.port -gt 0) {
        $tcp=$null
        try { $tcp=New-ProxyTcp $config.proxy.host $config.proxy.port;Write-Host 'Configured proxy TCP: reachable' } catch {Write-Warning 'Configured proxy TCP: unreachable'} finally {if ($tcp) {$tcp.Close()}}
        $protocol=Test-ProxyProtocol $config.proxy.host $config.proxy.port
    } else { $protocol=Find-LocalProxy }
    if ($protocol) { $protocol | Format-List | Out-Host } else { Write-Warning 'No supported proxy protocol detected at the checked endpoints.' }
    if ($TestOpenAI) { Test-Upstream $config }
    if ($TestChatGPT) { Test-Upstream $config 'chatgpt.com' '/backend-api/models' }
    $logs=@((Join-Path $installRoot 'logs'),(Join-Path $env:TEMP 'codex-proxy-logs'))
    foreach ($folder in $logs) { if (Test-Path -LiteralPath $folder) { $latest=Get-ChildItem -LiteralPath $folder -Filter 'proxy-*.log' -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1;if ($latest) {Write-Host ('Recent log: '+$latest.FullName);Get-Content -LiteralPath $latest.FullName -Tail 8 -Encoding UTF8 | Out-Host} } }
    exit 0
}
if (-not (Confirm-Change ($Action+' Codex-Proxy in '+$installRoot+'?'))) { Write-Host 'Cancelled.';exit 0 }
$record=Load-Manifest
if ($Action -eq 'Uninstall') {
    if (-not $record) { throw 'No ownership manifest; refusing to remove untracked files.' }
    foreach ($entry in $record.Files) {
        $path=[IO.Path]::GetFullPath($entry.Path)
        if ($entry.External) { if ([IO.Path]::GetFileName($path) -notin @('tdh.dll','codex_proxy.dll','codex-proxy.config-path')) {throw 'Unexpected external file in manifest'} }
        elseif (-not $path.StartsWith($installRoot+'\',[StringComparison]::OrdinalIgnoreCase)) {throw 'Managed path escaped installation'}
        if (Test-ProxyFile $path) {
            if ((Hash-File $path) -ne $entry.Hash) { Write-Warning ('Changed file preserved: '+$path);continue }
            Remove-Item -LiteralPath $path -Force
        }
        if ($entry.Backup) {
            $backup=[IO.Path]::GetFullPath($entry.Backup)
            if (-not $backup.StartsWith($installRoot+'\backups\',[StringComparison]::OrdinalIgnoreCase)) {throw 'Backup escaped installation'}
            if ((Test-ProxyFile $backup) -and -not (Test-ProxyFile $path)) { Copy-Item -LiteralPath $backup -Destination $path }
        }
    }
    $shell=New-Object -ComObject WScript.Shell
    foreach ($link in $record.Shortcuts) { if (Test-ProxyFile $link) { $shortcut=$shell.CreateShortcut($link);if ([IO.Path]::GetFullPath($shortcut.TargetPath) -eq (Join-Path $installRoot 'CodexDesktopLauncher.exe')) { Remove-Item -LiteralPath $link -Force } } }
    if ($Purge) {
        $verified=[IO.Path]::GetFullPath($installRoot)
        if ($verified -ne [IO.Path]::GetFullPath($record.Root) -or $record.Product -ne 'Codex-Proxy') {throw 'Purge ownership check failed'}
        Remove-Item -LiteralPath $verified -Recurse -Force
    }
    Write-Host 'Uninstalled. Config/logs retained unless -Purge was used.';exit 0
}
$source=Find-Source
[IO.Directory]::CreateDirectory($installRoot) | Out-Null
if (-not $record) { $record=[pscustomobject]@{Product='Codex-Proxy';Version='0.2.0';Root=$installRoot;Files=@();Shortcuts=@()} }
$record.Version='0.2.0';Write-ProxyJson $manifestPath $record
foreach ($name in @('codex-proxy.exe','CodexDesktopLauncher.exe','codex_proxy.dll','version.dll','tdh.dll','config-web.html','config.example.json','README.md','LICENSE.txt','AUTHORS.txt','UPSTREAM.txt')) {
    $file=Join-Path $source $name;if (-not (Test-ProxyFile $file)) {throw ('Incomplete portable package: '+$name)}
    Deploy-File $file (Join-Path $installRoot $name) $record
}
foreach ($directory in @('scripts','docs')) {
    $folder=Join-Path $source $directory
    if (Test-Path -LiteralPath $folder) { Get-ChildItem -LiteralPath $folder -File -Recurse | ForEach-Object { $relative=$_.FullName.Substring($source.TrimEnd('\').Length+1);Deploy-File $_.FullName (Join-Path $installRoot $relative) $record } }
}
$configPath=Join-Path $installRoot 'config.json'
if (-not (Test-ProxyFile $configPath)) {
    $initial=Get-Content -LiteralPath (Join-Path $installRoot 'config.example.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    $detected=$null
    if ($ProxyPort -gt 0) { if (-not $ProxyHost) {$ProxyHost='127.0.0.1'};$detected=Test-ProxyProtocol $ProxyHost $ProxyPort }
    else { $detected=Find-LocalProxy }
    if ($detected) { $initial.proxy.host=$detected.Host;$initial.proxy.port=$detected.Port;$initial.proxy.type=$detected.Type }
    elseif ($ProxyPort -gt 0) { $initial.proxy.host=$ProxyHost;$initial.proxy.port=$ProxyPort;Write-Warning 'Provided port did not answer the protocol probe.' }
    else { $initial.proxy.port=7897;Write-Warning 'No proxy detected. Initial config uses 127.0.0.1:7897; edit it before launching.' }
    if ($ProxyType -ne 'auto') { $initial.proxy.type=$ProxyType }
    Write-ProxyJson $configPath $initial
} else { Write-Host 'Existing config.json preserved.' }
if (-not $SkipCliShim) {
    if (-not $CliExe) { $CliExe=Find-CodexCli }
    if ($CliExe -and (Test-ProxyFile $CliExe)) {
        $cliDirectory=Split-Path ([IO.Path]::GetFullPath($CliExe)) -Parent
        foreach ($name in @('tdh.dll','codex_proxy.dll')) { Deploy-File (Join-Path $installRoot $name) (Join-Path $cliDirectory $name) $record $true }
        # A managed pointer supports custom -Destination without copying secrets.
        $locatorSource=Join-Path $installRoot '.codex-proxy-locator-new'
        try {
            [IO.File]::WriteAllText($locatorSource,$configPath,(New-Object Text.UTF8Encoding($false)))
            Deploy-File $locatorSource (Join-Path $cliDirectory 'codex-proxy.config-path') $record $true
        } finally { if (Test-ProxyFile $locatorSource) { Remove-Item -LiteralPath $locatorSource -Force } }
        Write-Host ('CLI shims deployed: '+$cliDirectory)
    } else { Write-Warning 'Native CLI not found; desktop installation is ready. Use codex-proxy.exe --exec or rerun Repair after installing Codex CLI.' }
}
$shell=New-Object -ComObject WScript.Shell
if ($ShortcutRoot) { $desktop=Join-Path $ShortcutRoot 'Desktop';$start=Join-Path $ShortcutRoot 'StartMenu' }
else { $desktop=[Environment]::GetFolderPath('Desktop');$start=Join-Path ([Environment]::GetFolderPath('Programs')) 'Codex-Proxy' }
foreach ($folder in @($desktop,$start)) {
    [IO.Directory]::CreateDirectory($folder) | Out-Null
    $link=Join-Path $folder 'Codex (代理).lnk';$shortcut=$shell.CreateShortcut($link)
    $shortcut.TargetPath=Join-Path $installRoot 'CodexDesktopLauncher.exe';$shortcut.Arguments='--config "'+$configPath+'"';$shortcut.WorkingDirectory=$installRoot
    $shortcut.Description='Codex with process proxy / Codex 进程代理';$shortcut.Save()
    if ($record.Shortcuts -notcontains $link) { $record.Shortcuts+=@($link) }
}
Write-ProxyJson $manifestPath $record
Write-Host ('Ready: '+$installRoot+'. Launch Codex (代理), or use codex-proxy.exe. Running applications were not stopped or injected.')
