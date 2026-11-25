[CmdletBinding()]
param(
    [ValidateSet('Release','Debug')][string]$Config='Release',
    [switch]$Clean,
    [switch]$RunTests,
    [switch]$Package,
    [string]$VisualStudio='D:\VisualStudioIDE',
    [string]$SdkRoot
)
$ErrorActionPreference='Stop'
# A WinPS child of pwsh may inherit only PowerShell 7 module directories.
# Restore the native module search entry inside this process, never in registry.
if ($PSVersionTable.PSEdition -eq 'Desktop') {
    $codexNativeModules=[IO.Path]::Combine($env:SystemRoot,'System32\WindowsPowerShell\v1.0\Modules')
    if (([string]$env:PSModulePath -split ';') -notcontains $codexNativeModules) { $env:PSModulePath=$codexNativeModules+';'+$env:PSModulePath }
}
$projectRoot=[IO.Path]::GetFullPath($PSScriptRoot)
$buildDirectory=[IO.Path]::GetFullPath((Join-Path $projectRoot ('build-phase2-'+$Config)))
if (-not $buildDirectory.StartsWith($projectRoot+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)) { throw 'Build directory escaped project root' }
if ($Clean -and (Test-Path -LiteralPath $buildDirectory)) { Remove-Item -LiteralPath $buildDirectory -Recurse -Force }
$python=Get-Command python.exe -ErrorAction SilentlyContinue
if (-not $python) { throw 'Python 3 is required for the build. Install Python and restart PowerShell.' }
$arguments=@((Join-Path $projectRoot 'tools\build.py'),'--config',$Config,'--build-dir',$buildDirectory,'--vs',$VisualStudio)
if ($SdkRoot) { $arguments+=@('--sdk-root',$SdkRoot) }
if (-not $RunTests) { $arguments+='--no-tests' }
& $python.Source @arguments
if ($LASTEXITCODE -ne 0) { throw "Build or tests failed ($LASTEXITCODE)" }
if ($RunTests) {
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $projectRoot 'tests\test_powershell_syntax.ps1') -Root $projectRoot
    if ($LASTEXITCODE -ne 0) { throw 'PowerShell syntax validation failed' }
}
if ($Package) {
    & $python.Source (Join-Path $projectRoot 'tools\package.py') --build-dir $buildDirectory --config $Config
    if ($LASTEXITCODE -ne 0) { throw 'Packaging failed' }
}
