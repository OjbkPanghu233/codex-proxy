[CmdletBinding()]
param([switch]$Yes,[switch]$SkipCliShim,[string]$Destination,[string]$SourceDir)
$ErrorActionPreference='Stop'
# A WinPS child of pwsh may inherit only PowerShell 7 module directories.
# Restore the native module search entry inside this process, never in registry.
if ($PSVersionTable.PSEdition -eq 'Desktop') {
    $codexNativeModules=[IO.Path]::Combine($env:SystemRoot,'System32\WindowsPowerShell\v1.0\Modules')
    if (([string]$env:PSModulePath -split ';') -notcontains $codexNativeModules) { $env:PSModulePath=$codexNativeModules+';'+$env:PSModulePath }
}
$arguments=@{Action='Install';Yes=$Yes;SkipCliShim=$SkipCliShim}
if ($Destination) {$arguments.Destination=$Destination}
if ($SourceDir) {$arguments.SourceDir=$SourceDir}
& (Join-Path $PSScriptRoot 'doctor.ps1') @arguments
