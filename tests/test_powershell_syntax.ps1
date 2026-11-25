param([string]$Root=(Split-Path $PSScriptRoot -Parent))
$ErrorActionPreference='Stop'
# A WinPS child of pwsh may inherit only PowerShell 7 module directories.
# Restore the native module search entry inside this process, never in registry.
if ($PSVersionTable.PSEdition -eq 'Desktop') {
    $codexNativeModules=[IO.Path]::Combine($env:SystemRoot,'System32\WindowsPowerShell\v1.0\Modules')
    if (([string]$env:PSModulePath -split ';') -notcontains $codexNativeModules) { $env:PSModulePath=$codexNativeModules+';'+$env:PSModulePath }
}
$files=@()
foreach ($folder in @('scripts','tests')) { $path=Join-Path $Root $folder;if (Test-Path -LiteralPath $path) { $files+=@(Get-ChildItem -LiteralPath $path -Filter '*.ps1' -File -Recurse) } }
$files+=Get-Item -LiteralPath (Join-Path $Root 'build.ps1')
$failed=$false
foreach ($file in $files) {
    $tokens=$null;$errors=$null
    $null=[Management.Automation.Language.Parser]::ParseFile($file.FullName,[ref]$tokens,[ref]$errors)
    if ($errors.Count) { $failed=$true;foreach ($parseIssue in $errors) { Write-Host ($file.FullName+':'+$parseIssue.Extent.StartLineNumber+': '+$parseIssue.Message) } }
}
if ($failed) { exit 1 }
Write-Host ('PowerShell AST: '+$files.Count+' scripts passed.')
exit 0
