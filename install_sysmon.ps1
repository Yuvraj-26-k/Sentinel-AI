$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$InstallDir = Join-Path $env:ProgramFiles "Sysmon"
$Zip = Join-Path $env:TEMP "Sysmon.zip"
$Url = "https://download.sysinternals.com/files/Sysmon.zip"

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run PowerShell as Administrator to install Sysmon."
}

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
if (-not (Test-Path (Join-Path $InstallDir "Sysmon64.exe"))) {
    Write-Host "[Sentinel] Downloading official Sysmon from Microsoft Sysinternals..."
    Invoke-WebRequest -Uri $Url -OutFile $Zip
    Expand-Archive -Path $Zip -DestinationPath $InstallDir -Force
}

Copy-Item (Join-Path $Root "sysmonconfig.xml") (Join-Path $InstallDir "sysmonconfig.xml") -Force
$Sysmon = Join-Path $InstallDir "Sysmon64.exe"
$service = Get-Service -Name Sysmon64 -ErrorAction SilentlyContinue
if ($service) {
    & $Sysmon -c (Join-Path $InstallDir "sysmonconfig.xml")
} else {
    & $Sysmon -accepteula -i (Join-Path $InstallDir "sysmonconfig.xml")
}
Write-Host "[Sentinel] Sysmon is installed and configured. Events are in Microsoft-Windows-Sysmon/Operational."
Remove-Item $Zip -Force -ErrorAction SilentlyContinue
