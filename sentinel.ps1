$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Root

if (-not (Test-Path ".venv\Scripts\python.exe")) {
    Write-Host "[Sentinel] Creating Python virtual environment..."
    py -3 -m venv .venv
}

Write-Host "[Sentinel] Installing/checking dependencies..."
& ".venv\Scripts\python.exe" -m pip install -q -r requirements.txt

$AlertFile = if ($env:SENTINEL_ALERT_FILE) { $env:SENTINEL_ALERT_FILE } else { Join-Path $HOME ".sentinel_alerts.jsonl" }
$ModelFile = if ($env:SENTINEL_MODEL_FILE) { $env:SENTINEL_MODEL_FILE } else { Join-Path $HOME ".nmap_ai_baseline.json" }
$LogFile = if ($env:SENTINEL_LOG_FILE) { $env:SENTINEL_LOG_FILE } else { Join-Path $Root "firewall.log" }

Write-Host "[Sentinel] Windows does not use UFW. Monitoring: $LogFile"
$Detector = Start-Process -FilePath ".venv\Scripts\python.exe" `
    -ArgumentList "smart_detector.py", "--log-file", $LogFile, "--model-file", $ModelFile, "--alert-file", $AlertFile `
    -PassThru -NoNewWindow

try {
    & ".venv\Scripts\python.exe" sentinel.py --alert-file $AlertFile
}
finally {
    if ($Detector -and -not $Detector.HasExited) {
        Stop-Process -Id $Detector.Id -Force
    }
}
