$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Root

if (-not (Test-Path ".venv\Scripts\python.exe")) {
    Write-Host "[Sentinel] Creating Python virtual environment..."
    py -3 -m venv .venv
}

Write-Host "[Sentinel] Installing/checking dependencies..."
& ".venv\Scripts\python.exe" -m pip install -q -r requirements.txt

Write-Host "[Sentinel] Checking Sysmon..."
if (-not (Get-Service -Name Sysmon64 -ErrorAction SilentlyContinue)) {
    try {
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Root "install_sysmon.ps1")
    } catch {
        Write-Warning "Sysmon setup skipped: $($_.Exception.Message)"
    }
}

$AlertFile = if ($env:SENTINEL_ALERT_FILE) { $env:SENTINEL_ALERT_FILE } else { Join-Path $HOME ".sentinel_alerts.jsonl" }
$ModelFile = if ($env:SENTINEL_MODEL_FILE) { $env:SENTINEL_MODEL_FILE } else { Join-Path $HOME ".nmap_ai_baseline.json" }
$DatabaseFile = if ($env:SENTINEL_DATABASE_FILE) { $env:SENTINEL_DATABASE_FILE } else { Join-Path $HOME ".sentinel.db" }
$ApiPort = if ($env:SENTINEL_API_PORT) { $env:SENTINEL_API_PORT } else { "8000" }
$Source = if ($env:SENTINEL_SOURCE) { $env:SENTINEL_SOURCE } elseif ($env:SENTINEL_LOG_FILE) { "windows-firewall" } else { "windows-native" }

$env:SENTINEL_DATABASE_FILE = $DatabaseFile
$DetectorArguments = @("smart_detector.py", "--source", $Source, "--model-file", $ModelFile, "--alert-file", $AlertFile, "--database-file", $DatabaseFile)
if ($env:SENTINEL_LOG_FILE) {
    $DetectorArguments += @("--log-file", $env:SENTINEL_LOG_FILE)
}
Write-Host "[Sentinel] Starting ingestion source: $Source"
$Detector = Start-Process -FilePath ".venv\Scripts\python.exe" `
    -ArgumentList ($DetectorArguments | ForEach-Object { '"' + $_.Replace('"', '\"') + '"' }) `
    -PassThru -NoNewWindow
$Api = Start-Process -FilePath ".venv\Scripts\python.exe" `
    -ArgumentList "-m uvicorn api:app --host 127.0.0.1 --port $ApiPort" `
    -PassThru -NoNewWindow

try {
    Write-Host "[Sentinel] Read-only alert API available at http://127.0.0.1:$ApiPort/api/health"
    & ".venv\Scripts\python.exe" sentinel.py --alert-file $AlertFile
}
finally {
    if ($Detector -and -not $Detector.HasExited) {
        Stop-Process -Id $Detector.Id -Force
    }
    if ($Api -and -not $Api.HasExited) {
        Stop-Process -Id $Api.Id -Force
    }
}
