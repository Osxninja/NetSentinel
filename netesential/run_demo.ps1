<#
.SYNOPSIS
    NetSentinel - PowerShell Launcher
    Author: Hardik
    Organization: Hidden Eye Security
.DESCRIPTION
    Launches NetSentinel All-in-One Engine or individual components:
      1. All-in-One Engine (Live Sniffer + ML + (EC)2 Multi-Agent + Dashboard + CLI)
      2. All-in-One with Immediate Simulation Test
      3. Standalone Streamlit SOC Web Dashboard
      4. Full Automated Verification Test Suite (11 unit tests)
.EXAMPLE
    .\run_demo.ps1
    .\run_demo.ps1 -AllInOne
    .\run_demo.ps1 -Dashboard
    .\run_demo.ps1 -RunTests
#>

param(
    [switch]$AllInOne,
    [switch]$Dashboard,
    [switch]$RunTests,
    [switch]$SimulateTest
)

$ErrorActionPreference = 'Stop'

Write-Host '=================================================================' -ForegroundColor Cyan
Write-Host ' NetSentinel - Autonomous Cybersecurity Anomaly Detection & SOC ' -ForegroundColor Cyan
Write-Host ' Developed by Hardik // Hidden Eye Security                      ' -ForegroundColor Magenta
Write-Host ' Live Packet Ingestion, Online ML & (EC)2 Multi-Agent Graph      ' -ForegroundColor DarkCyan
Write-Host '=================================================================' -ForegroundColor Cyan
Write-Host ''

# 1. Verify Python Environment
try {
    $pythonVersion = & python --version 2>&1
    Write-Host "[+] Python Environment: $pythonVersion" -ForegroundColor Green
} catch {
    Write-Host '[ERROR] Python is not installed or not in PATH.' -ForegroundColor Red
    exit 1
}

# 2. Check Dependencies
Write-Host '[*] Verifying Python dependencies...' -ForegroundColor Yellow
$checkDeps = & python -c "import scapy, sqlalchemy, aiosqlite, numpy, sklearn, networkx, rich, streamlit, psutil; print('OK')" 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host '[*] Installing missing dependencies from requirements.txt...' -ForegroundColor Yellow
    & python -m pip install -q -r requirements.txt
}
Write-Host '[+] Dependencies verified.' -ForegroundColor Green
Write-Host ''

# 3. Direct Switches
if ($RunTests) {
    Write-Host '[*] Executing test suite across all phases...' -ForegroundColor Cyan
    & python -m pytest tests/ -v
    exit 0
}

if ($Dashboard) {
    Write-Host '[*] Launching Streamlit SOC Web Dashboard...' -ForegroundColor Cyan
    & streamlit run dashboard.py
    exit 0
}

if ($AllInOne) {
    Write-Host '[*] Launching All-in-One NetSentinel Engine...' -ForegroundColor Cyan
    if ($SimulateTest) {
        & python main.py --simulate-test
    } else {
        & python main.py
    }
    exit 0
}

# 4. Interactive Menu
Write-Host 'Select an operation mode:' -ForegroundColor Yellow
Write-Host '  [1] All-in-One NetSentinel (RECOMMENDED: Live Sniffer + ML + Multi-Agent + Dashboard + CLI Shell)' -ForegroundColor White
Write-Host '  [2] All-in-One with Initial Simulation Test (Attack injection on boot)' -ForegroundColor White
Write-Host '  [3] Standalone Streamlit SOC Web Dashboard (http://localhost:8501)' -ForegroundColor White
Write-Host '  [4] Run Full Automated Test Suite (11 unit tests across all phases)' -ForegroundColor White
Write-Host '  [5] Exit' -ForegroundColor White
Write-Host ''

$choice = Read-Host 'Enter your choice (1-5) [default: 1]'
if ([string]::IsNullOrWhiteSpace($choice)) { $choice = '1' }

switch ($choice) {
    '1' {
        Write-Host '[*] Starting All-in-One NetSentinel Engine...' -ForegroundColor Cyan
        & python main.py
    }
    '2' {
        Write-Host '[*] Starting All-in-One NetSentinel with Startup Simulation...' -ForegroundColor Cyan
        & python main.py --simulate-test
    }
    '3' {
        Write-Host '[*] Starting Streamlit SOC Web Dashboard...' -ForegroundColor Cyan
        & streamlit run dashboard.py
    }
    '4' {
        & python -m pytest tests/ -v
    }
    default {
        Write-Host '[*] Exiting.' -ForegroundColor Yellow
    }
}
