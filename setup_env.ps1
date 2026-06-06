param(
    [switch]$SkipInstall
)

$ErrorActionPreference = "Stop"

function Write-Section($Title) {
    Write-Host ""
    Write-Host "== $Title ==" -ForegroundColor Cyan
}

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Root

Write-Section "Python"
$python = Get-Command python -ErrorAction SilentlyContinue
if (-not $python) {
    throw "python was not found. Install Python 3.10+ or add python to PATH."
}
python --version

Write-Section "Npcap / WinPcap"
$npcapService = Get-Service -Name npcap -ErrorAction SilentlyContinue
$npfService = Get-Service -Name npf -ErrorAction SilentlyContinue
if ($npcapService) {
    Write-Host "Npcap service: $($npcapService.Status)"
} elseif ($npfService) {
    Write-Host "WinPcap/NPF service: $($npfService.Status)"
} else {
    Write-Warning "Npcap/WinPcap service was not detected. Install Npcap before live capture."
}

$npcapDir = @("C:\Program Files\Npcap", "C:\Program Files (x86)\Npcap") | Where-Object { Test-Path $_ } | Select-Object -First 1
if ($npcapDir) {
    Write-Host "Npcap path: $npcapDir"
}

Write-Section "Wireshark"
$wireshark = Get-Command wireshark -ErrorAction SilentlyContinue
if ($wireshark) {
    Write-Host "Wireshark: $($wireshark.Source)"
} else {
    Write-Warning "Wireshark was not found in PATH. It can still be launched from the Start menu if installed."
}

Write-Section "Python virtual environment"
$venv = Join-Path $Root ".venv"
if (-not (Test-Path $venv)) {
    python -m venv $venv
}

$venvPython = Join-Path $venv "Scripts\python.exe"

if (-not $SkipInstall) {
    & $venvPython -m pip install --disable-pip-version-check --upgrade pip
    if ($LASTEXITCODE -ne 0) {
        throw "pip upgrade failed."
    }
    & $venvPython -m pip install --disable-pip-version-check -r (Join-Path $Root "requirements.txt")
    if ($LASTEXITCODE -ne 0) {
        throw "Dependency installation failed."
    }
}

Write-Section "Verify"
& $venvPython -c "import sys; print(sys.executable)"
if ($LASTEXITCODE -ne 0) {
    throw "Python verification failed."
}
& $venvPython -c "import scapy; print('scapy', scapy.__version__)"
if ($LASTEXITCODE -ne 0) {
    throw "Scapy verification failed."
}

$exp3Dir = Get-ChildItem -Path $Root -Directory | Where-Object { $_.Name -like '*_IP*' } | Select-Object -First 1
if (-not $exp3Dir) {
    throw "Experiment 3 directory was not found."
}
$analyzer = Join-Path $exp3Dir.FullName "ip_traffic_analyzer.py"
& $venvPython $analyzer --self-test
if ($LASTEXITCODE -ne 0) {
    throw "Experiment 3 self-test failed."
}

Write-Host ""
Write-Host "Environment check completed. Run live capture from an Administrator PowerShell." -ForegroundColor Green
