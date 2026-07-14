# Threat Intel Hub - PowerShell Setup (auto-downloads Node.js if missing)
# Run with: Right-click → Run with PowerShell

$Host.UI.RawUI.WindowTitle = "Threat Intel Hub Setup"
$ErrorActionPreference = "SilentlyContinue"

function Write-Header {
    Clear-Host
    Write-Host ""
    Write-Host "  ===================================================" -ForegroundColor Cyan
    Write-Host "    THREAT INTEL HUB v3.0  -  SETUP WIZARD" -ForegroundColor Cyan
    Write-Host "  ===================================================" -ForegroundColor Cyan
    Write-Host ""
}

function Write-Step { param($n, $msg) Write-Host "  [$n/3] $msg" -ForegroundColor Yellow }
function Write-OK   { param($msg)     Write-Host "  [OK] $msg"   -ForegroundColor Green  }
function Write-Fail { param($msg)     Write-Host "  [!]  $msg"   -ForegroundColor Red    }
function Write-Info { param($msg)     Write-Host "       $msg"   -ForegroundColor Gray   }

Write-Header

# ── STEP 1: Check / Install Node.js ─────────────────────────────────────────
Write-Step "1" "Checking Node.js..."

$nodeCmd = Get-Command node -ErrorAction SilentlyContinue

if (-not $nodeCmd) {
    Write-Fail "Node.js is NOT installed."
    Write-Host ""
    Write-Host "  Downloading Node.js LTS installer..." -ForegroundColor Yellow

    $nodeVersion = "20.14.0"
    $nodeUrl     = "https://nodejs.org/dist/v$nodeVersion/node-v$nodeVersion-x64.msi"
    $installer   = "$env:TEMP\node-installer.msi"

    try {
        Write-Info "Downloading from nodejs.org (this may take a minute)..."
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $nodeUrl -OutFile $installer -UseBasicParsing

        Write-Info "Running Node.js installer..."
        $proc = Start-Process msiexec.exe -ArgumentList "/i `"$installer`" /qb ADDLOCAL=ALL" -Wait -PassThru
        if ($proc.ExitCode -eq 0) {
            Write-OK "Node.js v$nodeVersion installed successfully!"
            # Refresh PATH
            $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
        } else {
            throw "Installer exited with code $($proc.ExitCode)"
        }
    } catch {
        Write-Fail "Auto-download failed: $_"
        Write-Host ""
        Write-Info "Opening nodejs.org manually..."
        Start-Process "https://nodejs.org/en/download/"
        Write-Host ""
        Write-Host "  Install Node.js, then run this script again." -ForegroundColor Yellow
        Read-Host "  Press Enter to exit"
        exit 1
    }
} else {
    $nodeVersion = (node --version 2>$null)
    Write-OK "Node.js $nodeVersion is installed."
}

# ── STEP 2: Install npm dependencies ────────────────────────────────────────
Write-Host ""
Write-Step "2" "Checking npm dependencies..."

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $scriptDir

if (-not (Test-Path "node_modules")) {
    Write-Info "Installing dependencies (first time only, 2-3 minutes)..."
    Write-Host ""

    $npmResult = Start-Process npm -ArgumentList "install" -Wait -PassThru -NoNewWindow
    if ($npmResult.ExitCode -ne 0) {
        Write-Fail "npm install failed. Try running: npm install"
        Read-Host "Press Enter to exit"
        exit 1
    }
    Write-Host ""
    Write-OK "All dependencies installed!"
} else {
    Write-OK "Dependencies already installed."
}

# ── STEP 3: Launch app ──────────────────────────────────────────────────────
Write-Host ""
Write-Step "3" "Launching Threat Intel Hub..."
Write-Host ""

npm start
