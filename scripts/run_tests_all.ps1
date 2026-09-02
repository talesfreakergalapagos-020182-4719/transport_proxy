param (
    [switch]$SkipWindows = $false,
    [switch]$SkipWSL = $false,
    [switch]$SkipDocker = $false
)

$ErrorActionPreference = "Stop"
$workingDir = Get-Location

Write-Host "========================================" -ForegroundColor Cyan
Write-Host " Transport Proxy - Cross-Platform Tests " -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$testsPassed = $true

# 1. Run natively on Windows
if (-not $SkipWindows) {
    Write-Host "[1/3] Running tests natively on Windows..." -ForegroundColor Yellow
    try {
        go test -v -cover ./...
        Write-Host " -> Windows tests PASSED`n" -ForegroundColor Green
    } catch {
        Write-Host " -> Windows tests FAILED`n" -ForegroundColor Red
        $testsPassed = $false
    }
} else {
    Write-Host "[1/3] Skipping Windows tests...`n" -ForegroundColor DarkGray
}

# 2. Run on WSL (assuming default distribution is Ubuntu)
if (-not $SkipWSL) {
    Write-Host "[2/3] Running tests on WSL..." -ForegroundColor Yellow
    
    # Check if WSL is available
    $wslCheck = wsl -l -q 2>$null
    if ($LASTEXITCODE -eq 0) {
        $drive = $workingDir.Drive.Name.ToLower()
        $path = $workingDir.Path.Substring(3).Replace('\', '/')
        $wslPath = "/mnt/$drive/$path"
        try {
            wsl -- bash -c "cd '$wslPath' && go test -v -cover ./..."
            if ($LASTEXITCODE -ne 0) { throw "WSL test failed" }
            Write-Host " -> WSL tests PASSED`n" -ForegroundColor Green
        } catch {
            Write-Host " -> WSL tests FAILED`n" -ForegroundColor Red
            $testsPassed = $false
        }
    } else {
        Write-Host " -> WSL is not available or not installed. Skipping WSL tests.`n" -ForegroundColor DarkGray
    }
} else {
    Write-Host "[2/3] Skipping WSL tests...`n" -ForegroundColor DarkGray
}

# 3. Run on Docker (Ubuntu)
if (-not $SkipDocker) {
    Write-Host "[3/3] Running tests on Docker (Ubuntu)..." -ForegroundColor Yellow
    
    $dockerOk = $false
    try {
        wsl -- bash -c "docker info >/dev/null 2>&1"
        if ($LASTEXITCODE -eq 0) { $dockerOk = $true }
    } catch {}

    if ($dockerOk) {
        try {
            Write-Host " -> Building Docker image tproxy-test..." -ForegroundColor Gray
            $drive = $workingDir.Drive.Name.ToLower()
            $path = $workingDir.Path.Substring(3).Replace('\', '/')
            $wslPath = "/mnt/$drive/$path"
            
            wsl -- bash -c "cd '$wslPath' && docker build -f Dockerfile.test -t tproxy-test ."
            if ($LASTEXITCODE -ne 0) { throw "Docker build failed" }
            
            Write-Host " -> Running tests in Docker..." -ForegroundColor Gray
            wsl -- bash -c "docker run --rm tproxy-test"
            if ($LASTEXITCODE -ne 0) { throw "Docker tests failed" }
            
            Write-Host " -> Docker tests PASSED`n" -ForegroundColor Green
        } catch {
            Write-Host " -> Docker tests FAILED`n" -ForegroundColor Red
            $testsPassed = $false
        }
    } else {
        Write-Host " -> Docker (via WSL) is not available or not running. Skipping Docker tests." -ForegroundColor DarkGray
        Write-Host "    [!] To run tests in Ubuntu, please install Docker in WSL with the following command:" -ForegroundColor Yellow
        Write-Host "    wsl -- bash -c `"curl -fsSL https://get.docker.com | sudo sh`"`n" -ForegroundColor Cyan
    }
} else {
    Write-Host "[3/3] Skipping Docker tests...`n" -ForegroundColor DarkGray
}

Write-Host "========================================" -ForegroundColor Cyan
if ($testsPassed) {
    Write-Host " ALL TEST SUITES PASSED!" -ForegroundColor Green
} else {
    Write-Host " SOME TEST SUITES FAILED! Check the logs above." -ForegroundColor Red
    exit 1
}
