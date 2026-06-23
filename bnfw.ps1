param(
  [switch]$Start,
  [switch]$Stop,
  [switch]$Connect,
  [switch]$Disconnect,
  [switch]$Status,
  [switch]$Restart,
  [switch]$Diagnose,
  [switch]$ClaimPort53
)

# --- Auto-Request Admin ---
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "Administrator privileges are required to manage DNS settings and port 53." -ForegroundColor Yellow
    Write-Host "Requesting elevation..." -ForegroundColor Cyan
    
    $args = @()
    if ($Start) { $args += "-Start" }
    if ($Stop) { $args += "-Stop" }
    if ($Connect) { $args += "-Connect" }
    if ($Disconnect) { $args += "-Disconnect" }
    if ($Status) { $args += "-Status" }
    if ($Restart) { $args += "-Restart" }
    if ($Diagnose) { $args += "-Diagnose" }
    if ($ClaimPort53) { $args += "-ClaimPort53" }
    
    Start-Process powershell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" $($args -join ' ')" -Verb RunAs
    exit
}
# --------------------------

$ProjectDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$PidFile = "$env:TEMP\bnfw.pid"
$DnsBackup = "$env:TEMP\bnfw_dns_backup.json"

function Get-ActiveInterface {
  $interfaces = @("Wi-Fi", "Ethernet", "WiFi", "Local Area Connection", "Ethernet0")
  foreach ($iface in $interfaces) {
    $adapter = Get-NetAdapter -Name $iface -ErrorAction SilentlyContinue
    if ($adapter -and $adapter.Status -eq "Up") { return $iface }
  }
  $first = Get-NetAdapter | Where-Object Status -Eq "Up" | Select-Object -First 1
  return $first.Name
}

function Save-DnsSettings($iface) {
  $serverAddresses = (Get-DnsClientServerAddress -InterfaceAlias $iface -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses
  @{ interface = $iface; servers = $serverAddresses } | ConvertTo-Json | Set-Content $DnsBackup
  Write-Host "  Saved DNS backup: $($serverAddresses -join ', ')"
}

function Restore-DnsSettings {
  if (!(Test-Path $DnsBackup)) {
    Write-Host "  No DNS backup found" -ForegroundColor Yellow
    return
  }
  $backup = Get-Content $DnsBackup | ConvertFrom-Json
  if ($backup.servers -and $backup.servers.Count -gt 0) {
    netsh interface ip set dns "$($backup.interface)" static $($backup.servers[0])
    Write-Host "  Restored DNS: $($backup.servers[0]) on $($backup.interface)"
  } else {
    netsh interface ip set dns "$($backup.interface)" dhcp
    Write-Host "  Restored DHCP DNS on $($backup.interface)"
  }
  Remove-Item $DnsBackup -Force -ErrorAction SilentlyContinue
}

function Start-BNFW {
  if (Test-Path $PidFile) {
    $processId = Get-Content $PidFile
    $proc = Get-Process -Id $processId -ErrorAction SilentlyContinue
    if ($proc) {
      Write-Host "Already running (PID $processId)" -ForegroundColor Yellow
      return
    }
    Remove-Item $PidFile -Force
  }

  Write-Host "Starting Neuron Network Shield..." -ForegroundColor Cyan
  $logFile = "$ProjectDir\bnfw.log"

  $startInfo = New-Object System.Diagnostics.ProcessStartInfo
  $startInfo.FileName = "node"
  $startInfo.Arguments = "src/index.js"
  $startInfo.WorkingDirectory = $ProjectDir
  $startInfo.UseShellExecute = $false
  $startInfo.CreateNoWindow = $true
  $startInfo.RedirectStandardOutput = $true
  $startInfo.RedirectStandardError = $true

  try {
    $ps = [System.Diagnostics.Process]::Start($startInfo)
    Start-Sleep 3
    $ps.Id | Set-Content $PidFile
    Write-Host "  Started (PID $($ps.Id))" -ForegroundColor Green

    if (!$ps.HasExited) {
      Write-Host ""
      Write-Host "Open dashboard at http://127.0.0.1:3000" -ForegroundColor Cyan
    } else {
      Write-Host "  Failed to start. Please ensure Node.js is installed." -ForegroundColor Red
    }
  } catch {
    Write-Host "  Failed to start. Please ensure Node.js is installed and in your PATH." -ForegroundColor Red
  }
}

function Stop-BNFW {
  if (!(Test-Path $PidFile)) {
    Write-Host "Not running (no PID file)" -ForegroundColor Yellow
    return
  }
  $processId = Get-Content $PidFile
  $proc = Get-Process -Id $processId -ErrorAction SilentlyContinue
  if ($proc) {
    Stop-Process -Id $processId -Force
    Write-Host "Stopped (PID $processId)" -ForegroundColor Green
  } else {
    Write-Host "Process $processId not found" -ForegroundColor Yellow
  }
  Remove-Item $PidFile -Force -ErrorAction SilentlyContinue
}

function Connect-BNFW {
  $iface = Get-ActiveInterface
  Write-Host "Interface: $iface" -ForegroundColor Cyan
  Save-DnsSettings $iface
  netsh interface ip set dns "$iface" static 127.0.0.1
  Write-Host "DNS set to 127.0.0.1 on $iface" -ForegroundColor Green
  Write-Host "Your whole PC now uses Neuron Network Shield" -ForegroundColor Cyan
}

function Disconnect-BNFW {
  Restore-DnsSettings
  Write-Host "DNS restored. Your PC no longer uses Neuron." -ForegroundColor Cyan
}

function Show-Status {
  $running = $false
  if (Test-Path $PidFile) {
    $processId = Get-Content $PidFile
    $proc = Get-Process -Id $processId -ErrorAction SilentlyContinue
    if ($proc) { $running = $true }
  }

  if ($running) {
    Write-Host "Service: Running (PID $(Get-Content $PidFile))" -ForegroundColor Green
  } else {
    Write-Host "Service: Stopped" -ForegroundColor Red
  }

  $iface = Get-ActiveInterface
  $dns = (Get-DnsClientServerAddress -InterfaceAlias $iface -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses
  Write-Host "DNS ($iface): $($dns -join ', ')" -ForegroundColor Cyan

  if ($dns -eq "127.0.0.1") {
    Write-Host "Traffic: Filtered" -ForegroundColor Green
  } else {
    Write-Host "Traffic: Direct" -ForegroundColor Yellow
  }
}

function Diagnose-BNFW {
  Write-Host "Neuron Diagnostics" -ForegroundColor Cyan
  Write-Host "═══════════════════════════════════"
  
  $proc = Get-Process -Name "node" -ErrorAction SilentlyContinue | Where-Object { $_.CommandLine -match "index" }
  if ($proc) {
    Write-Host "[OK] Node process running (PID $($proc.Id))" -ForegroundColor Green
  } else {
    Write-Host "[!!] Node process not running" -ForegroundColor Red
  }

  $port53 = netstat -ano | Select-String ":53 " | Select-String "UDP"
  $port53list = @()
  $port53 | ForEach-Object { $port53list += $_ }
  if ($port53list.Count -gt 0) {
    Write-Host "[OK] Port 53 listeners:" -ForegroundColor Green
    $port53list | ForEach-Object { Write-Host "     $_" }
  } else {
    Write-Host "[!!] No one listening on port 53" -ForegroundColor Red
  }
}

function Claim-Port53 {
  Write-Host "Attempting to free UDP Port 53..." -ForegroundColor Cyan
  
  # Try stopping Internet Connection Sharing (SharedAccess)
  $ics = Get-Service -Name "SharedAccess" -ErrorAction SilentlyContinue
  if ($ics -and $ics.Status -eq "Running") {
    Write-Host "  Stopping Internet Connection Sharing (SharedAccess)..." -ForegroundColor Yellow
    Stop-Service -Name "SharedAccess" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "SharedAccess" -StartupType Manual -ErrorAction SilentlyContinue
    Write-Host "  SharedAccess stopped." -ForegroundColor Green
  }

  # Kill any process holding UDP 53
  $port53 = netstat -ano | Select-String ":53 " | Select-String "UDP"
  $killed = $false
  foreach ($line in $port53) {
    if ($line -match "\s+(\d+)$") {
      $pidToKill = $matches[1]
      if ($pidToKill -ne "0" -and $pidToKill -ne $PID) {
        $proc = Get-Process -Id $pidToKill -ErrorAction SilentlyContinue
        if ($proc) {
          Write-Host "  Killing conflicting process: $($proc.ProcessName) (PID: $pidToKill)" -ForegroundColor Yellow
          Stop-Process -Id $pidToKill -Force -ErrorAction SilentlyContinue
          $killed = $true
        }
      }
    }
  }

  if (-not $killed) {
    Write-Host "  No conflicting processes found or they were already stopped." -ForegroundColor Green
  } else {
    Write-Host "  Port 53 should now be free." -ForegroundColor Green
  }
}

function Interactive-Menu {
  $exit = $false
  while (-not $exit) {
    Clear-Host
    Write-Host "=========================================" -ForegroundColor Cyan
    Write-Host "      Neuron: Network Shield Manager     " -ForegroundColor Cyan
    Write-Host "=========================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  1. Start Firewall Service"
    Write-Host "  2. Stop Firewall Service"
    Write-Host "  3. Restart Service"
    Write-Host "  4. Connect (Route PC Traffic to Neuron)"
    Write-Host "  5. Disconnect (Restore Normal DNS)"
    Write-Host "  6. Check Status"
    Write-Host "  7. Run Diagnostics"
    Write-Host "  8. Free Port 53 (Stop Conflicting Services)"
    Write-Host "  9. Exit"
    Write-Host ""
    Write-Host "=========================================" -ForegroundColor Cyan
    
    $choice = Read-Host "Select an option (1-9)"
    
    Write-Host ""
    switch ($choice) {
      '1' { Start-BNFW; Pause }
      '2' { Stop-BNFW; Pause }
      '3' { Stop-BNFW; Start-Sleep 1; Start-BNFW; Pause }
      '4' { Connect-BNFW; Pause }
      '5' { Disconnect-BNFW; Pause }
      '6' { Show-Status; Pause }
      '7' { Diagnose-BNFW; Pause }
      '8' { Claim-Port53; Pause }
      '9' { $exit = $true }
      default { Write-Host "Invalid option." -ForegroundColor Red; Start-Sleep 1 }
    }
  }
}

# ── Main ─────────────────────────────────────
if ($ClaimPort53) {
  Claim-Port53
} elseif ($Restart) {
  Stop-BNFW; Start-Sleep 1; Start-BNFW
} elseif ($Stop) {
  Stop-BNFW
} elseif ($Start) {
  Start-BNFW
} elseif ($Connect) {
  Connect-BNFW
} elseif ($Disconnect) {
  Disconnect-BNFW
} elseif ($Diagnose) {
  Diagnose-BNFW
} elseif ($Status) {
  Show-Status
} else {
  # Interactive mode
  Interactive-Menu
}
