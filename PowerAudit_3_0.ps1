########################################################################
#                                                                      #
#        PowerAudit_3.1.ps1 / Windows Configuration Audit         #
#                                                                      #
#        License : Apache 2                                            #
#        Authors : BlueTeam - v3.1                                     #
#                                                                      #
########################################################################

#Requires -Version 5.0

# ---------------------------------------------------------------------------
#  ADMINISTRATOR RIGHTS CHECK
# ---------------------------------------------------------------------------

$currentPrincipal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host ""
    Write-Host "  [ERROR] This script must be run as Administrator." -ForegroundColor Red
    Write-Host "  Please restart PowerShell with admin rights and run the script again." -ForegroundColor Yellow
    Write-Host ""
    Read-Host "  Press Enter to quit"
    exit 1
}

# ---------------------------------------------------------------------------
#  GLOBAL VARIABLES
# ---------------------------------------------------------------------------

# Force UTF-8 encoding for system command output capture (netsh, ipconfig, etc.)
# Without this, special characters may be corrupted (CP850/CP1252 -> UTF-8)
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding             = [System.Text.Encoding]::UTF8
# Also force Windows console code page to UTF-8
$null = chcp 65001 2>$null

$computername = $env:COMPUTERNAME
$date         = Get-Date -Format "MM-dd-yyyy"
$hour         = (Get-Date).ToString("HH:mm:ss")
$reportDateStr = (Get-Date).ToString("yyyy-MM-dd_HH-mm")
$Global:LastReportPath = ""

# ---------------------------------------------------------------------------
#  UTILITY FUNCTIONS
# ---------------------------------------------------------------------------

function Write-SectionHeader {
    param([string]$Title)
    $line = "-" * 70
    Write-Host ""
    Write-Host "  $line" -ForegroundColor DarkCyan
    Write-Host "  >> $Title" -ForegroundColor White
    Write-Host "  $line" -ForegroundColor DarkCyan
    Write-Host ""
}

function Write-ErrorMsg {
    param([string]$Msg)
    Write-Host "  [ERREUR] $Msg" -ForegroundColor Red
}

function Write-ProgressBar {
    param(
        [int]$Current,
        [int]$Total,
        [string]$Label = "",
        [int]$Width = 50
    )
    $pct    = [math]::Round($Current / $Total * 100)
    $filled = [math]::Round($Width * $Current / $Total)
    $empty  = $Width - $filled
    $bar    = ("#" * $filled) + ("." * $empty)
    Write-Host ("`r  [{0}] {1,3}% - {2,-40}" -f $bar, $pct, $Label) -NoNewline -ForegroundColor Cyan
}

function Show-ProcessTree {
    function Get-ProcessChildren {
        param($P, [int]$Depth = 1)
        $allProcs | Where-Object {
            $_.ParentProcessId -eq $P.ProcessID -and $_.ParentProcessId -ne 0
        } | ForEach-Object {
            $indent = " " * (3 * $Depth)
            $line = "$indent|-- " + $_.Name + "  pid=" + $_.ProcessID + "  ppid=" + $_.ParentProcessId
            $line
            Get-ProcessChildren -P $_ -Depth ($Depth + 1)
        }
    }
    $allProcs = Get-CimInstance Win32_Process
    $roots = $allProcs | Where-Object {
        -not (Get-Process -Id $_.ParentProcessId -ErrorAction SilentlyContinue) -or $_.ParentProcessId -eq 0
    } | Sort-Object ProcessID
    $output = @()
    foreach ($p in $roots) {
        $rootLine = $p.Name + "  pid=" + $p.ProcessID
        $output += $rootLine
        $children = Get-ProcessChildren -P $p -Depth 1
        $output  += $children
    }
    return $output
}

function Get-USBKeys {
    Push-Location
    Set-Location HKLM:\
    $devices = Get-Item 'HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\*\*' -ErrorAction SilentlyContinue
    if ($devices) {
        Get-ItemProperty $devices | Select-Object `
            @{Name = 'SerialNumber'; Expression = { $_.PSChildName.TrimEnd('&0').split('&')[-1] }},
            FriendlyName
    }
    Pop-Location
}

function Get-AntiVirusProduct {
    try {
        $av = Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop
        $state = [int]($av.productState)
        $defstatus = "Out of date"
        $rtstatus  = "Disabled"
        if ($state -eq 262144 -or $state -eq 266240 -or $state -eq 393216 -or $state -eq 397312) {
            $defstatus = "Up to date"
        }
        if ($state -eq 266240 -or $state -eq 266256 -or $state -eq 397312 -or $state -eq 397328 -or $state -eq 397584) {
            $rtstatus = "Enabled"
        }
        [PSCustomObject]@{
            "Name"                        = $av.displayName
            "ProductExecutable"           = $av.pathToSignedProductExe
            "Definition Status"           = $defstatus
            "Real-time Protection Status" = $rtstatus
        }
    } catch {
        [PSCustomObject]@{
            "Name"                        = "Unknown (WMI error)"
            "ProductExecutable"           = ""
            "Definition Status"           = "Unknown"
            "Real-time Protection Status" = "Unknown"
        }
    }
}

# ---------------------------------------------------------------------------
#  AUDIT MODULE CATALOG
# ---------------------------------------------------------------------------

$Global:AuditModules = [ordered]@{

    "01" = @{
        Name       = "Boot Manager"
        ShortName  = "BCD"
        Category   = "System"
        Conseil    = "[CRITICAL] Check for unknown or unsigned boot entries (suspicious dual-boot, boot-kits). A boot-kit (e.g. MBR rootkit) can persist before Windows loads and evade AV. Verify SecureBoot is active (bcdedit /enum firmware). Any entry with an unusual path to winload.exe is suspicious. [THREAT: Boot-kits, pre-OS persistence, UEFI rootkits]"
        HtmlAnchor = "bcd"
        Script     = {
            Write-SectionHeader "BOOT MANAGER (bcdedit)"
            try {
                $result = (cmd /c "chcp 65001 >nul 2>&1 & bcdedit") 2>&1
                $result | ForEach-Object { Write-Host "  $_" -ForegroundColor Cyan }
                return ($result -join "`n")
            } catch { Write-ErrorMsg $_.Exception.Message; return "" }
        }
    }

    "02" = @{
        Name       = "OS Information"
        ShortName  = "OS"
        Category   = "System"
        Conseil    = "[INFO] Check Windows version and build. An outdated system is exposed to public CVEs (e.g. EternalBlue MS17-010 on unpatched Win7/2008). Verify the machine is not end-of-life (EOL): Windows 7/8/2008 no longer receive patches. A very long uptime (>30d) may indicate pending updates or an avoided reboot. [THREAT: Known vulnerability exploitation, ransomware, worms]"
        HtmlAnchor = "infos"
        Script     = {
            Write-SectionHeader "SYSTEM INFORMATION"
            $os   = Get-CimInstance Win32_OperatingSystem
            $cs   = Get-CimInstance Win32_ComputerSystem
            $bios = Get-CimInstance Win32_BIOS
            $cpu  = (Get-CimInstance Win32_Processor).Name
            $domaine = if ($cs.PartOfDomain) { $cs.Domain } else { "WORKGROUP: $($cs.Workgroup)" }
            $uptime  = ((Get-Date) - $os.LastBootUpTime).ToString("dd'd' hh'h' mm'm'")
            $items = [ordered]@{
                "Machine Name"      = $cs.Name
                "Domain / Workgroup"    = $domaine
                "Operating System" = $os.Caption
                "Version"                = $os.Version
                "Build"                  = $os.BuildNumber
                "Architecture"           = $os.OSArchitecture
                "RAM (GB)"               = [math]::Round($cs.TotalPhysicalMemory / 1GB, 2)
                "Processor"             = $cpu
                "BIOS Version"           = $bios.SMBIOSBIOSVersion
                "Last Boot"      = $os.LastBootUpTime
                "Uptime"                 = $uptime
            }
            $output = @()
            foreach ($k in $items.Keys) {
                Write-Host ("  {0,-28}: " -f $k) -ForegroundColor DarkGray -NoNewline
                Write-Host $items[$k] -ForegroundColor White
                $output += ("{0,-28}: {1}" -f $k, $items[$k])
            }
            return ($output -join "`n")
        }
    }

    "03" = @{
        Name       = "Environment Variables"
        ShortName  = "ENV"
        Category   = "System"
        Conseil    = "[INFO] Check environment variables for suspicious PATH entries (e.g. a user folder before System32 enables DLL hijacking). Check TEMP/TMP: malware often writes and executes from these folders. A modified COMSPEC or PATHEXT variable may indicate persistence or compromise. [THREAT: DLL hijacking, execution from TEMP, hijacked variables]"
        HtmlAnchor = "infenv"
        Script     = {
            Write-SectionHeader "ENVIRONMENT VARIABLES"
            $result = Get-ChildItem Env: | Sort-Object Name
            $result | ForEach-Object {
                Write-Host ("  {0,-35}" -f $_.Name) -ForegroundColor DarkCyan -NoNewline
                Write-Host $_.Value -ForegroundColor Gray
            }
            return ($result | Format-Table -AutoSize | Out-String)
        }
    }

    "04" = @{
        Name       = "Process Tree"
        ShortName  = "PROC-TREE"
        Category   = "Processes"
        Conseil    = "[IMPORTANT] Analyze the parent/child process hierarchy. Typical anomalies: cmd.exe or powershell.exe child of word.exe/excel.exe (suspicious macro), svchost.exe launched by a process other than services.exe, explorer.exe with unexpected children. A system process (lsass, winlogon) with an unusual parent indicates injection. [THREAT: Office macros, process hollowing, code injection, RAT]"
        HtmlAnchor = "arbps"
        Script     = {
            Write-SectionHeader "PROCESS TREE"
            $result = Show-ProcessTree
            $result | ForEach-Object { Write-Host "  $_" -ForegroundColor Cyan }
            return ($result -join "`n")
        }
    }

    "05" = @{
        Name       = "Process List"
        ShortName  = "PROC-LIST"
        Category   = "Processes"
        Conseil    = "[IMPORTANT] Check processes with abnormal CPU/RAM usage (crypto-miner). Look for names mimicking legitimate system processes (svchost32.exe, lsass_.exe, svch0st.exe). A process with no path (empty Path) may indicate memory-injected code. Check processes running from %TEMP%, %APPDATA%, or %PUBLIC%. [THREAT: Crypto-miners, RAT, process injection, living-off-the-land]"
        HtmlAnchor = "lstps"
        Script     = {
            Write-SectionHeader "PROCESS LIST (Top 50 CPU)"
            $procs = Get-Process | Sort-Object CPU -Descending | Select-Object -First 50 `
                Name, Id, CPU,
                @{N="RAM(Mo)";  E={[math]::Round($_.WorkingSet64/1MB,1)}},
                @{N="Threads"; E={$_.Threads.Count}},
                Path
            $procs | ForEach-Object {
                Write-Host ("  {0,-30} PID:{1,-7} CPU:{2,-8} RAM:{3}Mo" -f `
                    $_.Name, $_.Id, $_.CPU, $_."RAM(Mo)") -ForegroundColor Cyan
            }
            return ($procs | Format-Table -AutoSize | Out-String)
        }
    }

    "06" = @{
        Name       = "PowerShell Policy"
        ShortName  = "EXEC-POL"
        Category   = "Security"
        Conseil    = "[CRITICAL] Bypass and Unrestricted allow any PS script to run without restriction. Recommended policy is RemoteSigned or AllSigned. An attacker can bypass the policy with powershell.exe -ExecutionPolicy Bypass -File malware.ps1: this policy alone is not a sufficient security barrier, but a permissive value indicates poor hygiene or past compromise. [THREAT: Suspicious script execution, fileless malware, PS-Emp1re/Invoke-Mimi-katz]"
        HtmlAnchor = "polpws"
        Script     = {
            Write-SectionHeader "POWERSHELL EXECUTION POLICY"
            $result = Get-ExecutionPolicy -List
            $result | ForEach-Object {
                $pol   = $_.ExecutionPolicy.ToString()
                $color = if ($pol -eq "Unrestricted" -or $pol -eq "Bypass") { "Red" } else { "Green" }
                Write-Host ("  {0,-20}: " -f $_.Scope) -ForegroundColor DarkGray -NoNewline
                Write-Host $pol -ForegroundColor $color
            }
            return ($result | Format-Table -AutoSize | Out-String)
        }
    }

    "07" = @{
        Name       = "Security Policy"
        ShortName  = "SECEDIT"
        Category   = "Security"
        Conseil    = "[CRITICAL] Check: MinimumPasswordLength >= 12, PasswordComplexity = 1, MaximumPasswordAge <= 90d, LockoutBadCount <= 5 (brute-force protection), LockoutDuration >= 15 min. PasswordComplexity = 0 or LockoutBadCount = 0 (no lockout) exposes to local brute-force. Verify auditing is enabled (AuditLogonEvents, AuditObjectAccess) for forensics. [THREAT: Local brute-force, pass-the-h4sh, no forensic traces]"
        HtmlAnchor = "polsec"
        Script     = {
            Write-SectionHeader "POLITIQUE DE SECURITE (secedit)"
            $tmpFile = "$env:TEMP\pwaudit_secedit_$($env:COMPUTERNAME).inf"
            try {
                secedit /export /cfg $tmpFile /quiet 2>&1 | Out-Null
                if (Test-Path $tmpFile) {
                    $content = Get-Content $tmpFile -Encoding Unicode
                    $inSection = $false
                    $importantSections = @("System Access","Password Policy","Account Lockout Policy","Audit Policy")
                    $content | ForEach-Object {
                        if ($_ -match "^\[(.+)\]") {
                            $secName   = $Matches[1]
                            $inSection = $importantSections -contains $secName
                            if ($inSection) { Write-Host "  [$secName]" -ForegroundColor Yellow }
                        } elseif ($inSection -and $_ -match "=") {
                            $parts = $_ -split "=", 2
                            Write-Host ("    {0,-40}= " -f $parts[0].Trim()) -ForegroundColor DarkGray -NoNewline
                            Write-Host $parts[1].Trim() -ForegroundColor Cyan
                        }
                    }
                    Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue
                    return ($content -join "`n")
                }
            } catch { Write-ErrorMsg $_.Exception.Message }
            return ""
        }
    }

    "08" = @{
        Name       = "Local Accounts"
        ShortName  = "USERS"
        Category   = "Accounts"
        Conseil    = "[CRITICAL] The built-in Administrator account must be renamed and disabled if unused: it is the default target for attack tools (Mimi-katz, Cr4ckMapExec). The Guest account must be disabled. Check accounts with no password (PasswordRequired=False): trivial local access vector. Check PasswordNeverExpires=True on active accounts (bad practice). Any unknown or inactive account for >90d must be disabled. [THREAT: Brute-force, lateral movement, privilege escalation]"
        HtmlAnchor = "licpt"
        Script     = {
            Write-SectionHeader "LOCAL ACCOUNTS"
            $users = Get-LocalUser | Select-Object Name, Enabled, PasswordRequired,
                LastLogon, PasswordLastSet, PasswordNeverExpires, Description
            $users | ForEach-Object {
                $color = if ($_.Enabled) { "Green" } else { "DarkGray" }
                $warn  = if (-not $_.PasswordRequired) { " [!MOT DE PASSE VIDE]" } else { "" }
                Write-Host ("  {0,-25}" -f $_.Name) -ForegroundColor $color -NoNewline
                Write-Host (" Actif:{0,-6} Derniere connexion:{1}{2}" -f `
                    $_.Enabled, $_.LastLogon, $warn) -ForegroundColor Gray
            }
            return ($users | Format-Table -AutoSize | Out-String)
        }
    }

    "09" = @{
        Name       = "Local Groups"
        ShortName  = "GROUPS"
        Category   = "Accounts"
        Conseil    = "[IMPORTANT] The Administrators group should only contain strictly necessary accounts. Check for service or generic accounts in privileged groups. The Remote Desktop Users group controls RDP access: limit to the strict minimum. Unknown members in Administrators or Backup Operators indicate compromise. [THREAT: Privilege escalation, persistence via group, RDP lateral movement]"
        HtmlAnchor = "ligrp"
        Script     = {
            Write-SectionHeader "LOCAL GROUPS"
            $output = @()
            Get-LocalGroup | Sort-Object Name | ForEach-Object {
                $grp = $_
                Write-Host "  [$($grp.Name)]" -ForegroundColor Yellow
                $output += "[$($grp.Name)]"
                try {
                    $members = Get-LocalGroupMember $grp.Name -ErrorAction SilentlyContinue
                    if ($members) {
                        $members | ForEach-Object {
                            $line = "    - " + $_.Name + " (" + $_.ObjectClass + ")"
                            Write-Host $line -ForegroundColor Cyan
                            $output += $line
                        }
                    } else {
                        Write-Host "    (empty)" -ForegroundColor DarkGray
                        $output += "  (empty)"
                    }
                } catch {
                    Write-Host "    (erreur lecture membres)" -ForegroundColor Red
                }
            }
            return ($output -join "`n")
        }
    }

    "10" = @{
        Name       = "Network Shares"
        ShortName  = "SHARES"
        Category   = "Network"
        Conseil    = "[CRITICAL] Administrative shares (C$, D$, ADMIN$, IPC$) are lateral movement vectors heavily used by ransomware (Wanna-Cry, Not-Petya) and tools like Ps-Exec/Cr4ckMapExec. Disable with: reg add HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters /v AutoShareWks /t REG_DWORD /d 0. Ensure SYSVOL/NETLOGON are only exposed if the machine is a domain controller. Any undocumented share is suspicious. [THREAT: Ransomware, SMB lateral movement, data exfiltration]"
        HtmlAnchor = "shares"
        Script     = {
            Write-SectionHeader "NETWORK SHARES"
            $shares = Get-SmbShare | Select-Object Name, Path, Description
            $shares | ForEach-Object {
                $color = if ($_.Name -match '\$') { "Yellow" } else { "Cyan" }
                Write-Host ("  {0,-20} -> {1,-40} {2}" -f $_.Name, $_.Path, $_.Description) -ForegroundColor $color
            }
            return ($shares | Format-Table -AutoSize | Out-String)
        }
    }

    "11" = @{
        Name       = "USB History"
        ShortName  = "USB"
        Category   = "System"
        Conseil    = "[IMPORTANT] USB history reveals all devices connected since installation. Check for unknown USB keys, USB network adapters (exfiltration), rubber ducky / BadUSB (HID keyboard emulation for command injection). In sensitive environments, Group Policy should block unauthorized USB devices. Each unknown entry must be justified by the user. [THREAT: BadUSB, physical exfiltration, malware introduction, HID injection]"
        HtmlAnchor = "usb"
        Script     = {
            Write-SectionHeader "USB DEVICE HISTORY"
            $result = Get-USBKeys
            if ($result) {
                $result | ForEach-Object {
                    Write-Host ("  {0,-40} {1}" -f $_.FriendlyName, $_.SerialNumber) -ForegroundColor Cyan
                }
                return ($result | Format-Table -AutoSize | Out-String)
            } else {
                Write-Host "  No USB device found in registry." -ForegroundColor DarkGray
                return "No USB device."
            }
        }
    }

    "12" = @{
        Name       = "Partitions / Disks"
        ShortName  = "DISK"
        Category   = "System"
        Conseil    = "[INFO] Disk space below 10% may indicate massive log/data collection by malware or active exfiltration. Check for hidden or unmounted partitions (rootkit persistence vector). BitLocker encryption should be active on mobile workstations (check with manage-bde -status). [THREAT: Exfiltration, pre-encryption ransomware, missing disk encryption]"
        HtmlAnchor = "part"
        Script     = {
            Write-SectionHeader "PARTITIONS AND DISKS"
            $disks = Get-PSDrive -PSProvider FileSystem | Select-Object Name, Root,
                @{N="Total(Go)";  E={[math]::Round(($_.Used + $_.Free)/1GB, 1)}},
                @{N="Libre(Go)";  E={[math]::Round($_.Free/1GB, 1)}},
                @{N="Utilise(Go)";E={[math]::Round($_.Used/1GB, 1)}},
                @{N="Libre%";     E={
                    $tot = $_.Used + $_.Free
                    if ($tot -gt 0) { [math]::Round($_.Free / $tot * 100, 0) } else { 0 }
                }}
            $disks | ForEach-Object {
                $pct   = $_."Libre%"
                $color = if ($pct -lt 10) { "Red" } elseif ($pct -lt 20) { "Yellow" } else { "Green" }
                Write-Host ("  {0}: {1,-8} Total:{2,8}Go  Libre:{3,8}Go  ({4}%)" -f `
                    $_.Name, $_.Root, $_."Total(Go)", $_."Libre(Go)", $pct) -ForegroundColor $color
            }
            return ($disks | Format-Table -AutoSize | Out-String)
        }
    }

    "13" = @{
        Name       = "Network Configuration"
        ShortName  = "IPCONFIG"
        Category   = "Network"
        Conseil    = "[IMPORTANT] Verify that configured DNS servers belong to the organization or known providers. A modified DNS (e.g. 8.8.8.8 replaced by an unknown IP) may indicate DNS hijacking. Multiple IPs on one interface may signal a tunnel or proxy. An APIPA address (169.254.x.x) indicates a DHCP issue that may isolate the machine. Check for undocumented virtual interfaces (VPN, Tor, tunnel). [THREAT: DNS hijacking, C2 via DNS, network tunnel, pivot]"
        HtmlAnchor = "cfrzo"
        Script     = {
            Write-SectionHeader "CONFIGURATION RESEAU (ipconfig /all)"
            $result = (cmd /c "chcp 65001 >nul 2>&1 & ipconfig /all") 2>&1
            $result | ForEach-Object {
                $line  = $_
                $color = "Gray"
                if ($line -match "IPv4|IPv6")             { $color = "Cyan" }
                elseif ($line -match "Passerelle|Gateway") { $color = "Yellow" }
                elseif ($line -match "DNS")                { $color = "Green" }
                elseif ($line -match "DHCP")               { $color = "Magenta" }
                Write-Host "  $line" -ForegroundColor $color
            }
            return ($result -join "`n")
        }
    }

    "14" = @{
        Name       = "Active Network Connections"
        ShortName  = "NETSTAT"
        Category   = "Network"
        Conseil    = "[CRITICAL] Check ESTABLISHED connections to unknown external IPs: possible C2 (Command & Control) communication from malware. Unusual listening ports (>1024 on a workstation) may indicate a RAT or backdoor. Check processes associated with ports: svchost.exe listening on a non-standard port is suspicious. Repeated connections to the same remote IP in TIME_WAIT may signal C2 beaconing. [THREAT: RAT, C2, backdoor, C2 beaconing, network exfiltration]"
        HtmlAnchor = "statrzo"
        Script     = {
            Write-SectionHeader "CONNEXIONS RESEAU ACTIVES (netstat -anob)"
            $result = (cmd /c "chcp 65001 >nul 2>&1 & netstat -anob") 2>&1
            $result | ForEach-Object {
                $line  = $_
                $color = "Gray"
                if ($line -match "LISTENING|ECOUTE")       { $color = "Yellow" }
                elseif ($line -match "ESTABLISHED|ETABLI") { $color = "Green" }
                elseif ($line -match "TIME_WAIT")           { $color = "DarkGray" }
                Write-Host "  $line" -ForegroundColor $color
            }
            return ($result -join "`n")
        }
    }

    "15" = @{
        Name       = "Routing Table"
        ShortName  = "ROUTE"
        Category   = "Network"
        Conseil    = "[IMPORTANT] An unexpected default route may redirect all traffic to a suspicious proxy. Static routes added to internal subnets from a workstation may indicate network pivoting or a lateral movement agent. Verify the default gateway matches the known infrastructure. [THREAT: Network pivot, man-in-the-middle, exfiltration via forced route]"
        HtmlAnchor = "route"
        Script     = {
            Write-SectionHeader "ROUTING TABLE"
            $result = (cmd /c "chcp 65001 >nul 2>&1 & netstat -r") 2>&1
            $result | ForEach-Object { Write-Host "  $_" -ForegroundColor Cyan }
            return ($result -join "`n")
        }
    }

    "16" = @{
        Name       = "Update Source (WSUS)"
        ShortName  = "WSUS"
        Category   = "Updates"
        Conseil    = "[IMPORTANT] If a WSUS server is configured, verify it is a known internal server. A hijacked WSUS (WSUS-pect attack) allows an attacker to distribute fake signed updates to all domain machines, leading to full infrastructure compromise. If no WSUS is configured, verify that automatic Windows Update is enabled. [THREAT: WSUS-pect, fake updates, full infrastructure compromise via WSUS]"
        HtmlAnchor = "wsus"
        Script     = {
            Write-SectionHeader "UPDATE SOURCE (WSUS)"
            $result = (cmd /c "chcp 65001 >nul 2>&1 & reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate /s") 2>&1
            if (($result -join "") -match "ERROR|Erreur") {
                Write-Host "  No WSUS configuration found (direct Microsoft update)." -ForegroundColor Yellow
            } else {
                $result | ForEach-Object { Write-Host "  $_" -ForegroundColor Cyan }
            }
            return ($result -join "`n")
        }
    }

    "17" = @{
        Name       = "Installed Updates"
        ShortName  = "HOTFIX"
        Category   = "Updates"
        Conseil    = "[CRITICAL] Check the date of the last update: more than 30 days without a patch is risky, more than 90 days is critical. Look for unpatched critical CVEs: EternalBlue (MS17-010), PrintNightmare (CVE-2021-34527), Log4Shell, CVE-2022-30190. Compare the Windows build with Microsoft releases to identify missing patches. Missing security KBs are a strong indicator of an open attack surface. [THREAT: Known CVE exploitation, ransomware, propagation worm]"
        HtmlAnchor = "maj"
        Script     = {
            Write-SectionHeader "INSTALLED UPDATES"
            $result = Get-HotFix | Sort-Object InstalledOn -Descending |
                Select-Object HotFixID, Description, InstalledBy, InstalledOn
            $result | Select-Object -First 30 | ForEach-Object {
                Write-Host ("  {0,-15} {1,-25} {2}" -f $_.HotFixID, $_.InstalledOn, $_.Description) -ForegroundColor Cyan
            }
            return ($result | Format-Table -AutoSize | Out-String)
        }
    }

    "18" = @{
        Name       = "Time Source (NTP)"
        ShortName  = "NTP"
        Category   = "Network"
        Conseil    = "[INFO] A large time drift (>5 min) may indicate time manipulation to falsify logs and complicate forensic analysis. An unauthorized external NTP server may signal a suspicious reconfiguration. In an AD domain, all machines should sync to the DC (W32TM /query /source). Time consistency is critical for event correlation in a SIEM. [THREAT: Anti-forensics, log tampering, Kerberos certificate invalidation]"
        HtmlAnchor = "ntp"
        Script     = {
            Write-SectionHeader "SOURCE DE TEMPS (NTP)"
            $result = (cmd /c "chcp 65001 >nul 2>&1 & w32tm /query /status") 2>&1
            $result | ForEach-Object {
                $color = if ($_ -match "Source|Stratum") { "Yellow" } else { "Cyan" }
                Write-Host "  $_" -ForegroundColor $color
            }
            return ($result -join "`n")
        }
    }

    "19" = @{
        Name       = "Wi-Fi Configuration"
        ShortName  = "WIFI"
        Category   = "Network"
        Conseil    = "[IMPORTANT] Ensure the machine does not auto-connect to open Wi-Fi networks (evil twin, rogue AP). Stored Wi-Fi profiles contain cleartext passwords recoverable via: netsh wlan show profile <name> key=clear. A Wi-Fi adapter in Monitor or AP mode may indicate a network scan/pivot tool. Disable Wi-Fi on fixed workstations in sensitive environments. [THREAT: Evil twin, Wi-Fi credential theft, rogue AP, wireless pivot]"
        HtmlAnchor = "wifi"
        Script     = {
            Write-SectionHeader "WI-FI CONFIGURATION"
            $result = (cmd /c "chcp 65001 >nul 2>&1 & netsh wlan show all") 2>&1
            $result | ForEach-Object {
                $line  = $_
                $color = "Gray"
                if ($line -match "SSID|Profil")                   { $color = "Yellow" }
                elseif ($line -match "Authentication|Encryption") { $color = "Cyan" }
                Write-Host "  $line" -ForegroundColor $color
            }
            return ($result -join "`n")
        }
    }

    "20" = @{
        Name       = "DNS Cache"
        ShortName  = "DNS-CACHE"
        Category   = "Network"
        Conseil    = "[IMPORTANT] DNS cache reveals domains recently contacted by the machine. Look for suspicious domains: DGA (random names like xk3m9p2.net), known C2 domains, brand-lookalike domains (typosquatting: micosoft.com). Many failed DNS queries may indicate DGA malware looking for its C2. Check unknown IPs/domains via VirusTotal or Shodan. [THREAT: C2 via DNS, DGA, DNS tunneling, data exfiltration via DNS]"
        HtmlAnchor = "dns"
        Script     = {
            Write-SectionHeader "DNS CACHE"
            $result = (cmd /c "chcp 65001 >nul 2>&1 & ipconfig /displaydns") 2>&1
            $result | ForEach-Object {
                $color = if ($_ -match "Nom d|Record Name") { "Yellow" } else { "Gray" }
                Write-Host "  $_" -ForegroundColor $color
            }
            # Extraire les URLs/domaines bruts pour la liste copiable
            $rawDomains = $result | ForEach-Object {
                if ($_ -match "(?i)Nom d.enregistrement\s*[:.]+\s*(.+)|Record Name\s*[:.]+\s*(.+)") {
                    $d = if ($Matches[1]) { $Matches[1].Trim() } else { $Matches[2].Trim() }
                    # Supprimer les ":" residuels en debut de valeur
                    $d = $d -replace "^[:\s]+", ""
                    $d = $d.Trim()
                    if ($d -and $d -ne "" -and $d -notmatch "^\s*$" -and $d -notmatch "^:") { $d }
                }
            } | Where-Object { $_ -and $_ -notmatch "^[:\s]*$" } | Sort-Object -Unique
            $domainList = $rawDomains -join "`n"
            # Separator visuel dans le shell
            Write-Host ""
            Write-Host "  ---- RAW DOMAINS ($($rawDomains.Count) unique) ----" -ForegroundColor Cyan
            $rawDomains | ForEach-Object { Write-Host "  $_" -ForegroundColor Green }
            # Retourner les deux blocs separes par un marqueur
            return ("=== LOG COMPLET ===" + "`n" + ($result -join "`n") + "`n`n=== DOMAINES BRUTS ===" + "`n" + $domainList)
        }
    }

    "21" = @{
        Name       = "Proxy Configuration"
        ShortName  = "PROXY"
        Category   = "Network"
        Conseil    = "[IMPORTANT] Un proxy configure a l'insu de l'utilisateur (ProxyEnable=1 avec IP inconnue) permet l'interceptation de tout le trafic HTTP/HTTPS (MITM). AutoConfigURL pointant vers un PAC file externe est un vecteur de redirection de trafic. Certains logiciel-suspects (ex: Trick-Bot, Emo-tet) modifient les parametres proxy pour exfiltrer des donnees ou intercepter des credentials. Verifier egalement HKLM en plus de HKCU car les deux peuvent etre utilises. [MENACE: MITM, interception HTTPS, exfiltration via proxy, vol de credentials]"
        HtmlAnchor = "proxy"
        Script     = {
            Write-SectionHeader "CONFIGURATION PROXY WEB"
            $proxy = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
            $keys  = @("ProxyEnable","ProxyServer","ProxyOverride","AutoConfigURL")
            $keys | ForEach-Object {
                $k   = $_
                $val = $proxy.$k
                if ($null -ne $val) {
                    $color = if ($k -eq "ProxyEnable" -and $val -eq 1) { "Yellow" } else { "Cyan" }
                    Write-Host ("  {0,-25}: {1}" -f $k, $val) -ForegroundColor $color
                }
            }
            return ($proxy | Select-Object ProxyEnable,ProxyServer,ProxyOverride,AutoConfigURL | Out-String)
        }
    }

    "22" = @{
        Name       = "ARP Table"
        ShortName  = "ARP"
        Category   = "Network"
        Conseil    = "[IMPORTANT] An ARP table with duplicate MAC addresses (two IPs with the same MAC or vice versa) may indicate an active ARP spoofing/poisoning attack on the network segment. ARP poisoning enables MITM: the attacker redirects traffic to themselves before forwarding. Verify the default gateway always has the same MAC address between audits. [THREAT: ARP spoofing, man-in-the-middle, local network interception]"
        HtmlAnchor = "arp"
        Script     = {
            Write-SectionHeader "ARP TABLE"
            $result = (cmd /c "chcp 65001 >nul 2>&1 & arp -a") 2>&1
            $result | ForEach-Object {
                $color = if ($_ -match "Interface") { "Yellow" } else { "Cyan" }
                Write-Host "  $_" -ForegroundColor $color
            }
            return ($result -join "`n")
        }
    }

    "23" = @{
        Name       = "HOSTS File"
        ShortName  = "HOSTS"
        Category   = "Network"
        Conseil    = "[CRITICAL] The HOSTS file is modified by many malicious tools to: block AV updates (redirect windowsupdate.com to 127.0.0.1), redirect banking sites to phishing servers, prevent communication with remediation servers. The file should only contain the localhost line (127.0.0.1 localhost) and optionally ::1 localhost. Any other entry must be justified. Compare hash between audits. [THREAT: AV evasion, local phishing, AV/update blocking, local DNS hijacking]"
        HtmlAnchor = "hosts"
        Script     = {
            Write-SectionHeader "HOSTS FILE"
            $hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
            $content   = Get-Content $hostsPath -ErrorAction SilentlyContinue
            $content | ForEach-Object {
                $color = if ($_ -match "^#") { "DarkGray" } else { "Yellow" }
                Write-Host "  $_" -ForegroundColor $color
            }
            return ($content -join "`n")
        }
    }

    "24" = @{
        Name       = "Services Status"
        ShortName  = "SERVICES"
        Category   = "Services"
        Conseil    = "[IMPORTANT] Reduire la surface d'attaque en desactivant les services inutiles : Spooler d'impression (si pas d'imprimante - vecteur Print-Nightmare), WinRM (si pas d'administration a distance - vecteur lateral), Telnet, FTP, SNMP (protocoles non chiffres). Un service avec un chemin sans guillemets contenant des espaces est vulnerable au Unquoted Service Path (privilege escalation). Verifier les services avec des binaires dans %TEMP% ou %APPDATA%. [MENACE: Print-Nightmare, unquoted path, service suspect, persistence]"
        HtmlAnchor = "svc"
        Script     = {
            Write-SectionHeader "SERVICES STATUS"
            $services = Get-Service | Sort-Object Status -Descending
            $running  = ($services | Where-Object {$_.Status -eq "Running"}).Count
            $stopped  = ($services | Where-Object {$_.Status -eq "Stopped"}).Count
            Write-Host "  Running: $running  |  Stopped: $stopped" -ForegroundColor Yellow
            Write-Host ""
            $services | ForEach-Object {
                $color = if ($_.Status -eq "Running") { "Green" } else { "DarkGray" }
                Write-Host ("  [{0,-8}] {1}" -f $_.Status, $_.DisplayName) -ForegroundColor $color
            }
            return ($services | Format-Table Name,Status,DisplayName -AutoSize | Out-String)
        }
    }

    "25" = @{
        Name       = "Firewall - Status"
        ShortName  = "FW-STATE"
        Category   = "Firewall"
        Conseil    = "[CRITICAL] The firewall must be active on all three profiles (Domain, Private, Public). A disabled firewall on the Public profile is a serious fault (unfiltered connections on unknown network). The Domain profile is often more permissive: verify that Public/Private is more restrictive. A disabled firewall may result from compromise (malware disabling protection) or poor administrative practice. [THREAT: Unfiltered connections, port scanning, direct exploitation of exposed services]"
        HtmlAnchor = "conffw"
        Script     = {
            Write-SectionHeader "ETAT DU PARE-FEU"
            $result = (cmd /c "chcp 65001 >nul 2>&1 & netsh advfirewall show allprofiles") 2>&1
            $result | ForEach-Object {
                $line  = $_
                $color = "Gray"
                if ($line -match " ON")      { $color = "Green" }
                if ($line -match " OFF")     { $color = "Red" }
                if ($line -match "Profil|Profile") { $color = "Yellow" }
                Write-Host "  $line" -ForegroundColor $color
            }
            return ($result -join "`n")
        }
    }

    "26" = @{
        Name       = "Firewall - Inbound Rules"
        ShortName  = "FW-IN"
        Category   = "Firewall"
        Conseil    = "[IMPORTANT] Verifier les regles autorisant des connexions entrantes sur des ports sensibles : RDP (3389) depuis Any (risque brute-force/Blue-Keep), WinRM (5985/5986) depuis Any (risque lateral), SMB (445) depuis Any (risque Eternal-Blue/ransom-ware). Un nombre de regles superieur a 200 indique generalement une accumulation non maitrisee. Les regles sans nom explicite ou avec des noms generiques sont suspectes. Privilegier des regles avec des IPs sources specifiques plutot que Any. [MENACE: RDP brute-force, Blue-Keep, Eternal-Blue, acces non autorise]"
        HtmlAnchor = "infw"
        Script     = {
            Write-SectionHeader "REGLES PARE-FEU ENTRANTES (activees uniquement)"
            $rules = Get-NetFirewallRule -Direction Inbound -Enabled True |
                Select-Object DisplayName, Action, Protocol, Profile |
                Sort-Object Action
            Write-Host "  Total active inbound rules: $($rules.Count)" -ForegroundColor Yellow
            $rules | ForEach-Object {
                $color = if ($_.Action -eq "Allow") { "Green" } else { "Red" }
                Write-Host ("  [{0,-6}] {1}" -f $_.Action, $_.DisplayName) -ForegroundColor $color
            }
            return ($rules | Format-Table -AutoSize | Out-String)
        }
    }

    "27" = @{
        Name       = "Firewall - Outbound Rules"
        ShortName  = "FW-OUT"
        Category   = "Firewall"
        Conseil    = "[INFO] Outbound rules are often overlooked but critical for defense-in-depth. A firewall blocking outbound traffic by default significantly limits malware capabilities: C2 connection, additional payload download, data exfiltration. Ensure PowerShell, cmd.exe, and mshta.exe are not allowed to initiate outbound internet connections (indicator of fileless malware or LOLBin). [THREAT: C2, exfiltration, LOLBins (mshta, certutil, bitsadmin), fileless malware]"
        HtmlAnchor = "outfw"
        Script     = {
            Write-SectionHeader "REGLES PARE-FEU SORTANTES (activees uniquement)"
            $rules = Get-NetFirewallRule -Direction Outbound -Enabled True |
                Select-Object DisplayName, Action, Protocol, Profile |
                Sort-Object Action
            Write-Host "  Total active outbound rules: $($rules.Count)" -ForegroundColor Yellow
            $rules | ForEach-Object {
                $color = if ($_.Action -eq "Allow") { "Green" } else { "Red" }
                Write-Host ("  [{0,-6}] {1}" -f $_.Action, $_.DisplayName) -ForegroundColor $color
            }
            return ($rules | Format-Table -AutoSize | Out-String)
        }
    }

    "28" = @{
        Name       = "Antivirus"
        ShortName  = "AV"
        Category   = "Security"
        Conseil    = "[CRITICAL] Antivirus must be active (Real-time Protection = Enabled) and up to date. Signatures older than 7 days no longer provide effective protection against recent threats. Check that the AV has not been disabled: some ransomware (RE-vil, Con-ti) disables AV before starting encryption. Multiple simultaneous AV products can cause conflicts and weaken protection. Supplement with EDR/XDR in sensitive environments. [THREAT: Ransomware, AV bypass, protection disabling, zero-day]"
        HtmlAnchor = "infav"
        Script     = {
            Write-SectionHeader "INFORMATIONS ANTIVIRUS"
            $result = Get-AntiVirusProduct
            $props  = @("Name","Definition Status","Real-time Protection Status","ProductExecutable")
            foreach ($k in $props) {
                $val = $result.$k
                if ($val) {
                    $color = "Cyan"
                    if ($k -eq "Real-time Protection Status") {
                        $color = if ($val -eq "Enabled") { "Green" } else { "Red" }
                    }
                    if ($k -eq "Definition Status") {
                        $color = if ($val -eq "Up to date") { "Green" } else { "Red" }
                    }
                    Write-Host ("  {0,-35}: " -f $k) -ForegroundColor DarkGray -NoNewline
                    Write-Host $val -ForegroundColor $color
                }
            }
            return ($result | Out-String)
        }
    }

    "29" = @{
        Name       = "Scheduled Tasks"
        ShortName  = "TASKS"
        Category   = "Persistence"
        Conseil    = "[IMPORTANT] Scheduled tasks are a heavily used persistence vector for malware. Check tasks in \Microsoft\Windows\... with actions pointing to %TEMP%, %APPDATA%, or running powershell.exe / wscript.exe / cscript.exe / mshta.exe with suspicious arguments. Check recently created tasks (creation date near an incident). A task without a known author or with a random GUID as name is suspicious. [THREAT: Malware persistence, delayed payload execution, scheduled backdoor]"
        HtmlAnchor = "tasks"
        Script     = {
            Write-SectionHeader "TACHES PLANIFIEES (actives)"
            $tasks = Get-ScheduledTask | Where-Object {$_.State -ne "Disabled"} |
                Select-Object TaskName, TaskPath, State | Sort-Object TaskPath
            $tasks | ForEach-Object {
                $color = if ($_.State -eq "Running") { "Yellow" } else { "Cyan" }
                Write-Host ("  [{0,-10}] {1}{2}" -f $_.State, $_.TaskPath, $_.TaskName) -ForegroundColor $color
            }
            return ($tasks | Format-Table -AutoSize | Out-String)
        }
    }

    "30" = @{
        Name       = "Installed Software"
        ShortName  = "APPS"
        Category   = "System"
        Conseil    = "[IMPORTANT] Check for unauthorized software: remote administration tools (AnyDesk, TeamViewer, RustDesk) installed without IT approval, penetration testing tools (Nmap, Wireshark, Msf-framework), cryptocurrency miners. Check versions: outdated Java, Adobe Reader, browsers, and Office are major exploitation vectors. Recently installed software (date near an incident) should be investigated first. [THREAT: RAT disguised as legitimate tool, outdated software exploitation, crypto-miner]"
        HtmlAnchor = "logs"
        Script     = {
            Write-SectionHeader "LOGICIELS INSTALLES (registre)"
            $paths = @(
                "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
                "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
                "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
            )
            $apps = $paths | ForEach-Object {
                Get-ItemProperty $_ -ErrorAction SilentlyContinue
            } | Where-Object { $_.DisplayName } |
                Select-Object DisplayName, DisplayVersion, Publisher |
                Sort-Object DisplayName -Unique
            Write-Host "  Total: $($apps.Count) software entries" -ForegroundColor Yellow
            $apps | ForEach-Object {
                Write-Host ("  {0,-50} v{1,-20} {2}" -f `
                    $_.DisplayName, $_.DisplayVersion, $_.Publisher) -ForegroundColor Cyan
            }
            return ($apps | Format-Table -AutoSize | Out-String)
        }
    }

    "31" = @{
        Name       = "System Log (last 50)"
        ShortName  = "EVT-SYS"
        Category   = "Logs"
        Conseil    = "[IMPORTANT] Analyser les erreurs et avertissements : echecs repetitifs du Service Control Manager (service crashe ou tue par un logiciel-suspect), erreurs Ntfs (corruption disque, possible ransom-ware en action), modifications repetees du type de demarrage de services (indicateur de manipulation). Les evenements de securite (ID 4624/4625/4648/4688) sont dans le journal Securite, consultable via l'Observateur d'evenements avec droits admin. [MENACE: Manipulation de services, activite ransom-ware, compromission systeme]"
        HtmlAnchor = "syst"
        Script     = {
            Write-SectionHeader "JOURNAL SYSTEME (50 derniers evenements)"
            $events = Get-EventLog -LogName System -Newest 50 -ErrorAction SilentlyContinue
            $output = @()
            $output += ("{0,-22} {1,-12} {2,-30} {3}" -f "Date/Heure","Type","Source","Message (1ere ligne)")
            $output += ("-" * 110)
            $events | ForEach-Object {
                $evtType = $_.EntryType.ToString()
                $color = switch ($evtType) {
                    "Error"   { "Red" }
                    "Warning" { "Yellow" }
                    default   { "Gray" }
                }
                # Premiere ligne du message uniquement, tronquee a 80 chars
                $msgLines = $_.Message -split [System.Environment]::NewLine
                $msg = $msgLines[0].Trim()
                if ($msg.Length -gt 80) { $msg = $msg.Substring(0, 77) + "..." }
                $line = ("{0,-22} {1,-12} {2,-30} {3}" -f `
                    $_.TimeGenerated.ToString("dd/MM/yyyy HH:mm:ss"), $evtType, $_.Source, $msg)
                Write-Host "  $line" -ForegroundColor $color
                $output += $line
            }
            return ($output -join "`r`n")
        }
    }

    "32" = @{
        Name       = "Application Log (last 50)"
        ShortName  = "EVT-APP"
        Category   = "Logs"
        Conseil    = "[INFO] Repetitive application errors may indicate unstable software (crash loop). Check errors from unknown processes or with paths in %TEMP%/%APPDATA%. CertEnroll/certificate errors may signal a PKI issue or suspicious certificate enrollment attempt. Security application crashes (AV, EDR) may be intentional. [THREAT: Malware crashing protections, application injection, suspicious instability]"
        HtmlAnchor = "evtapp"
        Script     = {
            Write-SectionHeader "JOURNAL APPLICATION (50 derniers evenements)"
            $events = Get-EventLog -LogName Application -Newest 50 -ErrorAction SilentlyContinue
            $output = @()
            $output += ("{0,-22} {1,-12} {2,-30} {3}" -f "Date/Heure","Type","Source","Message (1ere ligne)")
            $output += ("-" * 110)
            $events | ForEach-Object {
                $evtType = $_.EntryType.ToString()
                $color = switch ($evtType) {
                    "Error"   { "Red" }
                    "Warning" { "Yellow" }
                    default   { "Gray" }
                }
                $msgLines = $_.Message -split [System.Environment]::NewLine
                $msg = $msgLines[0].Trim()
                if ($msg.Length -gt 80) { $msg = $msg.Substring(0, 77) + "..." }
                $line = ("{0,-22} {1,-12} {2,-30} {3}" -f `
                    $_.TimeGenerated.ToString("dd/MM/yyyy HH:mm:ss"), $evtType, $_.Source, $msg)
                Write-Host "  $line" -ForegroundColor $color
                $output += $line
            }
            return ($output -join "`r`n")
        }
    }

    "33" = @{
        Name       = "GPO / GPResult"
        ShortName  = "GPO"
        Category   = "Security"
        Conseil    = "[IMPORTANT] Verify that expected security GPOs are applied: password policy, software restriction (SRP/AppLocker), Office macro disabling, removable device blocking, firewall configuration. Unapplied GPOs (empty RSoP) may indicate a broken AD link or manipulation. Check that GPOs do not contain undocumented startup or logon scripts. [THREAT: Security policy bypass, GPO persistence, AD lateral movement]"
        HtmlAnchor = "rsop"
        Script     = {
            Write-SectionHeader "STRATEGIES DE GROUPE (gpresult /R)"
            $result = (cmd /c "chcp 65001 >nul 2>&1 & gpresult /R") 2>&1
            $result | ForEach-Object {
                $line  = $_
                $color = "Gray"
                if ($line -match "Strategie|Policy|GPO") { $color = "Yellow" }
                if ($line -match "Applique|Applied")      { $color = "Green" }
                Write-Host "  $line" -ForegroundColor $color
            }
            return ($result -join "`n")
        }
    }

    "34" = @{
        Name       = "Startup Programs"
        ShortName  = "STARTUP"
        Category   = "Persistence"
        Conseil    = "[CRITICAL] Run/RunOnce keys are the most common persistence vector for malware. Check each entry: path must point to a known executable in a system folder, not %TEMP%, %APPDATA%, %PUBLIC%, or a path with random characters. A base64-encoded entry or arguments like powershell -enc is a strong indicator of compromise. Compare with a clean baseline. Also check: HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon (Userinit, Shell). [THREAT: Malware persistence, RAT, ransomware, fileless via registry]"
        HtmlAnchor = "logdem"
        Script     = {
            Write-SectionHeader "PROGRAMMES AU DEMARRAGE (Run Keys)"
            $runKeys = @(
                "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
                "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
                "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
                "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run"
            )
            $output = @()
            foreach ($key in $runKeys) {
                Write-Host "  [$key]" -ForegroundColor Yellow
                $output += "[$key]"
                $props = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
                if ($props) {
                    $props.PSObject.Properties | Where-Object {$_.Name -notmatch "^PS"} | ForEach-Object {
                        $line = "    " + $_.Name + " = " + $_.Value
                        Write-Host $line -ForegroundColor Cyan
                        $output += $line
                    }
                } else {
                    Write-Host "    (empty)" -ForegroundColor DarkGray
                    $output += "  (empty)"
                }
            }
            return ($output -join "`n")
        }
    }

    "35" = @{
        Name       = "IPv6 - Addresses and Privacy"
        ShortName  = "IPv6"
        Category   = "Network"
        Conseil    = "[INFO] If IPv6 is not used in the organization, disable it to reduce the attack surface. Teredo or 6to4 IPv6 addresses can be used to tunnel traffic and bypass firewalls not filtering IPv6. SLAAC (IPv6 auto-addressing) can assign addresses without DHCP control, making traceability difficult. An unknown IPv6 neighbor in the neighbor table may indicate a scanner or pivot. [THREAT: IPv6 tunnel, firewall bypass, network scan, pivot via Teredo]"
        HtmlAnchor = "adip6"
        Script     = {
            Write-SectionHeader "IPv6 - ADRESSES, INTERFACES, PRIVACY, NEIGHBORS"
            Write-Host "  -- Addresses --" -ForegroundColor Yellow
            (cmd /c "chcp 65001 >nul 2>&1 & netsh int ipv6 show addresses") 2>&1 | ForEach-Object { Write-Host "  $_" -ForegroundColor Cyan }
            Write-Host "  -- Interfaces --" -ForegroundColor Yellow
            (cmd /c "chcp 65001 >nul 2>&1 & netsh int ipv6 show int") 2>&1 | ForEach-Object { Write-Host "  $_" -ForegroundColor Cyan }
            Write-Host "  -- Privacy --" -ForegroundColor Yellow
            (cmd /c "chcp 65001 >nul 2>&1 & netsh int ipv6 show privacy") 2>&1 | ForEach-Object { Write-Host "  $_" -ForegroundColor Cyan }
            Write-Host "  -- Neighbors --" -ForegroundColor Yellow
            $nb = (cmd /c "chcp 65001 >nul 2>&1 & netsh int ipv6 show neighbor") 2>&1
            $nb | ForEach-Object { Write-Host "  $_" -ForegroundColor Cyan }
            return ($nb -join "`n")
        }
    }

    # =========================================================================
    #  NOUVEAUX MODULES - Categorie : Chiffrement
    # =========================================================================

    "36" = @{
        Name       = "BitLocker - Disk Encryption"
        ShortName  = "BITLOCKER"
        Category   = "Encryption"
        Conseil    = "[CRITICAL] All mobile workstations must have BitLocker active on C:. An unencrypted disk allows direct data reading if stolen (USB boot, disk extraction). Verify the recovery key is saved in AD or Azure AD. ProtectionStatus=Off indicates encryption is suspended (typically after a BIOS update): it must be re-enabled quickly. [THREAT: Data theft via disk extraction, unauthorized physical access, laptop theft]"
        HtmlAnchor = "bitlocker"
        Script     = {
            Write-SectionHeader "CHIFFREMENT BITLOCKER"
            $output = @()
            try {
                $vols = Get-BitLockerVolume -ErrorAction Stop
                $vols | ForEach-Object {
                    $status = $_.ProtectionStatus
                    $pct    = $_.EncryptionPercentage
                    $method = $_.EncryptionMethod
                    $color  = if ($status -eq "On") { "Green" } elseif ($status -eq "Off") { "Red" } else { "Yellow" }
                    $line = ("  {0,-6} Protection:{1,-10} Encryption:{2,4}%  Method:{3}" -f `
                        $_.MountPoint, $status, $pct, $method)
                    Write-Host $line -ForegroundColor $color
                    $output += $line
                    $_.KeyProtector | ForEach-Object {
                        $kline = ("         Protecteur : {0}" -f $_.KeyProtectorType)
                        Write-Host $kline -ForegroundColor DarkGray
                        $output += $kline
                    }
                }
            } catch {
                Write-Host "  BitLocker not available or not configured on this system." -ForegroundColor Yellow
                $output += "BitLocker not available."
            }
            return ($output -join "`n")
        }
    }

    "37" = @{
        Name       = "Certificates - System Store"
        ShortName  = "CERTS"
        Category   = "Encryption"
        Conseil    = "[IMPORTANT] Check for unknown root certificates in Cert:\LocalMachine\Root: a malicious root certificate enables transparent HTTPS interception (MITM on all TLS traffic). Check expired certificates that may block services. Self-signed certificates in the trust store are suspicious in enterprise environments. [THREAT: TLS/HTTPS interception, MITM via fake root certificate, network espionage]"
        HtmlAnchor = "certs"
        Script     = {
            Write-SectionHeader "CERTIFICATS DU MAGASIN SYSTEME"
            $output = @()
            $stores = @("Root","CA","My","TrustedPublisher")
            foreach ($storeName in $stores) {
                try {
                    $certs = Get-ChildItem "Cert:\LocalMachine\$storeName" -ErrorAction SilentlyContinue
                    if (-not $certs) { continue }
                    Write-Host ("  -- Store: LocalMachine\{0} ({1} certificate(s)) --" -f $storeName, $certs.Count) -ForegroundColor Yellow
                    $output += ("=== LocalMachine\{0} ({1} certs) ===" -f $storeName, $certs.Count)
                    $certs | Sort-Object NotAfter | ForEach-Object {
                        $expired = ($_.NotAfter -lt (Get-Date))
                        $expiring = ($_.NotAfter -lt (Get-Date).AddDays(30) -and -not $expired)
                        $color = if ($expired) { "Red" } elseif ($expiring) { "Yellow" } else { "DarkGray" }
                        $flag  = if ($expired) { "[EXPIRE]" } elseif ($expiring) { "[EXPIRE BIENTOT]" } else { "" }
                        $line  = ("  {0,-50} Exp:{1:dd/MM/yyyy}  {2}" -f `
                            ($_.Subject -replace "CN=","" -replace ",.*",""), $_.NotAfter, $flag)
                        Write-Host $line -ForegroundColor $color
                        $output += $line
                    }
                } catch {}
            }
            return ($output -join "`n")
        }
    }

    # =========================================================================
    #  NOUVEAUX MODULES - Categorie : Forensique
    # =========================================================================

    "38" = @{
        Name       = "Security Log (last 50)"
        ShortName  = "EVT-SEC"
        Category   = "Forensics"
        Conseil    = "[CRITICAL] The Security log contains critical authentication events. ID 4625 (logon failure) in bulk = ongoing brute-force. ID 4648 (logon with explicit credentials) = potential pass-the-h4sh. ID 4720/4732 (account creation / group addition) = suspicious persistence. ID 4698/4702 (scheduled task creation) = persistence. ID 4688 (process creation) if auditing enabled = execution traceability. [THREAT: Brute-force, pass-the-h4sh, suspicious account creation, privilege escalation]"
        HtmlAnchor = "evtsec"
        Script     = {
            Write-SectionHeader "JOURNAL SECURITE (50 derniers evenements)"
            $output = @()
            $output += ("{0,-22} {1,-8} {2,-8} {3,-25} {4}" -f "Date/Heure","EventID","Type","Source","Message")
            $output += ("-" * 110)
            # IDs critiques a surveiller
            $criticalIds = @(4625,4648,4720,4722,4724,4728,4732,4756,4698,4702,4688,4697,4776,1102)
            try {
                $events = Get-EventLog -LogName Security -Newest 50 -ErrorAction Stop
                $events | ForEach-Object {
                    $evtId   = $_.EventID
                    $isCrit  = $criticalIds -contains $evtId
                    $color   = if ($isCrit) { "Red" } elseif ($_.EntryType -eq "FailureAudit") { "Yellow" } else { "Gray" }
                    $flag    = if ($isCrit) { "[!]" } else { "   " }
                    $msg     = ($_.Message -split [System.Environment]::NewLine)[0].Trim()
                    if ($msg.Length -gt 60) { $msg = $msg.Substring(0,57) + "..." }
                    $line = ("{0,-22} {1} {2,-8} {3,-8} {4,-25} {5}" -f `
                        $_.TimeGenerated.ToString("dd/MM/yyyy HH:mm:ss"), $flag, $evtId,
                        $_.EntryType, $_.Source, $msg)
                    Write-Host "  $line" -ForegroundColor $color
                    $output += $line
                }
            } catch {
                $msg = "Access denied to Security log or empty log. Verify administrator rights."
                Write-Host "  $msg" -ForegroundColor Red
                $output += $msg
            }
            return ($output -join "`n")
        }
    }

    "39" = @{
        Name       = "Recently Modified Files (72h)"
        ShortName  = "RECENT-FILES"
        Category   = "Forensics"
        Conseil    = "[IMPORTANT] Recently modified files in sensitive folders may indicate suspicious activity. Check changes in: System32, startup folders, user profiles. New .exe or .dll files in %TEMP% or %APPDATA% are strong indicators of compromise. Files with double extensions (doc.exe, pdf.exe) are characteristic of RATs. [THREAT: Payload drop, system binary modification, dropper]"
        HtmlAnchor = "recentfiles"
        Script     = {
            Write-SectionHeader "FICHIERS RECEMMENT MODIFIES (72 heures)"
            $output = @()
            $since  = (Get-Date).AddHours(-72)
            $searchPaths = @(
                "$env:SystemRoot\System32",
                "$env:TEMP",
                "$env:APPDATA",
                "$env:PUBLIC",
                "$env:USERPROFILE\Downloads",
                "$env:USERPROFILE\Desktop",
                "C:\Users\Public"
            )
            $suspExtensions = @("*.exe","*.dll","*.bat","*.ps1","*.vbs","*.js","*.hta","*.cmd","*.scr","*.com","*.pif")
            foreach ($path in $searchPaths) {
                if (-not (Test-Path $path)) { continue }
                $files = @()
                foreach ($ext in $suspExtensions) {
                    $found = Get-ChildItem -Path $path -Filter $ext -Recurse -ErrorAction SilentlyContinue |
                        Where-Object { $_.LastWriteTime -ge $since -and -not $_.PSIsContainer } |
                        Select-Object -First 20
                    $files += $found
                }
                if ($files.Count -gt 0) {
                    Write-Host ("  -- {0} ({1} suspicious file(s)) --" -f $path, $files.Count) -ForegroundColor Yellow
                    $output += ("=== $path ===")
                    $files | Sort-Object LastWriteTime -Descending | ForEach-Object {
                        $color = if ($path -match "Temp|AppData|Public|Download|Desktop") { "Red" } else { "Cyan" }
                        $line  = ("  {0,-50} {1:dd/MM/yyyy HH:mm}  {2,10} Ko" -f `
                            $_.Name, $_.LastWriteTime, [math]::Round($_.Length/1KB,1))
                        Write-Host $line -ForegroundColor $color
                        $output += "$($_.FullName)  |  $($_.LastWriteTime)  |  $([math]::Round($_.Length/1KB,1)) Ko"
                    }
                } else {
                    Write-Host ("  {0}: no executable file recently modified" -f $path) -ForegroundColor DarkGray
                }
            }
            return ($output -join "`n")
        }
    }

    "40" = @{
        Name       = "Recent RDP Connections"
        ShortName  = "RDP-HIST"
        Category   = "Forensics"
        Conseil    = "[IMPORTANT] L'historique RDP revele les serveurs auxquels l'utilisateur s'est connecte et les utilisateurs qui se sont connectes en RDP sur ce poste. Des connexions vers des IPs inconnues peuvent indiquer un mouvement lateral. Des connexions depuis des IPs externes non attendues peuvent indiquer une compromission de credentials RDP. [MENACE: Mouvement lateral RDP, acces non autorise, compromission de credentials]"
        HtmlAnchor = "rdphist"
        Script     = {
            Write-SectionHeader "RDP CONNECTION HISTORY"
            $output = @()
            # Serveurs auxquels l'utilisateur s'est connecte (client RDP)
            $rdpKey = "HKCU:\Software\Microsoft\Terminal Server Client\Servers"
            Write-Host "  -- RDP servers contacted (client) --" -ForegroundColor Yellow
            $output += "=== Serveurs RDP contactes ==="
            if (Test-Path $rdpKey) {
                Get-ChildItem $rdpKey -ErrorAction SilentlyContinue | ForEach-Object {
                    $server = $_.PSChildName
                    $user   = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).UsernameHint
                    $line   = ("  Server: {0,-40}  User: {1}" -f $server, $user)
                    Write-Host $line -ForegroundColor Cyan
                    $output += $line
                }
            } else {
                Write-Host "  No RDP client connection history found." -ForegroundColor DarkGray
                $output += "No RDP client history."
            }
            # Connexions RDP recues (journal evenements)
            Write-Host ""
            Write-Host "  -- Inbound RDP connections (TerminalServices log) --" -ForegroundColor Yellow
            $output += "`n=== Connexions RDP recues ==="
            try {
                $rdpEvents = Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" `
                    -MaxEvents 30 -ErrorAction Stop |
                    Where-Object { $_.Id -in @(21,22,23,24,25) } |
                    Select-Object TimeCreated, Id, Message
                if ($rdpEvents) {
                    $rdpEvents | ForEach-Object {
                        $color = if ($_.Id -eq 21) { "Green" } elseif ($_.Id -in 23,24) { "Yellow" } else { "Gray" }
                        $msg = ($_.Message -split "`n")[0].Trim()
                        if ($msg.Length -gt 80) { $msg = $msg.Substring(0,77) + "..." }
                        $line = ("  [{0:dd/MM/yyyy HH:mm}] ID:{1}  {2}" -f $_.TimeCreated, $_.Id, $msg)
                        Write-Host $line -ForegroundColor $color
                        $output += $line
                    }
                } else {
                    Write-Host "  No recent inbound RDP connections." -ForegroundColor DarkGray
                    $output += "No recent RDP connection."
                }
            } catch {
                Write-Host "  TerminalServices log inaccessible or RDP not used." -ForegroundColor DarkGray
                $output += "TerminalServices log not available."
            }
            return ($output -join "`n")
        }
    }

    "41" = @{
        Name       = "PowerShell Activity (history)"
        ShortName  = "PS-HIST"
        Category   = "Forensics"
        Conseil    = "[CRITICAL] PowerShell history contains recently executed commands. Encoded commands (base64), calls to Download-String/Web-Client/Invoke-Expr, network connections from PS (New-Object Net.Web-Client) are strong indicators of suspicious activity or fileless attack. PS history can also be cleared by an attacker: its complete absence is suspicious. [THREAT: Fileless attack, payload download, remote execution via PS]"
        HtmlAnchor = "pshist"
        Script     = {
            Write-SectionHeader "POWERSHELL HISTORY"
            $output = @()
            $histPaths = @(
                "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt",
                "$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
            )
            $found = $false
            foreach ($histPath in $histPaths) {
                if (Test-Path $histPath) {
                    $found = $true
                    $lines = Get-Content $histPath -ErrorAction SilentlyContinue | Select-Object -Last 100
                    Write-Host ("  File: $histPath ({0} total lines)" -f (Get-Content $histPath).Count) -ForegroundColor Yellow
                    $output += "=== $histPath ==="
                    # Mettre en evidence les commandes suspectes
                    $suspPatterns = "(?i)DownloadString|WebClient|Invoke-Expression|iex |encodedcommand|-enc |base64|Net\.WebClient|Start-Process.*http|Invoke-WebRequest|curl.*http|wget.*http|bypass|hidden|nop\b"
                    $lines | ForEach-Object {
                        $line = $_
                        $isSusp = $line -match $suspPatterns
                        $color  = if ($isSusp) { "Red" } else { "Cyan" }
                        $flag   = if ($isSusp) { " [SUSPECT]" } else { "" }
                        Write-Host ("  $line$flag") -ForegroundColor $color
                        $output += "$line$flag"
                    }
                    break
                }
            }
            if (-not $found) {
                Write-Host "  PowerShell history not found (PSReadLine not installed or cleared)." -ForegroundColor Yellow
                $output += "PowerShell history not available or cleared."
            }
            return ($output -join "`n")
        }
    }

    # =========================================================================
    #  NOUVEAUX MODULES - Categorie : Vulnerabilites
    # =========================================================================

    "42" = @{
        Name       = "UAC Rights and Privileges"
        ShortName  = "UAC"
        Category   = "Vulnerabilities"
        Conseil    = "[CRITICAL] Disabled UAC removes confirmation prompts for privileged operations, allowing any process to obtain SYSTEM rights without interaction. ConsentPromptBehaviorAdmin=0 means silent elevation. Ensure the current user is not a permanent Administrator (least privilege). [THREAT: Silent privilege escalation, UAC bypass, SYSTEM execution without alert]"
        HtmlAnchor = "uac"
        Script     = {
            Write-SectionHeader "CONFIGURATION UAC ET PRIVILEGES"
            $output = @()
            # Etat UAC
            $uacKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
            $uac = Get-ItemProperty $uacKey -ErrorAction SilentlyContinue
            $items = [ordered]@{
                "EnableLUA"                    = $uac.EnableLUA
                "ConsentPromptBehaviorAdmin"   = $uac.ConsentPromptBehaviorAdmin
                "ConsentPromptBehaviorUser"    = $uac.ConsentPromptBehaviorUser
                "PromptOnSecureDesktop"        = $uac.PromptOnSecureDesktop
                "EnableVirtualization"         = $uac.EnableVirtualization
            }
            $uacLabels = @{
                "EnableLUA"                  = @{0="[RISQUE] UAC desactive"; 1="[OK] UAC active"}
                "ConsentPromptBehaviorAdmin" = @{0="[RISQUE] Elevation silencieuse"; 1="Credential si non-admin"; 2="[OK] Demande de confirmation"; 5="[OK] Demande confirmation bureau securise"}
                "PromptOnSecureDesktop"      = @{0="[RISK] Unsecured desktop"; 1="[OK] Secure desktop"}
            }
            foreach ($k in $items.Keys) {
                $val = $items[$k]
                $lbl = if ($uacLabels.ContainsKey($k) -and $null -ne $val -and $uacLabels[$k].ContainsKey([int]$val)) { $uacLabels[$k][[int]$val] } else { "" }
                $color = if ($lbl -match "RISQUE") { "Red" } elseif ($lbl -match "OK") { "Green" } else { "Cyan" }
                $line = ("  {0,-40}: {1,-5} {2}" -f $k, $val, $lbl)
                Write-Host $line -ForegroundColor $color
                $output += $line
            }
            Write-Host ""
            # Privileges du processus courant
            Write-Host "  -- Current token privileges --" -ForegroundColor Yellow
            $output += "`n=== Token courant ==="
            $whoami = (cmd /c "chcp 65001 >nul 2>&1 & whoami /priv") 2>&1
            $whoami | ForEach-Object {
                $color = if ($_ -match "Enabled|Active") { "Yellow" } else { "DarkGray" }
                Write-Host "  $_" -ForegroundColor $color
                $output += $_
            }
            return ($output -join "`n")
        }
    }

    "43" = @{
        Name       = "AppLocker / SRP"
        ShortName  = "APPLOCKER"
        Category   = "Vulnerabilities"
        Conseil    = "[IMPORTANT] AppLocker and Software Restriction Policies limit execution to authorized executables. Without these, any user can run any binary, PS script, VBS, or HTA. AppLocker should block execution from TEMP, APPDATA, and user folders. Absence of AppLocker rules on a sensitive machine is a major security gap. [THREAT: Payload execution, LOLBins, unauthorized scripts, AV bypass]"
        HtmlAnchor = "applocker"
        Script     = {
            Write-SectionHeader "APPLOCKER / SOFTWARE RESTRICTION POLICIES"
            $output = @()
            # Verifier AppLocker
            Write-Host "  -- AppLocker --" -ForegroundColor Yellow
            $output += "=== AppLocker ==="
            try {
                $alSvc = Get-Service -Name AppIDSvc -ErrorAction Stop
                $color  = if ($alSvc.Status -eq "Running") { "Green" } else { "Yellow" }
                $line   = ("  AppIDSvc service (AppLocker): {0}" -f $alSvc.Status)
                Write-Host $line -ForegroundColor $color
                $output += $line
                # Lire les regles AppLocker
                $alKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2"
                if (Test-Path $alKey) {
                    $categories = @("Exe","Msi","Script","Appx","Dll")
                    foreach ($cat in $categories) {
                        $catKey = "$alKey\$cat"
                        if (Test-Path $catKey) {
                            $rules = Get-ChildItem $catKey -ErrorAction SilentlyContinue
                            $line = ("  Rules {0,-8}: {1} rule(s) configured" -f $cat, $rules.Count)
                            $color = if ($rules.Count -gt 0) { "Green" } else { "Yellow" }
                            Write-Host $line -ForegroundColor $color
                            $output += $line
                        } else {
                            $line = ("  Rules {0,-8}: no rules" -f $cat)
                            Write-Host $line -ForegroundColor DarkGray
                            $output += $line
                        }
                    }
                } else {
                    Write-Host "  AppLocker not configured (no SrpV2 policy)." -ForegroundColor Red
                    $output += "AppLocker not configured."
                }
            } catch {
                Write-Host "  AppLocker service not available on this Windows edition." -ForegroundColor DarkGray
                $output += "AppLocker not available."
            }
            # Verifier SRP classique
            Write-Host ""
            Write-Host "  -- Software Restriction Policies (SRP) --" -ForegroundColor Yellow
            $output += "`n=== SRP ==="
            $srpKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer"
            if (Test-Path $srpKey) {
                Write-Host "  SRP configured." -ForegroundColor Green
                $output += "SRP configure."
            } else {
                Write-Host "  SRP not configured." -ForegroundColor Red
                $output += "SRP not configured."
            }
            return ($output -join "`n")
        }
    }

    "44" = @{
        Name       = "Credential Guard / LSA Protection"
        ShortName  = "LSAPROT"
        Category   = "Vulnerabilities"
        Conseil    = "[CRITICAL] LSA Protection (RunAsPPL) prevents reading lsass.exe memory by credential theft tools. Without this protection, Mimi-katz can extract hashes and cleartext passwords from lsass in seconds. Credential Guard isolates credentials in a virtualized environment. Both protections are essential on any administrator workstation. [THREAT: Credential theft from lsass, pass-the-h4sh, pass-the-t1cket]"
        HtmlAnchor = "lsaprot"
        Script     = {
            Write-SectionHeader "PROTECTION LSA / CREDENTIAL GUARD"
            $output = @()
            # LSA Protection (RunAsPPL)
            Write-Host "  -- LSA Protection (RunAsPPL) --" -ForegroundColor Yellow
            $lsaKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
            $lsaProps = Get-ItemProperty $lsaKey -ErrorAction SilentlyContinue
            $runAsPPL = $lsaProps.RunAsPPL
            $color = if ($runAsPPL -eq 1) { "Green" } else { "Red" }
            $label = if ($runAsPPL -eq 1) { "[PROTEGE] LSA RunAsPPL active" } else { "[RISQUE] LSA RunAsPPL desactive - lsass lisible" }
            Write-Host ("  RunAsPPL: {0}  {1}" -f $runAsPPL, $label) -ForegroundColor $color
            $output += "RunAsPPL=$runAsPPL  $label"
            # Credential Guard
            Write-Host ""
            Write-Host "  -- Credential Guard --" -ForegroundColor Yellow
            $cgKey = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard"
            $cgProps = Get-ItemProperty $cgKey -ErrorAction SilentlyContinue
            if ($cgProps) {
                $cgEnabled  = $cgProps.EnableVirtualizationBasedSecurity
                $cgRequired = $cgProps.RequirePlatformSecurityFeatures
                $cgColor = if ($cgEnabled -eq 1) { "Green" } else { "Yellow" }
                $cgLine1 = ("  VBS (Virtualization Based Security): {0}" -f $cgEnabled)
                $cgLine2 = ("  RequirePlatformSecurityFeatures: {0}" -f $cgRequired)
                Write-Host $cgLine1 -ForegroundColor $cgColor
                Write-Host $cgLine2 -ForegroundColor DarkGray
                $output += $cgLine1; $output += $cgLine2
            } else {
                Write-Host "  Device Guard / Credential Guard: registry key absent." -ForegroundColor DarkGray
                $output += "Device Guard not configured."
            }
            # WDigest (stockage mot de passe en clair)
            Write-Host ""
            Write-Host "  -- WDigest (cleartext passwords in memory) --" -ForegroundColor Yellow
            $wdKey = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
            $wdProps = Get-ItemProperty $wdKey -ErrorAction SilentlyContinue
            $useLogonCred = if ($wdProps) { $wdProps.UseLogonCredential } else { $null }
            $wdColor = if ($useLogonCred -eq 1) { "Red" } else { "Green" }
            $wdLabel = if ($useLogonCred -eq 1) { "[CRITICAL] WDigest actif : mots de passe en clair en memoire !" } else { "[OK] WDigest desactive (recommande)" }
            Write-Host ("  UseLogonCredential: {0}  {1}" -f $useLogonCred, $wdLabel) -ForegroundColor $wdColor
            $output += "WDigest UseLogonCredential=$useLogonCred  $wdLabel"
            return ($output -join "`n")
        }
    }

    "45" = @{
        Name       = "Established Connections - GeoIP"
        ShortName  = "NET-GEO"
        Category   = "Vulnerabilities"
        Conseil    = "[IMPORTANT] Verifier les connexions ESTABLISHED vers des IPs etrangeres ou des plages IP inhabituelles. Les connexions vers des hebergeurs cloud inconnus (AS non reconnus) peuvent indiquer un C2. Des connexions persistantes vers des pays avec lesquels l'organisation n'a pas de relation d'affaires sont suspectes. Croiser les IPs avec des bases de reputation (AbuseIPDB, VirusTotal). [MENACE: C2, exfiltration de donnees, communication avec infrastructure hostile]"
        HtmlAnchor = "netgeo"
        Script     = {
            Write-SectionHeader "CONNEXIONS ETABLIES (IPs externes)"
            $output = @()
            $output += ("{0,-25} {1,-25} {2,-8} {3}" -f "IP Locale","IP Distante","Port","Processus")
            $output += ("-" * 80)
            try {
                $conns = Get-NetTCPConnection -State Established -ErrorAction Stop |
                    Where-Object { $_.RemoteAddress -notmatch "^(127\.|::1|0\.0\.0\.0|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)" } |
                    Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort,
                        @{N="Processus";E={
                            try { (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Name }
                            catch { "?" }
                        }},
                        OwningProcess |
                    Sort-Object RemoteAddress
                if ($conns) {
                    $conns | ForEach-Object {
                        $line = ("{0,-25} {1,-25} {2,-8} {3} (PID:{4})" -f `
                            "$($_.LocalAddress):$($_.LocalPort)", "$($_.RemoteAddress):$($_.RemotePort)",
                            $_.RemotePort, $_.Processus, $_.OwningProcess)
                        # Colorer les processus suspects
                        $color = if ($_.Processus -match "(?i)powershell|cmd|wscript|cscript|mshta|rundll32") { "Red" }
                                 elseif ($_.Processus -match "(?i)chrome|firefox|edge|msedge|outlook") { "Green" }
                                 else { "Cyan" }
                        Write-Host "  $line" -ForegroundColor $color
                        $output += $line
                    }
                } else {
                    Write-Host "  No established connections to external IPs." -ForegroundColor DarkGray
                    $output += "No external connection established."
                }
            } catch {
                Write-Host "  [ERROR] $($_.Exception.Message)" -ForegroundColor Red
                $output += "[ERROR] $($_.Exception.Message)"
            }
            return ($output -join "`n")
        }
    }

    "46" = @{
        Name       = "Loaded PowerShell Modules"
        ShortName  = "PS-MODULES"
        Category   = "Vulnerabilities"
        Conseil    = "[IMPORTANT] Verifier les modules PS charges dans la session courante. Des modules inconnus ou non signes peuvent avoir ete importes par un attaquant. Verifier aussi les modules installes dans les chemins non standard (hors C:\Windows\System32\WindowsPowerShell). Les modules avec des fonctions comme Invoke-*, Get-Hash*, Out-Minidump sont caracteristiques des boites a outils offensives. [MENACE: Outils offensifs charges en memoire, persistance via module PS, attaque sans-fichier]"
        HtmlAnchor = "psmodules"
        Script     = {
            Write-SectionHeader "MODULES POWERSHELL ET POLITIQUE DE JOURNALISATION"
            $output = @()
            # Modules PS installes (hors systeme)
            Write-Host "  -- Installed PS modules (non-system) --" -ForegroundColor Yellow
            $output += "=== PS Modules ==="
            $modules = Get-Module -ListAvailable -ErrorAction SilentlyContinue |
                Where-Object { $_.Path -notmatch "(?i)System32|Program Files\\WindowsPowerShell\\Modules\\PackageManagement" } |
                Sort-Object Name
            if ($modules) {
                $modules | Select-Object -First 50 | ForEach-Object {
                    $color = "Cyan"
                    if ($_.Path -match "(?i)appdata|temp|users\\[^\\]+\\documents") { $color = "Yellow" }
                    $line = ("  {0,-40} v{1,-15} {2}" -f $_.Name, $_.Version, $_.Path)
                    Write-Host $line -ForegroundColor $color
                    $output += $line
                }
            } else {
                Write-Host "  No non-system module installed." -ForegroundColor DarkGray
                $output += "No non-system module."
            }
            # Journalisation PS
            Write-Host ""
            Write-Host "  -- PowerShell logging configuration --" -ForegroundColor Yellow
            $output += "`n=== Journalisation PS ==="
            $psLogKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell"
            $psKeys = @(
                @{K="$psLogKey\ScriptBlockLogging";  V="EnableScriptBlockLogging"; Label="Script Block Logging"},
                @{K="$psLogKey\ModuleLogging";        V="EnableModuleLogging";       Label="Module Logging"},
                @{K="$psLogKey\Transcription";        V="EnableTranscripting";       Label="Transcription"}
            )
            foreach ($pk in $psKeys) {
                $val = $null
                if (Test-Path $pk.K) { $val = (Get-ItemProperty $pk.K -ErrorAction SilentlyContinue).($pk.V) }
                $color = if ($val -eq 1) { "Green" } else { "Red" }
                $label = if ($val -eq 1) { "[ACTIVE]" } else { "[INACTIVE] - recommended for detection" }
                $line  = ("  {0,-30}: {1}" -f $pk.Label, $label)
                Write-Host $line -ForegroundColor $color
                $output += $line
            }
            return ($output -join "`n")
        }
    }


}

# ---------------------------------------------------------------------------
#  GENERATION DU RAPPORT HTML
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
#  SCORING DE SECURITE - Analyse automatique des resultats (46 modules)
# ---------------------------------------------------------------------------

function Compute-SecurityScore {
    param([hashtable]$Results)

    $domains = [System.Collections.Generic.List[object]]::new()

    function Has      { param($k,$p) if (-not $Results.ContainsKey($k)){return $false}; return ($Results[$k] -match $p) }
    function NotHas   { param($k,$p) if (-not $Results.ContainsKey($k)){return $false}; return (-not($Results[$k] -match $p)) }
    function ResultOf { param($k)    if ($Results.ContainsKey($k)){return $Results[$k]} else {return ""} }
    function AddDomain{ param($label,$anchor,$score,$issues,$weight)
        $domains.Add(@{Label=$label;Anchor=$anchor;Score=[math]::Max(0,[math]::Min(10,$score));Issues=$issues;Weight=$weight}) }

    # -- 01 BCD / Demarrage ----------------------------------------------------
    if ($Results.ContainsKey("01")) {
        $s=10; $i=@()
        if (Has "01" "(?i)bootdebug\s+yes|testsigning\s+yes") { $s-=4; $i+="Debug/test mode active (unsigned code execution)" }
        if (Has "01" "(?i)recoveryenabled\s+no")               { $s-=2; $i+="Recovery disabled" }
        AddDomain "Boot Manager (BCD)" "bcd" $s $i 2
    }

    # -- 02 OS / Version -------------------------------------------------------
    if ($Results.ContainsKey("02")) {
        $s=10; $i=@()
        $r = ResultOf "02"
        if ($r -match "(?i)Windows 7|Windows 8[^.1]|2008|2003|2000|XP|Vista") { $s-=7; $i+="End-of-life OS (EOL)" }
        elseif ($r -match "(?i)Windows 8\.1|2012")                              { $s-=4; $i+="OS proche fin de support" }
        if ($r -match "Uptime\s*:\s*(\d+)j") {
            $d=[int]$Matches[1]
            if ($d -gt 90) { $s-=3; $i+="Uptime $d jours - MAJ probablement en attente" }
            elseif ($d -gt 30) { $s-=1; $i+="Uptime $d days - check for updates" }
        }
        AddDomain "Operating System" "infos" $s $i 3
    }

    # -- 03 Variables d'environnement ------------------------------------------
    if ($Results.ContainsKey("03")) {
        $s=10; $i=@()
        $r = ResultOf "03"
        # PATH contenant un dossier utilisateur avant System32 = DLL hijacking
        if ($r -match "(?i)PATH.*Users.*System32|PATH.*Temp") { $s-=3; $i+="Suspicious PATH: user folder before System32 (DLL hijacking risk)" }
        if ($r -match "(?i)TEMP.*Users.*AppData") { }  # normal
        elseif ($r -match "(?i)TEMP\s*=\s*C:\\Windows") { $s-=2; $i+="TEMP variable points to C:\Windows (unusual)" }
        AddDomain "Environment Variables" "infenv" $s $i 1
    }

    # -- 04+05 Processus -------------------------------------------------------
    if ($Results.ContainsKey("05")) {
        $s=10; $i=@()
        $r = ResultOf "05"
        # Processus depuis TEMP ou APPDATA
        $suspProc = ($r -split "`n" | Where-Object { $_ -match "(?i)temp\\\\|appdata\\\\|public\\\\" -and $_ -match "\.(exe|dll|bat|ps1)" })
        if ($suspProc.Count -gt 0) { $s-=5; $i+="$($suspProc.Count) process(es) running from TEMP/APPDATA/PUBLIC detected" }
        # Noms imitant des processus systeme
        if ($r -match "(?i)svchost\d|svch0st|lsass_|csrss_|winlogon_") { $s-=5; $i+="Nom de processus imitant un binaire systeme (typosquatting)" }
        AddDomain "Processus actifs" "lstps" $s $i 3
    }

    # -- 06 ExecutionPolicy ----------------------------------------------------
    if ($Results.ContainsKey("06")) {
        $s=10; $i=@()
        if (Has "06" "(?i)Unrestricted") { $s-=6; $i+="ExecutionPolicy Unrestricted: any PS script can run" }
        elseif (Has "06" "(?i)Bypass")   { $s-=5; $i+="ExecutionPolicy Bypass detected" }
        elseif (Has "06" "(?i)Undefined") { $s-=2; $i+="ExecutionPolicy not defined on one or more scopes" }
        AddDomain "PowerShell Policy" "polpws" $s $i 2
    }

    # -- 07 Secedit ------------------------------------------------------------
    if ($Results.ContainsKey("07")) {
        $s=10; $i=@()
        $r = ResultOf "07"
        if ($r -match "MinimumPasswordLength\s*=\s*([0-9]+)") {
            $pl=[int]$Matches[1]
            if ($pl -lt 8)  { $s-=4; $i+="Mot de passe min $pl chars (recommande >= 12)" }
            elseif ($pl -lt 12) { $s-=2; $i+="Mot de passe min $pl chars (recommande >= 12)" }
        }
        if ($r -match "PasswordComplexity\s*=\s*0") { $s-=3; $i+="Password complexity disabled" }
        if ($r -match "LockoutBadCount\s*=\s*0")    { $s-=3; $i+="No lockout after failures (brute-force possible)" }
        if ($r -match "MaximumPasswordAge\s*=\s*0")  { $s-=2; $i+="Password expiration disabled" }
        AddDomain "Security Policy" "polsec" $s $i 3
    }

    # -- 08 Comptes locaux -----------------------------------------------------
    if ($Results.ContainsKey("08")) {
        $s=10; $i=@()
        $r = ResultOf "08"
        if ($r -match "(?i)(Administrator|Administrateur).*Actif\s*:\s*True") { $s-=3; $i+="Built-in Administrator account active" }
        if ($r -match "(?i)(Guest|Invite).*Actif\s*:\s*True")                  { $s-=3; $i+="Guest account active" }
        if ($r -match "(?i)\[!MOT DE PASSE VIDE\]")                            { $s-=5; $i+="Account(s) with no password detected" }
        AddDomain "Local Accounts" "licpt" $s $i 3
    }

    # -- 09 Groupes locaux -----------------------------------------------------
    if ($Results.ContainsKey("09")) {
        $s=10; $i=@()
        $r = ResultOf "09"
        # Compter les membres du groupe Administrateurs
        $inAdmBlock = $false; $admCount = 0
        ($r -split "`n") | ForEach-Object {
            if ($_ -match "Administrateurs|Administrators") { $inAdmBlock = $true }
            elseif ($_ -match "^\[") { $inAdmBlock = $false }
            elseif ($inAdmBlock -and $_ -match "^\s*-\s*.+") { $admCount++ }
        }
        if ($admCount -gt 3) { $s-=3; $i+="$admCount members in the Administrators group (least privilege not applied)" }
        elseif ($admCount -gt 2) { $s-=1; $i+="$admCount members in Administrators - verify if all necessary" }
        AddDomain "Local Groups" "ligrp" $s $i 2
    }

    # -- 10 Partages SMB -------------------------------------------------------
    if ($Results.ContainsKey("10")) {
        $s=10; $i=@()
        $r = ResultOf "10"
        $admShares = ([regex]::Matches($r,"(?i)\b[A-Z]\`$\b|ADMIN\`$|IPC\`$")).Count
        if ($admShares -gt 0) { $s-=3; $i+="$admShares partage(s) administratif(s) actif(s)" }
        $totalLines = ($r -split "`n" | Where-Object { $_ -match "\S" }).Count
        if ($totalLines -gt 8) { $s-=2; $i+="Many shares detected - verify undocumented ones" }
        AddDomain "Network Shares (SMB)" "shares" $s $i 3
    }

    # -- 11 USB ----------------------------------------------------------------
    if ($Results.ContainsKey("11")) {
        $s=10; $i=@()
        $r = ResultOf "11"
        $usbCount = ($r -split "`n" | Where-Object { $_ -match "\S" -and $_ -notmatch "^=|^-|^Serial|^Friendly" }).Count
        if ($usbCount -gt 10) { $s-=3; $i+="$usbCount USB devices in history - verify unknown ones" }
        elseif ($usbCount -gt 5) { $s-=1; $i+="$usbCount peripheriques USB historiques enregistres" }
        if ($r -match "(?i)SanDisk|Kingston|Samsung") { }  # marques courantes = ok
        AddDomain "USB History" "usb" $s $i 2
    }

    # -- 12 Disques ------------------------------------------------------------
    if ($Results.ContainsKey("12")) {
        $s=10; $i=@()
        $r = ResultOf "12"
        # Chercher les partitions avec peu d'espace libre
        ($r -split "`n") | ForEach-Object {
            if ($_ -match "\((\d+)%\)") {
                $pct = [int]$Matches[1]
                if ($pct -lt 10) { $s-=3; $i+="Partition with only $pct`% free space" }
                elseif ($pct -lt 20) { $s-=1; $i+="Partition with $pct`% free space" }
            }
        }
        AddDomain "Partitions / Disks" "part" $s $i 1
    }

    # -- 13 Configuration reseau -----------------------------------------------
    if ($Results.ContainsKey("13")) {
        $s=10; $i=@()
        $r = ResultOf "13"
        # DNS non standard (pas 8.8.8.8, 1.1.1.1 ou adresses privees)
        $dnsLines = ($r -split "`n" | Where-Object { $_ -match "(?i)DNS.*:.*\d+\.\d+\.\d+\.\d+" })
        if ($dnsLines | Where-Object { $_ -notmatch "(?i)8\.8\.8\.8|8\.8\.4\.4|1\.1\.1\.1|1\.0\.0\.1|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\." }) {
            $s-=2; $i+="Non-standard DNS servers detected - verify if authorized"
        }
        if ($r -match "169\.254\.\d+\.\d+") { $s-=3; $i+="Adresse APIPA detectee (probleme DHCP)" }
        AddDomain "Network Configuration" "cfrzo" $s $i 2
    }

    # -- 14 Netstat ------------------------------------------------------------
    if ($Results.ContainsKey("14")) {
        $s=10; $i=@()
        $listening = ([regex]::Matches((ResultOf "14"),"(?i)LISTENING|ECOUTE")).Count
        if ($listening -gt 20) { $s-=2; $i+="$listening ports en ecoute" }
        if (Has "14" "(?i):3389.*LISTENING|LISTENING.*:3389") { $s-=2; $i+="RDP (3389) expose en ecoute" }
        if (Has "14" "(?i):445.*LISTENING|LISTENING.*:445")   { $s-=2; $i+="SMB (445) exposed and listening" }
        if (Has "14" "(?i):5985.*LISTENING|:5986.*LISTENING") { $s-=2; $i+="WinRM (5985/5986) expose" }
        if (Has "14" "(?i):23\s|:21\s|:69\s")                 { $s-=3; $i+="Unencrypted protocol exposed (Telnet/FTP/TFTP)" }
        AddDomain "Ports and Connections" "statrzo" $s $i 3
    }

    # -- 16 WSUS ---------------------------------------------------------------
    if ($Results.ContainsKey("16")) {
        $s=10; $i=@()
        $r = ResultOf "16"
        if ($r -match "(?i)WUServer\s*REG_SZ\s*(.+)") {
            $wsusUrl = $Matches[1].Trim()
            # URL non HTTPS = risque WSUS-pect
            if ($wsusUrl -match "^http://") { $s-=4; $i+="WSUS configured over HTTP (unencrypted): WSUS-pect risk" }
        }
        if ($r -match "(?i)Erreur|ERROR|not found") { }  # pas de WSUS = MAJ directe Microsoft = ok
        AddDomain "Update Source (WSUS)" "wsus" $s $i 2
    }

    # -- 17 Mises a jour -------------------------------------------------------
    if ($Results.ContainsKey("17")) {
        $s=10; $i=@()
        $lines = (ResultOf "17") -split "`n" | Where-Object { $_ -match "\d{2}/\d{2}/\d{4}" }
        if ($lines.Count -gt 0) {
            try {
                $lastDate = [datetime]::ParseExact(([regex]::Match($lines[0],"\d{2}/\d{2}/\d{4}")).Value,"dd/MM/yyyy",$null)
                $daysSince = ((Get-Date) - $lastDate).Days
                if ($daysSince -gt 90) { $s-=5; $i+="Derniere MAJ il y a $daysSince jours (critique)" }
                elseif ($daysSince -gt 30) { $s-=3; $i+="Derniere MAJ il y a $daysSince jours" }
                elseif ($daysSince -gt 15) { $s-=1; $i+="Derniere MAJ il y a $daysSince jours" }
            } catch {}
        } else { $s-=3; $i+="Impossible de determiner la date de derniere MAJ" }
        AddDomain "Updates" "maj" $s $i 4
    }

    # -- 18 NTP ----------------------------------------------------------------
    if ($Results.ContainsKey("18")) {
        $s=10; $i=@()
        $r = ResultOf "18"
        if ($r -match "(?i)Non synchronis|Not synchronized|Unsync") { $s-=3; $i+="Clock not synchronized (forensic impact)" }
        if ($r -match "(?i)Derive|Drift.*[5-9]\d\d\d|Drift.*[1-9]\d{4}") { $s-=2; $i+="Derive horloge importante (logs potentiellement falsifies)" }
        AddDomain "Time Sync (NTP)" "ntp" $s $i 1
    }

    # -- 19 Wi-Fi --------------------------------------------------------------
    if ($Results.ContainsKey("19")) {
        $s=10; $i=@()
        $r = ResultOf "19"
        # Reseaux ouverts (pas de chiffrement)
        if ($r -match "(?i)Authentification\s*:\s*Ouvrir|Authentication\s*:\s*Open") { $s-=3; $i+="Open Wi-Fi profile (no encryption) saved" }
        # WEP = obsolete
        if ($r -match "(?i)Chiffrement\s*:\s*WEP|Cipher\s*:\s*WEP") { $s-=4; $i+="Obsolete WEP encryption detected" }
        $profileCount = ([regex]::Matches($r,"(?i)Profil\s*:")).Count
        if ($profileCount -gt 10) { $s-=1; $i+="$profileCount profils Wi-Fi enregistres (mots de passe recuperables)" }
        AddDomain "Wi-Fi Configuration" "wifi" $s $i 2
    }

    # -- 21 Proxy --------------------------------------------------------------
    if ($Results.ContainsKey("21")) {
        $s=10; $i=@()
        $r = ResultOf "21"
        if ($r -match "(?i)ProxyEnable\s*:\s*1") {
            $s-=2; $i+="Proxy active - verifier l'IP/domaine configure"
            if ($r -match "(?i)ProxyServer\s*:\s*([\d\.]+)") {
                $proxyIP = $Matches[1]
                if ($proxyIP -notmatch "^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)") {
                    $s-=3; $i+="Proxy pointing to public IP $proxyIP (suspicious)"
                }
            }
        }
        if ($r -match "(?i)AutoConfigURL\s*:\s*http") { $s-=2; $i+="AutoConfigURL (PAC) configure - risque de redirection trafic" }
        AddDomain "Proxy Configuration" "proxy" $s $i 2
    }

    # -- 22 ARP ----------------------------------------------------------------
    if ($Results.ContainsKey("22")) {
        $s=10; $i=@()
        $r = ResultOf "22"
        # Detecter doublons MAC (ARP poisoning)
        $macs = [regex]::Matches($r,"([0-9a-f]{2}[:-]){5}[0-9a-f]{2}") | ForEach-Object { $_.Value.ToLower() }
        $dupMacs = $macs | Group-Object | Where-Object { $_.Count -gt 1 }
        if ($dupMacs.Count -gt 0) { $s-=5; $i+="Duplicate MAC address(es) - possible ARP spoofing" }
        AddDomain "ARP Table" "arp" $s $i 2
    }

    # -- 23 HOSTS --------------------------------------------------------------
    if ($Results.ContainsKey("23")) {
        $s=10; $i=@()
        $nonComment = ((ResultOf "23") -split "`n" | Where-Object {
            $_ -match "^\s*[^#\s]" -and
            $_ -notmatch "^\s*127\.0\.0\.1\s+localhost" -and
            $_ -notmatch "^\s*::1\s+localhost" -and
            $_ -notmatch "^\s*$"
        })
        if ($nonComment.Count -gt 0) {
            $s -= [math]::Min(8, $nonComment.Count * 2)
            $i += "$($nonComment.Count) non-standard entry/entries in the HOSTS file"
        }
        AddDomain "HOSTS File" "hosts" $s $i 3
    }

    # -- 24 Services -----------------------------------------------------------
    if ($Results.ContainsKey("24")) {
        $s=10; $i=@()
        if (Has "24" "(?i)\[Running\].*Spooler|Spooler.*Running")               { $s-=2; $i+="Spooler active (Print-Nightmare if unpatched)" }
        if (Has "24" "(?i)\[Running\].*Telnet|Telnet.*Running")                  { $s-=4; $i+="Telnet active (unencrypted protocol)" }
        if (Has "24" "(?i)\[Running\].*SNMP|SNMP.*Running")                      { $s-=2; $i+="SNMP actif - verifier la communaute" }
        if (Has "24" "(?i)\[Running\].*RemoteRegistry|RemoteRegistry.*Running")  { $s-=3; $i+="RemoteRegistry actif (acces registre a distance)" }
        if (Has "24" "(?i)\[Running\].*WinRM|WinRM.*Running")                    { $s-=2; $i+="WinRM actif (PowerShell distant)" }
        AddDomain "Windows Services" "svc" $s $i 2
    }

    # -- 25 Pare-feu -----------------------------------------------------------
    if ($Results.ContainsKey("25")) {
        $s=10; $i=@()
        if (Has "25" "(?i)State\s+OFF|Etat\s+INACTIF|Etat\s+Desactive|OFF") {
            $s-=6; $i+="Firewall disabled on at least one profile"
        }
        if (NotHas "25" "(?i)Public.*ON|Public.*ACTIF") { $s-=3; $i+="Public firewall profile not confirmed active" }
        AddDomain "Firewall" "conffw" $s $i 4
    }

    # -- 26 Regles entrant FW --------------------------------------------------
    if ($Results.ContainsKey("26")) {
        $s=10; $i=@()
        $r = ResultOf "26"
        $ruleCount = ([regex]::Matches($r,"(?m)^\[Allow\]|\[Block\]")).Count
        if ($ruleCount -gt 300) { $s-=3; $i+="$ruleCount inbound rules (firewall likely misconfigured)" }
        if ($r -match "(?i)Allow.*Any.*3389|Allow.*0\.0\.0\.0.*3389") { $s-=3; $i+="RDP autorise depuis Any (toute source)" }
        if ($r -match "(?i)Allow.*Any.*445|Allow.*0\.0\.0\.0.*445")   { $s-=3; $i+="SMB autorise depuis Any (toute source)" }
        AddDomain "Inbound FW Rules" "infw" $s $i 2
    }

    # -- 28 Antivirus ----------------------------------------------------------
    if ($Results.ContainsKey("28")) {
        $s=10; $i=@()
        if (Has "28" "(?i)Real-time Protection Status\s*:\s*Disabled|Disabled") { $s-=5; $i+="AV real-time protection disabled" }
        if (Has "28" "(?i)Definition Status\s*:\s*Out of date|Out of date")      { $s-=4; $i+="Outdated AV signatures" }
        if (Has "28" "(?i)Inconnu")                                               { $s-=3; $i+="Antivirus not detected or read error" }
        AddDomain "Antivirus" "infav" $s $i 4
    }

    # -- 29 Taches planifiees --------------------------------------------------
    if ($Results.ContainsKey("29")) {
        $s=10; $i=@()
        $suspTasks = (ResultOf "29") -split "`n" | Where-Object {
            $_ -match "(?i)\\\\Users\\\\|\\\\Temp\\\\|\\\\AppData\\\\" -or
            $_ -match "(?i)powershell|wscript|cscript|mshta|cmd\.exe"
        }
        if ($suspTasks.Count -gt 5) { $s-=4; $i+="$($suspTasks.Count) task(s) with suspicious paths/exe" }
        elseif ($suspTasks.Count -gt 2) { $s-=2; $i+="$($suspTasks.Count) tasks with system executables - verify" }
        AddDomain "Scheduled Tasks" "tasks" $s $i 2
    }

    # -- 30 Logiciels installes ------------------------------------------------
    if ($Results.ContainsKey("30")) {
        $s=10; $i=@()
        $r = ResultOf "30"
        if ($r -match "(?i)AnyDesk|TeamViewer|RustDesk|UltraVNC|TightVNC|DWService") { $s-=3; $i+="Remote access tool detected - verify if authorized" }
        if ($r -match "(?i)Nmap|Wireshark|Metasploit|Mimikatz|Cobalt|Responder")     { $s-=5; $i+="Security/penetration testing tool detected" }
        if ($r -match "(?i)xmrig|nicehash|cgminer|bfgminer")                         { $s-=6; $i+="Cryptocurrency mining software detected" }
        if ($r -match "(?i)Tor Browser|Tor-Browser")                                  { $s-=2; $i+="Tor Browser detected" }
        AddDomain "Installed Software" "logs" $s $i 3
    }

    # -- 31 Journal Systeme ----------------------------------------------------
    if ($Results.ContainsKey("31")) {
        $s=10; $i=@()
        $r = ResultOf "31"
        $errors = ([regex]::Matches($r,"(?i)^.*Error")).Count
        $warns  = ([regex]::Matches($r,"(?i)^.*Warning")).Count
        if ($errors -gt 10) { $s-=3; $i+="$errors errors in recent system log" }
        elseif ($errors -gt 5) { $s-=1; $i+="$errors errors in system log" }
        if ($r -match "(?i)RT2870.*invalid|Service.*invalide.*0 non valide") { $s-=1; $i+="Repeated service error(s) detected" }
        AddDomain "System Log" "syst" $s $i 1
    }

    # -- 32 Journal Application ------------------------------------------------
    if ($Results.ContainsKey("32")) {
        $s=10; $i=@()
        $r = ResultOf "32"
        $errors = ([regex]::Matches($r,"(?m)Error")).Count
        if ($errors -gt 10) { $s-=2; $i+="$errors errors in recent application log" }
        if ($r -match "(?i)Application Error.*\.exe") { $s-=2; $i+="Application crash detected (check the process)" }
        AddDomain "Application Log" "evtapp" $s $i 1
    }

    # -- 33 GPO ----------------------------------------------------------------
    if ($Results.ContainsKey("33")) {
        $s=10; $i=@()
        $r = ResultOf "33"
        if ($r -match "(?i)RSOP.*vide|no data|Access.*denied") { $s-=3; $i+="GPO not applied or access denied" }
        if (NotHas "33" "(?i)Strategie|Policy|GPO") { $s-=2; $i+="No security GPO detected" }
        AddDomain "Group Policy (GPO)" "rsop" $s $i 2
    }

    # -- 34 Demarrage (Run keys) -----------------------------------------------
    if ($Results.ContainsKey("34")) {
        $s=10; $i=@()
        $r = ResultOf "34"
        $nonEmpty = ($r -split "`n" | Where-Object { $_ -match "=\s*.+" -and $_ -notmatch "^\s*\[" -and $_ -notmatch "vide" })
        $suspPaths = ($nonEmpty | Where-Object { $_ -match "(?i)temp|appdata|public|roaming" })
        if ($suspPaths.Count -gt 0) { $s-=5; $i+="$($suspPaths.Count) startup entry/entries with suspicious path" }
        elseif ($nonEmpty.Count -gt 8) { $s-=2; $i+="$($nonEmpty.Count) startup programs - verify unknown entries" }
        AddDomain "Startup Programs" "logdem" $s $i 3
    }

    # -- 36 BitLocker ----------------------------------------------------------
    if ($Results.ContainsKey("36")) {
        $s=10; $i=@()
        $r = ResultOf "36"
        if ($r -match "(?i)non disponible|non configure") { $s-=3; $i+="BitLocker not configured or not available" }
        elseif ($r -match "(?i)Protection\s*:\s*Off|ProtectionStatus.*Off") { $s-=5; $i+="BitLocker disabled on at least one volume" }
        elseif ($r -match "(?i)Chiffrement.*0%|EncryptionPercentage.*0") { $s-=4; $i+="Unencrypted volume detected" }
        AddDomain "BitLocker Encryption" "bitlocker" $s $i 3
    }

    # -- 37 Certificats --------------------------------------------------------
    if ($Results.ContainsKey("37")) {
        $s=10; $i=@()
        $r = ResultOf "37"
        $expired  = ([regex]::Matches($r,"\[EXPIRE\]")).Count
        $expiring = ([regex]::Matches($r,"\[EXPIRE BIENTOT\]")).Count
        if ($expired -gt 0)  { $s -= [math]::Min(4,$expired); $i+="$expired expired certificate(s) in stores" }
        if ($expiring -gt 0) { $s-=1; $i+="$expiring certificate(s) expiring within 30d" }
        AddDomain "System Certificates" "certs" $s $i 2
    }

    # -- 38 Journal Securite ---------------------------------------------------
    if ($Results.ContainsKey("38")) {
        $s=10; $i=@()
        $r = ResultOf "38"
        $fails    = ([regex]::Matches($r,"4625")).Count
        $explicit = ([regex]::Matches($r,"4648")).Count
        $newAcct  = ([regex]::Matches($r,"4720|4732|4728")).Count
        $newTask  = ([regex]::Matches($r,"4698|4702")).Count
        if ($fails -gt 10)   { $s-=4; $i+="$fails echecs de connexion (4625) - possible brute-force" }
        elseif ($fails -gt 3){ $s-=2; $i+="$fails echecs de connexion recents" }
        if ($explicit -gt 5) { $s-=3; $i+="$explicit logons explicites (4648) - possible pass-the-hash" }
        if ($newAcct -gt 0)  { $s-=4; $i+="Account or group creation/modification detected (4720/4732)" }
        if ($newTask -gt 0)  { $s-=3; $i+="Scheduled task creation detected in logs (4698/4702)" }
        if ($r -match "(?i)Acces refuse|Access denied") { $s-=1; $i+="Access denied to Security log - insufficient rights" }
        AddDomain "Security Log" "evtsec" $s $i 4
    }

    # -- 39 Fichiers recents ---------------------------------------------------
    if ($Results.ContainsKey("39")) {
        $s=10; $i=@()
        $r = ResultOf "39"
        $suspFiles = ($r -split "`n" | Where-Object { $_ -match "(?i)\.(exe|dll|bat|ps1|vbs|hta|cmd|scr)" -and $_ -match "(?i)temp|appdata|public|download|desktop" })
        if ($suspFiles.Count -gt 5)  { $s-=5; $i+="$($suspFiles.Count) fichiers executables suspects modifies en 72h" }
        elseif ($suspFiles.Count -gt 1) { $s-=3; $i+="$($suspFiles.Count) recent executable file(s) in sensitive folders" }
        elseif ($suspFiles.Count -eq 1) { $s-=1; $i+="1 recent executable file in a sensitive folder" }
        AddDomain "Recent Files (72h)" "recentfiles" $s $i 3
    }

    # -- 40 Historique RDP -----------------------------------------------------
    if ($Results.ContainsKey("40")) {
        $s=10; $i=@()
        $r = ResultOf "40"
        $rdpServers = ([regex]::Matches($r,"Serveur\s*:")).Count
        if ($rdpServers -gt 5) { $s-=2; $i+="$rdpServers RDP server(s) in history - verify connections" }
        if ($r -match "(?i)Serveur\s*:\s*\d+\.\d+\.\d+\.\d+") {
            # Connexion RDP vers IP directe (non DNS) = suspect
            $s-=2; $i+="RDP connection to direct IP in history (suspicious)"
        }
        AddDomain "RDP History" "rdphist" $s $i 2
    }

    # -- 41 Historique PowerShell ----------------------------------------------
    if ($Results.ContainsKey("41")) {
        $s=10; $i=@()
        $r = ResultOf "41"
        if ($r -match "(?i)non disponible|non installe|efface") { $s-=1; $i+="PS history absent or cleared (possible cleanup)" }
        $suspCmds = ($r -split "`n" | Where-Object { $_ -match "(?i)\[SUSPECT\]" })
        if ($suspCmds.Count -gt 3)  { $s-=5; $i+="$($suspCmds.Count) suspicious PS command(s) in history" }
        elseif ($suspCmds.Count -gt 0) { $s-=3; $i+="$($suspCmds.Count) commande(s) PS suspecte(s) detectee(s)" }
        AddDomain "PowerShell History" "pshist" $s $i 3
    }

    # -- 42 UAC ----------------------------------------------------------------
    if ($Results.ContainsKey("42")) {
        $s=10; $i=@()
        $r = ResultOf "42"
        if ($r -match "EnableLUA.*0|\[RISQUE\] UAC desactive") { $s-=5; $i+="UAC desactive - elevation silencieuse possible" }
        if ($r -match "ConsentPromptBehaviorAdmin.*0|\[RISQUE\] Elevation silencieuse") { $s-=4; $i+="Elevation UAC silencieuse configuree" }
        if ($r -match "(?i)SeDebugPrivilege.*Enabled") { $s-=3; $i+="Privilege SeDebugPrivilege actif (lecture memoire processus)" }
        AddDomain "UAC and Privileges" "uac" $s $i 3
    }

    # -- 43 AppLocker ----------------------------------------------------------
    if ($Results.ContainsKey("43")) {
        $s=10; $i=@()
        $r = ResultOf "43"
        if ($r -match "(?i)AppLocker non configure|SRP non configure") { $s-=3; $i+="AppLocker/SRP not configured (unrestricted execution)" }
        if ($r -match "(?i)AppIDSvc.*Stopped|AppIDSvc.*Arrete")        { $s-=2; $i+="AppLocker service stopped" }
        if ($r -match "(?i)aucune regle.*Exe|aucune regle.*Script")    { $s-=2; $i+="No AppLocker rule on Exe or Script" }
        AddDomain "AppLocker / SRP" "applocker" $s $i 2
    }

    # -- 44 LSA Protection / Credential Guard ----------------------------------
    if ($Results.ContainsKey("44")) {
        $s=10; $i=@()
        $r = ResultOf "44"
        if ($r -match "(?i)\[RISQUE\] LSA RunAsPPL desactive|RunAsPPL.*0") { $s-=4; $i+="LSA RunAsPPL disabled - lsass readable in memory" }
        if ($r -match "(?i)\[CRITICAL\] WDigest actif|UseLogonCredential.*1")  { $s-=5; $i+="WDigest active - cleartext passwords in memory!" }
        if ($r -match "EnableVirtualizationBasedSecurity.*0") { $s-=2; $i+="Virtualization Based Security disabled" }
        AddDomain "LSA Protection / Credential Guard" "lsaprot" $s $i 4
    }

    # -- 45 Connexions externes ------------------------------------------------
    if ($Results.ContainsKey("45")) {
        $s=10; $i=@()
        $r = ResultOf "45"
        if ($r -match "(?i)No connection|(?i)Aucune connexion") { }  # OK
        else {
            $extConns = ($r -split "`n" | Where-Object { $_ -match "\d+\.\d+\.\d+\.\d+" -and $_ -notmatch "^Date|^---" })
            if ($extConns.Count -gt 10) { $s-=2; $i+="$($extConns.Count) TCP connection(s) to external IPs" }
            $suspProcs = ($extConns | Where-Object { $_ -match "(?i)powershell|cmd|wscript|cscript|mshta|rundll32" })
            if ($suspProcs.Count -gt 0) { $s-=5; $i+="External connection(s) via suspicious process (PS/cmd/mshta)" }
        }
        AddDomain "External Connections" "netgeo" $s $i 3
    }

    # -- 46 Modules PS / Journalisation ----------------------------------------
    if ($Results.ContainsKey("46")) {
        $s=10; $i=@()
        $r = ResultOf "46"
        if ($r -match "(?i)Script Block Logging.*INACTIF") { $s-=2; $i+="PS Script Block Logging disabled (reduced detection)" }
        if ($r -match "(?i)Module Logging.*INACTIF")       { $s-=1; $i+="PS Module Logging disabled" }
        if ($r -match "(?i)Transcription.*INACTIF")        { $s-=1; $i+="PS Transcription disabled" }
        $suspMods = ($r -split "`n" | Where-Object { $_ -match "(?i)appdata|temp|users\\[^\\]+\\documents" })
        if ($suspMods.Count -gt 0) { $s-=3; $i+="$($suspMods.Count) PS module(s) in user folder (suspicious path)" }
        AddDomain "PS Modules / Logging" "psmodules" $s $i 2
    }

    # -- 04 Arbre processus -------------------------------------------------------
    if ($Results.ContainsKey("04")) {
        $s=10; $i=@()
        $r = ResultOf "04"
        # cmd/powershell enfant de word/excel/outlook = macro suspecte
        if ($r -match "(?i)WINWORD|EXCEL|POWERPNT|OUTLOOK") {
            if ($r -match "(?i)cmd\.exe|powershell") { $s-=5; $i+="cmd/PowerShell child of Word/Excel/Outlook (suspicious macro)" }
        }
        # svchost avec parent inhabituel
        if ($r -match "(?i)svchost.*ppid=(?!4|8|688|772|804|824)") { $s-=3; $i+="svchost.exe with unusual parent detected" }
        AddDomain "Process Tree" "arbps" $s $i 3
    }

    # -- 15 Table de routage -------------------------------------------------------
    if ($Results.ContainsKey("15")) {
        $s=10; $i=@()
        $r = ResultOf "15"
        # Routes statiques non standard (pas 0.0.0.0 ni 127. ni 224.)
        $suspRoutes = ($r -split "`n" | Where-Object {
            $_ -match "\d+\.\d+\.\d+\.\d+" -and
            $_ -notmatch "^\s*0\.0\.0\.0|127\.|224\.|255\.|169\.254\." -and
            $_ -match "(?i)static|statique"
        })
        if ($suspRoutes.Count -gt 3) { $s-=2; $i+="$($suspRoutes.Count) non-standard static routes - verify if legitimate" }
        AddDomain "Table de routage" "route" $s $i 1
    }

    # -- 20 Cache DNS -------------------------------------------------------
    if ($Results.ContainsKey("20")) {
        $s=10; $i=@()
        $r = ResultOf "20"
        # Domaines suspects dans le cache (DGA-like : beaucoup de chiffres/consonnes)
        $dnsEntries = ($r -split "`n" | Where-Object { $_ -match "(?i)Nom d|Record Name" })
        $suspDomains = ($dnsEntries | Where-Object { $_ -match "[a-z0-9]{12,}\.(com|net|org|ru|cn|tk|top|xyz)" })
        if ($suspDomains.Count -gt 0) { $s-=3; $i+="$($suspDomains.Count) domain(s) with potential DGA format in DNS cache" }
        AddDomain "Cache DNS" "dns" $s $i 2
    }

    # -- 27 Regles FW sortantes -------------------------------------------------------
    if ($Results.ContainsKey("27")) {
        $s=10; $i=@()
        $r = ResultOf "27"
        $ruleCount = ([regex]::Matches($r,"(?m)^\[Allow\]|\[Block\]")).Count
        if ($ruleCount -gt 300) { $s-=2; $i+="$ruleCount outbound rules (firewall not restrictive enough)" }
        # Pas de regles = tout autorise en sortie
        if ($ruleCount -eq 0) { $s-=1; $i+="No outbound rules: all outbound traffic allowed" }
        AddDomain "Outbound FW Rules" "outfw" $s $i 1
    }

    # -- 35 IPv6 -------------------------------------------------------
    if ($Results.ContainsKey("35")) {
        $s=10; $i=@()
        $r = ResultOf "35"
        if ($r -match "(?i)Teredo|6to4|isatap") { $s-=2; $i+="IPv6 tunnel (Teredo/6to4/ISATAP) active - possible firewall bypass" }
        AddDomain "IPv6" "adip6" $s $i 1
    }

    # -- Score global : formule inspiree CVSS ----------------------------------
    # Risque(domaine) = Impact x Exploitabilite
    #   Impact        = poids / 4  (normalise entre 0.25 et 1)
    #   Exploitabilite= (10 - score) / 10
    # Score global    = 10 - moyenne_ponderee_des_risques * 10
    # Punitive ceilings based on severity of failing critical domains
    # Thresholds: <5 = Critical, <7 = Warning, >=7 = Good

    $totalRisk    = 0
    $totalImpact  = 0
    $ceiling      = 10.0

    foreach ($d in $domains) {
        $impact         = $d.Weight / 4.0
        $exploitability = (10 - $d.Score) / 10.0
        $domainRisk     = $impact * $exploitability
        $totalRisk     += $domainRisk
        $totalImpact   += $impact

        # Plafonds punitifs : echec sur domaine critique = score global limite
        if     ($d.Weight -ge 4 -and $d.Score -le 2) { $ceiling = [math]::Min($ceiling, 3.9) } # desastre critique -> Critique certain
        elseif ($d.Weight -ge 4 -and $d.Score -le 4) { $ceiling = [math]::Min($ceiling, 4.9) } # echec critique -> Critique
        elseif ($d.Weight -ge 4 -and $d.Score -le 6) { $ceiling = [math]::Min($ceiling, 6.4) } # critique partiel -> Attention
        elseif ($d.Weight -ge 3 -and $d.Score -le 2) { $ceiling = [math]::Min($ceiling, 4.9) } # echec majeur -> Critique
        elseif ($d.Weight -ge 3 -and $d.Score -le 4) { $ceiling = [math]::Min($ceiling, 5.9) } # echec important -> Attention
    }

    if ($totalImpact -gt 0) {
        $avgRisk    = $totalRisk / $totalImpact
        $rawScore   = 10 - ($avgRisk * 10)
        $coverage   = [math]::Min(1.0, $domains.Count / 20.0)
        $globalScore = [math]::Round([math]::Min($ceiling, [math]::Max(0, $rawScore * $coverage + 5.0 * (1 - $coverage))), 1)
    } else {
        $globalScore = 5.0
    }

    return @{
        Global  = $globalScore
        Domains = $domains
    }
}


# ---------------------------------------------------------------------------
#  MITRE ATT&CK WINDOWS MATRIX - HTML Generation
# ---------------------------------------------------------------------------

function Generate-MitreMatrix {
    param([hashtable]$Results)

    # -------------------------------------------------------------------------
    # Evaluer les conditions basees sur les resultats collectes
    # -------------------------------------------------------------------------
    function Has { param($k,$p) if(-not $Results.ContainsKey($k)){return $false}; return ($Results[$k] -match $p) }
    function ResultOf { param($k) if($Results.ContainsKey($k)){return $Results[$k]} else {return ""} }

    # Flags de vulnerabilite (true = facilite cette technique)
    $F = @{}

    # Authentification / Comptes
    $F.NoLockout      = (Has "07" "LockoutBadCount\s*=\s*0")
    $F.WeakPwPolicy   = (Has "07" "MinimumPasswordLength\s*=\s*[0-7]\b|PasswordComplexity\s*=\s*0")
    $F.AdminActive    = (Has "08" "(?i)(Administrator|Administrateur).*Actif\s*:\s*True")
    $F.GuestActive    = (Has "08" "(?i)(Guest|Invite).*Actif\s*:\s*True")
    $F.NoPassword     = (Has "08" "(?i)\[!MOT DE PASSE VIDE\]")
    $F.WDigest        = (Has "44" "(?i)WDigest.*1|UseLogonCredential.*1|\[CRITICAL\] WDigest")
    $F.NoLSAPPL       = (Has "44" "(?i)RunAsPPL.*0|\[RISQUE\] LSA")
    $F.NoCredGuard    = (Has "44" "EnableVirtualizationBasedSecurity.*0")

    # Execution / PowerShell
    $F.PSUnrestricted = (Has "06" "(?i)Unrestricted|Bypass")
    $F.NoPSLogging    = (Has "46" "(?i)Script Block Logging.*INACTIF")
    $F.SuspPSHist     = (Has "41" "(?i)\[SUSPECT\]")
    $F.NoAppLocker    = (Has "43" "(?i)AppLocker non configure|aucune regle.*Exe")

    # Persistance
    $F.SuspStartup    = (Has "34" "(?i)temp|appdata|public|roaming")
    $F.SuspTasks      = (Has "29" "(?i)\\\\Temp\\\\|\\\\AppData\\\\")
    $F.SuspFiles      = (Has "39" "(?i)\[SUSPECT\]|\.(exe|dll|bat|ps1).*(?:temp|appdata)")
    $F.HostsModified  = ($Results.ContainsKey("23") -and ((ResultOf "23") -split "`n" | Where-Object {
        $_ -match "^\s*[^#\s]" -and $_ -notmatch "127\.0\.0\.1\s+localhost" -and $_ -notmatch "::1\s+localhost" -and $_ -notmatch "^\s*$"
    }).Count -gt 0)

    # Escalade de privileges
    $F.UACDisabled    = (Has "42" "(?i)EnableLUA.*0|\[RISQUE\] UAC desactive")
    $F.UACSilent      = (Has "42" "(?i)ConsentPromptBehaviorAdmin.*0")
    $F.SeDebug        = (Has "42" "(?i)SeDebugPrivilege.*Enabled")
    $F.AdminGroup     = ($Results.ContainsKey("09") -and ((ResultOf "09") -split "`n" | Where-Object { $_ -match "^\s*-\s*.+" }).Count -gt 5)

    # Mouvement lateral / Reseau
    $F.RDPOpen        = (Has "14" "(?i):3389.*LISTENING|LISTENING.*:3389")
    $F.SMBOpen        = (Has "14" "(?i):445.*LISTENING|LISTENING.*:445")
    $F.WinRMOpen      = (Has "14" "(?i):5985.*LISTENING|:5986.*LISTENING")
    $F.AdminShares    = (Has "10" "(?i)ADMIN\`\$|C\`\$|D\`\$")
    $F.RemoteRegistry = (Has "24" "(?i)RemoteRegistry.*Running")
    $F.RDPHistory     = (Has "40" "(?i)Serveur\s*:")

    # Exfiltration / C2
    $F.FWDisabled     = (Has "25" "(?i)State\s+OFF|Etat\s+INACTIF|OFF")
    $F.ProxySuspect   = (Has "21" "(?i)ProxyEnable.*1")
    $F.DNSSuspect     = (Has "20" "(?i)DGA|[a-z0-9]{12,}\.(ru|cn|tk|xyz)")
    $F.ExtConns       = ($Results.ContainsKey("45") -and (ResultOf "45") -notmatch "(?i)No connection|(?i)Aucune connexion")
    $F.NoFWOut        = (Has "27" "(?i)No outbound rule|(?i)Aucune regle|(?i)No rule")
    $F.IPv6Tunnel     = (Has "35" "(?i)Teredo|6to4|ISATAP")

    # Defense Evasion
    $F.AVDisabled     = (Has "28" "(?i)Disabled|Out of date|Inconnu")
    $F.NoUpdates      = (Has "17" "(?i)90 jours|critique")
    $F.BootDebug      = (Has "01" "(?i)bootdebug\s+yes|testsigning\s+yes")
    $F.NoBitLocker    = (Has "36" "(?i)desactive|non configure|Off")
    $F.WifiOpen       = (Has "19" "(?i)Open|WEP")
    $F.ARPAnomaly     = (Has "22" "(?i)Doublon")
    $F.WSUSHttp       = (Has "16" "(?i)http://")

    # Decouverte
    $F.SNMPActive     = (Has "24" "(?i)SNMP.*Running")
    $F.ManyPorts      = ($Results.ContainsKey("14") -and ([regex]::Matches((ResultOf "14"),"(?i)LISTENING|ECOUTE")).Count -gt 20)

    # -------------------------------------------------------------------------
    # Definition de la matrice MITRE ATT&CK Windows (tactiques + techniques)
    # -------------------------------------------------------------------------
    # Format : @{ ID; Nom; Tactique; Facilite(bool) }
    # Niveau : 0=neutre/gris, 1=possible/jaune, 2=facilite/orange, 3=critique/rouge

    $tactics = [ordered]@{
        "Reconnaissance"          = "TA0043"
        "Initial Access"          = "TA0001"
        "Execution"               = "TA0002"
        "Persistence"             = "TA0003"
        "Privilege Escalation"    = "TA0004"
        "Defense Evasion"         = "TA0005"
        "Credential Access"       = "TA0006"
        "Discovery"               = "TA0007"
        "Lateral Movement"        = "TA0008"
        "Collection"              = "TA0009"
        "Command and Control"     = "TA0011"
        "Exfiltration"            = "TA0010"
        "Impact"                  = "TA0040"
    }

    # Techniques par tactique: @(ID, Nom court, Niveau 0-3)
    # Le niveau est calcule dynamiquement depuis les flags
    # Pre-calcul des niveaux en [int] purs pour compatibilite PS5
    # [bool]*[int] interdit en PS5 -> on calcule les niveaux avant la hashtable
    $iNoLockout    = if ($F.NoLockout)     {1} else {0}
    $iWeakPw       = if ($F.WeakPwPolicy)  {1} else {0}
    $iAdminActive  = if ($F.AdminActive)   {1} else {0}
    $iNoPassword   = if ($F.NoPassword)    {1} else {0}
    $iWDigest      = if ($F.WDigest)       {1} else {0}
    $iNoLSAPPL     = if ($F.NoLSAPPL)      {1} else {0}
    $iNoCredGuard  = if ($F.NoCredGuard)   {1} else {0}
    $iPSUnrestr    = if ($F.PSUnrestricted){1} else {0}
    $iNoPSLog      = if ($F.NoPSLogging)   {1} else {0}
    $iSuspPS       = if ($F.SuspPSHist)    {1} else {0}
    $iNoAppLocker  = if ($F.NoAppLocker)   {1} else {0}
    $iSuspStart    = if ($F.SuspStartup)   {1} else {0}
    $iSuspTasks    = if ($F.SuspTasks)     {1} else {0}
    $iSuspFiles    = if ($F.SuspFiles)     {1} else {0}
    $iHostsMod     = if ($F.HostsModified) {1} else {0}
    $iUACDis       = if ($F.UACDisabled)   {1} else {0}
    $iUACSil       = if ($F.UACSilent)     {1} else {0}
    $iSeDebug      = if ($F.SeDebug)       {1} else {0}
    $iAdminGrp     = if ($F.AdminGroup)    {1} else {0}
    $iRDPOpen      = if ($F.RDPOpen)       {1} else {0}
    $iSMBOpen      = if ($F.SMBOpen)       {1} else {0}
    $iWinRM        = if ($F.WinRMOpen)     {1} else {0}
    $iAdminShr     = if ($F.AdminShares)   {1} else {0}
    $iRemReg       = if ($F.RemoteRegistry){1} else {0}
    $iRDPHist      = if ($F.RDPHistory)    {1} else {0}
    $iFWDis        = if ($F.FWDisabled)    {1} else {0}
    $iProxy        = if ($F.ProxySuspect)  {1} else {0}
    $iDNSSusp      = if ($F.DNSSuspect)    {1} else {0}
    $iExtConns     = if ($F.ExtConns)      {1} else {0}
    $iNoFWOut      = if ($F.NoFWOut)       {1} else {0}
    $iIPv6Tun      = if ($F.IPv6Tunnel)    {1} else {0}
    $iAVDis        = if ($F.AVDisabled)    {1} else {0}
    $iNoUpdates    = if ($F.NoUpdates)     {1} else {0}
    $iBootDbg      = if ($F.BootDebug)     {1} else {0}
    $iNoBitLock    = if ($F.NoBitLocker)   {1} else {0}
    $iWifiOpen     = if ($F.WifiOpen)      {1} else {0}
    $iARPAnom      = if ($F.ARPAnomaly)    {1} else {0}
    $iWSUSHttp     = if ($F.WSUSHttp)      {1} else {0}
    $iSNMP         = if ($F.SNMPActive)    {1} else {0}
    $iManyPorts    = if ($F.ManyPorts)     {1} else {0}

    # Niveaux combines (0=neutre, 1=possible, 2=eleve, 3=critique)
    $lRDPorWinRM   = [math]::Min(2, $iRDPOpen + $iWinRM)
    $lAdminOrNoPwd = [math]::Min(2, ($iAdminActive + $iNoPassword) * 2)
    $lPSorAL       = [math]::Min(2, ($iPSUnrestr + $iNoAppLocker) * 2)
    $lPS3          = [math]::Min(3, ($iPSUnrestr + $iNoPSLog) * 3)
    $lAL2          = $iNoAppLocker * 2
    $lNoUpd2       = $iNoUpdates * 2
    $lSuspT2       = $iSuspTasks * 2
    $lSuspS2       = $iSuspStart * 2
    $lSuspS3       = $iSuspStart * 3
    $lUACany3      = [math]::Min(3, ($iUACDis + $iUACSil) * 3)
    $lSeDbg3       = $iSeDebug * 3
    $lSeDbg2       = $iSeDebug * 2
    $lAdm2         = [math]::Min(2, $iAdminActive * 2)
    $lAdmGrp2      = [math]::Min(2, $iAdminGrp * 2)
    $lAVorFW3      = [math]::Min(3, ($iAVDis + $iFWDis) * 3)
    $lNoPSLog2     = $iNoPSLog * 2
    $lNoLSAorWD3   = [math]::Min(3, ($iNoLSAPPL + $iWDigest) * 3)
    $lWDigest2     = $iWDigest * 2
    $lARPorWifi2   = [math]::Min(2, ($iARPAnom + $iWifiOpen) * 2)
    $lNoCG2        = $iNoCredGuard * 2
    $lAdmShr2      = [math]::Min(2, $iAdminShr * 2)
    $lFWDis2       = $iFWDis * 2
    $lProxy2       = $iProxy * 2
    $lDNSorFW2     = [math]::Min(2, ($iDNSSusp + $iNoFWOut) * 2)
    $lIPv6orProxy2 = [math]::Min(2, ($iIPv6Tun + $iProxy) * 2)
    $lFWorFWO2     = [math]::Min(2, ($iFWDis + $iNoFWOut) * 2)
    $lIPv6orFW2    = [math]::Min(2, ($iIPv6Tun + $iFWDis) * 2)
    $lAdmShrSMB3   = [math]::Min(3, ($iAdminShr + $iSMBOpen) * 3)
    $lLSAorWD3     = [math]::Min(3, ($iNoLSAPPL + $iWDigest) * 3)
    $lRDP3         = [math]::Min(3, $iRDPOpen * 3)
    $lSMBRDP3      = [math]::Min(3, ($iAdminShr + $iSMBOpen) * 3)
    $lWinRM2       = $iWinRM * 2
    $lPassHash3    = [math]::Min(3, ($iNoLSAPPL + $iWDigest) * 3)
    $lTicket2      = $iNoCredGuard * 2
    $lAdmShrMvt2   = [math]::Min(2, $iAdminShr * 2)
    $lFWorFWO3     = [math]::Min(2, ($iFWDis + $iNoFWOut) * 2)
    $lExtConn      = $iExtConns
    $lBootOrBL     = [math]::Min(1, $iBootDbg + $iNoBitLock)
    $lAdmShrFW2    = [math]::Min(2, ($iAdminShr + $iSMBOpen) * 2)
    $lRmReg2       = $iRemReg * 2
    $lSNMPorPort   = [math]::Min(1, $iSNMP + $iManyPorts)

    $techniques = @{
        "Reconnaissance" = @(
            @("T1595","Active Scanning",        [math]::Min(1,$iManyPorts + $iSNMP)),
            @("T1592","Gather Host Info",        $iSNMP),
            @("T1590","Gather Network Info",     [math]::Min(1,$iSNMP + $iManyPorts)),
            @("T1589","Gather Identity Info",    0),
            @("T1598","Phishing for Info",       0)
        )
        "Initial Access" = @(
            @("T1566","Phishing",                0),
            @("T1190","Exploit Public App",      $iNoUpdates),
            @("T1133","External Remote Svc",     $lRDPorWinRM),
            @("T1091","Removable Media",         $iNoAppLocker),
            @("T1078","Valid Accounts",          $lAdminOrNoPwd),
            @("T1195","Supply Chain",            0),
            @("T1199","Trusted Relationship",    0)
        )
        "Execution" = @(
            @("T1059","Command/Script Interp",  $lPSorAL),
            @("T1059.001","PowerShell",          $lPS3),
            @("T1059.003","Windows Cmd Shell",  $lAL2),
            @("T1059.005","VBScript",            $lAL2),
            @("T1059.007","JavaScript",          $iNoAppLocker),
            @("T1203","Exploit for Execution",  $lNoUpd2),
            @("T1569","System Services",         $iSeDebug),
            @("T1204","User Execution",          $iNoPSLog),
            @("T1047","WMI",                     [math]::Min(1,$iPSUnrestr + $iNoAppLocker)),
            @("T1053","Scheduled Task",          $lSuspT2)
        )
        "Persistence" = @(
            @("T1053.005","Scheduled Task/Job", $lSuspT2),
            @("T1547.001","Registry Run Keys",  $lSuspS3),
            @("T1543","Create/Modify Svc",      $iSeDebug),
            @("T1574","Hijack Exec Flow",        $iNoAppLocker),
            @("T1136","Create Account",          $iAdminActive),
            @("T1098","Account Manipulation",   $lAdmGrp2),
            @("T1037","Boot/Logon Init Script", $iSuspStart),
            @("T1505","Server Software Comp",   0),
            @("T1176","Browser Extension",      0),
            @("T1197","BITS Jobs",               $iFWDis)
        )
        "Privilege Escalation" = @(
            @("T1548.002","Bypass UAC",          $lUACany3),
            @("T1055","Process Injection",       $lSeDbg3),
            @("T1068","Exploit Vuln",            $lNoUpd2),
            @("T1134","Access Token Manip",     $lSeDbg2),
            @("T1078","Valid Accounts",          $lAdminOrNoPwd),
            @("T1484","Domain Policy Mod",       0),
            @("T1611","Escape to Host",          0),
            @("T1574.002","DLL Side-Loading",   $iNoAppLocker)
        )
        "Defense Evasion" = @(
            @("T1562.001","Disable AV/FW",      $lAVorFW3),
            @("T1070","Indicator Removal",      $lNoPSLog2),
            @("T1027","Obfuscated Files",        $lNoPSLog2),
            @("T1055","Process Injection",      $lSeDbg2),
            @("T1218","Signed Binary Proxy",    $lAL2),
            @("T1548","Abuse Elevation Ctrl",   $lUACany3),
            @("T1112","Modify Registry",         $iSuspStart),
            @("T1564","Hide Artifacts",          $iNoPSLog),
            @("T1078","Valid Accounts",          $iAdminActive),
            @("T1197","BITS Jobs",               $iFWDis),
            @("T1553","Subvert Trust Ctrl",     $iBootDbg)
        )
        "Credential Access" = @(
            @("T1003.001","LSASS Memory",        $lNoLSAorWD3),
            @("T1110","Brute Force",             [math]::Min(3,$iNoLockout*2 + $iWeakPw)),
            @("T1555","Creds in Store",          $lWDigest2),
            @("T1552","Unsecured Credentials",  $lWDigest2),
            @("T1056","Input Capture",           $iNoLSAPPL),
            @("T1040","Network Sniffing",        $lARPorWifi2),
            @("T1187","Forced Auth",             $iSMBOpen),
            @("T1606","Forge Credentials",      $lNoCG2),
            @("T1539","Steal Web Session",      0),
            @("T1558","Steal Kerberos Ticket",  $lNoCG2)
        )
        "Discovery" = @(
            @("T1087","Account Discovery",       [math]::Min(1,$iRemReg + $iWinRM)),
            @("T1135","Network Share Disc",     $lAdmShr2),
            @("T1046","Network Svc Scan",       [math]::Min(1,$iManyPorts + $iSNMP)),
            @("T1082","System Info Disc",        [math]::Min(1,$iWinRM + $iRemReg)),
            @("T1083","File/Dir Discovery",      $iAdminShr),
            @("T1069","Permission Groups",       $iRemReg),
            @("T1057","Process Discovery",       $iWinRM),
            @("T1016","Sys Network Config",      $iSNMP),
            @("T1049","Sys Network Conns",       $iWinRM),
            @("T1012","Query Registry",          $lRmReg2),
            @("T1033","Sys Owner/User Disc",     $iWinRM)
        )
        "Lateral Movement" = @(
            @("T1021.001","Remote Desktop",      $lRDP3),
            @("T1021.002","SMB/Admin Shares",   $lSMBRDP3),
            @("T1021.006","WinRM",               $lWinRM2),
            @("T1550.002","Pass the Hash",       $lPassHash3),
            @("T1550.003","Pass the Ticket",     $lTicket2),
            @("T1570","Lateral Tool Transfer",  $lAdmShrMvt2),
            @("T1534","Internal Spearphishing", 0),
            @("T1563","Remote Svc Session",     [math]::Min(1,$iRDPOpen + $iWinRM))
        )
        "Collection" = @(
            @("T1560","Archive Collected",       $iExtConns),
            @("T1119","Automated Collection",    $iPSUnrestr),
            @("T1005","Data from Local Sys",     $iAdminShr),
            @("T1039","Data from Net Share",     $lAdmShr2),
            @("T1025","Data from Removable",     $iNoAppLocker),
            @("T1056","Input Capture",           $iNoLSAPPL),
            @("T1113","Screen Capture",          $iPSUnrestr),
            @("T1123","Audio Capture",           0),
            @("T1185","Browser Session",         0)
        )
        "Command and Control" = @(
            @("T1071","App Layer Protocol",      $lFWorFWO2),
            @("T1071.001","Web Protocols",       $lFWorFWO2),
            @("T1071.004","DNS C2",              $lDNSorFW2),
            @("T1090","Proxy",                   $lProxy2),
            @("T1095","Non-App Layer",           $lFWDis2),
            @("T1572","Protocol Tunneling",      $lIPv6orProxy2),
            @("T1573","Encrypted Channel",       $iFWDis),
            @("T1105","Ingress Tool Transfer",  $lFWorFWO2),
            @("T1219","Remote Access Tool",      $iFWDis),
            @("T1102","Web Service",             $iNoFWOut)
        )
        "Exfiltration" = @(
            @("T1041","Exfil over C2",           $lFWorFWO2),
            @("T1048","Exfil Alt Protocol",      $lIPv6orFW2),
            @("T1567","Exfil Web Service",       $lNoPSLog2),
            @("T1052","Exfil via Physical",      $iNoAppLocker),
            @("T1030","Data Transfer Limits",    $iExtConns),
            @("T1029","Scheduled Transfer",      $iSuspTasks)
        )
        "Impact" = @(
            @("T1486","Data Encrypted",          $lAdmShrFW2),
            @("T1490","Inhibit Sys Recovery",    $lBootOrBL),
            @("T1489","Service Stop",            $iSeDebug),
            @("T1491","Defacement",              $iAdminActive),
            @("T1499","Endpoint DoS",            $iNoUpdates),
            @("T1485","Data Destruction",        $lAdmShr2),
            @("T1561","Disk Wipe",               $iNoBitLock),
            @("T1078","Valid Accounts",          [math]::Min(1,$iAdminActive + $iNoPassword))
        )
    }


    # -------------------------------------------------------------------------
    # Calculer les stats globales
    # -------------------------------------------------------------------------
    $totalTech = 0; $critCount = 0; $warnCount = 0; $possCount = 0
    foreach ($tac in $techniques.Keys) {
        foreach ($t in $techniques[$tac]) {
            $totalTech++
            $lvl = [int]$t[2]
            if ($lvl -ge 3)     { $critCount++ }
            elseif ($lvl -eq 2) { $warnCount++ }
            elseif ($lvl -eq 1) { $possCount++ }
        }
    }
    $affectedCount = $critCount + $warnCount + $possCount

    # -------------------------------------------------------------------------
    # Generer le HTML de la matrice
    # -------------------------------------------------------------------------

    # En-tetes des tactiques
    $headerCells = ""
    foreach ($tac in $tactics.Keys) {
        $tacId = $tactics[$tac]
        $count = 0
        foreach ($t in $techniques[$tac]) { if ([int]$t[2] -gt 0) { $count++ } }
        $badge = if ($count -gt 0) { "<span class='tac-badge'>$count</span>" } else { "" }
        $headerCells += "<th class='tac-header' title='$tacId'>$tac $badge</th>`n"
    }

    # Corps de la matrice - trouver le nombre max de techniques par colonne
    $maxRows = 0
    foreach ($tac in $tactics.Keys) { if ($techniques[$tac].Count -gt $maxRows) { $maxRows = $techniques[$tac].Count } }

    $bodyRows = ""
    for ($row = 0; $row -lt $maxRows; $row++) {
        $bodyRows += "<tr>`n"
        foreach ($tac in $tactics.Keys) {
            $tacTechs = $techniques[$tac]
            if ($row -lt $tacTechs.Count) {
                $t    = $tacTechs[$row]
                $tid  = $t[0]; $tname = $t[1]; $tlvl = [int]$t[2]
                $cls  = switch ($tlvl) { 3 {"t-crit"} 2 {"t-warn"} 1 {"t-poss"} default {"t-none"} }
                $tip  = switch ($tlvl) { 3 {"CRITICAL - enabled by detected vulnerabilities"} 2 {"HIGH - favorable conditions"} 1 {"POSSIBLE - partial conditions"} default {"Not enabled"} }
                $url  = "https://attack.mitre.org/techniques/$($tid -replace '\.','/')/"
                $tidMap = @{
                    "T1003.001"="lsaprot"; "T1110"="polsec";     "T1059"="polpws";
                    "T1059.001"="polpws";  "T1059.003"="polpws"; "T1059.005"="polpws";
                    "T1059.007"="polpws";  "T1547.001"="logdem"; "T1053.005"="tasks";
                    "T1053"="tasks";       "T1562.001"="infav";  "T1021.001"="statrzo";
                    "T1021.002"="shares";  "T1021.006"="statrzo";"T1550.002"="lsaprot";
                    "T1550.003"="lsaprot"; "T1548.002"="uac";    "T1548"="uac";
                    "T1055"="lstps";       "T1068"="maj";        "T1133"="statrzo";
                    "T1078"="licpt";       "T1071"="outfw";      "T1071.001"="outfw";
                    "T1071.004"="dns";     "T1090"="proxy";      "T1095"="conffw";
                    "T1572"="adip6";       "T1105"="outfw";      "T1486"="shares";
                    "T1490"="bcd";         "T1041"="outfw";      "T1048"="outfw";
                    "T1567"="outfw";       "T1135"="shares";     "T1046"="statrzo";
                    "T1040"="arp";         "T1187"="shares";     "T1112"="logdem";
                    "T1197"="conffw";      "T1134"="uac";        "T1070"="psmodules";
                    "T1027"="pshist";      "T1204"="tasks";      "T1047"="polpws";
                    "T1098"="ligrp";       "T1136"="licpt";      "T1012"="rsop";
                    "T1082"="infos";       "T1083"="shares";     "T1016"="cfrzo";
                    "T1049"="statrzo";     "T1087"="licpt";      "T1069"="ligrp";
                    "T1057"="lstps";       "T1033"="infos";      "T1574"="polpws";
                    "T1574.002"="applocker";"T1218"="applocker"; "T1552"="lsaprot";
                    "T1555"="lsaprot";     "T1056"="lsaprot";    "T1558"="lsaprot";
                    "T1606"="lsaprot";     "T1543"="svc";        "T1489"="svc";
                    "T1499"="maj";         "T1485"="shares";     "T1491"="licpt";
                    "T1561"="bitlocker";   "T1570"="shares";     "T1560"="netgeo";
                    "T1119"="polpws";      "T1005"="shares";     "T1039"="shares";
                    "T1025"="applocker";   "T1113"="pshist";     "T1595"="statrzo";
                    "T1592"="svc";         "T1590"="cfrzo";      "T1219"="conffw";
                    "T1102"="outfw";       "T1563"="rdphist";    "T1030"="netgeo";
                    "T1029"="tasks";       "T1553"="bcd";        "T1176"="applocker";
                    "T1505"="svc";         "T1539"="pshist"
                }
                $internalAnchor = if ($tlvl -gt 0 -and $tidMap.ContainsKey($tid)) { $tidMap[$tid] } else { "" }
                if ($internalAnchor) {
                    $bodyRows += "<td class='tech-cell $cls' title='$tid - $tip'>" +
                        "<a href='$url' target='_blank' rel='noopener'>$tname<br><small>$tid</small></a>" +
                        "<a href='#$internalAnchor' class='tech-ext-link' onclick='event.preventDefault();navToAnchor(`"$internalAnchor`")' title='View in report'>&#8595;</a>" +
                        "</td>`n"
                } else {
                    $bodyRows += "<td class='tech-cell $cls' title='$tid - $tip'><a href='$url' target='_blank' rel='noopener'>$tname<br><small>$tid</small></a></td>`n"
                }
            } else {
                $bodyRows += "<td class='tech-cell t-empty'></td>`n"
            }
        }
        $bodyRows += "</tr>`n"
    }

    # Legende des flags actifs
    $activeFlags = ""
    $flagLabels = @{
        NoLockout     = "No account lockout (brute-force risk)"
        WeakPwPolicy  = "Weak password policy"
        AdminActive   = "Built-in Admin account active"
        NoPassword    = "Account with no password"
        WDigest       = "WDigest actif (MDP en memoire)"
        NoLSAPPL      = "LSA RunAsPPL disabled"
        PSUnrestricted= "PowerShell unrestricted"
        NoPSLogging   = "PS logging inactive"
        NoAppLocker   = "AppLocker non configure"
        SuspStartup   = "Suspicious startup entries"
        SuspTasks     = "Suspicious scheduled tasks"
        HostsModified = "HOSTS file modified"
        UACDisabled   = "UAC desactive"
        UACSilent     = "Elevation UAC silencieuse"
        SeDebug       = "SeDebugPrivilege actif"
        RDPOpen       = "RDP expose (port 3389)"
        SMBOpen       = "SMB exposed (port 445)"
        WinRMOpen     = "WinRM expose (5985/5986)"
        AdminShares   = "Admin shares active"
        FWDisabled    = "Pare-feu desactive"
        AVDisabled    = "AV disabled/outdated"
        NoUpdates     = "MAJ critiques manquantes"
        NoBitLocker   = "No disk encryption"
        WifiOpen      = "Open/WEP Wi-Fi"
        DNSSuspect    = "Cache DNS suspect"
        ProxySuspect  = "Proxy suspect configure"
        IPv6Tunnel    = "Tunnel IPv6 actif"
        ARPAnomaly    = "Anomalie ARP detcetee"
        ExtConns      = "Active external connections"
        NoFWOut       = "No outbound FW rules"
        WSUSHttp      = "WSUS en HTTP (non chiffre)"
        NoCredGuard   = "Credential Guard desactive"
        SuspFiles     = "Suspicious executable files"
        SuspPSHist    = "Suspicious PS history"
        ManyPorts     = "Many ports listening"
        SNMPActive    = "SNMP actif"
        BootDebug     = "Mode debug/test boot actif"
        RDPHistory    = "Historique RDP (connexions)"
        AdminGroup    = "Oversized Administrators group"
        RemoteRegistry= "RemoteRegistry actif"
    }
    $flagAnchors = @{
        NoLockout = "polsec"
        WeakPwPolicy = "polsec"
        AdminActive = "licpt"
        NoPassword = "licpt"
        WDigest = "lsaprot"
        NoLSAPPL = "lsaprot"
        PSUnrestricted = "polpws"
        NoPSLogging = "psmodules"
        NoAppLocker = "applocker"
        SuspStartup = "logdem"
        SuspTasks = "tasks"
        HostsModified = "hosts"
        UACDisabled = "uac"
        UACSilent = "uac"
        SeDebug = "uac"
        RDPOpen = "statrzo"
        SMBOpen = "statrzo"
        WinRMOpen = "statrzo"
        AdminShares = "shares"
        FWDisabled = "conffw"
        AVDisabled = "infav"
        NoUpdates = "maj"
        NoBitLocker = "bitlocker"
        WifiOpen = "wifi"
        DNSSuspect = "dns"
        ProxySuspect = "proxy"
        IPv6Tunnel = "adip6"
        ARPAnomaly = "arp"
        ExtConns = "netgeo"
        NoFWOut = "outfw"
        WSUSHttp = "wsus"
        NoCredGuard = "lsaprot"
        SuspFiles = "recentfiles"
        SuspPSHist = "pshist"
        ManyPorts = "statrzo"
        SNMPActive = "svc"
        BootDebug = "bcd"
        RDPHistory = "rdphist"
        AdminGroup = "ligrp"
        RemoteRegistry = "svc"
    }
    foreach ($fk in ($F.Keys | Sort-Object)) {
        if ($F[$fk] -eq $true) {
            $lbl = if ($flagLabels.ContainsKey($fk)) { $flagLabels[$fk] } else { $fk }
            $anc = if ($flagAnchors.ContainsKey($fk)) { $flagAnchors[$fk] } else { "" }
            if ($anc) {
                $activeFlags += "<a href='#$anc' class='flag-item flag-link' onclick='event.preventDefault();navToAnchor(`"$anc`")' title='Go to section'>$lbl <span class='flag-arrow'>&#8594;</span></a>`n"
            } else {
                $activeFlags += "<span class='flag-item'>$lbl</span>`n"
            }
        }
    }
    if (-not $activeFlags) { $activeFlags = "<span class='flag-none'>No significant vulnerability detected</span>" }

    $matrixHtml = @"
<section id='mitre-matrix' class='audit-section mitre-section'>
  <div class='section-header'>
    <h2>MITRE ATT&amp;CK Windows Matrix</h2>
    <span class='badge'>ATT&amp;CK</span>
    <span class='cat-pill'>$affectedCount / $totalTech techniques impacted</span>
  </div>

  <div class='mitre-body'>

    <!-- Stats -->
    <div class='mitre-stats'>
      <div class='ms-card crit'><div class='ms-num'>$critCount</div><div class='ms-lbl'>Critical</div></div>
      <div class='ms-card warn'><div class='ms-num'>$warnCount</div><div class='ms-lbl'>High</div></div>
      <div class='ms-card poss'><div class='ms-num'>$possCount</div><div class='ms-lbl'>Possible</div></div>
      <div class='ms-card none'><div class='ms-num'>$($totalTech - $affectedCount)</div><div class='ms-lbl'>Not applicable</div></div>
    </div>

    <!-- Legende couleurs -->
    <div class='mitre-legend'>
      <span class='leg-item t-crit'>Critique - vuln. detectees</span>
      <span class='leg-item t-warn'>High - favorable conditions</span>
      <span class='leg-item t-poss'>Possible - partial conditions</span>
      <span class='leg-item t-none'>Not enabled</span>
    </div>

    <!-- Vulnerabilites actives -->
    <div class='mitre-flags'>
      <div class='flags-title'>Detected vulnerabilities contributing to the matrix:</div>
      <div class='flags-list'>$activeFlags</div>
    </div>

    <!-- Matrice -->
    <div class='mitre-table-wrap'>
      <table class='mitre-table'>
        <thead><tr>$headerCells</tr></thead>
        <tbody>$bodyRows</tbody>
      </table>
    </div>

    <div class='mitre-footer'>
      Based on MITRE ATT&amp;CK v14 Enterprise / Windows. Click a technique to open the ATT&amp;CK page.
      Coloration automatique basee sur les resultats de l'audit -- non exhaustif.
    </div>

  </div>
</section>
"@

    return $matrixHtml
}


# ---------------------------------------------------------------------------
#  PLAN DE REMEDIATION - Generation HTML
# ---------------------------------------------------------------------------

function Generate-RemediationPlan {
    param([hashtable]$Results)

    function Has      { param($k,$p) if(-not $Results.ContainsKey($k)){return $false}; return ($Results[$k] -match $p) }
    function ResultOf { param($k)    if($Results.ContainsKey($k)){return $Results[$k]} else {return ""} }

    # Each action: @{ Prio(1=critical,2=high,3=medium); Cat; Title; Detail; Command; Ref }
    $actions = [System.Collections.Generic.List[object]]::new()
    function Add-Action { param($prio,$cat,$titre,$detail,$cmd,$ref,$anchor="")
        $actions.Add(@{Prio=$prio;Cat=$cat;Titre=$titre;Detail=$detail;Cmd=$cmd;Ref=$ref;Anchor=$anchor}) }

    # -- Accounts and authentication --
    if (Has "08" "(?i)\[!MOT DE PASSE VIDE\]") {
        Add-Action 1 "Accounts" "Set a password on all active accounts" `
            "Accounts without a password allow immediate access without any credential." `
            'net user <NomCompte> <NouveauMotDePasse>' `
            "CIS Control 5.2" `
            "licpt"
    }

    if (Has "08" "(?i)(Administrator|Administrateur).*Actif\s*:\s*True") {
        Add-Action 1 "Accounts" "Rename and disable the built-in Administrator account" `
            "The built-in Administrator account is the primary target of brute-force attacks." `
            'Rename-LocalUser -Name "Administrateur" -NewName "Admin_$(Get-Random -Max 9999)"
Disable-LocalUser -Name "Administrateur"' `
            "CIS Benchmark 2.3.1 / ANSSI R30" `
            "licpt"
    }

    if (Has "08" "(?i)(Guest|Invite).*Actif\s*:\s*True") {
        Add-Action 1 "Accounts" "Disable the Guest account" `
            "The Guest account allows authenticated access without known credentials." `
            'Disable-LocalUser -Name "Invite"
Disable-LocalUser -Name "Guest"' `
            "CIS Benchmark 2.3.1" `
            "licpt"
    }

    if (Has "07" "LockoutBadCount\s*=\s*0") {
        Add-Action 1 "Accounts" "Enable account lockout after failed attempts" `
            "Without lockout, brute-force attacks can test millions of passwords." `
            'net accounts /lockoutthreshold:5 /lockoutduration:30 /lockoutwindow:30' `
            "CIS Benchmark 1.2 / ANSSI R31" `
            "polsec"
    }

    if (Has "07" "PasswordComplexity\s*=\s*0") {
        Add-Action 1 "Accounts" "Enable password complexity" `
            "Without complexity, simple passwords (123456, firstname) are common." `
            'secedit /export /cfg C:\temp\secpol.cfg
# Editer PasswordComplexity = 1 dans le fichier
secedit /configure /db secedit.sdb /cfg C:\temp\secpol.cfg /overwrite' `
            "CIS Benchmark 1.1.5" `
            "polsec"
    }

    if (Has "07" "MinimumPasswordLength\s*=\s*[0-9]\b") {
        $pwlen = 0
        if ((ResultOf "07") -match "MinimumPasswordLength\s*=\s*([0-9]+)") { $pwlen = [int]$Matches[1] }
        if ($pwlen -lt 12) {
            Add-Action 2 "Accounts" "Increase minimum password length to 12" `
                "Current length: $pwlen. A 12+ char password resists dictionary attacks." `
                'net accounts /minpwlen:12' `
                "CIS Benchmark 1.1.6 / ANSSI R68" `
            "polsec"
        }

    }

    # ?? Pare-feu ????????????????????????????????????????????????????????????
    if (Has "25" "(?i)State\s+OFF|Etat\s+INACTIF|OFF") {
        Add-Action 1 "Firewall" "Re-enable Windows Firewall on all profiles" `
            "A disabled firewall leaves all ports exposed without filtering." `
            'Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True' `
            "CIS Benchmark 9.1 / ANSSI R17" `
            "conffw"
    }

    if (Has "14" "(?i):3389.*LISTENING|LISTENING.*:3389") {
        Add-Action 1 "Firewall" "Restrict RDP access to authorized IPs only" `
            "RDP exposed to all is the main entry point for brute-force attacks and ransomware." `
            'New-NetFirewallRule -DisplayName "RDP - Restreint" -Direction Inbound -Protocol TCP -LocalPort 3389 -RemoteAddress <IP_AUTORISEE> -Action Allow
New-NetFirewallRule -DisplayName "RDP - Bloquer tout" -Direction Inbound -Protocol TCP -LocalPort 3389 -Action Block' `
            "CIS Benchmark 18.9.65" `
            "statrzo"
    }

    if (Has "14" "(?i):445.*LISTENING|LISTENING.*:445") {
        Add-Action 1 "Firewall" "Block SMB port (445) inbound from Internet" `
            "SMB exposed to Internet allows exploitation of critical vulnerabilities (EternalBlue, etc.)." `
            'New-NetFirewallRule -DisplayName "Bloquer SMB entrant" -Direction Inbound -Protocol TCP -LocalPort 445 -Action Block' `
            "ANSSI R19 / MS Security Baseline" `
            "infw"
    }

    if (Has "14" "(?i):5985.*LISTENING|:5986.*LISTENING") {
        Add-Action 2 "Firewall" "Restrict WinRM to administration IPs only" `
            "WinRM allows remote PowerShell command execution." `
            'winrm set winrm/config/listener?Address=*+Transport=HTTP @{Source="<IP_ADMIN>"}' `
            "CIS Benchmark 18.6.1" `
            "statrzo"
    }


    # ?? Mises a jour ????????????????????????????????????????????????????????
    if ($Results.ContainsKey("17")) {
        $daysSince = 0
        $lines = (ResultOf "17") -split "`n" | Where-Object { $_ -match "\d{2}/\d{2}/\d{4}" }
        if ($lines.Count -gt 0) {
            try {
                $lastDate = [datetime]::ParseExact(([regex]::Match($lines[0],"\d{2}/\d{2}/\d{4}")).Value,"dd/MM/yyyy",$null)
                $daysSince = ((Get-Date) - $lastDate).Days
            } catch {}
        }
        if ($daysSince -gt 30) {
            Add-Action 1 "MAJ" "Install pending Windows updates ($daysSince days overdue)" `
                "Every day without updates exposes the system to public CVEs and automated exploitation tools." `
                '# Installer les MAJ via PowerShell (module PSWindowsUpdate requis)
Install-Module PSWindowsUpdate -Force
Get-WindowsUpdate -Install -AcceptAll -AutoReboot' `
                "CIS Control 7.3 / ANSSI R61" `
            "maj"
        }

    }

    # ?? Protection des credentials ??????????????????????????????????????????
    if (Has "44" "(?i)RunAsPPL.*0|\[RISQUE\] LSA") {
        Add-Action 1 "Credentials" "Enable LSA Protected Process Light (RunAsPPL)" `
            "Without RunAsPPL, lsass.exe is readable by any admin process, allowing credential extraction." `
            'reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL /t REG_DWORD /d 1 /f
# Redemarrage requis' `
            "ANSSI R62 / MS Security Baseline" `
            "lsaprot"
    }

    if (Has "44" "(?i)UseLogonCredential.*1|\[CRITICAL\] WDigest") {
        Add-Action 1 "Credentials" "Disable WDigest to eliminate cleartext passwords in memory" `
            "WDigest forces Windows to keep credentials in cleartext in lsass (legacy from Windows XP)." `
            'reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential /t REG_DWORD /d 0 /f' `
            "MS Security Advisory 2871997" `
            "lsaprot"
    }

    if (Has "44" "EnableVirtualizationBasedSecurity.*0") {
        Add-Action 2 "Credentials" "Enable Credential Guard (VBS)" `
            "Credential Guard isolates credentials in a virtualized environment inaccessible from the OS." `
            '# Via GPO : Configuration ordinateur > Modeles admin > Systeme > Device Guard
# Ou via registre :
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v EnableVirtualizationBasedSecurity /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LsaCfgFlags /t REG_DWORD /d 1 /f' `
            "MS Credential Guard Documentation" `
            "lsaprot"
    }


    # ?? UAC ?????????????????????????????????????????????????????????????????
    if (Has "42" "(?i)EnableLUA.*0|\[RISQUE\] UAC desactive") {
        Add-Action 1 "Privileges" "Re-enable UAC (User Account Control)" `
            "Disabled UAC allows any process to obtain SYSTEM privileges without a confirmation prompt." `
            'reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 1 /f
# Redemarrage requis' `
            "CIS Benchmark 2.3.7 / ANSSI R38" `
            "uac"
    }

    if (Has "42" "(?i)ConsentPromptBehaviorAdmin.*0") {
        Add-Action 1 "Privileges" "Configure UAC to prompt for confirmation (no silent elevation)" `
            "Silent elevation allows malicious programs to elevate without user alert." `
            'reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 5 /f' `
            "CIS Benchmark 2.3.7.2" `
            "uac"
    }


    # ?? Chiffrement ?????????????????????????????????????????????????????????
    if (Has "36" "(?i)desactive|non configure|Off") {
        Add-Action 1 "Encryption" "Enable BitLocker on the system volume" `
            "An unencrypted disk can be fully read if stolen (USB boot, disk extraction)." `
            'Enable-BitLocker -MountPoint "C:" -EncryptionMethod XtsAes256 -UsedSpaceOnly -SkipHardwareTest -RecoveryPasswordProtector' `
            "CIS Benchmark 18.9.11 / ANSSI R7" `
            "bitlocker"
    }


    # ?? Antivirus ???????????????????????????????????????????????????????????
    if (Has "28" "(?i)Disabled|Out of date") {
        Add-Action 1 "AV/EDR" "Re-enable and update the antivirus" `
            "A disabled or outdated AV offers no protection against recent threats." `
            '# For Windows Defender:
Set-MpPreference -DisableRealtimeMonitoring $false
Update-MpSignature' `
            "CIS Control 10.1" `
            "infav"
    }


    # ?? PowerShell ??????????????????????????????????????????????????????????
    if (Has "06" "(?i)Unrestricted|Bypass") {
        Add-Action 1 "PowerShell" "Restrict the PowerShell execution policy" `
            "Unrestricted/Bypass allows any PS script to run, a major vector for fileless attacks." `
            'Set-ExecutionPolicy RemoteSigned -Scope LocalMachine -Force
Set-ExecutionPolicy AllSigned -Scope CurrentUser -Force' `
            "CIS Benchmark 18.9.85.1 / ANSSI R62" `
            "polpws"
    }

    if (Has "46" "(?i)Script Block Logging.*INACTIF") {
        Add-Action 2 "PowerShell" "Enable PowerShell Script Block Logging" `
            "Script Block Logging records all executed PS code, including decoded commands (base64)." `
            'reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f' `
            "ANSSI R62 / CIS Benchmark 18.9.85.2" `
            "psmodules"
    }

    if (Has "46" "(?i)Module Logging.*INACTIF") {
        Add-Action 3 "PowerShell" "Enable PowerShell Module Logging" `
            "Module Logging records function calls from all loaded PS modules." `
            'reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" /v EnableModuleLogging /t REG_DWORD /d 1 /f' `
            "CIS Benchmark 18.9.85.1" `
            "psmodules"
    }


    # ?? AppLocker ???????????????????????????????????????????????????????????
    if (Has "43" "(?i)AppLocker non configure|aucune regle.*Exe") {
        Add-Action 2 "Execution Control" "Configure AppLocker to restrict execution" `
            "AppLocker bloque l'execution depuis TEMP, APPDATA et les dossiers utilisateurs." `
            '# Creer les regles par defaut AppLocker
$policy = Get-AppLockerPolicy -Effective
Set-AppLockerPolicy -XMLPolicy C:\AppLockerPolicy.xml
# Demarrer le service AppLocker
Start-Service AppIDSvc
Set-Service AppIDSvc -StartupType Automatic' `
            "CIS Benchmark 9.3 / ANSSI R59" `
            "applocker"
    }


    # ?? Services dangereux ??????????????????????????????????????????????????
    if (Has "24" "(?i)\[Running\].*Telnet|Telnet.*Running") {
        Add-Action 1 "Services" "Disable the Telnet service" `
            "Telnet transmits credentials in cleartext. Replace with SSH." `
            'Stop-Service -Name Telnet -Force
Set-Service -Name Telnet -StartupType Disabled' `
            "CIS Benchmark 18.9.24" `
            "svc"
    }

    if (Has "24" "(?i)\[Running\].*RemoteRegistry|RemoteRegistry.*Running") {
        Add-Action 2 "Services" "Disable the RemoteRegistry service" `
            "RemoteRegistry allows remote registry read/write, a reconnaissance vector." `
            'Stop-Service -Name RemoteRegistry -Force
Set-Service -Name RemoteRegistry -StartupType Disabled' `
            "CIS Benchmark 18.9.59 / ANSSI R19" `
            "svc"
    }

    if (Has "24" "(?i)\[Running\].*SNMP|SNMP.*Running") {
        Add-Action 2 "Services" "Disable SNMP or secure the community string" `
            "SNMP v1/v2 with community 'public' exposes system info to the entire network." `
            'Stop-Service -Name SNMP -Force
Set-Service -Name SNMP -StartupType Disabled' `
            "CIS Benchmark 18.9.65" `
            "svc"
    }


    # ?? Partages ????????????????????????????????????????????????????????????
    if (Has "10" "(?i)ADMIN\`\$|C\`\$") {
        Add-Action 2 "Network" "Disable hidden administrative shares" `
            "Admin shares (C`$, ADMIN`$) are exploited by ransomware to propagate." `
            'reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v AutoShareWks /t REG_DWORD /d 0 /f
# Supprimer immediatement les partages existants :
net share C$ /delete
net share ADMIN$ /delete' `
            "CIS Benchmark 18.9.62 / ANSSI R19" `
            "shares"
    }


    # ?? Fichier HOSTS ???????????????????????????????????????????????????????
    if (Has "23" "(?i)[^#\n]+\d+\.\d+\.\d+\.\d+") {
        $hostsLines = (ResultOf "23") -split "`n" | Where-Object {
            $_ -match "^\s*[^#\s]" -and $_ -notmatch "127\.0\.0\.1\s+localhost" -and $_ -notmatch "::1\s+localhost" }
        if ($hostsLines.Count -gt 0) {
            Add-Action 1 "Network" "Clean unauthorized entries from the HOSTS file" `
                "$($hostsLines.Count) entree(s) suspecte(s) trouvee(s). Ces entrees peuvent rediriger le trafic ou bloquer les MAJ AV." `
                '# Sauvegarder puis editer :
copy "$env:SystemRoot\System32\drivers\etc\hosts" "$env:TEMP\hosts.bak"
notepad "$env:SystemRoot\System32\drivers\etc\hosts"' `
                "ANSSI Hygiene Informatique R37" `
            "hosts"
        }

    }

    # ?? Journalisation ??????????????????????????????????????????????????????
    if ($Results.ContainsKey("46")) {
        Add-Action 2 "Logging" "Increase event log size" `
            "Logs that are too small are overwritten quickly, destroying forensic evidence." `
            'wevtutil sl Security /ms:1073741824
wevtutil sl System /ms:524288000
wevtutil sl Application /ms:524288000' `
            "ANSSI R52 / CIS Benchmark 18.9.26" `
            "syst"
    }

    if (Has "46" "(?i)Transcription.*INACTIF") {
        Add-Action 3 "Logging" "Enable PowerShell transcription" `
            "Transcription records all PS sessions in timestamped log files." `
            'reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" /v EnableTranscripting /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" /v OutputDirectory /t REG_SZ /d "C:\PSLogs" /f' `
            "CIS Benchmark 18.9.85.3" `
            "psmodules"
    }


    # ?? IPv6 ????????????????????????????????????????????????????????????????
    if (Has "35" "(?i)Teredo|6to4|ISATAP") {
        Add-Action 3 "Network" "Disable IPv6 tunnels (Teredo, 6to4, ISATAP)" `
            "These tunnels encapsulate IPv6 in IPv4 and bypass firewalls that do not filter IPv6." `
            'netsh interface teredo set state disabled
netsh interface 6to4 set state disabled
netsh interface isatap set state disabled' `
            "ANSSI R20" `
            "adip6"
    }


    # ?? Wi-Fi ???????????????????????????????????????????????????????????????
    if (Has "19" "(?i)WEP|Open.*Authentification|Authentication.*Open") {
        Add-Action 1 "Wi-Fi" "Remove Wi-Fi profiles with weak encryption (WEP/open)" `
            "WEP can be cracked in minutes. Open networks expose all traffic in cleartext." `
            '# Lister les profils :
netsh wlan show profiles
# Supprimer un profil :
netsh wlan delete profile name="<NomDuProfil>"' `
            "ANSSI Hygiene R14" `
            "wifi"
    }


    # ?? ARP / Reseau ????????????????????????????????????????????????????????
    if (Has "22" "(?i)Doublon") {
        Add-Action 1 "Network" "Investigate ARP anomaly (possible ARP spoofing)" `
            "A duplicate MAC address in the ARP table may indicate an active man-in-the-middle attack." `
            '# Verifier la table ARP :
arp -a
# Comparer avec la table de reference
# Identifier la machine avec l adresse MAC dupliquee' `
            "MITRE T1557.002" `
            "arp"
    }


    # ?? Proxy ???????????????????????????????????????????????????????????????
    if (Has "21" "(?i)ProxyEnable.*1") {
        Add-Action 2 "Network" "Verify and validate the proxy configuration" `
            "A proxy configured without the user's knowledge allows interception of all HTTP/HTTPS traffic." `
            '# Verifier le proxy configure :
Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" | Select ProxyServer,ProxyEnable
# Supprimer le proxy si non autorise :
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name ProxyEnable -Value 0' `
            "MITRE T1090" `
            "proxy"
    }


    # ?? Startup / Taches suspectes ??????????????????????????????????????????
    if (Has "34" "(?i)temp|appdata|public") {
        Add-Action 1 "Persistence" "Investigate and clean suspicious startup entries" `
            "Programs launching from TEMP or APPDATA are characteristic of malicious software." `
            '# Lister toutes les entrees Run :
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
# Supprimer une entree suspecte :
Remove-ItemProperty -Path "HKCU:\...\Run" -Name "<EntryName>"' `
            "MITRE T1547.001" `
            "logdem"
    }

    if (Has "29" "(?i)\\\\Temp\\\\|\\\\AppData\\\\") {
        Add-Action 1 "Persistence" "Audit and remove suspicious scheduled tasks" `
            "Tasks running scripts from TEMP or APPDATA are a sign of suspicious persistence." `
            '# Lister les taches suspectes :
Get-ScheduledTask | Where-Object { $_.Actions.Execute -match "temp|appdata" }
# Supprimer :
Unregister-ScheduledTask -TaskName "<Nom>" -Confirm:$false' `
            "MITRE T1053.005" `
            "tasks"
    }


    # ?? Journal securite ????????????????????????????????????????????????????
    if (Has "38" "(?i)4625") {
        Add-Action 1 "Forensics" "Investigate logon failures (EventID 4625)" `
            "Mass logon failures indicate active brute-force. Identify the source IP." `
            '# Lister les echecs de connexion avec IP source :
Get-EventLog -LogName Security -InstanceId 4625 -Newest 50 | Select-Object TimeGenerated,Message | Format-List' `
            "MITRE T1110" `
            "evtsec"
    }

    if (Has "38" "(?i)4720|4732") {
        Add-Action 1 "Forensics" "Investigate account creation/modification (4720/4732)" `
            "An account created or added to a group without authorization indicates persistence." `
            'Get-EventLog -LogName Security -InstanceId 4720,4732 -Newest 20 | Format-List' `
            "MITRE T1136" `
            "evtsec"
    }


    # ?? WSUS HTTP ???????????????????????????????????????????????????????????
    if (Has "16" "(?i)http://") {
        Add-Action 1 "MAJ" "Secure WSUS communication with HTTPS" `
            "A WSUS server over HTTP allows WSUS-pect attacks: distribution of fake updates." `
            '# Reconfigurer le serveur WSUS pour HTTPS (port 8531)
# Sur le serveur WSUS : wsusutil configuressl <FQDN>
# Sur les clients GPO : WUServer = https://<serveur>:8531' `
            "WSUS-pect mitigation / CIS" `
            "wsus"
    }


    # ?? Historique PS suspect ????????????????????????????????????????????????
    if (Has "41" "(?i)\[SUSPECT\]") {
        Add-Action 1 "Forensics" "Analyze suspicious PowerShell commands in history" `
            "Commands with -enc, Download-String or IEX are characteristic of a fileless attack." `
            '# Consulter l historique PS complet :
Get-Content "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
# Analyser les evenements Script Block (si active) :
Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" | Where-Object Id -eq 4104' `
            "MITRE T1059.001" `
            "pshist"
    }


    # ?? Trier par priorite, generer le HTML ?????????????????????????????????
    $sorted = $actions | Sort-Object { $_.Prio }
    $p1 = @($sorted | Where-Object { $_.Prio -eq 1 })
    $p2 = @($sorted | Where-Object { $_.Prio -eq 2 })
    $p3 = @($sorted | Where-Object { $_.Prio -eq 3 })
    $totalActions = $actions.Count

    function Build-ActionCards {
        param($list, $prioClass, $prioLabel)
        $html = ""
        foreach ($a in $list) {
            $cmdHtml = ""
            if ($a.Cmd) {
                $cmdEsc = [System.Web.HttpUtility]::HtmlEncode($a.Cmd)
                $cmdHtml = "<div class='rem-cmd'><span class='rem-cmd-label'>Commande :</span><pre>$cmdEsc</pre></div>"
            }
            $refHtml = if ($a.Ref) { "<span class='rem-ref'>Ref : $($a.Ref)</span>" } else { "" }
            $anchorHtml = if ($a.Anchor) { "<a href='#$($a.Anchor)' class='rem-section-link' onclick='event.preventDefault();navToAnchor(`"$($a.Anchor)`")'>&rarr; Go to section</a>" } else { "" }
            $html += @"
<div class='rem-card $prioClass'>
  <div class='rem-card-header'>
    <span class='rem-prio-badge'>$prioLabel</span>
    <span class='rem-cat'>$($a.Cat)</span>
    <span class='rem-title'>$($a.Titre)</span>
    $anchorHtml
  </div>
  <div class='rem-body'>
    <p class='rem-detail'>$($a.Detail)</p>
    $cmdHtml
    $refHtml
  </div>
</div>
"@
        }
        return $html
    }

    $cards1 = Build-ActionCards $p1 "p1" "CRITICAL"
    $cards2 = Build-ActionCards $p2 "p2" "HAUTE"
    $cards3 = Build-ActionCards $p3 "p3" "MOYENNE"

    if (-not $cards1 -and -not $cards2 -and -not $cards3) {
        $cards1 = "<div class='rem-empty'>No major vulnerability detected automatically. Check each section's recommendations.</div>"
    }

    $remHtml = @"
<section id='remediation' class='audit-section rem-section'>
  <div class='section-header'>
    <h2>Remediation Plan</h2>
    <span class='badge'>REMEDIATION</span>
    <span class='cat-pill'>$totalActions actions identifiees</span>
  </div>

  <div class='rem-body-wrap'>

    <div class='rem-summary'>
      <div class='rem-sum-card p1'>
        <span class='rem-sum-num'>$($p1.Count)</span>
        <span class='rem-sum-lbl'>Critical</span>
      </div>
      <div class='rem-sum-card p2'>
        <span class='rem-sum-num'>$($p2.Count)</span>
        <span class='rem-sum-lbl'>High priority</span>
      </div>
      <div class='rem-sum-card p3'>
        <span class='rem-sum-num'>$($p3.Count)</span>
        <span class='rem-sum-lbl'>Medium priority</span>
      </div>
      <div class='rem-disclaimer'>
        These remediations are automatically generated from detected findings.
        Test in a validation environment before deploying to production.
        Some actions require a restart.
      </div>
    </div>

    $(if ($cards1) { "<div class='rem-group-title p1-title'>Critical actions - address as a priority</div>$cards1" })
    $(if ($cards2) { "<div class='rem-group-title p2-title'>High priority actions</div>$cards2" })
    $(if ($cards3) { "<div class='rem-group-title p3-title'>Hardening actions</div>$cards3" })

  </div>
</section>
"@

    return $remHtml
}


function Build-HtmlReport {
    param([hashtable]$Results)

    $menuItems    = ""
    $contentItems = ""
    $dashboardHtml = ""
    $mitreHtml     = ""
    $remHtml       = ""

    # --- Calcul du score de securite ---
    $scoreData = Compute-SecurityScore -Results $Results
    $globalScore = $scoreData.Global
    $scoreDomains = $scoreData.Domains

    # Couleur du score global
    $scoreColor = if ($globalScore -ge 7) { "#3fb950" } elseif ($globalScore -ge 5) { "#d29922" } else { "#f85149" }
    $scoreLabel = if ($globalScore -ge 7) { "Good" } elseif ($globalScore -ge 5) { "Warning" } else { "Critical" }

    # --- Generer les cartes de domaine ---
    $domainCards = ""
    $sortedDomains = $scoreDomains | Sort-Object { $_.Score }
    foreach ($d in $sortedDomains) {
        $ds = $d.Score
        $dc = if ($ds -ge 8) { "#3fb950" } elseif ($ds -ge 5) { "#d29922" } else { "#f85149" }
        $dlabel = if ($ds -ge 8) { "OK" } elseif ($ds -ge 5) { "Warning" } else { "Critical" }
        $dClass = if ($ds -ge 8) { "ok" } elseif ($ds -ge 5) { "warn" } else { "crit" }
        $pct = [int]($ds * 10)
        $issuesHtml = ""
        if ($d.Issues.Count -gt 0) {
            foreach ($iss in $d.Issues) {
                $issuesHtml += "<li>$iss</li>"
            }
            $issuesHtml = "<ul class='domain-issues'>$issuesHtml</ul>"
        } else {
            $issuesHtml = "<p class='domain-ok'>No issue detected</p>"
        }
        $domainCards += @"
<a href='#$($d.Anchor)' class='domain-card $dClass'>
  <div class='dc-top'>
    <span class='dc-name'>$($d.Label)</span>
    <span class='dc-badge'>$dlabel</span>
  </div>
  <div class='dc-bar-wrap'>
    <div class='dc-bar' style='width:$pct%;background:$dc'></div>
  </div>
  <div class='dc-score-line'>
    <span class='dc-score' style='color:$dc'>$ds / 10</span>
    $issuesHtml
  </div>
</a>
"@
    }

    # --- Dashboard HTML ---
    $dashboardHtml = @"
<section id='dashboard' class='audit-section dashboard-section'>
  <div class='section-header'>
    <h2>Security Dashboard</h2>
    <span class='badge'>SYNTHESE</span>
    <span class='cat-pill'>Rapport $date</span>
  </div>

  <div class='dashboard-body'>

    <!-- Score global -->
    <div class='global-score-wrap'>
      <div class='global-gauge'>
        <svg viewBox='0 0 200 140' width='200' height='140'>
          <!-- Arc de fond -->
          <path d='M 20 105 A 80 80 0 0 1 180 105' fill='none' stroke='#30363d' stroke-width='16' stroke-linecap='round'/>
          <!-- Arc colore selon score -->
          <path id='gauge-arc' d='M 20 105 A 80 80 0 0 1 180 105' fill='none' stroke='$scoreColor' stroke-width='16' stroke-linecap='round'
            stroke-dasharray='251.3' stroke-dashoffset='$(251.3 - ($globalScore / 10 * 251.3))'
            style='transition: stroke-dashoffset 1s ease'/>
          <text x='100' y='95' text-anchor='middle' font-size='32' font-weight='700' fill='$scoreColor'>$globalScore</text>
          <text x='100' y='118' text-anchor='middle' font-size='12' fill='$scoreColor' font-weight='600'>/ 10  $scoreLabel</text>
        </svg>
      </div>
      <div class='global-meta'>
        <div class='gm-title'>Global Security Score</div>
        <div class='gm-machine'>$computername</div>
        <div class='gm-date'>Audit from $date a $hour</div>
        <div class='gm-modules'>$modCount modules analyzed</div>
        <div class='gm-legend'>
          <span class='leg crit'>0-4 Critical</span>
          <span class='leg warn'>5-6 Warning</span>
          <span class='leg ok'>7-10 Good</span>
        </div>
      </div>
    </div>

    <!-- Grille des domaines -->
    <div class='domains-title'>Domain Analysis <span class='domains-hint'>-- Click to go to the section</span></div>
    <div class='domains-grid'>
      $domainCards
    </div>

  </div>
</section>
"@

    # --- Matrice MITRE ---
    $mitreHtml = Generate-MitreMatrix -Results $Results

    # --- Remediation Plan ---
    Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue
    $remHtml = Generate-RemediationPlan -Results $Results

    # Construire index categories -> liste de cles
    # Utilise une ArrayList pour eviter le bug PowerShell ou += sur @() dans Hashtable
    # ne modifie pas le tableau stocke (il cree un nouveau tableau non reassigne)
    $allCats = @{}
    foreach ($key in $Global:AuditModules.Keys) {
        if ($Results.ContainsKey($key)) {
            $mod = $Global:AuditModules[$key]
            $cat = $mod["Category"]
            if (-not $allCats.ContainsKey($cat)) {
                $allCats[$cat] = [System.Collections.Generic.List[string]]::new()
            }
            $allCats[$cat].Add($key)
        }
    }

    # Construire le menu par categorie
    foreach ($cat in ($allCats.Keys | Sort-Object)) {
        $keysInCat = $allCats[$cat] | Sort-Object
        $count     = $allCats[$cat].Count
        $catId     = "cat-" + ($cat -replace '[^a-zA-Z0-9]', '')

        $menuItems += "<li class='cat-group'>`n"
        $menuItems += "  <button class='cat-toggle' data-target='$catId'>"
        $menuItems += "<span class='cat-arrow'>&#9654;</span> $cat"
        $menuItems += "  <span class='cat-count'>$count</span></button>`n"
        $menuItems += "  <ul class='cat-items' id='$catId'>`n"

        foreach ($k in $keysInCat) {
            $m      = $Global:AuditModules[$k]
            $anchor = $m["HtmlAnchor"]
            $short  = $m["ShortName"]
            $name   = $m["Name"]
            $menuItems += "    <li><a class='nav-link' href='#$anchor' data-anchor='$anchor'>"
            $menuItems += "<span class='nav-badge'>$short</span> $name</a></li>`n"
        }
        $menuItems += "  </ul>`n"
        $menuItems += "</li>`n"
    }

    # --- Sections de contenu ---
    foreach ($key in ($Results.Keys | Sort-Object)) {
        $m        = $Global:AuditModules[$key]
        $mName    = $m["Name"]
        $mShort   = $m["ShortName"]
        $mCat     = $m["Category"]
        $mAnchor  = $m["HtmlAnchor"]
        $mConseil = $m["Conseil"]
        $conseil = ""
        if ($mConseil) {
            $cClass = "info"; $cLabel = "INFO"; $cText = $mConseil
            if     ($mConseil -match "^\[CRITICAL\]")  { $cClass="critique";  $cLabel="CRITICAL";  $cText=$mConseil -replace "^\[CRITICAL\]\s*","" }
            elseif ($mConseil -match "^\[IMPORTANT\]") { $cClass="important"; $cLabel="IMPORTANT"; $cText=$mConseil -replace "^\[IMPORTANT\]\s*","" }
            elseif ($mConseil -match "^\[INFO\]")      { $cClass="info";      $cLabel="INFO";      $cText=$mConseil -replace "^\[INFO\]\s*","" }
            $conseil = "<div class='conseil $cClass'><span class='conseil-icon'>$cLabel</span><span class='conseil-text'>$cText</span></div>"
        }

        # Traitement special pour le cache DNS : extraire les deux blocs
        $extraHtml = ""
        if ($mAnchor -eq "dns" -and $Results[$key] -match "=== DOMAINES BRUTS ===") {
            $parts = $Results[$key] -split "=== DOMAINES BRUTS ==="
            $logPart    = if ($parts.Count -gt 0) { ($parts[0] -replace "=== LOG COMPLET ===
?
?","").Trim() } else { $Results[$key] }
            $domainPart = if ($parts.Count -gt 1) { $parts[1].Trim() } else { "" }
            $logEsc    = [System.Web.HttpUtility]::HtmlEncode($logPart)
            $domainEsc = [System.Web.HttpUtility]::HtmlEncode($domainPart)
            $domainCount = ($domainPart -split "`n" | Where-Object { $_ -match "\S" }).Count
            $extraHtml = @"
<div class='dns-domains-block'>
  <div class='dns-domains-header'>
    <span class='dns-domains-title'>Domaines bruts ($domainCount uniques) - copiable</span>
    <button class='dns-copy-btn' onclick='(function(b){var t=b.closest(".dns-domains-block").querySelector("textarea");t.select();document.execCommand("copy");b.textContent="Copie !";setTimeout(function(){b.textContent="Copier"},1500)})(this)'>Copier</button>
  </div>
  <textarea class='dns-domains-textarea' readonly spellcheck='false'>$domainEsc</textarea>
</div>
<pre class='output'>$logEsc</pre>
"@
            $contentItems += @"
<section id='$mAnchor' class='audit-section'>
  <div class='section-header'>
    <h2>$mName</h2>
    <span class='badge'>$mShort</span>
    <span class='cat-pill'>$mCat</span>
  </div>
  $conseil
  $extraHtml
</section>
"@
            continue
        }

        $rawText = [System.Web.HttpUtility]::HtmlEncode($Results[$key])
        $contentItems += @"
<section id='$mAnchor' class='audit-section'>
  <div class='section-header'>
    <h2>$mName</h2>
    <span class='badge'>$mShort</span>
    <span class='cat-pill'>$mCat</span>
  </div>
  $conseil
  <pre class='output'>$rawText</pre>
</section>
"@
    }

    $modCount = $Results.Count

    $html = @"
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>PowerAudit 3.0 -- $computername</title>
<style>
/* ===== RESET & VARIABLES ===== */
:root {
  --bg:       #0d1117;
  --bg2:      #161b22;
  --bg3:      #21262d;
  --bg4:      #2d333b;
  --border:   #30363d;
  --accent:   #58a6ff;
  --accent2:  #3fb950;
  --warn:     #d29922;
  --danger:   #f85149;
  --text:     #c9d1d9;
  --dim:      #8b949e;
  --sidebar-w: 270px;
  --header-h:  58px;
}
*, *::before, *::after { margin:0; padding:0; box-sizing:border-box; }
html { scroll-behavior: smooth; }
body {
  font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
  background: var(--bg);
  color: var(--text);
  line-height: 1.5;
}

/* ===== SCROLLBAR ===== */
::-webkit-scrollbar { width: 5px; height: 5px; }
::-webkit-scrollbar-track { background: var(--bg); }
::-webkit-scrollbar-thumb { background: var(--bg4); border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: var(--dim); }

/* ===== DASHBOARD ===== */
.dashboard-section .section-header { background: linear-gradient(135deg,#161b22 60%,#1f2937); }
.dashboard-body { padding: 24px 24px 28px; }

/* Score global */
.global-score-wrap {
  display: flex; align-items: center; gap: 32px;
  background: var(--bg3); border: 1px solid var(--border);
  border-radius: 10px; padding: 20px 28px; margin-bottom: 28px;
}
.global-gauge { flex-shrink: 0; }
.global-meta { display: flex; flex-direction: column; gap: 6px; }
.gm-title   { font-size: .95rem; font-weight: 600; color: var(--text); }
.gm-machine { font-size: 1.1rem; font-weight: 700; color: var(--accent); }
.gm-date, .gm-modules { font-size: .78rem; color: var(--dim); }
.gm-legend  { display: flex; gap: 10px; margin-top: 6px; flex-wrap: wrap; }
.leg { font-size: .7rem; padding: 2px 10px; border-radius: 12px; font-weight: 600; }
.leg.crit { background: rgba(248,81,73,.15);  color: #f85149; border:1px solid rgba(248,81,73,.3); }
.leg.warn { background: rgba(210,153,34,.15); color: #d29922; border:1px solid rgba(210,153,34,.3); }
.leg.ok   { background: rgba(63,185,80,.15);  color: #3fb950; border:1px solid rgba(63,185,80,.3); }

/* Titre grille */
.domains-title { font-size: .82rem; font-weight: 600; color: var(--dim);
  text-transform: uppercase; letter-spacing: .06em; margin-bottom: 14px; }
.domains-hint  { font-weight: 400; text-transform: none; letter-spacing: 0; }

/* Grille des cartes */
.domains-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(260px, 1fr));
  gap: 12px;
}

/* Carte domaine */
.domain-card {
  display: block; text-decoration: none;
  background: var(--bg3); border: 1px solid var(--border);
  border-radius: 8px; padding: 14px 16px;
  transition: border-color .15s, transform .1s;
  cursor: pointer;
}
.domain-card:hover { transform: translateY(-2px); }
.domain-card.crit { border-left: 3px solid #f85149; }
.domain-card.warn { border-left: 3px solid #d29922; }
.domain-card.ok   { border-left: 3px solid #3fb950; }
.domain-card.crit:hover { border-color: #f85149; }
.domain-card.warn:hover { border-color: #d29922; }
.domain-card.ok:hover   { border-color: #3fb950; }

.dc-top { display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; }
.dc-name { font-size: .82rem; font-weight: 600; color: var(--text); }
.dc-badge {
  font-size: .65rem; font-weight: 700; padding: 2px 8px; border-radius: 10px;
}
.domain-card.crit .dc-badge { background: rgba(248,81,73,.15);  color: #f85149; }
.domain-card.warn .dc-badge { background: rgba(210,153,34,.15); color: #d29922; }
.domain-card.ok   .dc-badge { background: rgba(63,185,80,.15);  color: #3fb950; }

.dc-bar-wrap { height: 5px; background: var(--bg4); border-radius: 3px; margin-bottom: 10px; overflow: hidden; }
.dc-bar      { height: 100%; border-radius: 3px; transition: width .8s ease; }

.dc-score-line { display: flex; flex-direction: column; gap: 6px; }
.dc-score { font-size: .82rem; font-weight: 700; }
.domain-issues { margin: 0; padding: 0 0 0 14px; font-size: .72rem; color: var(--dim); line-height: 1.6; }
.domain-issues li { margin-bottom: 2px; }
.domain-ok { font-size: .72rem; color: #3fb950; margin: 0; }


/* ===== MATRICE MITRE ===== */
.mitre-section .section-header { background: linear-gradient(135deg,#161b22 60%,#1a1f2e); }
.mitre-body { padding: 20px 20px 28px; }

/* Stats */
.mitre-stats { display:flex; gap:12px; margin-bottom:18px; flex-wrap:wrap; }
.ms-card { flex:1; min-width:90px; background:var(--bg3); border:1px solid var(--border);
  border-radius:8px; padding:12px 14px; text-align:center; }
.ms-num { font-size:1.6rem; font-weight:700; line-height:1; }
.ms-lbl { font-size:.7rem; color:var(--dim); margin-top:4px; }
.ms-card.crit .ms-num { color:#f85149; }
.ms-card.warn .ms-num { color:#d29922; }
.ms-card.poss .ms-num { color:#58a6ff; }
.ms-card.none .ms-num { color:var(--dim); }

/* Legende */
.mitre-legend { display:flex; gap:10px; flex-wrap:wrap; margin-bottom:14px; }
.leg-item { font-size:.72rem; padding:3px 10px; border-radius:4px; font-weight:600; }
.leg-item.t-crit { background:rgba(248,81,73,.25);  color:#f88; border:1px solid rgba(248,81,73,.5); }
.leg-item.t-warn { background:rgba(210,153,34,.25); color:#fa3; border:1px solid rgba(210,153,34,.5); }
.leg-item.t-poss { background:rgba(88,166,255,.2);  color:#8bf; border:1px solid rgba(88,166,255,.4); }
.leg-item.t-none { background:var(--bg3); color:var(--dim); border:1px solid var(--border); }

/* Flags actifs */
.mitre-flags { background:var(--bg3); border:1px solid var(--border); border-radius:6px;
  padding:12px 14px; margin-bottom:18px; }
.flags-title { font-size:.72rem; color:var(--dim); margin-bottom:8px; font-weight:600;
  text-transform:uppercase; letter-spacing:.05em; }
.flags-list  { display:flex; flex-wrap:wrap; gap:6px; }
.flag-item   { font-size:.7rem; background:rgba(248,81,73,.12); color:#f8a09b;
  border:1px solid rgba(248,81,73,.25); border-radius:4px; padding:2px 8px; }
a.flag-link  { text-decoration:none; cursor:pointer; transition:background .15s, border-color .15s; }
a.flag-link:hover { background:rgba(248,81,73,.28); border-color:rgba(248,81,73,.6); color:#fcc; }
.flag-arrow  { opacity:.7; font-size:.65rem; }
.flag-none   { font-size:.75rem; color:#3fb950; }

/* Table */
.mitre-table-wrap { overflow-x:auto; border:1px solid var(--border); border-radius:8px; }
.mitre-table { border-collapse:collapse; width:100%; min-width:1100px; }

/* En-tetes tactiques */
.tac-header { background:var(--bg4); color:var(--text); font-size:.68rem; font-weight:700;
  padding:8px 6px; text-align:center; border:1px solid var(--border); white-space:nowrap;
  letter-spacing:.03em; position:sticky; top:0; z-index:2; }
.tac-badge { display:inline-block; background:#f85149; color:#fff; font-size:.58rem;
  border-radius:10px; padding:0 5px; margin-left:4px; font-weight:700; }

/* Cellules techniques */
.tech-cell { padding:4px 5px; border:1px solid rgba(48,54,61,.6); vertical-align:top;
  font-size:.64rem; line-height:1.3; width:calc(100% / 13); min-width:82px; }
.tech-cell a { text-decoration:none; display:block; border-radius:3px; padding:3px 4px;
  transition:filter .1s; }
.tech-cell a:hover { filter:brightness(1.3); }
.tech-cell small { opacity:.7; font-size:.58rem; }

/* Niveaux */
.t-crit a { background:rgba(248,81,73,.3);  color:#faa; border:1px solid rgba(248,81,73,.5); }
.t-warn a { background:rgba(210,153,34,.25); color:#fc9; border:1px solid rgba(210,153,34,.4); }
.t-poss a { background:rgba(88,166,255,.18); color:#9cf; border:1px solid rgba(88,166,255,.3); }
.t-none a { background:var(--bg3); color:var(--dim); border:1px solid var(--border); }
.t-empty  { background:transparent; border-color:rgba(48,54,61,.3); }

/* Footer */
.mitre-footer { font-size:.68rem; color:var(--dim); margin-top:14px;
  padding-top:10px; border-top:1px solid var(--border); }

/* Lien MITRE sidebar */
.nav-link.mitre-link { color:#f85149; font-weight:600; }
.nav-link.mitre-link:hover { color:#f85149; border-left-color:#f85149; }
.nav-link.mitre-link.active { color:#f85149; border-left-color:#f85149;
  background:rgba(248,81,73,.08); }
/* ===== HEADER NAV LINKS ===== */
.header-nav {
  display: flex; align-items: center; gap: 4px; margin-left: 8px;
}
.hn-link {
  font-size: .75rem; font-weight: 600; padding: 4px 12px;
  border-radius: 5px; text-decoration: none; border: 1px solid transparent;
  transition: background .15s, border-color .15s, color .15s;
  white-space: nowrap;
}
.hn-link:hover { background: var(--bg3); border-color: var(--border); }
.hn-dashboard { color: var(--accent); }
.hn-dashboard:hover { border-color: var(--accent); }
.hn-mitre { color: #f85149; }
.hn-mitre:hover { border-color: #f85149; background: rgba(248,81,73,.08); }
.hn-rem { color: #d29922; }
.hn-rem:hover { border-color: #d29922; background: rgba(210,153,34,.08); }
.hn-refs { color: var(--dim); }
.hn-refs:hover { color: var(--text); border-color: var(--border); }
/* Lien actif dans le header */
.hn-link.hn-active { background: var(--bg3); border-color: currentColor; }

/* ===== PLAN DE REMEDIATION ===== */
.rem-section .section-header { background: linear-gradient(135deg,#161b22 60%,#1f1a0e); }
.rem-body-wrap { padding: 20px 20px 28px; }

/* Compteurs */
.rem-summary {
  display: flex; gap: 12px; margin-bottom: 22px; align-items: flex-start; flex-wrap: wrap;
}
.rem-sum-card {
  flex-shrink: 0; min-width: 100px; background: var(--bg3);
  border: 1px solid var(--border); border-radius: 8px;
  padding: 12px 16px; text-align: center;
}
.rem-sum-num { font-size: 1.6rem; font-weight: 700; line-height: 1; display: block; }
.rem-sum-lbl { font-size: .7rem; color: var(--dim); margin-top: 4px; display: block; }
.rem-sum-card.p1 .rem-sum-num { color: #f85149; }
.rem-sum-card.p2 .rem-sum-num { color: #d29922; }
.rem-sum-card.p3 .rem-sum-num { color: #58a6ff; }
.rem-disclaimer {
  flex: 1; min-width: 200px; font-size: .72rem; color: var(--dim);
  background: var(--bg3); border: 1px solid var(--border); border-radius: 8px;
  padding: 10px 14px; line-height: 1.6;
}

/* Titres de groupe */
.rem-group-title {
  font-size: .75rem; font-weight: 700; letter-spacing: .07em;
  text-transform: uppercase; padding: 6px 0 10px;
  margin-top: 8px; border-bottom: 1px solid var(--border);
  margin-bottom: 12px;
}
.p1-title { color: #f85149; }
.p2-title { color: #d29922; }
.p3-title { color: #58a6ff; }

/* Cartes d'action */
.rem-card {
  background: var(--bg2); border: 1px solid var(--border);
  border-radius: 8px; margin-bottom: 10px; overflow: hidden;
}
.rem-card.p1 { border-left: 3px solid #f85149; }
.rem-card.p2 { border-left: 3px solid #d29922; }
.rem-card.p3 { border-left: 3px solid #58a6ff; }

.rem-card-header {
  background: var(--bg3); padding: 9px 14px;
  display: flex; align-items: center; gap: 10px; flex-wrap: wrap;
  border-bottom: 1px solid var(--border);
}
.rem-prio-badge {
  font-size: .65rem; font-weight: 700; padding: 2px 8px;
  border-radius: 4px; flex-shrink: 0;
}
.rem-card.p1 .rem-prio-badge { background: rgba(248,81,73,.2);  color: #f85149; border: 1px solid rgba(248,81,73,.4); }
.rem-card.p2 .rem-prio-badge { background: rgba(210,153,34,.2); color: #d29922; border: 1px solid rgba(210,153,34,.4); }
.rem-card.p3 .rem-prio-badge { background: rgba(88,166,255,.2); color: #58a6ff; border: 1px solid rgba(88,166,255,.4); }
.rem-cat { font-size: .68rem; background: var(--bg); border: 1px solid var(--border);
  border-radius: 4px; padding: 1px 8px; color: var(--dim); flex-shrink: 0; }
.rem-title { font-size: .88rem; font-weight: 600; color: var(--text); }

.rem-body { padding: 12px 14px; display: flex; flex-direction: column; gap: 10px; }
.rem-detail { font-size: .8rem; color: var(--dim); line-height: 1.6; margin: 0; }

.rem-cmd { background: var(--bg); border: 1px solid var(--border); border-radius: 5px; overflow: hidden; }
.rem-cmd-label { display: block; font-size: .65rem; font-weight: 700; color: var(--dim);
  padding: 4px 12px 2px; text-transform: uppercase; letter-spacing: .06em; }
.rem-cmd pre {
  margin: 0; padding: 8px 12px 10px;
  font-family: 'Cascadia Code','Consolas','Courier New',monospace;
  font-size: .74rem; line-height: 1.6; color: #7ee787;
  overflow-x: auto; white-space: pre;
}

.rem-ref { font-size: .68rem; color: var(--accent); font-style: italic; }
.rem-section-link {
  margin-left: auto; font-size: .72rem; font-weight: 600;
  color: var(--accent); text-decoration: none; white-space: nowrap;
  padding: 2px 10px; border: 1px solid rgba(88,166,255,.3);
  border-radius: 4px; background: rgba(88,166,255,.08);
  transition: background .15s, border-color .15s;
  flex-shrink: 0;
}
.rem-section-link:hover { background: rgba(88,166,255,.18); border-color: var(--accent); }
/* Lien interne MITRE : prend tout l espace, lien externe petit en haut droite */
.tech-cell { position: relative; }
.tech-internal { display: block; width: 100%; }
.tech-ext-link {
  position: absolute; top: 2px; right: 3px;
  font-size: .55rem; color: var(--dim); text-decoration: none;
  opacity: .6; transition: opacity .15s;
  line-height: 1;
}
.tech-ext-link:hover { opacity: 1; color: var(--accent); }
/* Bloc DNS domaines bruts */
.dns-domains-block {
  margin: 12px 18px 0;
  border: 1px solid var(--border); border-radius: 6px; overflow: hidden;
}
.dns-domains-header {
  background: var(--bg3); padding: 7px 12px;
  display: flex; align-items: center; justify-content: space-between;
  border-bottom: 1px solid var(--border);
}
.dns-domains-title { font-size: .75rem; font-weight: 600; color: var(--accent); }
.dns-copy-btn {
  background: rgba(88,166,255,.15); border: 1px solid rgba(88,166,255,.3);
  border-radius: 4px; color: var(--accent); font-size: .7rem;
  padding: 3px 12px; cursor: pointer; font-weight: 600;
  transition: background .15s;
}
.dns-copy-btn:hover { background: rgba(88,166,255,.3); }
.dns-domains-textarea {
  display: block; width: 100%; height: 140px;
  background: var(--bg); color: #7ee787;
  font-family: 'Cascadia Code','Consolas',monospace; font-size: .76rem;
  line-height: 1.6; padding: 10px 14px; border: none; outline: none;
  resize: vertical; box-sizing: border-box;
}
.rem-empty { padding: 24px; text-align: center; color: #3fb950; font-size: .85rem; }

/* Lien sidebar remediation */
.nav-link.rem-link { color: #d29922; font-weight: 600; }
.nav-link.rem-link:hover { color: #d29922; border-left-color: #d29922; }
.nav-link.rem-link.active { color: #d29922; border-left-color: #d29922; background: rgba(210,153,34,.08); }


/* Lien dashboard dans sidebar */
.nav-link.dashboard-link { font-weight: 600; color: var(--accent); border-left-color: var(--accent) !important; }

/* Section references en bas du sidebar */
#sidebar-refs {
  border-top: 1px solid var(--border);
  margin-top: auto;
  flex-shrink: 0;
}
/* Bouton toggle ferme/ouvre la liste */
.refs-toggle-btn {
  width: 100%; background: none; border: none; cursor: pointer;
  display: flex; align-items: center; gap: 7px;
  padding: 9px 12px; color: var(--dim);
  font-size: .68rem; font-weight: 700; letter-spacing: .07em;
  text-transform: uppercase; text-align: left;
  transition: color .15s, background .15s;
}
.refs-toggle-btn:hover { color: var(--text); background: var(--bg3); }
.refs-toggle-btn.open  { color: var(--text); }
.refs-toggle-icon {
  font-size: .5rem; transition: transform .2s; display: inline-block; flex-shrink: 0;
}
.refs-toggle-btn.open .refs-toggle-icon { transform: rotate(90deg); }
.refs-title-text { flex: 1; }
.refs-count {
  background: var(--bg3); border: 1px solid var(--border);
  border-radius: 8px; padding: 0 5px; font-size: .6rem; color: var(--dim);
}
/* Liste des refs (masquee par defaut) */
#refs-list { padding: 2px 0 10px; }
.ref-link {
  display: flex; align-items: flex-start; gap: 8px;
  padding: 5px 4px; border-radius: 5px;
  text-decoration: none; color: var(--dim);
  font-size: .74rem; line-height: 1.35;
  transition: background .12s, color .12s;
  margin-bottom: 1px;
}
.ref-link:hover { background: var(--bg3); color: var(--text); }
.ref-link .ref-icon {
  flex-shrink: 0; width: 20px; height: 20px; border-radius: 4px;
  display: flex; align-items: center; justify-content: center;
  font-size: .6rem; font-weight: 700; margin-top: 1px;
}
.ref-link .ref-body { flex: 1; overflow: hidden; }
.ref-link .ref-name { font-weight: 600; color: var(--text); display: block;
  white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.ref-link .ref-org  { font-size: .67rem; color: var(--dim); }
.ref-link.anssi  .ref-icon { background: rgba(0,114,188,.2);  color: #0072bc; }
.ref-link.cis    .ref-icon { background: rgba(255,138,0,.2);  color: #ff8a00; }
.ref-link.nist   .ref-icon { background: rgba(63,185,80,.2);  color: #3fb950; }
.ref-link.mitre  .ref-icon { background: rgba(248,81,73,.2);  color: #f85149; }
.ref-link.ssi    .ref-icon { background: rgba(139,148,158,.2); color: #8b949e; }

/* ===== TOP HEADER ===== */
#header {
  position: fixed; top: 0; left: 0; right: 0;
  height: var(--header-h);
  background: var(--bg2);
  border-bottom: 1px solid var(--border);
  display: flex; align-items: center;
  padding: 0 18px; gap: 10px;
  z-index: 200;
}
.header-logo {
  height: 36px;
  width: auto;
  flex-shrink: 0;
  filter: drop-shadow(0 1px 4px rgba(0,120,255,.4));
}
#header .logo { font-size: 1rem; font-weight: 700; color: var(--accent); white-space: nowrap; }
#header .logo span { color: var(--dim); font-weight: 400; font-size: .85rem; }
.pill {
  background: var(--bg3); border: 1px solid var(--border);
  border-radius: 20px; padding: 2px 11px;
  font-size: .72rem; color: var(--dim); white-space: nowrap;
}
.pill strong { color: var(--text); }
.header-right { margin-left: auto; display: flex; align-items: center; gap: 8px; }
#search-input {
  background: var(--bg3); border: 1px solid var(--border);
  border-radius: 6px; padding: 4px 10px; color: var(--text);
  font-size: .78rem; width: 180px; outline: none;
  transition: border-color .2s;
}
#search-input:focus { border-color: var(--accent); }
#search-input::placeholder { color: var(--dim); }

/* ===== SIDEBAR ===== */
#sidebar {
  position: fixed;
  top: var(--header-h); left: 0; bottom: 0;
  width: var(--sidebar-w);
  background: var(--bg2);
  border-right: 1px solid var(--border);
  overflow-y: auto;
  z-index: 100;
  display: flex; flex-direction: column;
}
#sidebar-top {
  padding: 10px 12px 6px;
  border-bottom: 1px solid var(--border);
  font-size: .68rem; color: var(--dim);
  display: flex; justify-content: space-between; align-items: center;
}
#sidebar-top strong { color: var(--accent); font-size: .8rem; }
#expand-all, #collapse-all {
  background: none; border: 1px solid var(--border); border-radius: 4px;
  color: var(--dim); font-size: .68rem; padding: 2px 7px; cursor: pointer;
  transition: all .15s;
}
#expand-all:hover, #collapse-all:hover { border-color: var(--accent); color: var(--accent); }
#sidebar nav { flex: 1; overflow-y: auto; padding: 6px 0 20px; }
#sidebar ul { list-style: none; }

/* Category group */
.cat-group { margin: 3px 0; }
.cat-toggle {
  width: 100%; background: none; border: none; cursor: pointer;
  display: flex; align-items: center; gap: 7px;
  padding: 6px 14px; color: var(--dim);
  font-size: .7rem; font-weight: 700; letter-spacing: .08em;
  text-transform: uppercase; text-align: left;
  transition: color .15s;
}
.cat-toggle:hover { color: var(--text); }
.cat-arrow {
  font-size: .55rem; transition: transform .2s;
  display: inline-block; color: var(--dim);
}
.cat-toggle.open .cat-arrow { transform: rotate(90deg); }
.cat-count {
  margin-left: auto; background: var(--bg3);
  border: 1px solid var(--border); border-radius: 10px;
  padding: 0 6px; font-size: .65rem; color: var(--dim);
}

/* Nav items list */
.cat-items { display: none; padding-left: 4px; }
.cat-items.open { display: block; }
.cat-items li { position: relative; }

/* Nav link */
.nav-link {
  display: flex; align-items: center; gap: 7px;
  padding: 5px 14px 5px 18px;
  color: var(--dim); text-decoration: none;
  font-size: .78rem;
  border-left: 2px solid transparent;
  transition: background .12s, color .12s, border-color .12s;
  white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
}
.nav-link:hover {
  background: var(--bg3); color: var(--text);
  border-left-color: var(--bg4);
}
.nav-link.active {
  background: rgba(88,166,255,.08);
  color: var(--accent);
  border-left-color: var(--accent);
}
.nav-badge {
  flex-shrink: 0;
  background: var(--bg3); border: 1px solid var(--border);
  border-radius: 3px; padding: 0 5px;
  font-size: .62rem; font-family: monospace;
  color: var(--accent);
}
.nav-link.active .nav-badge { background: rgba(88,166,255,.15); border-color: var(--accent); }

/* Search highlight */
.nav-link.hidden-search { display: none; }

/* ===== MAIN CONTENT ===== */
#content {
  margin-left: var(--sidebar-w);
  margin-top: var(--header-h);
  padding: 28px 36px 60px;
}

/* Section cards */
.audit-section {
  background: var(--bg2);
  border: 1px solid var(--border);
  border-radius: 8px;
  margin-bottom: 22px;
  overflow: hidden;
  scroll-margin-top: calc(var(--header-h) + 12px);
}
.section-header {
  background: var(--bg3);
  border-bottom: 1px solid var(--border);
  padding: 11px 18px;
  display: flex; align-items: center; gap: 10px;
}
.section-header h2 {
  font-size: .92rem; font-weight: 600; color: var(--text);
  flex: 1;
}
.badge {
  background: var(--bg); border: 1px solid var(--border);
  border-radius: 4px; padding: 1px 8px;
  font-size: .68rem; font-family: monospace; color: var(--accent);
  flex-shrink: 0;
}
.cat-pill {
  background: rgba(88,166,255,.08); border: 1px solid rgba(88,166,255,.2);
  border-radius: 20px; padding: 1px 9px;
  font-size: .66rem; color: var(--accent);
  flex-shrink: 0;
}

/* Conseil block */
.conseil {
  margin: 12px 18px 0;
  padding: 9px 14px;
  border-radius: 6px;
  font-size: .78rem;
  display: flex; gap: 10px; align-items: flex-start;
  line-height: 1.6;
}
.conseil-icon { flex-shrink: 0; font-size: .7rem; font-weight: 700;
  padding: 2px 7px; border-radius: 4px; margin-top: 2px; white-space: nowrap; }
.conseil-text  { flex: 1; }
.conseil.critique  { background: rgba(248,81,73,.07);  border: 1px solid rgba(248,81,73,.3);  color: #f8a09b; }
.conseil.critique  .conseil-icon { background: rgba(248,81,73,.2);  color: #f85149; border: 1px solid rgba(248,81,73,.4); }
.conseil.important { background: rgba(210,153,34,.07); border: 1px solid rgba(210,153,34,.3); color: var(--warn); }
.conseil.important .conseil-icon { background: rgba(210,153,34,.2); color: var(--warn); border: 1px solid rgba(210,153,34,.4); }
.conseil.info      { background: rgba(88,166,255,.06); border: 1px solid rgba(88,166,255,.2); color: #79b8ff; }
.conseil.info      .conseil-icon { background: rgba(88,166,255,.15); color: var(--accent); border: 1px solid rgba(88,166,255,.3); }

/* Output pre */
pre.output {
  padding: 16px 18px;
  overflow-x: auto;
  font-family: 'Cascadia Code', 'Consolas', 'Courier New', monospace;
  font-size: .76rem; line-height: 1.65;
  color: #7ee787;
  white-space: pre-wrap; word-break: break-all;
}

/* Back to top */
#back-to-top {
  position: fixed; bottom: 24px; right: 24px;
  background: var(--bg3); border: 1px solid var(--border);
  border-radius: 50%; width: 38px; height: 38px;
  color: var(--dim); font-size: 1rem; cursor: pointer;
  display: flex; align-items: center; justify-content: center;
  opacity: 0; transition: opacity .2s, border-color .2s, color .2s;
  z-index: 300;
}
#back-to-top.visible { opacity: 1; }
#back-to-top:hover { border-color: var(--accent); color: var(--accent); }
</style>
</head>
<body>

<!-- TOP HEADER -->
<div id="header">
  <img src="data:image/png;base64,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" alt="BlueHat" class="header-logo" />
  <div class="logo">PowerAudit <span>3.0</span></div>
  <span class="pill"><strong>$computername</strong></span>
  <span class="pill">$date</span>
  <nav class="header-nav">
    <a class="hn-link hn-dashboard" href="#dashboard"        data-anchor="dashboard">Dashboard</a>
    <a class="hn-link hn-mitre"     href="#mitre-matrix"     data-anchor="mitre-matrix">Matrice MITRE</a>
    <a class="hn-link hn-rem"       href="#remediation"      data-anchor="remediation">Remediation</a>
    <a class="hn-link hn-refs"      href="#sidebar-refs-anchor">References</a>
  </nav>
  <div class="header-right">
    <input id="search-input" type="text" placeholder="Filter sections..." />
  </div>
</div>

<!-- SIDEBAR -->
<div id="sidebar">
  <div id="sidebar-top">
    <strong>Navigation</strong>
    <div style="display:flex;gap:5px">
      <button id="expand-all">Expand all</button>
      <button id="collapse-all">Collapse all</button>
    </div>
  </div>
  <nav>
    <ul id="nav-list">
    <li><a class='nav-link dashboard-link' href='#dashboard' data-anchor='dashboard'>Dashboard</a></li>
    <li><a class='nav-link mitre-link' href='#mitre-matrix' data-anchor='mitre-matrix'>Matrice MITRE ATT&amp;CK</a></li>
    <li><a class='nav-link rem-link' href='#remediation' data-anchor='remediation'>Remediation Plan</a></li>
$menuItems
    </ul>
  </nav>

  <!-- REFERENCES DE SECURITE -->
  <div id="sidebar-refs">
    <button id="refs-toggle" class="refs-toggle-btn">
      <span class="refs-toggle-icon">&#9654;</span>
      <span class="refs-title-text">Security References</span>
      <span class="refs-count">11</span>
    </button>
    <div id="refs-list" style="display:none">

    <a class="ref-link cis" href="https://www.cisecurity.org/cis-benchmarks" target="_blank" rel="noopener">
      <span class="ref-icon">CI</span>
      <span class="ref-body">
        <span class="ref-name">CIS Benchmarks Windows</span>
        <span class="ref-org">CIS -- Windows 10/11 hardening</span>
      </span>
    </a>

    <a class="ref-link cis" href="https://www.cisecurity.org/controls" target="_blank" rel="noopener">
      <span class="ref-icon">CI</span>
      <span class="ref-body">
        <span class="ref-name">CIS Controls v8</span>
        <span class="ref-org">CIS -- 18 essential security controls</span>
      </span>
    </a>

    <a class="ref-link nist" href="https://www.nist.gov/cyberframework" target="_blank" rel="noopener">
      <span class="ref-icon">NI</span>
      <span class="ref-body">
        <span class="ref-name">NIST Cybersecurity Framework</span>
        <span class="ref-org">NIST -- CSF 2.0</span>
      </span>
    </a>

    <a class="ref-link nist" href="https://csrc.nist.gov/pubs/sp/800/171/r3/final" target="_blank" rel="noopener">
      <span class="ref-icon">NI</span>
      <span class="ref-body">
        <span class="ref-name">NIST SP 800-171 Rev3</span>
        <span class="ref-org">NIST -- Protecting Controlled Unclassified Info</span>
      </span>
    </a>

    <a class="ref-link nist" href="https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final" target="_blank" rel="noopener">
      <span class="ref-icon">NI</span>
      <span class="ref-body">
        <span class="ref-name">NIST SP 800-53 Rev5</span>
        <span class="ref-org">NIST -- Security and Privacy Controls</span>
      </span>
    </a>

    <a class="ref-link mitre" href="https://attack.mitre.org/matrices/enterprise/windows/" target="_blank" rel="noopener">
      <span class="ref-icon">MT</span>
      <span class="ref-body">
        <span class="ref-name">MITRE ATT&amp;CK Windows</span>
        <span class="ref-org">MITRE -- Tactics and techniques</span>
      </span>
    </a>

    <a class="ref-link mitre" href="https://attack.mitre.org/mitigations/enterprise/" target="_blank" rel="noopener">
      <span class="ref-icon">MT</span>
      <span class="ref-body">
        <span class="ref-name">ATT&amp;CK Mitigations</span>
        <span class="ref-org">MITRE -- Mitigations per technique</span>
      </span>
    </a>

    <a class="ref-link ssi" href="https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/windows-security-configuration-framework/windows-security-baselines" target="_blank" rel="noopener">
      <span class="ref-icon">MS</span>
      <span class="ref-body">
        <span class="ref-name">Microsoft Security Baselines</span>
        <span class="ref-org">Microsoft -- MSCT security baselines</span>
      </span>
    </a>

    <a class="ref-link ssi" href="https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/wdac" target="_blank" rel="noopener">
      <span class="ref-icon">MS</span>
      <span class="ref-body">
        <span class="ref-name">WDAC / AppLocker Guide</span>
        <span class="ref-org">Microsoft -- Application control</span>
      </span>
    </a>

    <a class="ref-link ssi" href="https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview" target="_blank" rel="noopener">
      <span class="ref-icon">MS</span>
      <span class="ref-body">
        <span class="ref-name">Windows LAPS</span>
        <span class="ref-org">Microsoft -- Local Admin Password Solution</span>
      </span>
    </a>

    <a class="ref-link nist" href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog" target="_blank" rel="noopener">
      <span class="ref-icon">CI</span>
      <span class="ref-body">
        <span class="ref-name">CISA Microsoft Advisories</span>
        <span class="ref-org">CISA -- Active threats and patches</span>
      </span>
    </a>

    <a class="ref-link mitre" href="https://www.sans.org/white-papers/" target="_blank" rel="noopener">
      <span class="ref-icon">SA</span>
      <span class="ref-body">
        <span class="ref-name">SANS White Papers</span>
        <span class="ref-org">SANS Institute -- Security research</span>
      </span>
    </a>

    </div>
  </div>
</div>

<!-- MAIN CONTENT -->
<main id="content">
$dashboardHtml
$mitreHtml
$remHtml
$contentItems
</main>

<!-- BACK TO TOP -->
<button id="back-to-top" title="Back to top">&#8679;</button>

<script>
(function() {

  var headerH      = 58;

  // Fonction de navigation interne utilisee par les liens MITRE et Remediation
  window.navToAnchor = function(anchor) {
    var target = document.getElementById(anchor);
    if (!target) return;
    setActiveLink(anchor);
    scrollingNow = true;
    clearTimeout(scrollTimer);
    var top = target.getBoundingClientRect().top + window.scrollY - headerH - 10;
    window.scrollTo({ top: top, behavior: 'smooth' });
    scrollTimer = setTimeout(function() {
      scrollingNow = false;
      setActiveLink(getActiveAnchor());
    }, 700);
  };

  var scrollingNow = false;   // bloque le scroll-spy pendant navigation programmee
  var scrollTimer  = null;

  // --- Ouvrir / fermer un groupe sans toucher aux autres ---
  function openGroup(btn, ul)  { btn.classList.add('open');    ul.classList.add('open');    }
  function closeGroup(btn, ul) { btn.classList.remove('open'); ul.classList.remove('open'); }

  // Ouvre la categorie parente d'un lien SANS toucher aux autres groupes
  function ensureParentOpen(linkEl) {
    var ul = linkEl.closest('.cat-items');
    if (!ul) return;
    if (!ul.classList.contains('open')) {
      ul.classList.add('open');
      var btn = document.querySelector('[data-target="' + ul.id + '"]');
      if (btn) btn.classList.add('open');
    }
  }

  // --- Initialisation : tous les groupes ouverts par defaut ---
  document.querySelectorAll('.cat-toggle').forEach(function(btn) {
    var ul = document.getElementById(btn.getAttribute('data-target'));
    openGroup(btn, ul);
    btn.addEventListener('click', function() {
      if (ul.classList.contains('open')) { closeGroup(btn, ul); }
      else { openGroup(btn, ul); }
    });
  });

  document.getElementById('expand-all').addEventListener('click', function() {
    document.querySelectorAll('.cat-toggle').forEach(function(btn) {
      openGroup(btn, document.getElementById(btn.getAttribute('data-target')));
    });
  });

  document.getElementById('collapse-all').addEventListener('click', function() {
    document.querySelectorAll('.cat-toggle').forEach(function(btn) {
      closeGroup(btn, document.getElementById(btn.getAttribute('data-target')));
    });
  });

  // --- Recherche : filtre les liens, ouvre les groupes concernes ---
  document.getElementById('search-input').addEventListener('input', function() {
    var q = this.value.trim().toLowerCase();
    document.querySelectorAll('.nav-link').forEach(function(a) {
      if (!q || a.textContent.toLowerCase().indexOf(q) !== -1) {
        a.classList.remove('hidden-search');
        if (q) ensureParentOpen(a);
      } else {
        a.classList.add('hidden-search');
      }
    });
  });

  // --- Scroll-spy : met en surbrillance le lien de la section visible ---
  var sections = document.querySelectorAll('.audit-section');
  var navLinks = document.querySelectorAll('.nav-link');

  function getActiveAnchor() {
    var scrollY = window.scrollY + headerH + 30;
    var active  = null;
    sections.forEach(function(sec) {
      if (sec.offsetTop <= scrollY) { active = sec.id; }
    });
    return active;
  }

  function setActiveLink(anchor) {
    navLinks.forEach(function(a) {
      if (a.getAttribute('data-anchor') === anchor) {
        a.classList.add('active');
        // Scroll automatique du sidebar pour garder le lien visible
        var sidebar  = document.getElementById('sidebar');
        var linkTop  = a.getBoundingClientRect().top;
        var sideTop  = sidebar.getBoundingClientRect().top;
        var sideH    = sidebar.offsetHeight;
        if (linkTop < sideTop + 60 || linkTop > sideTop + sideH - 60) {
          sidebar.scrollTop += linkTop - sideTop - sideH / 2;
        }
        // NE PAS ouvrir/fermer les groupes ici -- c'est le bug principal
      } else {
        a.classList.remove('active');
      }
    });
  }

  function updateActive() {
    if (scrollingNow) return;   // on ignore pendant un scroll programme
    setActiveLink(getActiveAnchor());
  }

  window.addEventListener('scroll', updateActive, { passive: true });
  updateActive();

  // --- Clic sur un lien : scroll programme + surlignage immediat ---
  navLinks.forEach(function(a) {
    a.addEventListener('click', function(e) {
      e.preventDefault();
      var anchor = this.getAttribute('data-anchor');
      var target = document.getElementById(anchor);
      if (!target) return;

      // Surlignage immediat sans attendre le scroll
      setActiveLink(anchor);

      // Bloquer le scroll-spy pendant l'animation de scroll
      scrollingNow = true;
      clearTimeout(scrollTimer);

      var top = target.getBoundingClientRect().top + window.scrollY - headerH - 10;
      window.scrollTo({ top: top, behavior: 'smooth' });

      // Debloquer apres la fin de l'animation (max ~600ms)
      scrollTimer = setTimeout(function() {
        scrollingNow = false;
        setActiveLink(getActiveAnchor());
      }, 650);
    });
  });

  // --- Header nav links scroll-spy ---
  var hnLinks = document.querySelectorAll('.hn-link[data-anchor]');
  function updateHeaderNav() {
    if (scrollingNow) return;
    var anchor = getActiveAnchor();
    hnLinks.forEach(function(a) {
      if (a.getAttribute('data-anchor') === anchor) { a.classList.add('hn-active'); }
      else { a.classList.remove('hn-active'); }
    });
  }
  window.addEventListener('scroll', updateHeaderNav, { passive: true });
  updateHeaderNav();

  // Clic sur les liens header
  hnLinks.forEach(function(a) {
    a.addEventListener('click', function(e) {
      e.preventDefault();
      var anchor = this.getAttribute('data-anchor');
      var target = document.getElementById(anchor);
      if (!target) return;
      setActiveLink(anchor);
      hnLinks.forEach(function(x) { x.classList.remove('hn-active'); });
      this.classList.add('hn-active');
      scrollingNow = true;
      clearTimeout(scrollTimer);
      var top = target.getBoundingClientRect().top + window.scrollY - headerH - 10;
      window.scrollTo({ top: top, behavior: 'smooth' });
      scrollTimer = setTimeout(function() {
        scrollingNow = false;
        setActiveLink(getActiveAnchor());
        updateHeaderNav();
      }, 650);
    });
  });

  // Lien References -> scroller vers le bas du sidebar
  var refsAnchorLink = document.querySelector('.hn-refs');
  if (refsAnchorLink) {
    refsAnchorLink.addEventListener('click', function(e) {
      e.preventDefault();
      var refsList = document.getElementById('refs-list');
      var refsBtn  = document.getElementById('refs-toggle');
      var sidebar  = document.getElementById('sidebar');
      var isOpen   = refsList && refsList.style.display !== 'none';
      if (refsList) refsList.style.display = isOpen ? 'none' : 'block';
      if (refsBtn)  refsBtn.classList.toggle('open', !isOpen);
      if (!isOpen && sidebar) {
        setTimeout(function() {
          sidebar.scrollTo({ top: sidebar.scrollHeight, behavior: 'smooth' });
        }, 50);
      }
    });
  }

  // --- Bouton retour en haut ---
  var backBtn = document.getElementById('back-to-top');
  window.addEventListener('scroll', function() {
    backBtn.classList.toggle('visible', window.scrollY > 300);
  }, { passive: true });
  backBtn.addEventListener('click', function() {
    scrollingNow = true;
    clearTimeout(scrollTimer);
    window.scrollTo({ top: 0, behavior: 'smooth' });
    scrollTimer = setTimeout(function() { scrollingNow = false; }, 650);
  });

  // --- Toggle section references ---
  var refsBtn  = document.getElementById('refs-toggle');
  var refsList = document.getElementById('refs-list');
  if (refsBtn && refsList) {
    refsBtn.addEventListener('click', function() {
      var isOpen = refsList.style.display !== 'none';
      refsList.style.display = isOpen ? 'none' : 'block';
      refsBtn.classList.toggle('open', !isOpen);
    });
  }

})();
</script>
</body>
</html>
"@
    return $html
}

# ---------------------------------------------------------------------------
#  INTERACTIVE MENUS
# ---------------------------------------------------------------------------

function Show-Banner {
    Clear-Host
    $now = Get-Date

    Write-Host '                      ......ox0WMMMMMMMMMMMMMMMMK..'  -ForegroundColor DarkCyan
    Write-Host '                     .MMMMNxxxxxxxxxxxdxxxxxxxxxNM.'  -ForegroundColor DarkCyan
    Write-Host '                 ..MMWxxxxxxxxxxxxddxk000KK00kxxx0M.'  -ForegroundColor DarkCyan
    Write-Host '                .KM0xxxxxxxxxxdox00K00KK0kxxxxxxxxKM.'  -ForegroundColor DarkCyan
    Write-Host '               .MMxxxxxxxxdoxk0K00000OkxxxxxxxxxxxxMM..'  -ForegroundColor DarkCyan
    Write-Host '               MMxlollllxxkK00KK00kxxxxxxxxxxxoxxxxxMX.'  -ForegroundColor DarkCyan
    Write-Host '             .MMxxxxxxxx0K0000OxxxxxxxxxxxxxoodxxxxxxM:.'  -ForegroundColor DarkCyan
    Write-Host '             ,Mxxxxxxxx0K0OkxxxxxxxxxxxxxoooooxxxxxxxKMMMX'  -ForegroundColor DarkCyan
    Write-Host '            .MMxxxxxxxxxxxxxxxxxxxxxxxoooooooxxxxxxxxxxxxxkKMMMW..'  -ForegroundColor DarkCyan
    Write-Host '            .MxxxxxxxxxxxxxxxxxxdooooooolllxxxxxxxxxxxxxkxxxxxxxWMW.'  -ForegroundColor DarkCyan
    Write-Host '            XMxxxxxxxxxxxxxxooooollllllloxxxxxxxxxxxxxMMMxxxxxxxxxkMW'''  -ForegroundColor DarkCyan
    Write-Host '           .MWxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxOMMMMMMxxxxxxxxxxMW.'  -ForegroundColor DarkCyan
    Write-Host '           .MOxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxOMM0000KMMWxxxxxxxxxkM.'  -ForegroundColor DarkCyan
    Write-Host '          ..MxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxOMMK00000000MMxxxxxxxxxxkM.'  -ForegroundColor DarkCyan
    Write-Host '        ...MMkxxxxxxxxxxxxxxxxxxxxxxxxxKMMM000000000000MOxxxxxxxxxxxMM.'  -ForegroundColor DarkCyan
    Write-Host '       .cMMxMMMMMNkkxxxxxxxxxO0WMMMMMMMMM00000000000WXxxxxxxxxxxxxxKM.'  -ForegroundColor DarkCyan
    Write-Host '    ...MMxxxxMMMMMMMMMMMMMMMMMMMMMMMMMMMMX000000NWxxxxxxxxxxxxxxxxWM..'  -ForegroundColor DarkCyan
    Write-Host '    .MMxxxxxxxMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMWxxxxxxxxxxxxxxxxxxxxMM..'  -ForegroundColor DarkCyan
    Write-Host '   xMkxxxxxxxxxxMMMMMMMMMMMMMMMMMMMMMMkxxxxxxxxxxxxxxxxxxxxxxxxMM..'  -ForegroundColor DarkCyan
    Write-Host '  WMxxxxxxxxxxxxxxxxxxxxxkxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxMMx.'  -ForegroundColor DarkCyan
    Write-Host '.cMxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxkMM'''  -ForegroundColor DarkCyan
    Write-Host '.MXxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxMMN..'  -ForegroundColor DarkCyan
    Write-Host '.MNxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxMMM.'  -ForegroundColor DarkCyan
    Write-Host '.''MkxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxOMMMc..'  -ForegroundColor DarkCyan
    Write-Host '  .MMxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxOMMMM..'  -ForegroundColor DarkCyan
    Write-Host '   ..NMMMOxxxxxxxxxxxxxxxxxxxxxxxxxOWMMMMMK ...'  -ForegroundColor DarkCyan
    Write-Host '        ..KMMMMMMMMMMMMMMMMMMMMMMXc''..'  -ForegroundColor DarkCyan
    Write-Host '                .... .. ...'  -ForegroundColor DarkCyan
    Write-Host ""
    Write-Host ""
    Write-Host "  ======================================================================" -ForegroundColor DarkCyan
    Write-Host ""
    Write-Host "                          P O W E R A U D I T" -ForegroundColor White
    Write-Host ""
    Write-Host "              A U D I T   --   v 3 . 1   --   B l u e T e a m" -ForegroundColor DarkCyan
    Write-Host ""
    Write-Host "  ======================================================================" -ForegroundColor DarkCyan
    Write-Host ""

    $os = (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).Caption
    Write-Host ("  Machine  :  {0}" -f $computername) -ForegroundColor White
    Write-Host ("  OS       :  {0}" -f $os) -ForegroundColor White
    Write-Host ("  Date     :  {0}" -f $now.ToString("dd/MM/yyyy  HH:mm:ss")) -ForegroundColor White
    Write-Host ""
    Write-Host "  ======================================================================" -ForegroundColor DarkCyan
    Write-Host ""
}

function Show-MainMenu {
    Show-Banner
    Write-Host "  MAIN MENU" -ForegroundColor Yellow
    Write-Host "  ----------------------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  REPORTS" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "    [1]  Full audit      -- all modules -- HTML report" -ForegroundColor Green
    Write-Host "    [2]  Selective audit -- choose modules" -ForegroundColor Green
    Write-Host ""
    Write-Host "  INVESTIGATION" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "    [3]  Run a module    -- result in shell" -ForegroundColor Cyan
    Write-Host "    [4]  Open last HTML report" -ForegroundColor Cyan
    Write-Host "    [5]  Machine summary" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  ----------------------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "    [Q]  Quit" -ForegroundColor DarkGray
    Write-Host ""
    $choice = Read-Host "  Your choice"
    return $choice.Trim()
}

function Run-Menu2 {
    # Liste simple de cles selectionnees - tableau global de strings
    $Global:Menu2Selection = @()

    while ($true) {
        # --- Affichage du menu ---
        Clear-Host
        Write-Host ""
        Write-Host "  +==================================================================+" -ForegroundColor Cyan
        Write-Host "  |  MENU 2 -- MODULE SELECTION FOR CUSTOM REPORT               |" -ForegroundColor Cyan
        Write-Host "  +==================================================================+" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "  Commands: [number] check/uncheck  |  A=all  |  N=none  |  V=validate & generate  |  Q=back" -ForegroundColor DarkGray
        Write-Host ("  " + ("-" * 90))
        Write-Host ""

        $currentCategory = ""
        foreach ($key in $Global:AuditModules.Keys) {
            $m   = $Global:AuditModules[$key]
            $cat = $m["Category"]
            if ($cat -ne $currentCategory) {
                $currentCategory = $cat
                Write-Host ("  --- {0} ---" -f $currentCategory.ToUpper()) -ForegroundColor DarkYellow
            }
            if ($Global:Menu2Selection -contains $key) {
                Write-Host ("  [X] {0}  {1,-12}  {2}" -f $key, $m["ShortName"], $m["Name"]) -ForegroundColor Green
            } else {
                Write-Host ("  [ ] {0}  {1,-12}  {2}" -f $key, $m["ShortName"], $m["Name"]) -ForegroundColor DarkGray
            }
        }

        Write-Host ""
        Write-Host ("  Selected modules: {0}/{1}   (V=validate and generate report  |  Q=back without generating)" -f $Global:Menu2Selection.Count, $Global:AuditModules.Count) -ForegroundColor Yellow
        Write-Host ""

        # --- Lecture de la commande ---
        $cmd = Read-Host "  Your command"
        $cmd = $cmd.Trim().TrimEnd("`r","`n"," ").TrimStart("`r","`n"," ")


        if ($cmd -eq "Q" -or $cmd -eq "q") {
            return $null
        }
        elseif ($cmd -eq "V" -or $cmd -eq "v") {
            if ($Global:Menu2Selection.Count -eq 0) {
                Write-Host "  No module selected." -ForegroundColor Red
                Start-Sleep -Seconds 1
            } else {
                return $Global:Menu2Selection
            }
        }
        elseif ($cmd -eq "A" -or $cmd -eq "a") {
            $Global:Menu2Selection = @($Global:AuditModules.Keys)
        }
        elseif ($cmd -eq "N" -or $cmd -eq "n") {
            $Global:Menu2Selection = @()
        }
        elseif ($Global:AuditModules.Contains($cmd)) {
            if ($Global:Menu2Selection -contains $cmd) {
                $Global:Menu2Selection = $Global:Menu2Selection | Where-Object { $_ -ne $cmd }
                Write-Host ("  [-] {0} removed" -f $cmd) -ForegroundColor DarkGray
            } else {
                $Global:Menu2Selection += $cmd
                Write-Host ("  [+] {0} added" -f $cmd) -ForegroundColor Green
            }
            Start-Sleep -Milliseconds 300
        }
        else {
            Write-Host ("  '{0}' not recognized." -f $cmd) -ForegroundColor Red
            Start-Sleep -Milliseconds 700
        }
    }
}

function Run-Menu3 {
    while ($true) {
        Clear-Host
        Write-Host ""
        Write-Host "  +==================================================================+" -ForegroundColor Cyan
        Write-Host "  |  MENU 3 -- INDIVIDUAL EXECUTION (result in shell)           |" -ForegroundColor Cyan
        Write-Host "  +==================================================================+" -ForegroundColor Cyan
        Write-Host ""
        $currentCategory = ""
        foreach ($key in $Global:AuditModules.Keys) {
            $m   = $Global:AuditModules[$key]
            $cat = $m["Category"]
            if ($cat -ne $currentCategory) {
                $currentCategory = $cat
                Write-Host ("  --- {0} ---" -f $currentCategory.ToUpper()) -ForegroundColor DarkYellow
            }
            Write-Host ("  [{0}]  {1,-12}  {2}" -f $key, $m["ShortName"], $m["Name"]) -ForegroundColor Cyan
        }
        Write-Host ""

        $cmd = (Read-Host "  Module number (Q=back to main menu)").Trim()

        if ($cmd -eq "Q" -or $cmd -eq "q") {
            return
        }
        elseif ($Global:AuditModules.Contains($cmd)) {
            $m = $Global:AuditModules[$cmd]
            Clear-Host
            Write-Host ""
            Write-Host ("  +------------------------------------------------------------------+") -ForegroundColor Cyan
            Write-Host ("  |  MODULE {0,-10}  {1,-47}|" -f $m.ShortName, $m.Name) -ForegroundColor Cyan
            Write-Host ("  +------------------------------------------------------------------+") -ForegroundColor Cyan
            Write-Host ""
            $startTime = Get-Date
            try {
                & $m.Script
            } catch {
                Write-Host ""
                Write-Host "  [ERROR] $($_.Exception.Message)" -ForegroundColor Red
            }
            $elapsed = ((Get-Date) - $startTime).TotalSeconds
            Write-Host ""
            Write-Host ("  " + ("=" * 68)) -ForegroundColor DarkCyan
            Write-Host ("  Module completed in {0:F1}s" -f $elapsed) -ForegroundColor Yellow
            Write-Host ("  " + ("=" * 68)) -ForegroundColor DarkCyan
            Write-Host ""
            Read-Host "  Press Enter to return to the list"
        }
        else {
            Write-Host ("  '{0}' not recognized." -f $cmd) -ForegroundColor Red
            Start-Sleep -Milliseconds 700
        }
    }
}

# ---------------------------------------------------------------------------
#  MODULE EXECUTION
# ---------------------------------------------------------------------------

function Run-Modules {
    param(
        [string[]]$Keys,
        [bool]$GenerateHtml = $true,
        [string]$ReportType = "full_report"
    )

    $sortedKeys = $Keys | Sort-Object
    $total      = $sortedKeys.Count
    $current    = 0
    $results    = @{}

    Write-Host ""
    Write-Host "  Starting audit -- $total module(s) selected" -ForegroundColor Yellow
    Write-Host ""

    foreach ($key in $sortedKeys) {
        $m = $Global:AuditModules[$key]
        $current++
        Write-ProgressBar -Current $current -Total $total -Label $m.Name
        Write-Host ""
        $startTime = Get-Date
        try {
            $output      = & $m.Script
            $results[$key] = if ($output) { $output | Out-String } else { "(No result)" }
        } catch {
            Write-Host "  [ERROR module $key] $($_.Exception.Message)" -ForegroundColor Red
            $results[$key] = "[ERROR] $($_.Exception.Message)"
        }
        $elapsed = ((Get-Date) - $startTime).TotalSeconds
        Write-Host ("  OK {0} -- completed in {1:F1}s" -f $m.Name, $elapsed) -ForegroundColor DarkGreen
    }

    Write-Host ""
    Write-ProgressBar -Current $total -Total $total -Label "Termine !"
    Write-Host ""
    Write-Host ""
    Write-Host "  Audit complete!" -ForegroundColor Green

    if ($GenerateHtml -and $results.Count -gt 0) {
        Write-Host "  Generating HTML report..." -ForegroundColor Cyan
        Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue
        $htmlContent = Build-HtmlReport -Results $results
        $reportDateStr  = (Get-Date).ToString("yyyy-MM-dd_HH-mm")
        $reportDir      = ".\pwaudit_${computername}_${ReportType}_${reportDateStr}.html"
        $Global:LastReportPath = $reportDir
        $htmlContent | Out-File -FilePath $reportDir -Encoding UTF8
        Write-Host "  Report saved: $reportDir" -ForegroundColor Green
    }

    # Ne pas retourner $results pour eviter l'affichage dans le shell
}

# ---------------------------------------------------------------------------
#  MAIN LOOP
# ---------------------------------------------------------------------------

while ($true) {
    $choice = Show-MainMenu

    switch ($choice) {
        "1" {
            Write-Host ""
            Write-Host "  Starting full audit ($($Global:AuditModules.Count) modules)..." -ForegroundColor Green
            Write-Host ""
            $allKeys = [string[]]($Global:AuditModules.Keys | Sort-Object)
            Run-Modules -Keys $allKeys -GenerateHtml $true -ReportType "full_report"
            Write-Host ""
            Read-Host "  Press Enter to return to menu"
        }
        "2" {
            $selectedSet = Run-Menu2
            if ($null -ne $selectedSet -and $selectedSet.Count -gt 0) {
                Write-Host ""
                Write-Host "  $($selectedSet.Count) module(s) selected. Starting..." -ForegroundColor Yellow
                Run-Modules -Keys ([string[]]$selectedSet) -GenerateHtml $true -ReportType "partial_report"
                Write-Host ""
                Read-Host "  Press Enter to return to menu"
            } elseif ($null -ne $selectedSet) {
                Write-Host "  No module selected." -ForegroundColor Red
                Start-Sleep -Seconds 1
            }
        }
        "3" {
            Run-Menu3
        }
        "4" {
            # Ouvrir le dernier rapport HTML
            if ($Global:LastReportPath -and (Test-Path $Global:LastReportPath)) {
                Write-Host ""
                Write-Host "  Opening report: $Global:LastReportPath" -ForegroundColor Cyan
                Start-Process $Global:LastReportPath
                Start-Sleep -Seconds 1
            } else {
                Write-Host ""
                Write-Host "  No report found. Run an audit first (option 1 or 2)." -ForegroundColor Red
                Start-Sleep -Seconds 2
            }
        }
        "5" {
            Clear-Host
            Show-Banner
            Write-Host "  ---- FULL MACHINE SUMMARY ----------------------------------" -ForegroundColor Cyan
            Write-Host ""

            # --- SYSTEME ---
            Write-Host ""
            Write-Host "  ---- SYSTEM --------------------------------------------------------" -ForegroundColor DarkYellow
            Write-Host ""
            try {
                $os      = Get-CimInstance Win32_OperatingSystem
                $cs      = Get-CimInstance Win32_ComputerSystem
                $bios    = Get-CimInstance Win32_BIOS
                $cpu     = (Get-CimInstance Win32_Processor | Select-Object -First 1).Name
                $uptime  = ((Get-Date) - $os.LastBootUpTime).ToString("dd'd' hh'h' mm'm'")
                $ramTotal = [math]::Round($cs.TotalPhysicalMemory/1GB,1)
                $ramFree  = [math]::Round($os.FreePhysicalMemory/1MB,1)
                $domaine  = if ($cs.PartOfDomain) { $cs.Domain } else { "WORKGROUP" }

                Write-Host ("    Machine name    : {0}" -f $cs.Name)                                          -ForegroundColor White
                Write-Host ("    Domain          : {0}" -f $domaine)                                          -ForegroundColor White
                Write-Host ("    OS              : {0}" -f $os.Caption)                                       -ForegroundColor White
                Write-Host ("    Version / Build : {0}  (build {1})" -f $os.Version, $os.BuildNumber)         -ForegroundColor White
                Write-Host ("    Architecture   : {0}" -f $os.OSArchitecture)                                -ForegroundColor White
                Write-Host ("    CPU             : {0}" -f $cpu)                                              -ForegroundColor White
                Write-Host ("    RAM             : {0} Go total  /  {1} Go libre" -f $ramTotal, $ramFree)     -ForegroundColor White
                Write-Host ("    BIOS            : {0}  (ver. {1})" -f $bios.Manufacturer, $bios.SMBIOSBIOSVersion) -ForegroundColor White
                Write-Host ("    Uptime          : {0}" -f $uptime)                                           -ForegroundColor White
            } catch {
                Write-Host "    [ERROR] $($_.Exception.Message)" -ForegroundColor Red
            }

            # --- DISQUES ---
            Write-Host ""
            Write-Host "  ---- DISKS --------------------------------------------------------" -ForegroundColor DarkYellow
            Write-Host ""
            try {
                $disks = Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3"
                foreach ($d in $disks) {
                    $total = [math]::Round($d.Size/1GB,1)
                    $free  = [math]::Round($d.FreeSpace/1GB,1)
                    $used  = [math]::Round($total - $free,1)
                    $pct   = [math]::Round($used / $total * 100)
                    $bar   = ("#" * [math]::Round($pct/5)) + ("." * (20 - [math]::Round($pct/5)))
                    $col   = if ($pct -gt 90) { "Red" } elseif ($pct -gt 75) { "Yellow" } else { "Green" }
                    Write-Host ("    {0}  [{1}] {2,3}%  --  {3} Go / {4} Go utilises" -f $d.DeviceID, $bar, $pct, $used, $total) -ForegroundColor $col
                }
            } catch {
                Write-Host "    [ERROR] $($_.Exception.Message)" -ForegroundColor Red
            }

            # --- COMPTES ---
            Write-Host ""
            Write-Host "  ---- LOCAL ACCOUNTS -------------------------------------------------" -ForegroundColor DarkYellow
            Write-Host ""
            try {
                $localUsers = Get-LocalUser | Sort-Object Enabled -Descending
                foreach ($u in $localUsers) {
                    $statut = if ($u.Enabled) { "[ACTIF]  " } else { "[inactif]" }
                    $col    = if ($u.Enabled) { "Green" } else { "DarkGray" }
                    $admin  = (Get-LocalGroupMember "Administrators" -ErrorAction SilentlyContinue | Where-Object { $_.Name -match $u.Name }) -ne $null
                    $role   = if ($admin) { " [ADMIN]" } else { "" }
                    Write-Host ("    {0}  {1}{2}" -f $statut, $u.Name, $role) -ForegroundColor $col
                }
            } catch {
                Write-Host "    [ERROR] $($_.Exception.Message)" -ForegroundColor Red
            }

            # --- CLE WINDOWS ---
            Write-Host ""
            Write-Host "  ---- WINDOWS LICENSE KEY -----------------------------------------" -ForegroundColor DarkYellow
            Write-Host ""
            try {
                $key = (Get-WmiObject -query 'select * from SoftwareLicensingService').OA3xOriginalProductKey
                if ($key) {
                    Write-Host ("    OEM Key         : {0}" -f $key) -ForegroundColor Green
                } else {
                    # Methode alternative via registre encode
                    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
                    $digitalId = (Get-ItemProperty -Path $regPath).DigitalProductId
                    if ($digitalId) {
                        $keyOffset = 52
                        $isWin8    = [math]::Floor($digitalId[66] / 6) -band 1
                        $digitalId[66] = ($digitalId[66] -band 0xF7) -bor (($isWin8 -band 2) * 4)
                        $chars = "BCDFGHJKMPQRTVWXY2346789"
                        $last  = 0
                        $decoded = ""
                        for ($i = 24; $i -ge 0; $i--) {
                            $cur = 0
                            for ($j = 14; $j -ge 0; $j--) {
                                $cur = $cur * 256 -bxor $digitalId[$j + $keyOffset]
                                $digitalId[$j + $keyOffset] = [math]::Floor($cur / 24)
                                $cur = $cur % 24
                            }
                            $decoded = $chars[$cur] + $decoded
                            $last    = $cur
                        }
                        if ($isWin8 -eq 1) {
                            $decoded = $decoded.Substring($last+1) + "N" + $decoded.Substring(0,$last)
                        }
                        $productKey = $decoded.Substring(1,5)+"-"+$decoded.Substring(6,5)+"-"+$decoded.Substring(11,5)+"-"+$decoded.Substring(16,5)+"-"+$decoded.Substring(21,5)
                        Write-Host ("    Product Key     : {0}" -f $productKey) -ForegroundColor Green
                    } else {
                        Write-Host "    Key not found (digital license or unavailable)" -ForegroundColor DarkGray
                    }
                }
            } catch {
                Write-Host "    [ERROR] $($_.Exception.Message)" -ForegroundColor Red
            }

            # --- WIFI ---
            Write-Host ""
            Write-Host "  ---- SAVED WIFI NETWORKS ---------------------------------------" -ForegroundColor DarkYellow
            Write-Host ""
            try {
                $profiles = (netsh wlan show profiles) | Select-String "Profil Tous les utilisateurs" |
                    ForEach-Object { ($_ -split ":")[1].Trim() }
                if (-not $profiles) {
                    $profiles = (netsh wlan show profiles) | Select-String "All User Profile" |
                        ForEach-Object { ($_ -split ":")[1].Trim() }
                }
                if ($profiles) {
                    foreach ($p in $profiles) {
                        $detail = netsh wlan show profile name="$p" key=clear 2>$null
                        $pwd    = ($detail | Select-String "Key Content|Key Content") |
                            ForEach-Object { ($_ -split ":")[1].Trim() }
                        if (-not $pwd) { $pwd = "(password not available)" }
                        Write-Host ("    SSID  : {0}" -f $p)   -ForegroundColor Cyan
                        Write-Host ("    Password: {0}" -f $pwd) -ForegroundColor Yellow
                        Write-Host ""
                    }
                } else {
                    Write-Host "    No saved WiFi profile." -ForegroundColor DarkGray
                }
            } catch {
                Write-Host "    [ERROR] $($_.Exception.Message)" -ForegroundColor Red
            }

            # --- RAPPORT ---
            Write-Host ""
            Write-Host "  ---- REPORT --------------------------------------------------------" -ForegroundColor DarkYellow
            Write-Host ""
            if ($Global:LastReportPath -and (Test-Path $Global:LastReportPath)) {
                $rapportDate = (Get-Item $Global:LastReportPath).LastWriteTime.ToString("dd/MM/yyyy HH:mm")
                Write-Host ("    Last report     : {0}" -f $Global:LastReportPath) -ForegroundColor DarkCyan
                Write-Host ("    Generated on    : {0}" -f $rapportDate)            -ForegroundColor DarkCyan
            } else {
                Write-Host "    No HTML report generated for this machine." -ForegroundColor DarkGray
            }

            Write-Host ""
            Write-Host "  +====================================================================+" -ForegroundColor DarkCyan
            Write-Host ""
            Read-Host "  Press Enter to return to menu"
        }
        { $_ -eq "Q" -or $_ -eq "q" } {
            Write-Host ""
            Write-Host "  Goodbye!" -ForegroundColor Cyan
            Write-Host ""
            exit 0
        }
        default {
            Write-Host "  Invalid choice." -ForegroundColor Red
            Start-Sleep -Milliseconds 700
        }
    }
}
