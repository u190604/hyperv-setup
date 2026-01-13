<# 
Hyper-V Host + VM Provisioning Script (Windows 11)

What it does:
- Enables Hyper-V + required components
- Creates a Gen2 VM with VHDX, CPU, RAM, NIC, Secure Boot config, ISO attached

Notes:
- Default Switch is managed by Windows and provides NAT + DHCP. You can't rename it or set its subnet easily.
- External switch bridges to your physical NIC to put VM on your LAN.

#>

# GLOBAL PARAMS
$VMName      = $null
$ISOPath     = "C:\VM\iso\kickstart-almalinux-9.7-minimal.iso"
$NetworkMode = "External"
$ExternalSwitchName = "External Switch"
$ExternalNicName    = $null
$VMPath        = "C:\VM";
$VHDDir        = "$VMPath\Disks"
$VHDPath       = $null
$VHDSizeGB     = 60
$CPUCount        = 2
$MemoryStartupGB = 4
$MemoryMinGB     = 2
$MemoryMaxGB     = 8
$UseStaticMac    = $true
$MacAddress      = $null

function Get-RequiredInput([string]$PromptText) {
    do {
        $value = Read-Host $PromptText
    } while ([string]::IsNullOrWhiteSpace($value))
    return $value
}

function Get-AvailableVMName([string]$PromptText) {
    do {
        $name = Get-RequiredInput $PromptText
        $existing = Get-VM -Name $name -ErrorAction SilentlyContinue
        if ($existing) {
            Write-Host "VM name '$name' already exists." -ForegroundColor Yellow
            $choice = Read-Host "Choose: (D)elete existing VM, (N)ew name"
            switch ($choice.ToLower()) {
                "d" {
                    Write-Host "Deleting VM '$name'..." -ForegroundColor Cyan
                    Remove-VM -Name $name -Force -Confirm:$false
                    return $name
                }
                "n" {
                    $existing = $true
                }
                default {
                    Write-Host "Invalid choice. Enter D or N." -ForegroundColor Yellow
                    $existing = $true
                }
            }
        }
    } while ($existing)
    return $name
}

function New-MacAddress {
    $prefix = 0x00, 0x15, 0x5D
    $suffix = @(
        Get-Random -Minimum 0x00 -Maximum 0xFF
        Get-Random -Minimum 0x00 -Maximum 0xFF
        Get-Random -Minimum 0x00 -Maximum 0xFF
    )
    return ("{0:X2}-{1:X2}-{2:X2}-{3:X2}-{4:X2}-{5:X2}" -f ($prefix + $suffix))
}

function Normalize-PathInput([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path)) { return $Path }
    $clean = $Path.Trim()
    if (
        ($clean.StartsWith('"') -and $clean.EndsWith('"')) -or
        ($clean.StartsWith("'") -and $clean.EndsWith("'"))
    ) {
        $clean = $clean.Substring(1, $clean.Length - 2)
    }
    return $clean
}

function Resolve-FilePath([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path)) { throw "Non empty path is required." }
    $clean = Normalize-PathInput $Path
    $item = Get-Item -LiteralPath $clean -ErrorAction Stop
    if ($item.PSIsContainer) { throw "Path provided points to a directory: $clean" }
    return $item
}

function Resolve-VHDPathConflict([string]$Path, [string]$DefaultDir) {
    $current = $Path
    while (Test-Path -LiteralPath $current) {
        Write-Host "VHDX already exists: $current" -ForegroundColor Yellow
        $choice = Read-Host "Choose: (O)verwrite, (R)euse, (N)ew name"
        switch ($choice.ToLower()) {
            "o" {
                Remove-Item -LiteralPath $current -Force
                return $current
            }
            "r" {
                return $current
            }
            "n" {
                $newName = Get-RequiredInput "Enter new VHDX name or full path"
                $clean = Normalize-PathInput $newName
                if (-not [System.IO.Path]::IsPathRooted($clean)) {
                    $clean = Join-Path $DefaultDir $clean
                }
                if ([System.IO.Path]::GetExtension($clean) -eq "") {
                    $clean = "$clean.vhdx"
                }
                $current = $clean
            }
            default {
                Write-Host "Invalid choice. Enter O, R, or N." -ForegroundColor Yellow
            }
        }
    }
    return $current
}

function Get-VHDSizeGB([int]$DefaultSizeGB) {
    do {
        $inputSize = Read-Host "Enter disk size in GB (10-100) or press Enter for ${DefaultSizeGB}GB"
        if ([string]::IsNullOrWhiteSpace($inputSize)) {
            return $DefaultSizeGB
        }
        if ([int]::TryParse($inputSize, [ref]$size) -and $size -ge 10 -and $size -le 100) {
            return $size
        }
        Write-Host "Invalid size. Enter a number between 10 and 100, or press Enter for default." -ForegroundColor Yellow
    } while ($true)
}

function Get-FreeScsiSlot([string]$VMName) {
    $usedDevices = @()
    $usedDevices += Get-VMHardDiskDrive -VMName $VMName -ErrorAction SilentlyContinue
    $usedDevices += Get-VMDvdDrive -VMName $VMName -ErrorAction SilentlyContinue

    foreach ($controller in 0..3) {
        $usedLocations = $usedDevices |
            Where-Object { $_.ControllerNumber -eq $controller } |
            Select-Object -ExpandProperty ControllerLocation
        $freeLocation = (0..63 | Where-Object { $_ -notin $usedLocations }) | Select-Object -First 1
        if ($null -ne $freeLocation) {
            return @{
                ControllerNumber   = $controller
                ControllerLocation = $freeLocation
            }
        }
    }

    throw "No available SCSI controller slots for VM: $VMName"
}

function Select-PhysicalAdapter([string]$DefaultName) {
    $adapters = Get-NetAdapter -Physical | Sort-Object Name
    if (-not $adapters) {
        throw "No physical network adapters found."
    }

    Write-Host "Available physical adapters:" -ForegroundColor Cyan
    for ($i = 0; $i -lt $adapters.Count; $i++) {
        $a = $adapters[$i]
        Write-Host "  [$i] $($a.Name) - $($a.InterfaceDescription) - $($a.Status) - $($a.LinkSpeed)"
    }

    $defaultIndex = $null
    if (-not [string]::IsNullOrWhiteSpace($DefaultName)) {
        for ($i = 0; $i -lt $adapters.Count; $i++) {
            if ($adapters[$i].Name -eq $DefaultName) {
                $defaultIndex = $i
                break
            }
        }
    }

    do {
        if ($null -ne $defaultIndex) {
            $prompt = "Select adapter index or press Enter for [$defaultIndex] $DefaultName"
        } else {
            $prompt = "Select adapter index"
        }
        $choice = Read-Host $prompt
        if ([string]::IsNullOrWhiteSpace($choice) -and $null -ne $defaultIndex) {
            return $adapters[$defaultIndex].Name
        }
        if ([int]::TryParse($choice, [ref]$index) -and $index -ge 0 -and $index -lt $adapters.Count) {
            return $adapters[$index].Name
        }
        Write-Host "Invalid selection. Enter a number from 0 to $($adapters.Count - 1)." -ForegroundColor Yellow
    } while ($true)
}

function Ensure-ExternalSwitch([string]$SwitchName, [string]$NicName) {
    if ([string]::IsNullOrWhiteSpace($SwitchName)) {
        $SwitchName = "External Switch"
    }

    $existing = Get-VMSwitch -Name $SwitchName -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Host "External switch already exists: $SwitchName" -ForegroundColor Green
        return $existing
    }

    $selectedNic = Select-PhysicalAdapter $NicName
    $adapter = Get-NetAdapter -Name $selectedNic -ErrorAction SilentlyContinue
    if (-not $adapter) {
        throw "Network adapter not found: $selectedNic"
    }

    Write-Host "Creating external switch '$SwitchName' on adapter '$selectedNic'..." -ForegroundColor Cyan
    return New-VMSwitch -Name $SwitchName -NetAdapterName $selectedNic -AllowManagementOS $true
}


function Assert-Admin {
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) { throw "Run this script as Administrator." }
}

function Assert-Windows11 {
    $os = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
    $build = [int]$os.CurrentBuild
    if (-not $build -or $build -lt 22000) {
        throw "This script requires Windows 11. Detected build: $build"
    } 
}

function Confirm-HyperVPresent {
    $hv = Get-WindowsOptionalFeature -Online -FeatureName "Microsoft-Hyper-V-All"
    if ($hv.State -eq "Enabled") {
        return $true
    }
    do {
        $choice = Read-Host "Hyper-V is not enabled. Continue and enable it? (Y/N)"
        switch ($choice.ToLower()) {
            "y" { return $true }
            "n" { return $false }
            default { Write-Host "Please enter Y or N." -ForegroundColor Yellow }
        }
    } while ($true)
}

function Enable-HyperV {
    Write-Host "Enabling Hyper-V (if needed)..." -ForegroundColor Cyan

    $features = @(
        "Microsoft-Hyper-V-All",
        "HypervisorPlatform",
        "VirtualMachinePlatform"
    )

    foreach ($f in $features) {
        $state = (Get-WindowsOptionalFeature -Online -FeatureName $f).State
        if ($state -ne "Enabled") {
            Enable-WindowsOptionalFeature -Online -FeatureName $f -All -NoRestart | Out-Null
            Write-Host "  Enabled feature: $f"
        } else {
            Write-Host "  Already enabled: $f"
        }
    }

    # Hyper-V management tools (usually included, but ensure)
    $cap = Get-WindowsCapability -Online | Where-Object Name -like "Rsat.HyperV.Tools*"
    if ($cap -and $cap.State -ne "Installed") {
        Add-WindowsCapability -Online -Name $cap.Name | Out-Null
        Write-Host "  Installed capability: $($cap.Name)"
    }

    Write-Host "Hyper-V enablement complete. If this is the first run, a reboot may be required." -ForegroundColor Yellow
}

function Show-HostBanner {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    $cpu = Get-CimInstance -ClassName Win32_Processor | Select-Object -First 1
    $memBytes = $os.TotalVisibleMemorySize * 1KB
    $memGB = [math]::Round($memBytes / 1GB, 1)
    $hostName = $env:COMPUTERNAME

    Write-Host ""
    Write-Host "Hyper-V Host Info" -ForegroundColor Cyan
    Write-Host "  Hostname : $hostName"
    Write-Host "  OS       : $($os.Caption) ($($os.Version))"
    Write-Host "  CPU      : $($cpu.Name)"
    Write-Host "  Memory   : $memGB GB"
    Write-Host ""
    Write-Host "Current VMs" -ForegroundColor Cyan
    $vms = Get-VM -ErrorAction SilentlyContinue
    if ($vms) {
        $vms | Sort-Object Name | Format-Table -AutoSize Name, State, CPUUsage, MemoryAssigned
    } else {
        Write-Host "  No VMs found."
    }
    Write-Host ""
}

function Ensure-VMFolders {
    New-Item -ItemType Directory -Force -Path @($VMPath, $VHDDir) | Out-Null
}

function New-OrUpdate-VM {
    # Validate ISO
    if (-not (Test-Path $ISOPath)) { throw "ISO not found: $ISOPath" }

    Ensure-VMFolders

    # Select switch
    if ($NetworkMode -eq "DefaultSwitch") {
        $switch = Get-VMSwitch | Where-Object Name -eq "Default Switch"
        if (-not $switch) { throw "Default Switch not found. Is Hyper-V installed and rebooted?" }
        $switchName = $switch.Name
        Write-Host "Using switch: $switchName" -ForegroundColor Green
    }
    elseif ($NetworkMode -eq "External") {
        $switch = Get-VMSwitch -Name $ExternalSwitchName -ErrorAction SilentlyContinue
        if (-not $switch) {
            $switch = Ensure-ExternalSwitch -SwitchName $ExternalSwitchName -NicName $ExternalNicName
        }
        $switchName = $switch.Name
        Write-Host "Using switch: $switchName" -ForegroundColor Green
    }
    else {
        throw "Invalid NetworkMode '$NetworkMode'. Use 'DefaultSwitch' or 'External'."
    }

    # Create VHD if missing
    if (-not (Test-Path $VHDPath)) {
        Write-Host "Creating VHDX: $VHDPath ($VHDSizeGB GB)..." -ForegroundColor Cyan
        New-VHD -Path $VHDPath -SizeBytes ($VHDSizeGB * 1GB) -Dynamic -BlockSizeBytes 1MB | Out-Null
    } else {
        Write-Host "VHDX exists: $VHDPath" -ForegroundColor Green
    }

    # Create or update VM
    $isNewVM = $false
    $vm = Get-VM -Name $VMName -ErrorAction SilentlyContinue
    if (-not $vm) {
        Write-Host "Creating VM '$VMName' (Gen2)..." -ForegroundColor Cyan
        $vm = New-VM -Name $VMName -Generation 2 -Path $VMPath -MemoryStartupBytes ($MemoryStartupGB * 1GB) -VHDPath $VHDPath -SwitchName $switchName
        $isNewVM = $true
    } else {
        Write-Host "VM already exists: $VMName" -ForegroundColor Green
        # Ensure NIC is connected to desired switch
        $ad = Get-VMNetworkAdapter -VMName $VMName -ErrorAction SilentlyContinue
        if ($ad -and $ad.SwitchName -ne $switchName) {
            Connect-VMNetworkAdapter -VMName $VMName -SwitchName $switchName
            Write-Host "  Connected NIC to switch: $switchName"
        }
    }

    # CPU + Memory settings
    Set-VMProcessor -VMName $VMName -Count $CPUCount

    Set-VMMemory -VMName $VMName `
        -DynamicMemoryEnabled $true `
        -MinimumBytes ($MemoryMinGB * 1GB) `
        -StartupBytes ($MemoryStartupGB * 1GB) `
        -MaximumBytes ($MemoryMaxGB * 1GB)

    # Secure Boot: try common templates; fall back to Off if unsupported.
    # If your distro ISO fails to boot, set SecureBoot off: Set-VMFirmware -VMName $VMName -EnableSecureBoot Off
    try {
        Set-VMFirmware -VMName $VMName -EnableSecureBoot On -SecureBootTemplate "MicrosoftUEFICertificateAuthority" -ErrorAction Stop
    } catch {
        Write-Warning "Secure Boot template 'MicrosoftUEFICertificateAuthority' not supported. Trying 'MicrosoftWindows'."
        try {
            Set-VMFirmware -VMName $VMName -EnableSecureBoot On -SecureBootTemplate "MicrosoftWindows" -ErrorAction Stop
        } catch {
            Write-Warning "Secure Boot templates not supported. Disabling Secure Boot."
            Set-VMFirmware -VMName $VMName -EnableSecureBoot Off
        }
    }

    # Disable checkpoints (snapshots) for this VM
    Set-VM -VMName $VMName -CheckpointType Disabled

    # Attach ISO to DVD drive (create if missing)
    $dvd = Get-VMDvdDrive -VMName $VMName -ErrorAction SilentlyContinue
    if (-not $dvd) {
        $slot = Get-FreeScsiSlot $VMName
        Add-VMDvdDrive -VMName $VMName -Path $ISOPath `
            -ControllerNumber $slot.ControllerNumber `
            -ControllerLocation $slot.ControllerLocation | Out-Null
    } else {
        Set-VMDvdDrive -VMName $VMName -Path $ISOPath | Out-Null
    }

    # Ensure boot order: DVD first for install, then disk
    $dvd = Get-VMDvdDrive -VMName $VMName
    $hdd = Get-VMHardDiskDrive -VMName $VMName
    Set-VMFirmware -VMName $VMName -BootOrder @($dvd, $hdd)

    # Static MAC (optional)
    if ($UseStaticMac) {
        if ($isNewVM -and [string]::IsNullOrWhiteSpace($StaticMac)) {
            $MacAddress = New-MacAddress
        }
        if (-not [string]::IsNullOrWhiteSpace($MacAddress)) {
            $ad = Get-VMNetworkAdapter -VMName $VMName
            if ($ad.MacAddressSpoofing -ne "Off") {
                Set-VMNetworkAdapter -VMName $VMName -MacAddressSpoofing Off | Out-Null
            }
            Set-VMNetworkAdapter -VMName $VMName -StaticMacAddress $MacAddress | Out-Null
            Write-Host "Set static MAC: $MacAddress" -ForegroundColor Green
        }
    }

    # Useful integration services
    Enable-VMIntegrationService -VMName $VMName -Name "Guest Service Interface" -ErrorAction SilentlyContinue | Out-Null

    Write-Host "VM configured: $VMName" -ForegroundColor Green
}

# -----------------------------
# RUN
# -----------------------------
try {
    Assert-Windows11
    Assert-Admin
    Show-HostBanner
    if (-not (Confirm-HyperVPresent)) {
        throw "Hyper-V not enabled. Aborting at user request."
    }
    Enable-HyperV

    $defaultExternalSwitchName = $ExternalSwitchName
    if ([string]::IsNullOrWhiteSpace($defaultExternalSwitchName)) {
        $defaultExternalSwitchName = "External Switch"
    }
    $switchInput = Read-Host "Enter external switch name or press Enter for '$defaultExternalSwitchName'"
    if (-not [string]::IsNullOrWhiteSpace($switchInput)) {
        $ExternalSwitchName = $switchInput
    } else {
        $ExternalSwitchName = $defaultExternalSwitchName
    }
    $null = Ensure-ExternalSwitch -SwitchName $ExternalSwitchName -NicName $ExternalNicName

    if ([string]::IsNullOrWhiteSpace($VMName)) {
        $VMName = Get-AvailableVMName "Enter VM name"
    }

    if ([string]::IsNullOrWhiteSpace($VHDPath)) {
        $VHDPath = Join-Path $VHDDir "$VMName.vhdx"
    }
    $VHDPath = Resolve-VHDPathConflict $VHDPath $VHDDir
    $VHDSizeGB = Get-VHDSizeGB $VHDSizeGB

    if ([string]::IsNullOrWhiteSpace($ISOPath)) {
        $ISOPath = Get-RequiredInput "Enter full path to ISO file (default `"$ISOPath`")"
    }
    $isoPathObject = Resolve-FilePath $ISOPath
    $ISOPath = $isoPathObject.FullName

    # If Hyper-V was just enabled, you may need to reboot before the next part works.
    # We'll still try to proceed; if it fails, reboot and re-run.
    New-OrUpdate-VM

    Write-Host "Starting VM..." -ForegroundColor Cyan
    Start-VM -Name $VMName | Out-Null

    Write-Host "Done. Open Hyper-V Manager -> '$VMName' -> Connect to complete OS install." -ForegroundColor Green
}
catch {
    Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
    throw
}
