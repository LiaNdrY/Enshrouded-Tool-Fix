# Creator LiaNdrY
$ver = "1.0.6"
$Host.UI.RawUI.WindowTitle = "Enshrouder Tool Fix v$ver"
# Checking whether the script is running with administrator rights
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "This script must be run as an administrator." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Press Enter to close the console..."
    [Console]::ReadLine() | Out-Null
    exit
}
Write-Host "Script is running as an administrator. Proceeding with the work..." -ForegroundColor Green
Write-Host ""
# Finding the path to the installed game folder on Steam
$game_id = 1203620
try {
    $steamPath = (Get-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Valve\Steam" -Name "InstallPath").InstallPath
} catch {
    Write-Host "Steam is not installed. Further operation of the script is impossible." -ForegroundColor Red
    Write-Host ""
    Read-Host -Prompt "Press Enter to Exit"
    exit
}
try {
    $logFile = "$steamPath\logs\console_log.txt"
} catch {
    Write-Host "Cannot find file $logFile. Reinstall Steam. Further operation of the script is impossible." -ForegroundColor Red
    Write-Host ""
    Read-Host -Prompt "Press Enter to Exit"
    exit
}
$pattern = 'Game process added : AppID ' + $game_id + ' "(.*?\.exe)'
$matches = Select-String -Path $logFile -Pattern $pattern -AllMatches
if ($matches.Matches.Count -gt 0) {
    $lastMatch = $matches.Matches[-1]
    $gamePath_1 = $lastMatch.Groups[1].Value
    if ($gamePath_1[0] -eq '"') {
        $gamePath_1 = $gamePath_1.Substring(1)
    }
    $gamePath_0 = Split-Path -Path $gamePath_1
    if ($gamePath_0[0] -eq '"') {
        $gamePath_0 = $gamePath_0.Substring(1)
    }
    if (Test-Path $gamePath_1) {
        Write-Host "Found installed game in: $gamePath_0"
        Write-Host ""
    } else {
        Write-Host "Path to the installed game does not exist: $gamePath_0"
        Write-Host ""
        Read-Host -Prompt "Press Enter to Exit"
        exit
    }
} else {
    Write-Host "No installed game found"
    Write-Host ""
    Read-Host -Prompt "Press Enter to Exit"
    exit
}
# Checking Vulkan API layer versions for old versions
$Api_Video0 = (Get-ItemProperty -Path "HKLM:\HARDWARE\DEVICEMAP\VIDEO" -ErrorAction SilentlyContinue).'\Device\Video0' -replace '\\Registry\\Machine\\', 'HKLM:\\'
$Api_Video_x64 = (Get-ItemProperty -Path "$Api_Video0" -ErrorAction SilentlyContinue).PSObject.Properties | Where-Object { $_.Name -match 'Vulkan' -and $_.Name -match 'Driver' -and $_.Name -notmatch 'Wow' }
$Api_Video_x86 = (Get-ItemProperty -Path "$Api_Video0" -ErrorAction SilentlyContinue).PSObject.Properties | Where-Object { $_.Name -match 'Vulkan' -and $_.Name -match 'Driver' -and $_.Name -match 'Wow' }
$paths = @(
    "HKCU:\SOFTWARE\Khronos\Vulkan\ImplicitLayers",
    "HKCU:\SOFTWARE\Wow6432Node\Khronos\Vulkan\ImplicitLayers",
    "HKLM:\SOFTWARE\Khronos\Vulkan\ImplicitLayers",
    "HKLM:\SOFTWARE\WOW6432Node\Khronos\Vulkan\ImplicitLayers"
)
$keyPaths = @{}
foreach ($path in $paths) {
    $properties = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
    if ($properties) {
        foreach ($property in $properties.PSObject.Properties) {
            if ($property.MemberType -eq "NoteProperty" -and $property.Name -like "*.json") {
                if ($property.Name -like "*32.json" -or $property.Name -like "*64.json") {
                    $architecture = if ($property.Name -like "*32.json") { "x86" } else { "x64" }
                } else {
                    $architecture = if ($path -like "*Wow6432Node*") { "x86" } else { "x64" }
                }
                $keyPaths[$property.Name] = @{
                    Path = $path
                    Description = ""
                    Architecture = $architecture
                    Api_Version = ""
                }
            }
        }
    }
}
$keyPaths[$Api_Video_x86.Name] = @{
    Path = $Api_Video0
    Description = ""
    Architecture = "x86"
    Api_Version = ""
}
$keyPaths[$Api_Video_x64.Name] = @{
    Path = $Api_Video0
    Description = ""
    Architecture = "x64"
    Api_Version = ""
}
$uniqueKeyPaths = @{}
$keyPaths.GetEnumerator() | Group-Object -Property { [System.IO.Path]::GetFileName($_.Name) } | Sort-Object -Property { [System.IO.Path]::GetFileName($_.Group[0].Name) } | ForEach-Object {
    $uniqueKeyPaths[$_.Group[0].Name] = $_.Group[0].Value
}
foreach ($entry in $uniqueKeyPaths.GetEnumerator() | Sort-Object { [System.IO.Path]::GetFileName($_.Key) }) {
    $jsonPath = $entry.Key
    if (Test-Path $jsonPath) {
        $jsonContent = Get-Content -Path $jsonPath -Raw | ConvertFrom-Json
        $apiVersion = $jsonContent.layer.api_version
        $description = $jsonContent.layer.description
        $architecture = $entry.Value.Architecture
        $uniqueKeyPaths[$entry.Name].Description = $description
        $uniqueKeyPaths[$entry.Name].Api_Version = $apiVersion
    } else {
        if ($jsonPath -eq $Api_Video_x64.name) {
            if (Test-Path $Api_Video_x64.value) {
                $jsonContent = Get-Content -Path $Api_Video_x64.value -Raw | ConvertFrom-Json
                $apiVersion = $jsonContent.layer.api_version
                $description = $jsonContent.layer.description
                $architecture = $entry.Value.Architecture
                $uniqueKeyPaths[$entry.Name].Description = $description
                $uniqueKeyPaths[$entry.Name].Api_Version = $apiVersion
            } else {
                Write-Host "File $Api_Video_x64.value not found." -ForegroundColor Red
            }
        }
        if ($jsonPath -eq $Api_Video_x86.name) {
            if (Test-Path $Api_Video_x86.value) {
                $jsonContent = Get-Content -Path $Api_Video_x86.value -Raw | ConvertFrom-Json
                $apiVersion = $jsonContent.layer.api_version
                $description = $jsonContent.layer.description
                $architecture = $entry.Value.Architecture
                $uniqueKeyPaths[$entry.Name].Description = $description
                $uniqueKeyPaths[$entry.Name].Api_Version = $apiVersion
            } else {
                Write-Host "File $Api_Video_x86.value not found." -ForegroundColor Red
            }
        }
    }
}
Write-Host "Checking Vulkan layer API versions..."
foreach ($entry in $uniqueKeyPaths.GetEnumerator() | Sort-Object { [System.IO.Path]::GetFileName($_.Key) }) {
    if ([version]$entry.Value.Api_Version -lt [version]"1.2") {
        Write-Host "$($entry.Value.Description) $($entry.Value.Architecture)" -NoNewline -ForegroundColor Red
        Write-Host " (v$($entry.Value.Api_Version)) - this version is outdated and will be removed" -ForegroundColor Red
        if ($entry.Key -notlike "*json*") {
            Remove-ItemProperty -Path $entry.Value.Path -Name $entry.Key -ErrorAction SilentlyContinue
        }
    } else {
        Write-Host "$($entry.Value.Description) $($entry.Value.Architecture)" -NoNewline
        Write-Host " (v$($entry.Value.Api_Version))" -ForegroundColor Green
    }
}
# Checking Vulkan API Versions
Write-Host ""
$FolderCache = $gamePath_0.Substring(0, $gamePath_0.Length - 18) + "\shadercache\$game_id"
Write-Host "Checking Vulkan Runtime versions..."
Write-Host ""
$LastVRVer = (Invoke-WebRequest -Uri 'https://sdk.lunarg.com/sdk/download/latest/windows/config.json' -UseBasicParsing | ConvertFrom-Json).version
Write-Host "Latest Vulkan Runtime version: " -NoNewline
Write-Host $LastVRVer -ForegroundColor Green
$dllPath = "$env:SystemRoot\System32\vulkan-1.dll"
$CurDllVer = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($dllPath).FileVersion
Write-Host "Installed Vulkan Runtime version: " -NoNewline
Write-Host $CurDllVer -ForegroundColor Green
Write-Host ""
if ([version]$CurDllVer -lt [version]$LastVRVer) {
    Write-Host "Downloading the latest Vulkan Runtime..."
    Write-Host ""
    $downloadUrl = "https://sdk.lunarg.com/sdk/download/latest/windows/vulkan-runtime.exe"
    $downloadPath = "$env:TEMP\vulkan-runtime.exe"
    Invoke-WebRequest -Uri $downloadUrl -OutFile $downloadPath
    Write-Host "Installing the latest Vulkan Runtime..."
    Write-Host ""
    Start-Process -FilePath $downloadPath -ArgumentList "/S" -Wait
    Remove-Item -Path $downloadPath -Force
    Write-Host "Installation complete, checking Vulkan Runtime versions..."
    Write-Host ""
    $dllPath = "$env:SystemRoot\System32\vulkan-1.dll"
    $CurDllVer = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($dllPath).FileVersion
    Write-Host "Latest Vulkan Runtime version: " + $LastVRVer -ForegroundColor Green
    Write-Host "Installed Vulkan Runtime version: " + $CurDllVer -ForegroundColor Green
    Write-Host ""
}
# Finding processes using the Vulkan API
Write-Host "Looking for running processes using Vulkan..."
$processes = Get-Process
$vulkanProcesses = @()
foreach ($process in $processes) {
    $modules = $process.Modules
    foreach ($module in $modules) {
        if ($module.ModuleName -like "*vulkan*") {
            $vulkanProcesses += $process
            break
        }
    }
}
if ($vulkanProcesses.Count -eq 0) {
    Write-Host "Processes using Vulkan were not found." -ForegroundColor Green
    Write-Host ""
} else {
    $vulkanProcesses | Select-Object ProcessName, Id, Path | Out-Host
}
# Clearing the cache of nVidia video cards
$paths_nVidia = @(
    "$env:LOCALAPPDATA\NVIDIA\GLCache",
    "$env:LOCALAPPDATA\NVIDIA\DXCache",
    "$env:LOCALAPPDATA\NVIDIA Corporation\NV_Cache",
    "$env:LOCALAPPDATA\NVIDIA Corporation\NvTmRep",
    "$env:ProgramData\NVIDIA Corporation\NV_Cache",
    "$env:ProgramData\NVIDIA Corporation\NvTelemetry"
)
if (Test-Path "$env:LOCALAPPDATA\NVIDIA") {
    Write-Host "Clearing nVidia GPU cache: " -NoNewline
    foreach ($path in $paths_nVidia) {
        if (Test-Path $path) {
            try {
                Remove-Item -Path $path -Recurse -Force -ErrorAction SilentlyContinue
            } catch {
                Write-Host "Error deleting $path" -ForegroundColor Red
            }
        }
    }
    Write-Host "Done" -ForegroundColor Green
}
# Clearing the cache of AMD video cards
$paths_AMD = @(
    "$env:LOCALAPPDATA\AMD\GLCache",
    "$env:LOCALAPPDATA\AMD\DxCache",
    "$env:LOCALAPPDATA\AMD\DxcCache",
    "$env:LOCALAPPDATA\AMD\Dx9Cache",
    "$env:LOCALAPPDATA\AMD\VkCache"
)
if (Test-Path "$env:LOCALAPPDATA\AMD") {
    Write-Host "Clearing AMD GPU cache: " -NoNewline
    foreach ($path in $paths_AMD) {
        if (Test-Path $path) {
            try {
                Remove-Item -Path $path -Recurse -Force -ErrorAction SilentlyContinue
            } catch {
                Write-Host "Error deleting $path" -ForegroundColor Red
            }
        }
    }
    Write-Host "Done" -ForegroundColor Green
}
# Clearing the cache in the Steam directory
Write-Host "Clearing game shader cache in $FolderCache\: " -NoNewline
Remove-Item -Path $FolderCache -Recurse -Force -ErrorAction SilentlyContinue
Write-Host "Done" -ForegroundColor Green
Write-Host ""
Write-Host "After starting the game, it will start recompiling shaders after entering your world, shader compilation will continue (this will take some time ~10 min), you can observe the progress at the bottom of the menu by pressing ESC" -ForegroundColor Yellow
Write-Host ""
$fileJson = "$gamePath_0\enshrouded_local.json"
if (Test-Path -Path $fileJson) {
    Write-Host "Set the native resolution for the game: " -NoNewline
    Add-Type -AssemblyName System.Windows.Forms
    $screens = [System.Windows.Forms.Screen]::AllScreens
    foreach ($screen in $screens) {
        if ($screen.Primary) {
            $primaryMonitorWidth = $screen.Bounds.Width
            $primaryMonitorHeight = $screen.Bounds.Height
            break
        }
    }
    $json = Get-Content -Path $fileJson | ConvertFrom-Json
    $json.graphics.windowPosition.x = 0
    $json.graphics.windowPosition.y = 0
    $json.graphics.windowSize.x = $($primaryMonitorWidth)
    $json.graphics.windowSize.y = $($primaryMonitorHeight)
    $json.graphics.forceBackbufferResolution.x = 0
    $json.graphics.forceBackbufferResolution.y = 0
    $json | ConvertTo-Json | Set-Content -Path $fileJson
    Write-Host "Done ($($primaryMonitorWidth)x$($primaryMonitorHeight))" -ForegroundColor Green
    Write-Host ""
} else {
    Write-Host "Set the native resolution for the game: " -NoNewline
    Write-Host "The enshrouded_local.json file is missing from the game folder." -ForegroundColor Red
    Write-Host ""
}
# Setting the minimum FOV
$fileJsonSG = "$env:USERPROFILE\Saved Games\Enshrouded\enshrouded_user.json"
if (Test-Path -Path $fileJsonSG) {
    Write-Host "Set the minimum FOV in the game: " -NoNewline
    $json = Get-Content -Path $fileJsonSG | ConvertFrom-Json
    $json.graphics.fov = 42480000
    $json | ConvertTo-Json | Set-Content -Path $fileJsonSG
    Write-Host "Done" -ForegroundColor Green
    Write-Host "In the future, you can increase the FOV in the game settings if it stops crashing." -ForegroundColor Yellow
    Write-Host ""
} else {
    Write-Host "Set the minimum FOV in the game: " -NoNewline
    Write-Host "The enshrouded_local.json file is missing from the Saved Games folder." -ForegroundColor Red
    Write-Host ""
}
# Enable/disable GameDVR
$gameDvrEnabled = (Get-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_Enabled" -ErrorAction SilentlyContinue).GameDVR_Enabled
$gameDvrPolicy = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\ApplicationManagement\AllowGameDVR" -Name "value" -ErrorAction SilentlyContinue).value
Write-Host "GameDVR indirectly affects performance in games; it is advisable to disable it if you have a weak video card." -ForegroundColor Yellow
if ($gameDvrEnabled -eq 0 -and $gameDvrPolicy -eq 0) {
    Write-Host "GameDVR Status: " -NoNewline
    Write-Host "Off" -ForegroundColor Green
    $answer = Read-Host "Want to enable GameDVR? (Y - Yes / Any - No)"
    if ($answer -eq "Y") {
        Write-Host "GameDVR Status: " -NoNewline
        Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_Enabled" -Value 1 -Type DWORD
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\ApplicationManagement\AllowGameDVR" -Name "value" -Value 1 -Type DWORD
        Write-Host "On" -ForegroundColor Green
    } else {
    }
} else {
    Write-Host "GameDVR Status: " -NoNewline
    Write-Host "On" -ForegroundColor Green
    $answer = Read-Host "Want to disable GameDVR? (Y - Yes / Any - No)"
    if ($answer -eq "Y") {
        Write-Host "GameDVR Status: " -NoNewline
        Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_Enabled" -Value 0 -Type DWORD
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\ApplicationManagement\AllowGameDVR" -Name "value" -Value 0 -Type DWORD
        Write-Host "Off" -ForegroundColor Green
    } else {
    }
}
# Check RAM
Write-Host ""
$Ram = [Math]::Round((Get-CimInstance -ClassName Win32_ComputerSystem).TotalPhysicalMemory / 1GB)
if ($Ram -lt 16) {
    Write-Host "RAM: " -NoNewline
    Write-Host "$Ram GB" -ForegroundColor Red
    Write-Host "Attention: the amount of RAM is less than 16 GB, in order for the game to start you need to enter the steam key in the game parameters: " -NoNewline -ForegroundColor Yellow
    Write-Host "--disable-ram-check" -ForegroundColor Green
    Write-Host "Even if the game starts with this parameter, it will most likely crash sooner or later." -ForegroundColor Red
} else {
    Write-Host "RAM: " -NoNewline
    Write-Host "$Ram GB" -ForegroundColor Green
}
# Check VRAM
Write-Host ""
$VideoCard = Get-CimInstance -ClassName Win32_VideoController | Where-Object { $_.AdapterCompatibility }
$vRam0 = (Get-ItemProperty -Path "HKLM:\HARDWARE\DEVICEMAP\VIDEO" -ErrorAction SilentlyContinue).'\Device\Video0' -replace '\\Registry\\Machine\\', 'HKLM:\\'
$vRam1 = [Math]::Round((Get-ItemProperty -Path "$vRam0" -ErrorAction SilentlyContinue).'HardwareInformation.qwMemorySize' / 1024 / 1024 / 1024)
if ($vRam1 -lt 6) {
    Write-Host "Video Card: " -NoNewline
    Write-Host $($VideoCard.Name) -NoNewline
    Write-Host " ($vRam1 GB)" -ForegroundColor Red
    Write-Host "Attention: the amount of video memory is less than 6 GB; in order for the game to start, you must enter the steam key in the game parameters: " -NoNewline -ForegroundColor Yellow
    Write-Host "--disable-vram-check" -ForegroundColor Green
    Write-Host "Even if the game starts with this parameter, it will most likely crash sooner or later." -ForegroundColor Red
} else {
    Write-Host "Video Card: " -NoNewline
    Write-Host "$($VideoCard.Name) ($vRam1 GB)" -ForegroundColor Green
}
Write-Host ""
Write-Host "The texture quality setting affects the amount of video memory consumed by the game:" -ForegroundColor Yellow
Write-Host "Low (~5 GB), Medium (~5.5 GB), High (~6.5 GB), Ultra (~8.5 GB)" -ForegroundColor Yellow
Write-Host ""
Write-Host "It's recommended to update your video card drivers if you have an older version and a newer one is available." -ForegroundColor Yellow
Write-Host "After that, you must run this utility again to check the Vulkan API version." -ForegroundColor Yellow
Write-Host ""
if ($($VideoCard.Name) -like "*nvidia*") {
    Write-Host "Link to the latest video driver: " -NoNewline
    Write-Host "(https://www.nvidia.com/Download/index.aspx)" -ForegroundColor Green
    Write-Host "You can also try the beta driver for Vulkan: " -NoNewline
    Write-Host "(https://developer.nvidia.com/downloads/vulkan-beta-53837-windows)" -ForegroundColor Green
} elseif ($($VideoCard.Name) -like "*amd*") {
    Write-Host "Link to the latest video driver: " -NoNewline
    Write-Host "(https://www.amd.com/en/support/kb/release-notes/rn-rad-win-23-40-02-03-enshrouded)" -ForegroundColor Green
} else {
    Write-Host "Video card not recognized."
}
# Completing script execution
Write-Host ""
Write-Host "A restart of the computer is required." -ForegroundColor Yellow
Write-Host ""
Read-Host -Prompt "Press Enter to Exit"
