# Creator LiaNdrY
$ver = "1.0.2"
$Host.UI.RawUI.WindowTitle = "Enshrouder Tool Fix v$ver"
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "This script must be run as an administrator." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Press Enter to close the console..."
    [Console]::ReadLine() | Out-Null
    exit
}
$game_id = 1203620
Write-Host "Script is running as an administrator. Proceeding with the work..." -ForegroundColor Green
Write-Host ""
$steamPath = (Get-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Valve\Steam" -Name "InstallPath").InstallPath
$logFile = "$steamPath\logs\console_log.txt"
$pattern = 'Game process added : AppID 1203620 "(.*?\.exe)"'
$matches = Select-String -Path $logFile -Pattern $pattern -AllMatches
if ($matches.Matches.Count -gt 0) {
    $lastMatch = $matches.Matches[-1]
    $gamePath_1 = $lastMatch.Groups[1].Value
    $gamePath_0 = $gamePath_1.Substring(0, $gamePath_1.Length - 15)
    if (Test-Path $gamePath_1) {
        Write-Host "Installed game found at: $gamePath_0"
        Write-Host ""
    } else {
        Write-Host "Path to the installed game does not exist: $gamePath_0"
        Write-Host ""
        Read-Host -Prompt "Press Enter to exit"
        exit
    }
} else {
    Write-Host "No installed game found"
    Write-Host ""
    Read-Host -Prompt "Press Enter to exit"
    exit
}
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
    Write-Host "Completed" -ForegroundColor Green
}
$paths_AMD = @(
    "$env:LOCALAPPDATA\AMD\GLCache",
    "$env:LOCALAPPDATA\AMD\DxCache",
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
    Write-Host "Completed" -ForegroundColor Green
}
Write-Host "Clearing game shader cache in $FolderCache\: " -NoNewline
Remove-Item -Path $FolderCache -Recurse -Force -ErrorAction SilentlyContinue
Write-Host "Completed" -ForegroundColor Green
Write-Host ""
Write-Host "After starting the game, it will start recompiling shaders after entering your world, shader compilation will continue (this will take some time ~10 min), you can observe the progress at the bottom of the menu by pressing ESC" -ForegroundColor Yellow
Write-Host ""
$fileJson = "$gamePath_0\enshrouded_local.json"
if (Test-Path -Path $fileJson) {
    Write-Host "Setting the optimal resolution for the game: " -NoNewline
    $monitor = Get-CimInstance -ClassName Win32_VideoController
    $json = Get-Content -Path $fileJson | ConvertFrom-Json
    $json.graphics.windowPosition.x = 0
    $json.graphics.windowPosition.y = 0
    $json.graphics.windowSize.x = $monitor.CurrentHorizontalResolution
    $json.graphics.windowSize.y = $monitor.CurrentVerticalResolution
    $json.graphics.forceBackbufferResolution.x = 0
    $json.graphics.forceBackbufferResolution.y = 0
    $json | ConvertTo-Json | Set-Content -Path $fileJson
    Write-Host "Completed" -ForegroundColor Green
    Write-Host ""
} else {
    Write-Host "Setting the optimal resolution for the game: " -NoNewline
    Write-Host "The enshrouded_local.json file is missing from the game folder." -ForegroundColor Red
    Write-Host ""
}
$gameDvrEnabled = (Get-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_Enabled" -ErrorAction SilentlyContinue).GameDVR_Enabled
$gameDvrPolicy = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\ApplicationManagement\AllowGameDVR" -Name "value" -ErrorAction SilentlyContinue).value
if ($gameDvrEnabled -eq 0 -and $gameDvrPolicy -eq 0) {
    Write-Host "Disabling GameDVR: " -NoNewline
    Write-Host "GameDVR is already disabled" -ForegroundColor Green
} else {
    Write-Host "Disabling GameDVR: " -NoNewline
    Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_Enabled" -Value 0 -Type DWORD
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\ApplicationManagement\AllowGameDVR" -Name "value" -Value 0 -Type DWORD
    Write-Host "Completed" -ForegroundColor Green
}
Write-Host ""
$VideoCard = Get-CimInstance -ClassName Win32_VideoController | Where-Object { $_.AdapterCompatibility }
$vRam0 = (Get-ItemProperty -Path "HKLM:\HARDWARE\DEVICEMAP\VIDEO" -ErrorAction SilentlyContinue).'\Device\Video0' -replace '\\Registry\\Machine\\', 'HKLM:\\'
$vRam1 = [Math]::Round((Get-ItemProperty -Path "$vRam0" -ErrorAction SilentlyContinue).'HardwareInformation.qwMemorySize' / 1024 / 1024 / 1024)
if ($vRam1 -lt 6) {
    Write-Host "Video card: " -NoNewline
    Write-Host $($VideoCard.Name) -NoNewline
    Write-Host " ($vRam1 GB)" -ForegroundColor Red
    Write-Host "Warning: Video memory size is less than 6 GB, you won't be able to play the game =(" -ForegroundColor Red
} else {
    Write-Host "Video card: " -NoNewline
    Write-Host "$($VideoCard.Name) ($vRam1 GB)" -ForegroundColor Green
}
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
Write-Host ""
Write-Host "A restart of the computer is required." -ForegroundColor Yellow
Write-Host ""
Read-Host -Prompt "Press Enter to exit"
