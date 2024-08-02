# Creator LiaNdrY
$ver = "1.1.6"
$Host.UI.RawUI.WindowTitle = "Enshrouded Tool Fix v$ver"
$logFilePath = "$env:TEMP\Enshrouded_Tool_Fix.log"
if (Test-Path -Path $logFilePath) {
    Remove-Item -Path $logFilePath
}
# Function for writing to a file and outputting to the console
function WHaL {
    param(
        [Parameter(ValueFromPipeline=$true)]
        [string]$Message,
        [switch]$NoNewline,
        [System.ConsoleColor]$ForegroundColor = [System.ConsoleColor]::Gray
    )
    if ([string]::IsNullOrWhiteSpace($Message)) {
        Write-Host ""
        Write-Output "" | Out-File -FilePath $logFilePath -Encoding UTF8 -Append
        return
    }
    $Message | Out-File -FilePath $logFilePath -Encoding UTF8 -Append -NoNewline:$NoNewline
    if ($NoNewline) {
        Write-Host $Message -NoNewline -ForegroundColor $ForegroundColor
    } else {
        Write-Host $Message -ForegroundColor $ForegroundColor
    }
}
# Checking whether the script is running with administrator rights
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    WHaL "This script must be run as an administrator." -ForegroundColor Yellow
    WHaL ""
    WHaL "Press Enter to close the console..."
    [Console]::ReadLine() | Out-Null
    exit
}
WHaL "Script is running as an administrator. Proceeding with the work..." -ForegroundColor Green
WHaL ""
# Finding the path to the installed game folder on Steam
$game_id = 1203620
function Format-Json([Parameter(Mandatory, ValueFromPipeline)][String] $json) {
  $indent = 0;
  ($json -Split '\n' |
    % {
      if ($_ -match '[\}\]]') {
        $indent--
      }
      $line = (' ' * $indent * 2) + $_.TrimStart().Replace(':  ', ': ')
      if ($_ -match '[\{\[]') {
        $indent++
      }
      $line
  }) -Join "`n"
}
try {
    $steamPath = (Get-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Valve\Steam" -Name "InstallPath").InstallPath
} catch {
    WHaL "Steam is not installed. Further operation of the script is impossible." -ForegroundColor Red
    WHaL ""
    Read-Host -Prompt "Press Enter to Exit"
    exit
}
try {
    $logFile = "$steamPath\logs\console_log.txt"
} catch {
    WHaL "Cannot find file $logFile. Reinstall Steam. Further operation of the script is impossible." -ForegroundColor Red
    WHaL ""
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
        WHaL "Found installed game in: $gamePath_0"
        WHaL ""
    } else {
        WHaL "Path to the installed game does not exist: $gamePath_0"
        WHaL ""
        Read-Host -Prompt "Press Enter to Exit"
        exit
    }
} else {
    WHaL "No installed game found"
    WHaL "If you moved the game to another drive and never launched it after moving it. Then you need to run it at least once and then run this script again." -ForegroundColor Yellow
    WHaL ""
    Read-Host -Prompt "Press Enter to Exit"
    exit
}
# Checking Vulkan API layer versions for old versions
$vCardPath = Get-ItemProperty -Path "HKLM:\HARDWARE\DEVICEMAP\VIDEO" -ErrorAction SilentlyContinue
$minValue = [int]::MaxValue
foreach ($property in $vCardPath.PSObject.Properties) {
    if ($property.Value -like "\*\*\*\*\*\Video\{*}\*") {
        $path = $property.Value -replace '\\Registry\\Machine\\', 'HKLM:\\'
        $value = [int]($path -replace '.*\\(\d+)$', '$1')
        if ($value -lt $minValue) {
            $minValue = $value
            $Api_Video0 = $path
        }
    }
}
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
        $libraryPathICD = $jsonContent.ICD.library_path
        $api_VersionICD = $jsonContent.ICD.api_version
        $apiVersion = $jsonContent.layer.api_version
        $description = $jsonContent.layer.description
        $architecture = $entry.Value.Architecture
        $uniqueKeyPaths[$entry.Name].Description = $description
        $uniqueKeyPaths[$entry.Name].Api_Version = $apiVersion
    } else {
        if ($jsonPath -eq $Api_Video_x64.name) {
            if (Test-Path $Api_Video_x64.value) {
                $jsonContent = Get-Content -Path $Api_Video_x64.value -Raw | ConvertFrom-Json
                $libraryPathICD_x64 = $jsonContent.ICD.library_path
                $api_VersionICD_x64 = $jsonContent.ICD.api_version
                if ($jsonContent.PSObject.Properties.Name -contains 'layer') {
                    $apiVersion = $jsonContent.layer.api_version
                    $description = $jsonContent.layer.description
                } elseif ($jsonContent.PSObject.Properties.Name -contains 'layers') {
                    $apiVersion = $jsonContent.layers.api_version
                    $description = $jsonContent.layers.description
                } else {
                    $jsonfilename_x64 = [System.IO.Path]::GetFileName($Api_Video_x64.value)
                    if ($jsonfilename_x64 -notcontains 'igvk') {
                        $apiVersion = $jsonContent.ICD.api_version
                        $description = "INTEL Overlay Layer"
                    } elseif ($jsonfilename_x64 -notcontains 'igvk') {
                        $apiVersion = $jsonContent.ICD.api_version
                        $description = "Unknown Overlay Layer"
                    } else {
                        WHaL "Neither 'layer' nor 'layers' property found in JSON." -ForegroundColor Red
                        if ($jsonPath -eq $Api_Video_x64.name) {
                            WHaL "Problem in file: $($Api_Video_x64.value)" -ForegroundColor Yellow
                        } else {
                            WHaL "Problem in file: $jsonPath" -ForegroundColor Yellow
                        }
                    return
                    }
                }
                $architecture = $entry.Value.Architecture
                $uniqueKeyPaths[$entry.Name].Description = $description
                $uniqueKeyPaths[$entry.Name].Api_Version = $apiVersion
            } else {
                WHaL "File $($Api_Video_x64.value) not found." -ForegroundColor Red
            }
        }
        if ($jsonPath -eq $Api_Video_x86.name) {
            if (Test-Path $Api_Video_x86.value) {
                $jsonContent = Get-Content -Path $Api_Video_x86.value -Raw | ConvertFrom-Json
                $libraryPathICD_x86 = $jsonContent.ICD.library_path
                $api_VersionICD_x86 = $jsonContent.ICD.api_version
                if ($jsonContent.PSObject.Properties.Name -contains 'layer') {
                    $apiVersion = $jsonContent.layer.api_version
                    $description = $jsonContent.layer.description
                } elseif ($jsonContent.PSObject.Properties.Name -contains 'layers') {
                    $apiVersion = $jsonContent.layers.api_version
                    $description = $jsonContent.layers.description
                } else {
                    $jsonfilename_x86 = [System.IO.Path]::GetFileName($Api_Video_x86.value)
                    if ($jsonfilename_x86 -notcontains 'igvk') {
                        $apiVersion = $jsonContent.ICD.api_version
                        $description = "INTEL Overlay Layer"
                    } elseif ($jsonfilename_x86 -notcontains 'igvk') {
                        $apiVersion = $jsonContent.ICD.api_version
                        $description = "Unknown Overlay Layer"
                    } else {
                        WHaL "Neither 'layer' nor 'layers' property found in JSON." -ForegroundColor Red
                        if ($jsonPath -eq $Api_Video_x86.name) {
                            WHaL "Problem in file: $($Api_Video_x86.value)" -ForegroundColor Yellow
                        } else {
                            WHaL "Problem in file: $jsonPath" -ForegroundColor Yellow
                        }
                    return
                    }
                }
                $architecture = $entry.Value.Architecture
                $uniqueKeyPaths[$entry.Name].Description = $description
                $uniqueKeyPaths[$entry.Name].Api_Version = $apiVersion
            } else {
                WHaL "File $($Api_Video_x86.value) not found." -ForegroundColor Red
            }
        }
    }
}
WHaL "Checking Vulkan layer API versions..."
$messageIntelPrinted = $false
$apiVersion_ICD_x86 = if (![string]::IsNullOrWhiteSpace($api_VersionICD_x86)) { $api_VersionICD_x86 } elseif (![string]::IsNullOrWhiteSpace($apiVersion)) { $apiVersion } else { "0.0.000" }
$apiVersion_ICD_x64 = if (![string]::IsNullOrWhiteSpace($api_VersionICD_x64)) { $api_VersionICD_x64 } elseif (![string]::IsNullOrWhiteSpace($apiVersion)) { $apiVersion } else { "0.0.000" }
foreach ($entry in $uniqueKeyPaths.GetEnumerator() | Sort-Object { [System.IO.Path]::GetFileName($_.Key) }) {
    $apiVersion = if ([string]::IsNullOrWhiteSpace($entry.Value.Api_Version)) { "0.0.000" } else { $entry.Value.Api_Version }
    $description = if ([string]::IsNullOrWhiteSpace($entry.Value.Description)) { "Layer name is empty" } else { $entry.Value.Description }
    if ((![string]::IsNullOrWhiteSpace($entry.Value.Description)) -and ([version]$apiVersion -gt [version]"1.2")) {
        WHaL "$description $($entry.Value.Architecture)" -NoNewline
        WHaL " (v$apiVersion)" -ForegroundColor Green
    }
    if ([version]$apiVersion -lt [version]"1.2") {
        if ($entry.Key -like "*json*") {
            WHaL "$description $($entry.Value.Architecture)" -NoNewline -ForegroundColor Red
            WHaL " (v$apiVersion) - this version is outdated and will be removed" -ForegroundColor Red
            Remove-ItemProperty -Path $entry.Value.Path -Name $entry.Key -ErrorAction SilentlyContinue
        }
        if (($entry.Key -notlike "*json*") -and (($libraryPathICD_x86 -notlike "*igvk32.dll*") -or ($libraryPathICD_x64 -notlike "*igvk64.dll*"))) {
            WHaL "$description $($entry.Value.Architecture) (v$apiVersion) - The Vulkan API layer is out of date, please update your video driver." -ForegroundColor Red
        } else {
            continue
        }
    }
}
# Checking Vulkan API Versions
WHaL ""
$FolderCache = $gamePath_0.Substring(0, $gamePath_0.Length - 18) + "\shadercache\$game_id"
WHaL "Checking Vulkan Runtime versions..."
WHaL ""
$LastVRVer = (Invoke-WebRequest -Uri 'https://sdk.lunarg.com/sdk/download/latest/windows/config.json' -UseBasicParsing | ConvertFrom-Json).version
WHaL "Latest Vulkan Runtime version: " -NoNewline
WHaL $LastVRVer -ForegroundColor Green
$dllPath = "$env:SystemRoot\System32\vulkan-1.dll"
$CurDllVer = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($dllPath).FileVersion
WHaL "Installed Vulkan Runtime version: " -NoNewline
WHaL $CurDllVer -ForegroundColor Green
WHaL ""
if ([version]$CurDllVer -lt [version]$LastVRVer) {
    $vulkanFiles = @(
        "$env:SystemRoot\System32\vulkan-1.dll"
        "$env:SystemRoot\System32\vulkaninfo.exe"
        "$env:SystemRoot\System32\vulkan-1-999-0-0-0.dll"
        "$env:SystemRoot\System32\vulkaninfo-1-999-0-0-0.exe"
        "$env:SystemRoot\SysWOW64\vulkan-1.dll"
        "$env:SystemRoot\SysWOW64\vulkaninfo.exe"
        "$env:SystemRoot\SysWOW64\vulkan-1-999-0-0-0.dll"
        "$env:SystemRoot\SysWOW64\vulkaninfo-1-999-0-0-0.exe"
    )
    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    $messagePrinted = $false
    foreach ($vulkanFile in $vulkanFiles) {
        if (Test-Path $vulkanFile) {
            try {
                $fileOwner = (Get-Acl -Path $vulkanFile).Owner
                if ($fileOwner -eq "NT AUTHORITY\SYSTEM" -or $fileOwner -eq "NT SERVICE\TrustedInstaller") {
                    takeown /F $vulkanFile > $null
                    & icacls $vulkanFile /grant:r "$($currentUser):(F)" > $null
                } else {
                    if (-not $messagePrinted) {
                        WHaL "Vulkan Runtime files are not locked by the System." -ForegroundColor Green
                        WHaL ""
                        $messagePrinted = $true
                    }
                }
            } catch {
                WHaL "An error occurred while processing $vulkanFile" -ForegroundColor Red
                WHaL ""
            }
        } else {
            WHaL "File $vulkanFile does not exist." -ForegroundColor Yellow
            WHaL ""
        }
    }
    WHaL "Downloading the latest Vulkan Runtime..."
    WHaL ""
    $downloadUrl = "https://sdk.lunarg.com/sdk/download/latest/windows/vulkan-runtime.exe"
    $downloadPath = "$env:TEMP\vulkan-runtime.exe"
    Invoke-WebRequest -Uri $downloadUrl -OutFile $downloadPath
    WHaL "Installing the latest Vulkan Runtime..."
    WHaL ""
    Start-Process -FilePath $downloadPath -ArgumentList "/S" -Wait
    Remove-Item -Path $downloadPath -Force
    WHaL "Installation complete, checking Vulkan Runtime versions..."
    WHaL ""
    $CurDllVer = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($dllPath).FileVersion
    WHaL "Latest Vulkan Runtime version: " -NoNewline
    WHaL $LastVRVer -ForegroundColor Green
    WHaL "Installed Vulkan Runtime version: " -NoNewline
    WHaL $CurDllVer -ForegroundColor Green
    WHaL ""
}
# Finding processes using the Vulkan API
WHaL "Looking for running processes using Vulkan..."
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
    WHaL "Processes using Vulkan were not found." -ForegroundColor Green
    WHaL ""
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
    WHaL "Clearing nVidia GPU cache: " -NoNewline
    foreach ($path in $paths_nVidia) {
        if (Test-Path $path) {
            try {
                Remove-Item -Path $path -Recurse -Force -ErrorAction SilentlyContinue
            } catch {
                WHaL "Error deleting $path" -ForegroundColor Red
            }
        }
    }
    WHaL "Done" -ForegroundColor Green
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
    WHaL "Clearing AMD GPU cache: " -NoNewline
    foreach ($path in $paths_AMD) {
        if (Test-Path $path) {
            try {
                Remove-Item -Path $path -Recurse -Force -ErrorAction SilentlyContinue
            } catch {
                WHaL "Error deleting $path" -ForegroundColor Red
            }
        }
    }
    WHaL "Done" -ForegroundColor Green
}
# Clearing the cache of INTEL video cards
$paths_INTEL = @(
    "$env:USERPROFILE\appdata\locallow\Intel\ShaderCache"
)
if (Test-Path "$env:USERPROFILE\appdata\locallow\Intel") {
    WHaL "Clearing INTEL GPU cache: " -NoNewline
    foreach ($path in $paths_AMD) {
        if (Test-Path $path) {
            try {
                Remove-Item -Path $path -Recurse -Force -ErrorAction SilentlyContinue
            } catch {
                WHaL "Error deleting $path" -ForegroundColor Red
            }
        }
    }
    WHaL "Done" -ForegroundColor Green
}
# Clearing the cache in the Steam directory
WHaL "Clearing game shader cache in $FolderCache\: " -NoNewline
Remove-Item -Path $FolderCache -Recurse -Force -ErrorAction SilentlyContinue
WHaL "Done" -ForegroundColor Green
WHaL ""
WHaL "After starting the game, it will start recompiling shaders after entering your world, shader compilation will continue (this will take some time ~10 min), you can observe the progress at the bottom of the menu by pressing ESC" -ForegroundColor Yellow
# Setting the native resolution in the game
WHaL ""
$fileJson = "$gamePath_0\enshrouded_local.json"
if (Test-Path -Path $fileJson) {
    WHaL "Set the native resolution for the game: " -NoNewline
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
    $json.graphics.windowMode = "Fullscreen"
    $json.graphics.windowPosition.x = 0
    $json.graphics.windowPosition.y = 0
    $json.graphics.windowSize.x = $($primaryMonitorWidth)
    $json.graphics.windowSize.y = $($primaryMonitorHeight)
    $json.graphics.forceBackbufferResolution.x = 0
    $json.graphics.forceBackbufferResolution.y = 0
    $json.graphics.sleepInBackground = $false
    $json | ConvertTo-Json -Depth 100 | Format-Json |
        ForEach-Object {$_ -replace "(?m)  (?<=^(?:  )*)", "`t" } |
        Set-Content -Path $fileJson
    WHaL "Done ($($primaryMonitorWidth)x$($primaryMonitorHeight))" -ForegroundColor Green
    WHaL ""
} else {
    WHaL "Set the native resolution for the game: " -NoNewline
    WHaL "The enshrouded_local.json file is missing from the game folder." -ForegroundColor Red
    WHaL ""
}
# Setting the minimum FOV
$fileJsonSG = "$env:USERPROFILE\Saved Games\Enshrouded\enshrouded_user.json"
if (Test-Path -Path $fileJsonSG) {
    WHaL "Set the minimum FOV in the game: " -NoNewline
    $json = Get-Content -Path $fileJsonSG -Raw | ConvertFrom-Json
    if ($json.graphics -and $json.graphics.PSObject.Properties.Name -contains 'fov') {
        $json.graphics.fov = "42480000"
    } else {
        WHaL "The 'fov' property does not exist in the enshrouded_user.json file." -ForegroundColor Yellow
        if (!$json.graphics) {
            $json | Add-Member -NotePropertyName 'graphics' -NotePropertyValue ([PSCustomObject]@{})
        }
        $json.graphics | Add-Member -NotePropertyName 'fov' -NotePropertyValue "42480000"
    }
    $json | ConvertTo-Json -Depth 100 | Format-Json |
        ForEach-Object {$_ -replace "(?m)  (?<=^(?:  )*)", "`t" } |
        Set-Content -Path $fileJsonSG
    WHaL "Done" -ForegroundColor Green
    WHaL "In the future, you can increase the FOV in the game settings if it stops crashing." -ForegroundColor Yellow
    WHaL ""
} else {
    WHaL "Set the minimum FOV in the game: " -NoNewline
    WHaL "The enshrouded_user.json file is missing from the Saved Games folder." -ForegroundColor Red
    WHaL ""
}
# Set Powerplan
$guids = @{
    "High performance" = "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"
    "Balanced"         = "381b4222-f694-41f0-9685-ff5bb260df2e"
    "Power saver"      = "a1841308-3541-4fab-bc81-f71556f20b4a"
}
$powerSchemes = powercfg -l
$activeGUID = ($powerSchemes | Select-String -Pattern '(?<=\().+?(?=\))' -AllMatches).Matches.Value
if ($activeGUID -eq $guids["Balanced"] -or $activeGUID -eq $guids["Power saver"]) {
    powercfg /S $guids["High performance"]
    WHaL "Changing the power saving scheme to 'High Performance': " -NoNewline
    WHaL "Done" -ForegroundColor Green
} else {
    $powerScheme = Get-CimInstance -Namespace root\cimv2\power -ClassName Win32_PowerPlan -Filter "IsActive='true'"
    WHaL "Changing the power saving scheme to 'High Performance': " -NoNewline
    WHaL "The scheme has not been changed since it is already installed - " -ForegroundColor Yellow -NoNewline
    WHaL $powerScheme.ElementName -ForegroundColor Yellow
}
# Increase system responsiveness and network throughput
WHaL ""
$perfomanceSystem = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile"
$values = @{
    "NetworkThrottlingIndex" = 20
    "SystemResponsiveness" = 10
}
if (!(Test-Path $perfomanceSystem)) {
    New-Item -Path $perfomanceSystem -Force | Out-Null
}
foreach ($key in $values.Keys) {
    Set-ItemProperty -Path $perfomanceSystem -Name $key -Value $values[$key] -Type "DWord"
}
WHaL "Improve input responsiveness and network throughput: " -NoNewline
WHaL "Done" -ForegroundColor Green
WHaL ""
# Enable/disable GameDVR
$gameDvrEnabled = (Get-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_Enabled" -ErrorAction SilentlyContinue).GameDVR_Enabled
$gameDvrPolicy = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\ApplicationManagement\AllowGameDVR" -Name "value" -ErrorAction SilentlyContinue).value
WHaL "GameDVR indirectly affects performance in games; it is advisable to disable it if you have a weak video card." -ForegroundColor Yellow
if ($gameDvrEnabled -eq 0 -and $gameDvrPolicy -eq 0) {
    WHaL "GameDVR Status: " -NoNewline
    WHaL "Off" -ForegroundColor Green
    $answer = Read-Host "Want to enable GameDVR? (Y - Yes / Any - No)"
    if ($answer -eq "Y") {
        WHaL "GameDVR Status: " -NoNewline
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\ApplicationManagement\AllowGameDVR" -Name "value" -Value 1 -Type DWORD
        WHaL "On" -ForegroundColor Green
    } else {
    }
} else {
    WHaL "GameDVR Status: " -NoNewline
    WHaL "On" -ForegroundColor Green
    $answer = Read-Host "Want to disable GameDVR? (Y - Yes / Any - No)"
    if ($answer -eq "Y") {
        WHaL "GameDVR Status: " -NoNewline
        Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_Enabled" -Value 0 -Type DWORD
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\ApplicationManagement\AllowGameDVR" -Name "value" -Value 0 -Type DWORD
        WHaL "Off" -ForegroundColor Green
    } else {
    }
}
# Checking processor support on AVX instructions
WHaL ""
WHaL "CPU Info..."
Add-Type -TypeDefinition @"
    using System;
    using System.Runtime.InteropServices;

    public class ProcessorInfo
    {
        [DllImport("kernel32.dll")]
        public static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll")]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll")]
        public static extern bool IsProcessorFeaturePresent(int ProcessorFeature);

        public const int PF_AVX = 39;

        public static bool IsAVXSupported()
        {
            IntPtr kernel32 = GetModuleHandle("kernel32.dll");
            IntPtr procAddress = GetProcAddress(kernel32, "IsProcessorFeaturePresent");
            return IsProcessorFeaturePresent(PF_AVX);
        }
    }
"@
$processorName = (Get-CimInstance -ClassName Win32_Processor).Name
if ([ProcessorInfo]::IsAVXSupported()) {
    WHaL "Name CPU: $processorName"
    WHaL "AVX support: " -NoNewline
    WHaL "Yes" -ForegroundColor Green
} else {
    WHaL "Name CPU: $processorName"
    WHaL "AVX support: " -NoNewline
    WHaL "No" -ForegroundColor Red
    WHaL ""
    WHaL "Unfortunately, your processor does not support the AVX instruction set, the game will not be able to start without this set." -ForegroundColor Red
}
# Checking the parameters of the paging file
$gameLog = "$gamePath_0\enshrouded.log"
$textLogMemory = "*Could not allocate new memory block, error: out of memory*"
if (Test-Path $gameLog) {
    $logContent = Get-Content $gameLog
    if ($logContent -like $textLogMemory) {
        $result = $true
    } else {
        $result = $false
    }
} else {
    $result = $null
}
WHaL ""
$swapFile = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "PagingFiles").PagingFiles
if (($swapFile -eq "?:\pagefile.sys") -and ($result -eq $true)) {
    WHaL "Auto-selection of the paging file size: " -NoNewline
    WHaL "Yes" -ForegroundColor Green
    WHaL "The message 'Out of memory' was found in the log file." -ForegroundColor Yellow
}
elseif (($swapFile -ne "?:\pagefile.sys") -and (($result -eq $false) -or ($result -eq $null))) {
    WHaL "Auto-selection of the paging file size: " -NoNewline
    WHaL "No" -ForegroundColor Yellow
    WHaL "The message 'Out of memory' was not found in the log file." -ForegroundColor Yellow
}
elseif ($swapFile -eq "?:\pagefile.sys") {
    WHaL "Auto-selection of the paging file size: " -NoNewline
    WHaL "Yes" -ForegroundColor Green
}
elseif (($swapFile -ne "?:\pagefile.sys") -and ($result -eq $true)) {
    WHaL "Auto-selection of the paging file size: " -NoNewline
    WHaL "No" -ForegroundColor Yellow
    WHaL "The message 'Out of memory' was found in the log file." -ForegroundColor Yellow
    WHaL "If your game crashes immediately, it is advisable to set the auto-selection of the paging file size by the system." -ForegroundColor Yellow
    $answer = Read-Host "Do you want to do this? (Y - Yes / Any - No)"
    if ($answer -eq "Y") {
        SystemPropertiesPerformance.exe /pagefile
        WHaL ""
        WHaL "- Click the " -NoNewline
        WHaL "'Change'" -NoNewline -ForegroundColor Green
        WHaL " button"
        WHaL "- Select the disk on which you have a paging file"
        WHaL "- Specify " -NoNewline
        WHaL "'System managed size'" -NoNewline -ForegroundColor Green
        WHaL ", then click the " -NoNewline
        WHaL "'Set'" -NoNewline -ForegroundColor Green
        WHaL " button"
        WHaL "- After that, check the box " -NoNewline
        WHaL "'Automatically manage paging file size for all drives'" -ForegroundColor Green
        WHaL "- Click " -NoNewline
        WHaL "'Ok'" -ForegroundColor Green
        WHaL "The system will ask you to reboot for the changes to take effect, postpone this process and exit this script, after which you can reboot the system." -ForegroundColor Yellow
        Read-Host -Prompt "Press Enter to Continue"
    } else {
    }
}
# Check RAM
WHaL ""
$Ram = [Math]::Round((Get-CimInstance -ClassName Win32_ComputerSystem).TotalPhysicalMemory / 1GB)
if ($Ram -lt 16) {
    WHaL "RAM: " -NoNewline
    WHaL "$Ram GB" -ForegroundColor Red
    WHaL "Attention: the amount of RAM is less than 16 GB" -ForegroundColor Yellow
    WHaL "It is very likely that the game will show you a warning that your system does not meet the minimum requirements. You can acknowledge this message and proceed at your own risk." -ForegroundColor Yellow
} else {
    WHaL "RAM: " -NoNewline
    WHaL "$Ram GB" -ForegroundColor Green
}
# Check VRAM
WHaL ""
$VideoCard = Get-CimInstance -ClassName Win32_VideoController | Where-Object { $_.AdapterCompatibility }
$dxPath = $Api_Video0 -split '\\'
$dxVideoPath = Get-ItemProperty -Path ("HKLM:\SOFTWARE\Microsoft\DirectX\" + $dxPath[-2]) -ErrorAction SilentlyContinue
$vRamDX = [Math]::Round(($dxVideoPath.DedicatedVideoMemory) / 1GB)
if ($vRamDX -lt 6) {
    WHaL "Video Card: $($VideoCard.Name)" -NoNewline
    WHaL " ($vRamDX GB)" -ForegroundColor Red
    WHaL "Attention: the amount of video memory is less than 6 GB" -ForegroundColor Yellow
    WHaL "Additionally, with only 4GB of VRAM, the game limits texture settings. You can't change them in-game." -ForegroundColor Red
    WHaL "It is very likely that the game will show you a warning that your system does not meet the minimum requirements. You can acknowledge this message and proceed at your own risk." -ForegroundColor Yellow
} else {
    WHaL "Video Card: " -NoNewline
    WHaL "$($VideoCard.Name) ($vRamDX GB)" -ForegroundColor Green
}
WHaL ""
WHaL "The Texture Resolution setting affects the amount of video memory consumed by the game:" -ForegroundColor Yellow
WHaL "Performance (~5 GB), Balanced (~5.5 GB), Quality (~6.5 GB), Max.Quality (~8.5 GB)" -ForegroundColor Yellow
WHaL ""
WHaL "It's recommended to update your video card drivers if you have an older version and a newer one is available." -ForegroundColor Yellow
WHaL "After that, you must run this utility again to check the Vulkan API version." -ForegroundColor Yellow
WHaL ""
if ($($VideoCard.Name) -like "*nvidia*") {
    WHaL "Link to the latest video driver: " -NoNewline
    WHaL "(https://www.nvidia.com/Download/index.aspx)" -ForegroundColor Green
    WHaL "You can also try the beta driver for Vulkan: " -NoNewline
    WHaL "(https://developer.nvidia.com/downloads/vulkan-beta-53837-windows)" -ForegroundColor Green
} elseif ($($VideoCard.Name) -like "*radeon*" -or $($VideoCard.Name) -like "*amd*") {
    WHaL "Link to the latest video driver: " -NoNewline
    WHaL "(https://www.amd.com/en/support)" -ForegroundColor Green
} elseif (($($VideoCard.Name) -like "*intel*") -or ($($VideoCard.Name) -like "*arc*") -or ($($VideoCard.Name) -like "*iris*")) {
    WHaL "Link to the latest video driver: " -NoNewline
    WHaL "(https://www.techpowerup.com/download/intel-graphics-drivers/)" -ForegroundColor Green
} else {
    WHaL "Video card not recognized."
}
# Completing script execution
WHaL ""
WHaL 'Even if after all the corrections you have made, the game continues to crash after some time, most likely the problem is in the game itself. Either you have a very large and complex "castle", or you have a large number of crops. (This problem seems to be known to developers and it remains only to wait for patches.)' -ForegroundColor Yellow
WHaL ""
WHaL "The computer must be restarted for the changes to take effect." -ForegroundColor Yellow
WHaL ""
# Write data to log file
$dateTime = Get-Date -Format "yyyy-MM-ddTHH-mm-ss"
if (-not (Test-Path -Path "$gamePath_0\Enshrouded_Tool_Fix")) {
    New-Item -Path "$gamePath_0\Enshrouded_Tool_Fix" -ItemType Directory -Force
}
Copy-Item -Path $logFilePath -Destination "$gamePath_0\Enshrouded_Tool_Fix\Enshrouded_Tool_Fix_$dateTime.log"
Remove-Item -Path $logFilePath -Force
Start-Process -FilePath "$gamePath_0\Enshrouded_Tool_Fix"
Read-Host -Prompt "Press Enter to Exit"
exit
