# Creator LiaNdrY
[CmdletBinding()]
param()

$script:ToolVersion = '1.1.13'
$script:GameId = 1203620
$script:LogFilePath = Join-Path -Path $env:TEMP -ChildPath 'Enshrouded_Tool_Fix.log'

# Function for writing to a file and outputting to the console
function Write-LogMessage {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline = $true)]
        [AllowEmptyString()]
        [string]$Message,

        [switch]$NoNewline,

        [System.ConsoleColor]$ForegroundColor = [System.ConsoleColor]::Gray
    )

    process {
        if ([string]::IsNullOrWhiteSpace($Message)) {
            Write-Host ''
            Write-Output '' | Out-File -FilePath $script:LogFilePath -Encoding UTF8 -Append
            return
        }

        $Message | Out-File -FilePath $script:LogFilePath -Encoding UTF8 -Append -NoNewline:$NoNewline
        Write-Host $Message -ForegroundColor $ForegroundColor -NoNewline:$NoNewline
    }
}

# Serialize JSON without modifying values inside strings.
function Format-Json {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [string]$Json
    )
    process {
        $indent = 0
        ($Json -split "`r?`n" | ForEach-Object {
            $trimmedLine = $_.Trim()
            if ($trimmedLine -match '^[\}\]]') {
                $indent = [Math]::Max(0, $indent - 1)
            }
            $line = (' ' * ($indent * 2)) + $trimmedLine
            if ($trimmedLine -match '[\{\[]\s*,?$') {
                $indent++
            }
            $line
        }) -join "`n"
    }
}

# Read and save game configuration as strict UTF-8 with a durable original backup.
function Read-GameJson {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path)

    $encoding = New-Object System.Text.UTF8Encoding($false, $true)
    $text = [System.IO.File]::ReadAllText($Path, $encoding)
    return ConvertFrom-Json -InputObject $text -ErrorAction Stop
}

function Save-FormattedJson {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][object]$InputObject,
        [Parameter(Mandatory = $true)][string]$Path
    )

    $jsonText = ConvertTo-Json -InputObject $InputObject -Depth 100 | Format-Json
    $null = ConvertFrom-Json -InputObject $jsonText -ErrorAction Stop
    $directory = Split-Path -Path $Path -Parent
    if ([string]::IsNullOrWhiteSpace($directory) -or -not [System.IO.Directory]::Exists($directory)) {
        throw "The destination directory does not exist: $directory"
    }

    $encoding = New-Object System.Text.UTF8Encoding($false, $true)
    $temporaryPath = Join-Path $directory ('.{0}.{1}.tmp' -f [System.IO.Path]::GetFileName($Path), [Guid]::NewGuid().ToString('N'))
    $backupPath = "$Path.bak"
    $replacementBackupPath = Join-Path $directory ('.{0}.{1}.rollback.tmp' -f [System.IO.Path]::GetFileName($Path), [Guid]::NewGuid().ToString('N'))
    $newContent = $jsonText + [Environment]::NewLine

    try {
        if ([System.IO.File]::Exists($Path)) {
            $oldContent = [System.IO.File]::ReadAllText($Path, $encoding)
            $previous = ConvertFrom-Json -InputObject $oldContent -ErrorAction Stop
            $previousContent = ConvertTo-Json -InputObject $previous -Depth 100 -Compress
            $newComparable = ConvertTo-Json -InputObject $InputObject -Depth 100 -Compress
            if ($previousContent -ceq $newComparable) { return }
            if (-not [System.IO.File]::Exists($backupPath)) {
                [System.IO.File]::Copy($Path, $backupPath, $false)
            }
        }

        [System.IO.File]::WriteAllText($temporaryPath, $newContent, $encoding)
        $null = Read-GameJson -Path $temporaryPath
        if ([System.IO.File]::Exists($Path)) {
            try {
                [System.IO.File]::Replace($temporaryPath, $Path, $replacementBackupPath)
            }
            catch [System.PlatformNotSupportedException] {
                [System.IO.File]::Copy($temporaryPath, $Path, $true)
                [System.IO.File]::Delete($temporaryPath)
            }
            catch [System.IO.IOException] {
                [System.IO.File]::Copy($temporaryPath, $Path, $true)
                [System.IO.File]::Delete($temporaryPath)
            }
        }
        else {
            [System.IO.File]::Move($temporaryPath, $Path)
        }
    }
    catch {
        throw "Failed to save JSON file '$Path': $($_.Exception.Message)"
    }
    finally {
        if ([System.IO.File]::Exists($temporaryPath)) {
            [System.IO.File]::Delete($temporaryPath)
        }
        if ([System.IO.File]::Exists($replacementBackupPath)) {
            [System.IO.File]::Delete($replacementBackupPath)
        }
    }
}

# Resolve Windows Saved Games and choose the current Enshrouded settings layout.
function Get-SavedGamesPath {
    if (-not ('EnshroudedKnownFolders' -as [type])) {
        Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public static class EnshroudedKnownFolders
{
    [DllImport("shell32.dll")]
    private static extern int SHGetKnownFolderPath(ref Guid folderId, uint flags, IntPtr token, out IntPtr path);

    public static string SavedGames()
    {
        Guid id = new Guid("4C5C32FF-BB9D-43B0-B5B4-2D72E54EAAA4");
        IntPtr path;
        int result = SHGetKnownFolderPath(ref id, 0, IntPtr.Zero, out path);
        if (result != 0) return null;
        try { return Marshal.PtrToStringUni(path); }
        finally { Marshal.FreeCoTaskMem(path); }
    }
}
"@
    }
    try {
        $resolved = [EnshroudedKnownFolders]::SavedGames()
        if (-not [string]::IsNullOrWhiteSpace($resolved)) { return $resolved }
    }
    catch {
        Write-Verbose "Saved Games known-folder lookup failed: $($_.Exception.Message)"
    }
    return (Join-Path $env:USERPROFILE 'Saved Games')
}

function Resolve-GameConfigurationPaths {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$GameDirectory,
        [string]$SavedGamesPath
    )

    if ([string]::IsNullOrWhiteSpace($SavedGamesPath)) { $SavedGamesPath = Get-SavedGamesPath }
    $localCandidates = @(
        (Join-Path $SavedGamesPath 'keen games\Enshrouded\local_settings.json'),
        (Join-Path $GameDirectory 'enshrouded_local.json')
    )
    $userCandidates = @(
        (Join-Path $SavedGamesPath 'Enshrouded\migrated\enshrouded_user.json'),
        (Join-Path $SavedGamesPath 'Enshrouded\enshrouded_user.json')
    )
    $localPath = $null
    $userPath = $null
    foreach ($candidate in $localCandidates) {
        if ([System.IO.File]::Exists($candidate)) { $localPath = $candidate; break }
    }
    foreach ($candidate in $userCandidates) {
        if ([System.IO.File]::Exists($candidate)) { $userPath = $candidate; break }
    }
    return [PSCustomObject]@{
        LocalPath = $localPath
        UserPath = $userPath
        LocalCandidates = $localCandidates
        UserCandidates = $userCandidates
        SavedGamesPath = $SavedGamesPath
    }
}

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]$identity
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function ConvertTo-NormalizedSteamPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $normalizedPath = [Environment]::ExpandEnvironmentVariables($Path.Trim()).Replace('/', '\')
    if ($normalizedPath.Length -gt 3) {
        $normalizedPath = $normalizedPath.TrimEnd('\')
    }

    return $normalizedPath
}

function Get-SteamInstallPath {
    $registryCandidates = @(
        @{ Path = 'HKCU:\SOFTWARE\Valve\Steam'; Name = 'SteamPath' },
        @{ Path = 'HKLM:\SOFTWARE\WOW6432Node\Valve\Steam'; Name = 'InstallPath' },
        @{ Path = 'HKLM:\SOFTWARE\Valve\Steam'; Name = 'InstallPath' }
    )

    foreach ($candidate in $registryCandidates) {
        try {
            $registryName = [string]$candidate.Name
            $registryValue = Get-ItemProperty -Path $candidate.Path -Name $registryName -ErrorAction Stop
            $steamPath = ConvertTo-NormalizedSteamPath -Path ([string]$registryValue.$registryName)

            if (-not [string]::IsNullOrWhiteSpace($steamPath) -and (Test-Path -LiteralPath $steamPath -PathType Container)) {
                return $steamPath
            }
        }
        catch {
            continue
        }
    }

    $fallbackPaths = @(
        $(if (${env:ProgramFiles(x86)}) { Join-Path -Path ${env:ProgramFiles(x86)} -ChildPath 'Steam' }),
        $(if ($env:ProgramFiles) { Join-Path -Path $env:ProgramFiles -ChildPath 'Steam' })
    ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }

    foreach ($fallbackPath in $fallbackPaths) {
        if (Test-Path -LiteralPath $fallbackPath -PathType Container) {
            return (ConvertTo-NormalizedSteamPath -Path $fallbackPath)
        }
    }

    return $null
}

function Get-SteamLibraryPathsFromVdf {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Content,

        [Parameter(Mandatory = $true)]
        [string]$SteamPath
    )

    $libraryPaths = [System.Collections.Generic.List[string]]::new()
    $seenPaths = @{}

    $defaultLibrary = ConvertTo-NormalizedSteamPath -Path $SteamPath
    $libraryPaths.Add($defaultLibrary)
    $seenPaths[$defaultLibrary] = $true

    $pathMatches = [regex]::Matches(
        $Content,
        '(?im)^\s*"path"\s+"(?<value>(?:\\.|[^"])*)"\s*$'
    )

    if ($pathMatches.Count -eq 0) {
        $pathMatches = [regex]::Matches(
            $Content,
            '(?im)^\s*"\d+"\s+"(?<value>(?:\\.|[^"])*)"\s*$'
        )
    }

    foreach ($match in $pathMatches) {
        $libraryPath = $match.Groups['value'].Value.Replace('\\', '\').Replace('\"', '"')
        if ([string]::IsNullOrWhiteSpace($libraryPath)) {
            continue
        }

        $libraryPath = ConvertTo-NormalizedSteamPath -Path $libraryPath
        if ($seenPaths.ContainsKey($libraryPath)) {
            continue
        }

        $seenPaths[$libraryPath] = $true
        $libraryPaths.Add($libraryPath)
    }

    return $libraryPaths.ToArray()
}

function Get-SteamLibraryPaths {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SteamPath
    )

    $libraryFiles = @(
        (Join-Path -Path $SteamPath -ChildPath 'config\libraryfolders.vdf'),
        (Join-Path -Path $SteamPath -ChildPath 'steamapps\libraryfolders.vdf')
    )

    $libraryPaths = [System.Collections.Generic.List[string]]::new()
    $seenPaths = @{}
    $defaultLibrary = ConvertTo-NormalizedSteamPath -Path $SteamPath
    $libraryPaths.Add($defaultLibrary)
    $seenPaths[$defaultLibrary] = $true

    foreach ($libraryFile in $libraryFiles) {
        if (-not (Test-Path -LiteralPath $libraryFile -PathType Leaf)) {
            continue
        }

        try {
            $content = Get-Content -LiteralPath $libraryFile -Raw -ErrorAction Stop
            $parsedPaths = @(Get-SteamLibraryPathsFromVdf -Content $content -SteamPath $SteamPath)
        }
        catch {
            continue
        }

        foreach ($libraryPath in $parsedPaths) {
            if ($seenPaths.ContainsKey($libraryPath)) {
                continue
            }

            $seenPaths[$libraryPath] = $true
            $libraryPaths.Add($libraryPath)
        }
    }

    return $libraryPaths.ToArray()
}

function Get-SteamAppInstallDirectoryFromManifest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Content
    )

    $match = [regex]::Match(
        $Content,
        '(?im)^\s*"installdir"\s+"(?<value>(?:\\.|[^"])*)"\s*$'
    )

    if (-not $match.Success) {
        return $null
    }

    return $match.Groups['value'].Value.Replace('\\', '\').Replace('\"', '"')
}

function Find-SteamAppInstallation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SteamPath,

        [Parameter(Mandatory = $true)]
        [int]$AppId,

        [Parameter(Mandatory = $true)]
        [string]$ExecutableName
    )

    foreach ($libraryPath in (Get-SteamLibraryPaths -SteamPath $SteamPath)) {
        $steamAppsPath = Join-Path -Path $libraryPath -ChildPath 'steamapps'
        $manifestPath = Join-Path -Path $steamAppsPath -ChildPath ("appmanifest_{0}.acf" -f $AppId)

        if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
            continue
        }

        try {
            $manifestContent = Get-Content -LiteralPath $manifestPath -Raw -ErrorAction Stop
            $installDirectoryName = Get-SteamAppInstallDirectoryFromManifest -Content $manifestContent
        }
        catch {
            continue
        }

        if ([string]::IsNullOrWhiteSpace($installDirectoryName)) {
            continue
        }

        $gameDirectory = Join-Path -Path (Join-Path -Path $steamAppsPath -ChildPath 'common') -ChildPath $installDirectoryName
        $executablePath = Join-Path -Path $gameDirectory -ChildPath $ExecutableName

        if (-not (Test-Path -LiteralPath $executablePath -PathType Leaf)) {
            continue
        }

        return [PSCustomObject]@{
            LibraryPath    = $libraryPath
            SteamAppsPath  = $steamAppsPath
            ManifestPath   = $manifestPath
            GameDirectory  = $gameDirectory
            ExecutablePath = $executablePath
        }
    }

    return $null
}

function Get-ShaderCachePath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$GameDirectory,

        [Parameter(Mandatory = $true)]
        [int]$AppId
    )

    $commonDirectory = Split-Path -Path $GameDirectory -Parent
    $steamAppsDirectory = Split-Path -Path $commonDirectory -Parent
    return Join-Path -Path $steamAppsDirectory -ChildPath ("shadercache\{0}" -f $AppId)
}

function Get-PrimaryVideoRegistryPath {
    $videoMap = Get-ItemProperty -Path 'HKLM:\HARDWARE\DEVICEMAP\VIDEO' -ErrorAction SilentlyContinue
    if (-not $videoMap) {
        return $null
    }

    $video0 = $videoMap.PSObject.Properties | Where-Object { $_.Name -eq '\Device\Video0' } | Select-Object -First 1
    if ($video0 -and $video0.Value -like '\*\*\*\*\*\Video\{*}\*') {
        return ($video0.Value -replace '\\Registry\\Machine\\', 'HKLM:\')
    }

    $bestIndex = [int]::MaxValue
    $bestPath = $null

    foreach ($property in $videoMap.PSObject.Properties) {
        if ($property.Value -notlike '\*\*\*\*\*\Video\{*}\*') {
            continue
        }

        $path = $property.Value -replace '\\Registry\\Machine\\', 'HKLM:\'
        $indexText = $path -replace '.*\\(\d+)$', '$1'
        $index = 0

        if (-not [int]::TryParse($indexText, [ref]$index)) {
            continue
        }

        if ($index -lt $bestIndex) {
            $bestIndex = $index
            $bestPath = $path
        }
    }

    return $bestPath
}

function Get-VideoControllerForRegistryPath {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [string]$VideoRegistryPath
    )

    $controllers = @(Get-CimInstance -ClassName Win32_VideoController | Where-Object { $_.AdapterCompatibility })
    if ($controllers.Count -eq 0) {
        return $null
    }

    if (-not [string]::IsNullOrWhiteSpace($VideoRegistryPath)) {
        $driverDescription = (Get-ItemProperty -Path $VideoRegistryPath -Name 'DriverDesc' -ErrorAction SilentlyContinue).DriverDesc
        if (-not [string]::IsNullOrWhiteSpace([string]$driverDescription)) {
            $matchedController = $controllers | Where-Object { $_.Name -eq $driverDescription } | Select-Object -First 1
            if ($matchedController) {
                return $matchedController
            }
        }
    }

    return $controllers | Select-Object -First 1
}

function Get-VulkanArchitecture {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$RegistryPath,

        [Parameter(Mandatory = $true)]
        [string]$ValueName
    )

    if ($ValueName -like '*32.json') {
        return 'x86'
    }

    if ($ValueName -like '*64.json') {
        return 'x64'
    }

    if ($RegistryPath -like '*Wow6432Node*') {
        return 'x86'
    }

    return 'x64'
}

function Get-VulkanLayerMetadata {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$JsonPath,

        [Parameter(Mandatory = $true)]
        [string]$Architecture
    )

    if (-not (Test-Path -LiteralPath $JsonPath)) {
        return $null
    }

    $jsonContent = Get-Content -LiteralPath $JsonPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    $metadata = [System.Collections.Generic.List[object]]::new()

    if ($jsonContent.PSObject.Properties.Name -contains 'layer') {
        $metadata.Add([PSCustomObject]@{
            ApiVersion    = $jsonContent.layer.api_version
            Description   = $jsonContent.layer.description
            Architecture  = $Architecture
            LibraryPath   = $jsonContent.layer.library_path
            IcdApiVersion = $null
        })
    }
    elseif ($jsonContent.PSObject.Properties.Name -contains 'layers') {
        foreach ($layer in @($jsonContent.layers)) {
            $metadata.Add([PSCustomObject]@{
                ApiVersion    = $layer.api_version
                Description   = $layer.description
                Architecture  = $Architecture
                LibraryPath   = $layer.library_path
                IcdApiVersion = $null
            })
        }
    }
    elseif ($jsonContent.PSObject.Properties.Name -contains 'ICD') {
        $fileName = [System.IO.Path]::GetFileName($JsonPath)
        $metadata.Add([PSCustomObject]@{
            ApiVersion    = $jsonContent.ICD.api_version
            Description   = if ($fileName -like '*igvk*') { 'INTEL Overlay Layer' } else { 'Unknown Overlay Layer' }
            Architecture  = $Architecture
            LibraryPath   = $jsonContent.ICD.library_path
            IcdApiVersion = $jsonContent.ICD.api_version
        })
    }

    return $metadata
}

function Get-LatestVulkanRuntimeInfo {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Manifest
    )

    $windowsData = $Manifest.windows
    if (-not $windowsData) {
        return $null
    }

    $runtimeEntries = foreach ($versionName in $windowsData.PSObject.Properties.Name) {
        $runtime = $windowsData.$versionName.files | Where-Object { $_.name -eq 'Runtime' } | Select-Object -First 1
        if ($runtime) {
            [PSCustomObject]@{
                Version  = $versionName
                FileName = $runtime.file_name
                Sha256   = $runtime.sha
            }
        }
    }

    return $runtimeEntries | Sort-Object { [version]$_.Version } -Descending | Select-Object -First 1
}

function Test-VulkanVersionOutdated {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Version
    )

    $parsed = $null
    if (-not [version]::TryParse($Version, [ref]$parsed)) { return $false }
    return ($parsed -lt [version]'1.2')
}


function Test-FileSha256 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$ExpectedHash
    )

    if (-not (Test-Path -LiteralPath $Path) -or [string]::IsNullOrWhiteSpace($ExpectedHash)) {
        return $false
    }

    $actualHash = (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash
    return $actualHash.Equals($ExpectedHash, [System.StringComparison]::OrdinalIgnoreCase)
}

function Invoke-DownloadFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [Uri]$Uri,

        [Parameter(Mandatory = $true)]
        [string]$OutFile
    )

    $previousSecurityProtocol = $null
    $restoreSecurityProtocol = $false

    if ($PSVersionTable.PSVersion.Major -lt 6) {
        $previousSecurityProtocol = [Net.ServicePointManager]::SecurityProtocol
        [Net.ServicePointManager]::SecurityProtocol = $previousSecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        $restoreSecurityProtocol = $true
    }

    try {
        $ProgressPreference = 'SilentlyContinue'
        Invoke-WebRequest -Uri $Uri -OutFile $OutFile -UseBasicParsing -TimeoutSec 30 -ErrorAction Stop | Out-Null
    }
    finally {
        if ($restoreSecurityProtocol) {
            [Net.ServicePointManager]::SecurityProtocol = $previousSecurityProtocol
        }
    }
}

# Download the Vulkan installer with a bounded network wait and a console progress bar.
function Invoke-DownloadFileWithProgress {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][Uri]$Uri,
        [Parameter(Mandatory = $true)][string]$OutFile,
        [ValidateRange(1, 600)][int]$TimeoutSeconds = 30
    )

    $previousSecurityProtocol = $null
    $restoreSecurityProtocol = $false
    if ($PSVersionTable.PSVersion.Major -lt 6) {
        $previousSecurityProtocol = [Net.ServicePointManager]::SecurityProtocol
        [Net.ServicePointManager]::SecurityProtocol = $previousSecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        $restoreSecurityProtocol = $true
    }

    $client = $null
    $response = $null
    $inputStream = $null
    $outputStream = $null
    $idleCancellation = $null
    $downloadComplete = $false
    $progressWritten = $false

    try {
        Add-Type -AssemblyName System.Net.Http -ErrorAction Stop
        $client = New-Object System.Net.Http.HttpClient
        $client.Timeout = [TimeSpan]::FromSeconds($TimeoutSeconds)
        $response = $client.GetAsync($Uri, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead).GetAwaiter().GetResult()
        $response.EnsureSuccessStatusCode() | Out-Null

        $inputStream = $response.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
        $outputStream = [System.IO.File]::Open($OutFile, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
        $totalBytes = $response.Content.Headers.ContentLength
        $receivedBytes = 0L
        $lastPercent = -1
        $lastUpdate = [System.Diagnostics.Stopwatch]::StartNew()
        $buffer = New-Object byte[] 131072
        $idleCancellation = New-Object System.Threading.CancellationTokenSource

        while ($true) {
            $idleCancellation.CancelAfter($TimeoutSeconds * 1000)
            $readBytes = $inputStream.ReadAsync($buffer, 0, $buffer.Length, $idleCancellation.Token).GetAwaiter().GetResult()
            if ($readBytes -eq 0) { break }

            $outputStream.Write($buffer, 0, $readBytes)
            $receivedBytes += $readBytes

            if ($totalBytes -gt 0) {
                $percent = [Math]::Min(100, [int][Math]::Floor(100.0 * $receivedBytes / $totalBytes))
                if ($percent -ne $lastPercent -and ($lastUpdate.ElapsedMilliseconds -ge 200 -or $percent -eq 100)) {
                    $filled = [int][Math]::Floor($percent * 0.24)
                    $bar = ('=' * $filled) + ('.' * (24 - $filled))
                    $message = ('[{0}] {1,3}%  {2:N1}/{3:N1} MiB' -f $bar, $percent, ($receivedBytes / 1MB), ($totalBytes / 1MB))
                    Write-Host ("`r" + $message) -NoNewline
                    $progressWritten = $true
                    $lastPercent = $percent
                    $lastUpdate.Restart()
                }
            }
            elseif ($lastUpdate.ElapsedMilliseconds -ge 500) {
                Write-Host ("`rDownloaded {0:N1} MiB" -f ($receivedBytes / 1MB)) -NoNewline
                $progressWritten = $true
                $lastUpdate.Restart()
            }
        }

        $outputStream.Flush()
        if ($null -ne $totalBytes -and $receivedBytes -ne $totalBytes) {
            throw "Incomplete Vulkan Runtime download: received $receivedBytes of $totalBytes bytes."
        }
        $downloadComplete = $true
    }
    finally {
        if ($progressWritten) { Write-Host '' }
        if ($idleCancellation) { $idleCancellation.Dispose() }
        if ($outputStream) { $outputStream.Dispose() }
        if ($inputStream) { $inputStream.Dispose() }
        if ($response) { $response.Dispose() }
        if ($client) { $client.Dispose() }
        if (-not $downloadComplete -and (Test-Path -LiteralPath $OutFile)) {
            Remove-Item -LiteralPath $OutFile -Force -ErrorAction SilentlyContinue
        }
        if ($restoreSecurityProtocol) {
            [Net.ServicePointManager]::SecurityProtocol = $previousSecurityProtocol
        }
    }
}

function Get-InstallerExitStatus {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [int]$ExitCode
    )

    if ($ExitCode -eq 0) {
        return 'Success'
    }

    if ($ExitCode -eq 3010) {
        return 'SuccessRebootRequired'
    }

    return 'Failure'
}

function Get-PrimaryDisplayResolution {
    if (-not ('NativeDisplaySettings' -as [type])) {
        Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public static class NativeDisplaySettings
{
    private const int ENUM_CURRENT_SETTINGS = -1;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct DEVMODE
    {
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)] public string dmDeviceName;
        public short dmSpecVersion;
        public short dmDriverVersion;
        public short dmSize;
        public short dmDriverExtra;
        public int dmFields;
        public int dmPositionX;
        public int dmPositionY;
        public int dmDisplayOrientation;
        public int dmDisplayFixedOutput;
        public short dmColor;
        public short dmDuplex;
        public short dmYResolution;
        public short dmTTOption;
        public short dmCollate;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)] public string dmFormName;
        public short dmLogPixels;
        public int dmBitsPerPel;
        public int dmPelsWidth;
        public int dmPelsHeight;
        public int dmDisplayFlags;
        public int dmDisplayFrequency;
        public int dmICMMethod;
        public int dmICMIntent;
        public int dmMediaType;
        public int dmDitherType;
        public int dmReserved1;
        public int dmReserved2;
        public int dmPanningWidth;
        public int dmPanningHeight;
    }

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool EnumDisplaySettings(string deviceName, int modeNum, ref DEVMODE devMode);

    public static bool TryGetCurrentResolution(out int width, out int height)
    {
        DEVMODE mode = new DEVMODE();
        mode.dmDeviceName = new string(new char[32]);
        mode.dmFormName = new string(new char[32]);
        mode.dmSize = (short)Marshal.SizeOf(typeof(DEVMODE));

        if (!EnumDisplaySettings(null, ENUM_CURRENT_SETTINGS, ref mode))
        {
            width = 0;
            height = 0;
            return false;
        }

        width = mode.dmPelsWidth;
        height = mode.dmPelsHeight;
        return width > 0 && height > 0;
    }
}
"@
    }

    $width = 0
    $height = 0
    if (-not [NativeDisplaySettings]::TryGetCurrentResolution([ref]$width, [ref]$height)) {
        return $null
    }

    return [PSCustomObject]@{
        Width  = $width
        Height = $height
    }
}

function Get-SystemManagedPageFile {
    $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    if ($null -eq $computerSystem -or $null -eq $computerSystem.AutomaticManagedPagefile) {
        throw 'Windows did not provide the AutomaticManagedPagefile property.'
    }
    return [bool]$computerSystem.AutomaticManagedPagefile
}

function Get-VulkanProcesses {
    $result = [System.Collections.Generic.List[object]]::new()

    foreach ($process in Get-Process) {
        try {
            foreach ($module in $process.Modules) {
                if ($module.ModuleName -like '*vulkan*') {
                    $result.Add($process)
                    break
                }
            }
        }
        catch {
            continue
        }
    }

    return $result
}

function Get-CacheCleanupStatus {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateRange(0, [int]::MaxValue)]
        [int]$ExistingPathCount,

        [Parameter(Mandatory = $true)]
        [ValidateRange(0, [int]::MaxValue)]
        [int]$InitialItemCount,

        [Parameter(Mandatory = $true)]
        [ValidateRange(0, [int]::MaxValue)]
        [int]$RemainingItemCount,

        [Parameter(Mandatory = $true)]
        [ValidateRange(0, [int]::MaxValue)]
        [int]$ErrorCount,

        [bool]$VerificationSucceeded = $true
    )

    if (-not $VerificationSucceeded) { return 'Failed' }
    if ($ExistingPathCount -eq 0) {
        return 'Missing'
    }

    if ($InitialItemCount -eq 0) {
        if ($ErrorCount -gt 0) {
            return 'Failed'
        }

        return 'Empty'
    }

    if ($RemainingItemCount -eq 0) {
        return 'Done'
    }

    if ($RemainingItemCount -lt $InitialItemCount) {
        return 'Partial'
    }

    return 'Failed'
}

function Clear-CachePaths {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Paths,

        [string]$Filter
    )

    $existingPaths = [System.Collections.Generic.List[string]]::new()
    foreach ($path in $Paths) {
        if (Test-Path -LiteralPath $path -PathType Container) {
            $existingPaths.Add($path)
        }
    }

    if ($existingPaths.Count -eq 0) {
        return [PSCustomObject]@{
            Status             = 'Missing'
            ExistingPathCount  = 0
            InitialItemCount   = 0
            RemainingItemCount = 0
            ErrorCount         = 0
            VerificationSucceeded = $true
            Errors             = @()
            RemainingItems     = @()
        }
    }

    $errors = [System.Collections.Generic.List[string]]::new()
    $initialItemCount = 0
    $initialScanSucceeded = $true

    foreach ($path in $existingPaths) {
        try {
            if ([string]::IsNullOrWhiteSpace($Filter)) {
                $initialItemCount += @(Get-ChildItem -LiteralPath $path -Force -Recurse -ErrorAction Stop).Count
                $itemsToRemove = @(Get-ChildItem -LiteralPath $path -Force -ErrorAction Stop)
            }
            else {
                $itemsToRemove = @(Get-ChildItem -LiteralPath $path -Filter $Filter -File -Force -ErrorAction Stop)
                $initialItemCount += $itemsToRemove.Count
            }
        }
        catch {
            $initialScanSucceeded = $false
            $errors.Add("${path}: $($_.Exception.Message)")
            continue
        }

        foreach ($item in $itemsToRemove) {
            try {
                Remove-Item -LiteralPath $item.FullName -Recurse -Force -ErrorAction Stop
            }
            catch {
                $errors.Add("$($item.FullName): $($_.Exception.Message)")
            }
        }
    }

    $remainingItemCount = 0
    $remainingItems = [System.Collections.Generic.List[string]]::new()
    $verificationSucceeded = $true
    foreach ($path in $existingPaths) {
        try {
            $items = if ([string]::IsNullOrWhiteSpace($Filter)) {
                Get-ChildItem -LiteralPath $path -Force -Recurse -ErrorAction Stop
            }
            else {
                Get-ChildItem -LiteralPath $path -Filter $Filter -File -Force -ErrorAction Stop
            }
            foreach ($item in $items) {
                $remainingItemCount++
                if ($remainingItems.Count -lt 10) {
                    $kind = if ($item.PSIsContainer) { 'Directory' } else { 'File' }
                    $remainingItems.Add("${kind}: $($item.FullName)")
                }
            }
        }
        catch {
            $verificationSucceeded = $false
            $errors.Add("${path}: $($_.Exception.Message)")
        }
    }

    $verified = $verificationSucceeded -and $initialScanSucceeded
    $status = Get-CacheCleanupStatus `
        -ExistingPathCount $existingPaths.Count `
        -InitialItemCount $initialItemCount `
        -RemainingItemCount $remainingItemCount `
        -ErrorCount $errors.Count `
        -VerificationSucceeded $verified

    return [PSCustomObject]@{
        Status             = $status
        ExistingPathCount  = $existingPaths.Count
        InitialItemCount   = $initialItemCount
        RemainingItemCount = $remainingItemCount
        ErrorCount         = $errors.Count
        VerificationSucceeded = $verified
        Errors             = @($errors.ToArray())
        RemainingItems     = @($remainingItems.ToArray())
    }
}

# Format bounded diagnostics without changing cleanup behavior.
function Get-CacheCleanupDiagnosticLines {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][object]$Result,
        [ValidateRange(1, 50)][int]$MaxEntries = 10
    )

    if ($Result.Status -ne 'Failed' -and $Result.Status -ne 'Partial') { return }

    $remaining = @($Result.RemainingItems | Where-Object { $null -ne $_ })
    if ($remaining.Count -gt 0) {
        '  Remaining cache entries:'
        foreach ($entry in ($remaining | Select-Object -First $MaxEntries)) {
            "    $entry"
        }
        if ($Result.RemainingItemCount -gt [Math]::Min($MaxEntries, $remaining.Count)) {
            '    (additional entries omitted)'
        }
    }
    elseif ($Result.RemainingItemCount -gt 0) {
        '  Remaining paths could not be determined.'
    }

    $errors = @($Result.Errors | Where-Object { $null -ne $_ })
    if ($errors.Count -gt 0) {
        '  Cleanup errors:'
        foreach ($errorText in ($errors | Select-Object -First $MaxEntries)) {
            "    $errorText"
        }
        if ($Result.ErrorCount -gt $MaxEntries) {
            "    ($($Result.ErrorCount - $MaxEntries) more errors omitted)"
        }
    }
    elseif ($Result.RemainingItemCount -gt 0) {
        '  No deletion error was recorded; the remaining items were detected during verification.'
    }
}

function Write-CacheCleanupResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Result,

        [switch]$DetailedOnFailure
    )

    switch ($Result.Status) {
        'Done' {
            Write-LogMessage 'Done' -ForegroundColor Green
        }
        'Partial' {
            Write-LogMessage "Partially cleared ($($Result.RemainingItemCount) cache item(s) remain)" -ForegroundColor Yellow
        }
        'Empty' {
            Write-LogMessage 'Nothing to clear' -ForegroundColor Green
        }
        'Missing' {
            Write-LogMessage 'Nothing to clear (cache path not found)' -ForegroundColor Yellow
        }
        default {
            if ($null -ne $Result.VerificationSucceeded -and -not $Result.VerificationSucceeded) {
                Write-LogMessage 'Not Done (cache contents could not be fully verified)' -ForegroundColor Red
            }
            else {
                Write-LogMessage "Not Done ($($Result.RemainingItemCount) cache item(s) remain after cleanup)" -ForegroundColor Red
            }
        }
    }

    if ($DetailedOnFailure -and $Result.Status -in @('Partial', 'Failed')) {
        foreach ($line in @(Get-CacheCleanupDiagnosticLines -Result $Result)) {
            Write-LogMessage $line -ForegroundColor Yellow
        }
    }
}

function Set-NativeResolutionConfiguration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Configuration,

        [Parameter(Mandatory = $true)]
        [ValidateRange(1, [int]::MaxValue)]
        [int]$Width,

        [Parameter(Mandatory = $true)]
        [ValidateRange(1, [int]::MaxValue)]
        [int]$Height
    )

    if (-not $Configuration.graphics) {
        throw "The 'graphics' object does not exist in the local settings JSON."
    }

    if (-not $Configuration.graphics.windowSize) {
        throw "The 'graphics.windowSize' object does not exist in the local settings JSON."
    }

    if (-not ($Configuration.graphics.windowSize.PSObject.Properties.Name -contains 'x') -or
        -not ($Configuration.graphics.windowSize.PSObject.Properties.Name -contains 'y')) {
        throw "The 'graphics.windowSize' object does not contain both 'x' and 'y' properties."
    }

    $Configuration.graphics.windowSize.x = $Width
    $Configuration.graphics.windowSize.y = $Height
    return $Configuration
}

function Set-MinimumFovConfiguration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Configuration
    )

    if (-not $Configuration.graphics) {
        $Configuration | Add-Member -NotePropertyName 'graphics' -NotePropertyValue ([PSCustomObject]@{})
    }

    if ($Configuration.graphics.PSObject.Properties.Name -contains 'fov') {
        $Configuration.graphics.fov = '42480000'
    }
    else {
        $Configuration.graphics | Add-Member -NotePropertyName 'fov' -NotePropertyValue '42480000'
    }

    return $Configuration
}

function Get-PowerPlanGuidFromLine {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Line
    )

    $match = [regex]::Match($Line, '(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b')
    if ($match.Success) {
        return $match.Value.ToLowerInvariant()
    }

    return $null
}

function Get-ActivePowerPlanGuid {
    foreach ($line in (powercfg /getactivescheme)) {
        $guid = Get-PowerPlanGuidFromLine -Line $line
        if ($guid) {
            return $guid
        }
    }

    return $null
}

function Get-GameDvrState {
    [CmdletBinding()]
    param([AllowNull()][object]$UserValue, [AllowNull()][object]$PolicyValue)
    if ($PolicyValue -eq 0 -or $UserValue -eq 0) { return 'Off' }
    if ($PolicyValue -eq $null -and $UserValue -eq $null) { return 'Not configured' }
    return 'On'
}

function Get-PageFileAssessment {
    [CmdletBinding()]
    param(
        [AllowNull()][Nullable[bool]]$SystemManaged,
        [AllowNull()][Nullable[bool]]$OutOfMemoryFound
    )
    if ($null -eq $SystemManaged) { return 'Unknown' }
    if ($SystemManaged -and $OutOfMemoryFound -eq $true) { return 'SystemManagedWithOutOfMemory' }
    if (-not $SystemManaged -and ($OutOfMemoryFound -eq $false -or $null -eq $OutOfMemoryFound)) {
        return 'ManualWithoutOutOfMemory'
    }
    if ($SystemManaged) { return 'SystemManaged' }
    if ($OutOfMemoryFound -eq $true) { return 'ManualWithOutOfMemory' }
    return 'Unknown'
}

# Write a DWORD and verify the effective registry value.
function Set-VerifiedRegistryDword {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][int]$Value
    )
    if (-not (Test-Path -Path $Path)) {
        New-Item -Path $Path -Force -ErrorAction Stop | Out-Null
    }
    New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType DWord -Force -ErrorAction Stop | Out-Null
    $readBack = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
    if ([int]$readBack.$Name -ne $Value) {
        throw "Registry verification failed: $Path\\$Name"
    }
}

# Avoid removing a registry manifest containing both old and supported Vulkan layers.
function Test-RemoveVulkanManifest {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][object[]]$MetadataEntries)

    if ($MetadataEntries.Count -eq 0) { return $false }
    foreach ($item in $MetadataEntries) {
        $version = $null
        if (-not [version]::TryParse([string]$item.ApiVersion, [ref]$version)) { return $false }
        if (-not (Test-VulkanVersionOutdated -Version ([string]$item.ApiVersion))) { return $false }
    }
    return $true
}

function Convert-GpuDriverVersionForDisplay {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('NVIDIA', 'AMD', 'Intel')]
        [string]$Vendor,

        [Parameter(Mandatory = $true)]
        [string]$DriverVersion
    )

    if ($Vendor -eq 'NVIDIA') {
        $parts = $DriverVersion -split '\.'
        if ($parts.Count -ge 4 -and $parts[2].Length -ge 2) {
            return ($parts[2].Substring(1) + $parts[3]).Insert(3, '.')
        }
    }
    elseif ($Vendor -eq 'Intel') {
        $parts = $DriverVersion -split '\.'
        if ($parts.Count -ge 4) {
            return $parts[2..3] -join '.'
        }
    }

    return $DriverVersion
}

function Get-VulkanRegistryEntries {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [string]$VideoRegistryPath
    )

    $entries = [System.Collections.Generic.List[object]]::new()
    $seenEntries = @{}

    $implicitLayerPaths = @(
        'HKCU:\SOFTWARE\Khronos\Vulkan\ImplicitLayers',
        'HKCU:\SOFTWARE\Wow6432Node\Khronos\Vulkan\ImplicitLayers',
        'HKLM:\SOFTWARE\Khronos\Vulkan\ImplicitLayers',
        'HKLM:\SOFTWARE\WOW6432Node\Khronos\Vulkan\ImplicitLayers'
    )

    foreach ($registryPath in $implicitLayerPaths) {
        $properties = Get-ItemProperty -Path $registryPath -ErrorAction SilentlyContinue
        if (-not $properties) {
            continue
        }

        foreach ($property in $properties.PSObject.Properties) {
            if ($property.MemberType -ne 'NoteProperty' -or $property.Name -notlike '*.json') {
                continue
            }

            if ($property.Value -is [ValueType] -and [int64]$property.Value -ne 0) {
                continue
            }

            $key = '{0}|{1}' -f $registryPath, $property.Name
            if ($seenEntries.ContainsKey($key)) {
                continue
            }

            $seenEntries[$key] = $true
            $entries.Add([PSCustomObject]@{
                RegistryPath      = $registryPath
                RegistryValueName = $property.Name
                JsonPath          = $property.Name
                Architecture      = Get-VulkanArchitecture -RegistryPath $registryPath -ValueName $property.Name
                IsDisplayDriver   = $false
            })
        }
    }

    $driverRegistryPaths = @(
        'HKLM:\SOFTWARE\Khronos\Vulkan\Drivers',
        'HKLM:\SOFTWARE\WOW6432Node\Khronos\Vulkan\Drivers'
    )

    foreach ($registryPath in $driverRegistryPaths) {
        $properties = Get-ItemProperty -Path $registryPath -ErrorAction SilentlyContinue
        if (-not $properties) {
            continue
        }

        foreach ($property in $properties.PSObject.Properties) {
            if ($property.MemberType -ne 'NoteProperty' -or $property.Name -notlike '*.json') {
                continue
            }

            if ($property.Value -is [ValueType] -and [int64]$property.Value -ne 0) {
                continue
            }

            $architecture = if ($registryPath -like '*WOW6432Node*') { 'x86' } else { 'x64' }
            $key = '{0}|{1}' -f $architecture, $property.Name
            if ($seenEntries.ContainsKey($key)) {
                continue
            }

            $seenEntries[$key] = $true
            $entries.Add([PSCustomObject]@{
                RegistryPath      = $registryPath
                RegistryValueName = $property.Name
                JsonPath          = $property.Name
                Architecture      = $architecture
                IsDisplayDriver   = $true
            })
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($VideoRegistryPath)) {
        $videoProperties = Get-ItemProperty -Path $VideoRegistryPath -ErrorAction SilentlyContinue
        if ($videoProperties) {
            foreach ($property in $videoProperties.PSObject.Properties) {
                if ($property.Name -notmatch 'Vulkan' -or $property.Name -notmatch 'Driver' -or $property.Name -match 'SCD') {
                    continue
                }

                $architecture = if ($property.Name -match 'Wow') { 'x86' } else { 'x64' }
                foreach ($jsonPath in @($property.Value)) {
                    if ([string]::IsNullOrWhiteSpace([string]$jsonPath)) {
                        continue
                    }

                    $key = '{0}|{1}' -f $architecture, [string]$jsonPath
                    if ($seenEntries.ContainsKey($key)) {
                        continue
                    }

                    $seenEntries[$key] = $true
                    $entries.Add([PSCustomObject]@{
                        RegistryPath      = $VideoRegistryPath
                        RegistryValueName = $property.Name
                        JsonPath          = [string]$jsonPath
                        Architecture      = $architecture
                        IsDisplayDriver   = $true
                    })
                }
            }
        }
    }

    return $entries | Sort-Object Architecture, JsonPath
}

function Get-NormalizedVersionText {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$Value,

        [string]$Default = 'unknown'
    )

    if ($Value -is [System.Object[]]) {
        $Value = $Value | Select-Object -First 1
    }

    $text = [string]$Value
    if ([string]::IsNullOrWhiteSpace($text)) {
        return $Default
    }

    return $text
}

function Test-AvxSupported {
    if (-not ('ProcessorInfo' -as [type])) {
        Add-Type -TypeDefinition @"
using System.Runtime.InteropServices;

public static class ProcessorInfo
{
    private const uint PF_AVX_INSTRUCTIONS_AVAILABLE = 39;

    [DllImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsProcessorFeaturePresent(uint processorFeature);

    public static bool IsAVXSupported()
    {
        return IsProcessorFeaturePresent(PF_AVX_INSTRUCTIONS_AVAILABLE);
    }
}
"@
    }

    return [ProcessorInfo]::IsAVXSupported()
}

# Classify Intel desktop processors against the 13th/14th Gen Vmin Shift list.
function Get-IntelVminProcessorClassification {
    [CmdletBinding()]
    param(
        [string]$ProcessorName,
        [string]$Manufacturer
    )

    $isIntel = ($Manufacturer -match '^(GenuineIntel|Intel)$') -or ($ProcessorName -match '\bIntel\b')
    if (-not $isIntel) {
        return [PSCustomObject]@{ Category = 'NotIntel'; Model = $null }
    }

    $match = [regex]::Match($ProcessorName, '(?i)\bi(?<tier>[3579])-(?<number>1[34][0-9]{3})(?<suffix>[a-z0-9]*)\b')
    if (-not $match.Success) {
        $category = if ($ProcessorName -match '(?i)\b(?:13th|14th)\s+Gen\b') { 'Review' } else { 'NotApplicable' }
        return [PSCustomObject]@{ Category = $category; Model = $null }
    }

    $tier = $match.Groups['tier'].Value
    $number = $match.Groups['number'].Value
    $suffix = $match.Groups['suffix'].Value.ToUpperInvariant()
    $model = 'i{0}-{1}{2}' -f $tier, $number, $suffix

    if ($suffix -match '^(HX|HK|H|U|P|Y|G[0-9]*)$') {
        return [PSCustomObject]@{ Category = 'NotApplicable'; Model = $model }
    }

    $affected = (
        (($tier -eq '9') -and ($number -in @('13900', '14900')) -and ($suffix -in @('', 'F', 'K', 'KF', 'KS'))) -or
        (($tier -eq '7') -and ($number -in @('13700', '14700')) -and ($suffix -in @('', 'F', 'K', 'KF'))) -or
        (($tier -eq '7') -and ($number -in @('13790', '14790')) -and ($suffix -eq 'F')) -or
        (($tier -eq '5') -and ($number -in @('13600', '14600')) -and ($suffix -in @('K', 'KF')))
    )

    if ($affected) {
        return [PSCustomObject]@{ Category = 'Affected'; Model = $model }
    }

    if ($tier -eq '3' -or (($tier -eq '5') -and ($suffix -notmatch '^K'))) {
        return [PSCustomObject]@{ Category = 'NotApplicable'; Model = $model }
    }

    return [PSCustomObject]@{ Category = 'Review'; Model = $model }
}

# Decode documented Windows REG_BINARY CPU microcode revision layouts.
function ConvertFrom-IntelMicrocodeBytes {
    [CmdletBinding()]
    param([AllowNull()][byte[]]$Bytes)

    if ($null -eq $Bytes -or $Bytes.Length -notin @(4, 8)) { return $null }

    $first = [BitConverter]::ToUInt32($Bytes, 0)
    if ($Bytes.Length -eq 4) {
        if ($first -eq 0) { return $null }
        return $first
    }

    $second = [BitConverter]::ToUInt32($Bytes, 4)
    if ($first -eq 0 -and $second -ne 0) { return $second }
    if ($second -eq 0 -and $first -ne 0) { return $first }
    if ($first -ne 0 -and $first -eq $second) { return $first }
    return $null
}

# Read the active CPU microcode revision without modifying hardware or Windows.
function Get-IntelMicrocodeRevision {
    [CmdletBinding()]
    param()

    try {
        $cpuKey = 'HKLM:\HARDWARE\DESCRIPTION\System\CentralProcessor\0'
        $value = (Get-ItemProperty -LiteralPath $cpuKey -Name 'Update Revision' -ErrorAction Stop).'Update Revision'
        if ($value -isnot [byte[]]) { return $null }
        return ConvertFrom-IntelMicrocodeBytes -Bytes $value
    }
    catch {
        return $null
    }
}

# Evaluate only the active microcode revision; BIOS contents are not inferred.
function Get-IntelVminAssessment {
    [CmdletBinding()]
    param(
        [string]$ProcessorName,
        [string]$Manufacturer,
        [AllowNull()][Nullable[uint32]]$MicrocodeRevision
    )

    $classification = Get-IntelVminProcessorClassification -ProcessorName $ProcessorName -Manufacturer $Manufacturer
    $status = $classification.Category
    if ($status -eq 'Affected') {
        if ($null -eq $MicrocodeRevision -or $MicrocodeRevision -eq 0) {
            $status = 'UnknownRevision'
        }
        elseif ($MicrocodeRevision -lt [uint32]0x12F) {
            $status = 'UpdateRecommended'
        }
        else {
            $status = 'RecommendedRevisionLoaded'
        }
    }

    return [PSCustomObject]@{
        Category         = $classification.Category
        Model            = $classification.Model
        Status           = $status
        MicrocodeRevision = $MicrocodeRevision
        MinimumRevision  = [uint32]0x12F
    }
}

# Display a read-only microcode warning for potentially affected Intel CPUs.
function Write-IntelVminAssessment {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][object]$Assessment,
        [AllowNull()][object]$Bios,
        [AllowNull()][object]$BaseBoard
    )

    if ($Assessment.Category -in @('NotIntel', 'NotApplicable')) { return }

    Write-LogMessage ''
    Write-LogMessage '================ INTEL CPU MICROCODE CHECK ================' -ForegroundColor Yellow
    $modelName = if ($Assessment.Model) { $Assessment.Model } else { 'Unknown 13th/14th Gen Intel model' }
    Write-LogMessage "CPU model: $modelName"

    if ($null -ne $Assessment.MicrocodeRevision -and $Assessment.MicrocodeRevision -ne 0) {
        Write-LogMessage ('Active microcode revision: 0x{0:X}' -f [uint32]$Assessment.MicrocodeRevision)
    }
    else {
        Write-LogMessage 'Active microcode revision: Unknown' -ForegroundColor Yellow
    }

    if ($BaseBoard) {
        Write-LogMessage ('Motherboard: {0} {1}' -f [string]$BaseBoard.Manufacturer, [string]$BaseBoard.Product)
    }
    if ($Bios) {
        Write-LogMessage ('BIOS version: {0}' -f [string]$Bios.SMBIOSBIOSVersion)
    }

    switch ($Assessment.Status) {
        'UpdateRecommended' {
            Write-LogMessage 'WARNING: This Intel processor is on the published Vmin Shift list.' -ForegroundColor Red
            Write-LogMessage 'The active microcode is older than Intel recommendation 0x12F.' -ForegroundColor Red
            Write-LogMessage 'Check for the latest BIOS from your motherboard or system manufacturer.' -ForegroundColor Yellow
        }
        'UnknownRevision' {
            Write-LogMessage 'WARNING: This Intel processor is on the published Vmin Shift list.' -ForegroundColor Red
            Write-LogMessage 'The active microcode revision could not be verified.' -ForegroundColor Yellow
            Write-LogMessage 'Check your latest BIOS and microcode version with the manufacturer.' -ForegroundColor Yellow
        }
        'RecommendedRevisionLoaded' {
            Write-LogMessage 'Active microcode meets the Intel 0x12F minimum recommendation.' -ForegroundColor Green
            Write-LogMessage 'This does not establish that the BIOS itself is current.' -ForegroundColor Yellow
        }
        'Review' {
            Write-LogMessage 'This 13th/14th Gen Intel model could not be confidently classified.' -ForegroundColor Yellow
            Write-LogMessage 'Review its applicability and BIOS updates with the manufacturer.' -ForegroundColor Yellow
        }
    }

    Write-LogMessage 'BIOS microcode contents and Intel Default Settings cannot be verified here.' -ForegroundColor Yellow
    Write-LogMessage 'Enable Intel Default Settings and follow your system vendor BIOS guidance.' -ForegroundColor Yellow
    Write-LogMessage 'This tool will never install or modify BIOS firmware.' -ForegroundColor Yellow
    Write-LogMessage 'Intel guidance: https://www.intel.com/content/www/us/en/support/articles/000102331/processors.html' -ForegroundColor Cyan
    Write-LogMessage '===========================================================' -ForegroundColor Yellow
}

# Check Vulkan Runtime independently so failed downloads cannot skip game optimizations.
function Invoke-VulkanRuntimeUpdate {
    $manifestUrl = 'https://vulkan.lunarg.com/sdk/files.json'
    $tempManifestPath = Join-Path -Path $env:TEMP -ChildPath ('enshrouded-lunarg-{0}.json' -f [Guid]::NewGuid().ToString('N'))

    try {
        Write-LogMessage 'Fetching Vulkan Runtime version manifest (30-second timeout)...'
        Invoke-DownloadFile -Uri $manifestUrl -OutFile $tempManifestPath
    }
    catch {
        Write-LogMessage "Failed to download json file: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    try {
        $manifest = Read-GameJson -Path $tempManifestPath
        $latestRuntime = Get-LatestVulkanRuntimeInfo -Manifest $manifest
    }
    catch {
        Write-LogMessage "Failed to parse JSON: $($_.Exception.Message)" -ForegroundColor Red
        Remove-Item -LiteralPath $tempManifestPath -Force -ErrorAction SilentlyContinue
        return
    }
    finally {
        Remove-Item -LiteralPath $tempManifestPath -Force -ErrorAction SilentlyContinue
    }

    if (-not $latestRuntime) {
        Write-LogMessage 'Could not find version (windows) with Runtime file.' -ForegroundColor Red
        return
    }

    $latestRuntimeVersion = $latestRuntime.Version
    $runtimeDownloadUrl = "https://sdk.lunarg.com/sdk/download/$latestRuntimeVersion/windows/$($latestRuntime.FileName)"

    Write-LogMessage 'Latest Vulkan Runtime version: ' -NoNewline
    Write-LogMessage $latestRuntimeVersion -ForegroundColor Green

    $vulkanDllPath = Join-Path -Path $env:SystemRoot -ChildPath 'System32\vulkan-1.dll'
    $currentRuntimeVersion = if (Test-Path -LiteralPath $vulkanDllPath) {
        [System.Diagnostics.FileVersionInfo]::GetVersionInfo($vulkanDllPath).FileVersion
    }
    else {
        '0.0.0.0'
    }
    Write-LogMessage 'Installed Vulkan Runtime version: ' -NoNewline
    Write-LogMessage $currentRuntimeVersion -ForegroundColor Green
    Write-LogMessage ''

    if ([version]$currentRuntimeVersion -lt [version]$latestRuntimeVersion) {
        Write-LogMessage 'Downloading the latest Vulkan Runtime...'
        Write-LogMessage ''
        $runtimeInstallerPath = Join-Path -Path $env:TEMP -ChildPath ('enshrouded-runtime-{0}.exe' -f [Guid]::NewGuid().ToString('N'))
        $installerSucceeded = $false

        try {
            Invoke-DownloadFileWithProgress -Uri $runtimeDownloadUrl -OutFile $runtimeInstallerPath

            if (-not (Test-FileSha256 -Path $runtimeInstallerPath -ExpectedHash $latestRuntime.Sha256)) {
                Write-LogMessage 'Downloaded Vulkan Runtime failed SHA-256 verification. Installation aborted.' -ForegroundColor Red
                return
            }

            Write-LogMessage 'Vulkan Runtime SHA-256 verification: ' -NoNewline
            Write-LogMessage 'Passed' -ForegroundColor Green

            $signature = Get-AuthenticodeSignature -FilePath $runtimeInstallerPath
            if ($signature.Status -eq 'Valid') {
                Write-LogMessage 'Vulkan Runtime Authenticode signature: ' -NoNewline
                Write-LogMessage 'Valid' -ForegroundColor Green
            }
            else {
                Write-LogMessage "Vulkan Runtime Authenticode signature verification failed: $($signature.Status). Installation aborted." -ForegroundColor Red
                return
            }

            Write-LogMessage ''
            $vulkanFiles = @(
                "$env:SystemRoot\System32\vulkan-1.dll",
                "$env:SystemRoot\System32\vulkaninfo.exe",
                "$env:SystemRoot\System32\vulkan-1-999-0-0-0.dll",
                "$env:SystemRoot\System32\vulkaninfo-1-999-0-0-0.exe",
                "$env:SystemRoot\SysWOW64\vulkan-1.dll",
                "$env:SystemRoot\SysWOW64\vulkaninfo.exe",
                "$env:SystemRoot\SysWOW64\vulkan-1-999-0-0-0.dll",
                "$env:SystemRoot\SysWOW64\vulkaninfo-1-999-0-0-0.exe"
            )

            $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
            $unlockedMessagePrinted = $false

            foreach ($vulkanFile in $vulkanFiles) {
                if (-not (Test-Path -LiteralPath $vulkanFile)) {
                    Write-LogMessage "File $vulkanFile does not exist." -ForegroundColor Yellow
                    Write-LogMessage ''
                    continue
                }

                try {
                    $fileOwner = (Get-Acl -LiteralPath $vulkanFile).Owner
                    if ($fileOwner -eq 'NT AUTHORITY\SYSTEM' -or $fileOwner -eq 'NT SERVICE\TrustedInstaller') {
                        & takeown /F $vulkanFile > $null
                        if ($LASTEXITCODE -ne 0) { throw "takeown failed with code $LASTEXITCODE" }
                        & icacls $vulkanFile /grant:r "$($currentUser):(F)" > $null
                        if ($LASTEXITCODE -ne 0) { throw "icacls failed with code $LASTEXITCODE" }
                    }
                    elseif (-not $unlockedMessagePrinted) {
                        Write-LogMessage 'Vulkan Runtime file ownership does not require adjustment.' -ForegroundColor Green
                        Write-LogMessage ''
                        $unlockedMessagePrinted = $true
                    }
                }
                catch {
                    Write-LogMessage "An error occurred while processing $vulkanFile" -ForegroundColor Red
                    Write-LogMessage ''
                }
            }


            Write-LogMessage 'Installing the latest Vulkan Runtime...'
            Write-LogMessage ''
            $installerProcess = Start-Process -FilePath $runtimeInstallerPath -ArgumentList '/auto' -Wait -PassThru -ErrorAction Stop
            $installerStatus = Get-InstallerExitStatus -ExitCode $installerProcess.ExitCode

            if ($installerStatus -eq 'Failure') {
                Write-LogMessage "Vulkan Runtime installer failed with exit code $($installerProcess.ExitCode)." -ForegroundColor Red
                return
            }

            if ($installerStatus -eq 'SuccessRebootRequired') {
                Write-LogMessage 'Vulkan Runtime installer completed and requested a reboot.' -ForegroundColor Yellow
            }

            $installerSucceeded = $true
        }
        catch {
            Write-LogMessage "Failed to install Vulkan Runtime: $($_.Exception.Message)" -ForegroundColor Red
            return
        }
        finally {
            Remove-Item -LiteralPath $runtimeInstallerPath -Force -ErrorAction SilentlyContinue
        }

        if ($installerSucceeded) {
            Write-LogMessage 'Installation complete, checking Vulkan Runtime versions...'
            Write-LogMessage ''
            $currentRuntimeVersion = if (Test-Path -LiteralPath $vulkanDllPath) {
                [System.Diagnostics.FileVersionInfo]::GetVersionInfo($vulkanDllPath).FileVersion
            }
            else {
                '0.0.0.0'
            }
            Write-LogMessage 'Latest Vulkan Runtime version: ' -NoNewline
            Write-LogMessage $latestRuntimeVersion -ForegroundColor Green
            Write-LogMessage 'Installed Vulkan Runtime version: ' -NoNewline
            if ([version]$currentRuntimeVersion -ge [version]$latestRuntimeVersion) {
                Write-LogMessage $currentRuntimeVersion -ForegroundColor Green
            }
            else {
                Write-LogMessage $currentRuntimeVersion -ForegroundColor Red
                Write-LogMessage 'Vulkan Runtime installation finished, but the installed loader version is still older than expected.' -ForegroundColor Red
            }
            Write-LogMessage ''
        }
    }

}

function Invoke-EnshroudedToolFix {
    $Host.UI.RawUI.WindowTitle = "Enshrouded Tool Fix v$script:ToolVersion"

    if (Test-Path -LiteralPath $script:LogFilePath) {
        Remove-Item -LiteralPath $script:LogFilePath -Force
    }

    # Checking whether the script is running with administrator rights
    if (-not (Test-IsAdministrator)) {
        Write-LogMessage 'This script must be run as an administrator.' -ForegroundColor Yellow
        Write-LogMessage ''
        Write-LogMessage 'Press Enter to close the console...'
        [Console]::ReadLine() | Out-Null
        return
    }

    Write-LogMessage "Script version: $script:ToolVersion"
    Write-LogMessage "Hostname: $env:COMPUTERNAME" -ForegroundColor Green
    Write-LogMessage 'Script is running as an administrator. Proceeding with the work...' -ForegroundColor Green
    Write-LogMessage ''

    # Finding the path to the installed game folder on Steam
    $steamPath = Get-SteamInstallPath
    if ([string]::IsNullOrWhiteSpace($steamPath)) {
        Write-LogMessage 'Steam is not installed. Further operation of the script is impossible.' -ForegroundColor Red
        Write-LogMessage ''
        Read-Host -Prompt 'Press Enter to Exit' | Out-Null
        return
    }

    $gameInstallation = Find-SteamAppInstallation -SteamPath $steamPath -AppId $script:GameId -ExecutableName 'enshrouded.exe'
    if (-not $gameInstallation) {
        Write-LogMessage "Enshrouded (Steam AppID $($script:GameId)) was not found in any configured Steam library." -ForegroundColor Red
        Write-LogMessage 'The script checks Steam library manifests directly; launching the game first is not required.' -ForegroundColor Yellow
        Write-LogMessage ''
        Read-Host -Prompt 'Press Enter to Exit' | Out-Null
        return
    }

    $gameDirectory = $gameInstallation.GameDirectory
    $gameExecutablePath = $gameInstallation.ExecutablePath

    Write-LogMessage "Found installed game in: $gameDirectory"
    Write-LogMessage ''

    # Checking Vulkan API layer versions for old versions
    $videoRegistryPath = Get-PrimaryVideoRegistryPath
    $vulkanEntries = @(Get-VulkanRegistryEntries -VideoRegistryPath $videoRegistryPath)

    Write-LogMessage 'Checking Vulkan layer API versions...'

    foreach ($entry in $vulkanEntries) {
        $metadataEntries = @()
        try {
            $metadataEntries = @(Get-VulkanLayerMetadata -JsonPath $entry.JsonPath -Architecture $entry.Architecture)
        }
        catch {
            Write-LogMessage "Failed to parse Vulkan JSON: $($entry.JsonPath)" -ForegroundColor Red
            continue
        }

        if ($metadataEntries.Count -eq 0) {
            Write-LogMessage "File $($entry.JsonPath) not found or contains no supported Vulkan metadata." -ForegroundColor Red
            continue
        }

        $removeWholeManifest = (-not $entry.IsDisplayDriver) -and (Test-RemoveVulkanManifest -MetadataEntries $metadataEntries)
        $containsOldLayer = $false
        foreach ($metadata in $metadataEntries) {
            $apiVersion = Get-NormalizedVersionText -Value $metadata.ApiVersion
            $description = if ([string]::IsNullOrWhiteSpace([string]$metadata.Description)) { 'Layer name is empty' } else { [string]$metadata.Description }

            if (-not $entry.IsDisplayDriver -and -not [string]::IsNullOrWhiteSpace([string]$metadata.Description) -and -not (Test-VulkanVersionOutdated -Version $apiVersion)) {
                Write-LogMessage "$description $($entry.Architecture)" -NoNewline
                Write-LogMessage " (v$apiVersion)" -ForegroundColor Green
            }

            if (-not (Test-VulkanVersionOutdated -Version $apiVersion)) {
                continue
            }

            if (-not $entry.IsDisplayDriver) {
                Write-LogMessage "$description $($entry.Architecture)" -NoNewline -ForegroundColor Red
                $containsOldLayer = $true
                if (-not $removeWholeManifest) {
                    Write-LogMessage " (v$apiVersion) - mixed or unverifiable manifest; registry entry preserved" -ForegroundColor Yellow
                }
                else {
                    Write-LogMessage " (v$apiVersion) - outdated manifest will be removed" -ForegroundColor Yellow
                }
                continue
            }

            $libraryPath = [string]$metadata.LibraryPath
            $isIntelDriver = ($entry.Architecture -eq 'x86' -and $libraryPath -like '*igvk32.dll*') -or
                             ($entry.Architecture -eq 'x64' -and $libraryPath -like '*igvk64.dll*')
            if (-not $isIntelDriver) {
                Write-LogMessage "$description $($entry.Architecture) (v$apiVersion) - The Vulkan API driver is out of date, please update your video driver." -ForegroundColor Red
            }
        }
        if ($containsOldLayer -and $removeWholeManifest) {
            try {
                Remove-ItemProperty -Path $entry.RegistryPath -Name $entry.RegistryValueName -ErrorAction Stop
                Write-LogMessage "Removed outdated Vulkan manifest registration: $($entry.RegistryValueName)" -ForegroundColor Green
            }
            catch {
                Write-LogMessage "Failed to remove Vulkan manifest registration: $($_.Exception.Message)" -ForegroundColor Red
            }
        }
    }

    # Checking Vulkan API Versions
    Write-LogMessage ''
    $folderCache = Get-ShaderCachePath -GameDirectory $gameDirectory -AppId $script:GameId
    Write-LogMessage 'Checking Vulkan Runtime versions...'
    Write-LogMessage ''

    try {
        Invoke-VulkanRuntimeUpdate
    }
    catch {
        Write-LogMessage "Vulkan Runtime check failed; continuing with other optimizations: $($_.Exception.Message)" -ForegroundColor Red
    }

    # Finding processes using the Vulkan API
    Write-LogMessage 'Looking for running processes using Vulkan...'
    $vulkanProcesses = @(Get-VulkanProcesses)
    if ($vulkanProcesses.Count -eq 0) {
        Write-LogMessage 'Processes using Vulkan were not found.' -ForegroundColor Green
        Write-LogMessage ''
    }
    else {
        $vulkanProcesses | Select-Object ProcessName, Id, Path | Out-Host
    }

    # Clearing the cache of DirectX
    $directXCachePath = Join-Path -Path $env:LOCALAPPDATA -ChildPath 'D3DSCache'
    if (Test-Path -LiteralPath $directXCachePath) {
        Write-LogMessage 'Clearing DirectX cache: ' -NoNewline
        $cacheResult = Clear-CachePaths -Paths @($directXCachePath)
        Write-CacheCleanupResult -Result $cacheResult
    }

    # Clearing the cache of nVidia video cards
    $nvidiaCachePaths = @(
        "$env:LOCALAPPDATA\NVIDIA\GLCache",
        "$env:LOCALAPPDATA\NVIDIA\DXCache",
        "$env:LOCALAPPDATA\NVIDIA Corporation\NV_Cache",
        "$env:ProgramData\NVIDIA Corporation\NV_Cache"
    )
    if (@($nvidiaCachePaths | Where-Object { Test-Path -LiteralPath $_ }).Count -gt 0) {
        Write-LogMessage 'Clearing nVidia GPU cache: ' -NoNewline
        $cacheResult = Clear-CachePaths -Paths $nvidiaCachePaths
        Write-CacheCleanupResult -Result $cacheResult -DetailedOnFailure
    }

    # Clearing the cache of AMD video cards
    $amdCachePaths = @(
        "$env:LOCALAPPDATA\AMD\GLCache",
        "$env:LOCALAPPDATA\AMD\DxCache",
        "$env:LOCALAPPDATA\AMD\DxcCache",
        "$env:LOCALAPPDATA\AMD\Dx9Cache",
        "$env:LOCALAPPDATA\AMD\VkCache"
    )
    if (@($amdCachePaths | Where-Object { Test-Path -LiteralPath $_ }).Count -gt 0) {
        Write-LogMessage 'Clearing AMD GPU cache: ' -NoNewline
        $cacheResult = Clear-CachePaths -Paths $amdCachePaths
        Write-CacheCleanupResult -Result $cacheResult
    }

    # Clearing the cache of INTEL video cards
    $intelRoot = Join-Path -Path $env:USERPROFILE -ChildPath 'appdata\locallow\Intel'
    $intelCachePaths = @((Join-Path -Path $intelRoot -ChildPath 'ShaderCache'))
    if (@($intelCachePaths | Where-Object { Test-Path -LiteralPath $_ }).Count -gt 0) {
        Write-LogMessage 'Clearing INTEL GPU cache: ' -NoNewline
        $cacheResult = Clear-CachePaths -Paths $intelCachePaths
        Write-CacheCleanupResult -Result $cacheResult
    }

    # Clearing the cache in the Steam directory and LocalAppData
    Write-LogMessage "Clearing game shader cache in $folderCache\: " -NoNewline
    $cacheResult = Clear-CachePaths -Paths @($folderCache)
    Write-CacheCleanupResult -Result $cacheResult

    $gameCachePath = Join-Path -Path $env:LOCALAPPDATA -ChildPath 'enshrouded\caches'
    Write-LogMessage "Clearing game shader cache in $gameCachePath\: " -NoNewline
    $cacheResult = Clear-CachePaths -Paths @($gameCachePath) -Filter '*.bin'
    Write-CacheCleanupResult -Result $cacheResult

    Write-LogMessage ''
    Write-LogMessage 'After starting the game, it will start recompiling shaders after entering your world, shader compilation will continue (this will take some time ~10 min), you can observe the progress at the bottom of the menu by pressing ESC' -ForegroundColor Yellow

    # Update native resolution in current settings, with a legacy fallback.
    Write-LogMessage ''
    try {
        $configurationPaths = Resolve-GameConfigurationPaths -GameDirectory $gameDirectory
    }
    catch {
        Write-LogMessage "Unable to locate game configuration files: $($_.Exception.Message)" -ForegroundColor Red
        $configurationPaths = [PSCustomObject]@{ LocalPath = $null; UserPath = $null }
    }
    $localConfigPath = $configurationPaths.LocalPath
    Write-LogMessage 'Set the native resolution for the game: ' -NoNewline
    if ($localConfigPath) {
        try {
            $primaryResolution = Get-PrimaryDisplayResolution
            if (-not $primaryResolution) { throw 'Primary monitor was not found.' }
            $configuration = Read-GameJson -Path $localConfigPath
            $configuration = Set-NativeResolutionConfiguration -Configuration $configuration -Width $primaryResolution.Width -Height $primaryResolution.Height
            Save-FormattedJson -InputObject $configuration -Path $localConfigPath
            Write-LogMessage "Done ($($primaryResolution.Width)x$($primaryResolution.Height)) [$localConfigPath]" -ForegroundColor Green
        }
        catch {
            Write-LogMessage "Not Done ($($_.Exception.Message))" -ForegroundColor Red
        }
    }
    else {
        Write-LogMessage 'Not Done (local_settings.json and legacy enshrouded_local.json not found)' -ForegroundColor Yellow
    }

    # Update minimum FOV in the current user settings, with a legacy fallback.
    Write-LogMessage ''
    $userConfigPath = $configurationPaths.UserPath
    Write-LogMessage 'Set the minimum FOV in the game: ' -NoNewline
    if ($userConfigPath) {
        try {
            $configuration = Read-GameJson -Path $userConfigPath
            $configuration = Set-MinimumFovConfiguration -Configuration $configuration
            Save-FormattedJson -InputObject $configuration -Path $userConfigPath
            Write-LogMessage "Done [$userConfigPath]" -ForegroundColor Green
            Write-LogMessage 'In the future, you can increase the FOV in the game settings if it stops crashing.' -ForegroundColor Yellow
        }
        catch {
            Write-LogMessage "Not Done ($($_.Exception.Message))" -ForegroundColor Red
        }
    }
    else {
        Write-LogMessage 'Not Done (migrated and legacy enshrouded_user.json not found)' -ForegroundColor Yellow
    }

    # Apply the normal process priority and verify the registry write.
    $priorityRegistryPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\enshrouded.exe\PerfOptions'
    Write-LogMessage "Set the priority of the enshrouded.exe file to 'Normal' when starting: " -NoNewline
    try {
        Set-VerifiedRegistryDword -Path $priorityRegistryPath -Name 'CpuPriorityClass' -Value 2
        Write-LogMessage 'Done' -ForegroundColor Green
    }
    catch {
        Write-LogMessage "Not Done ($($_.Exception.Message))" -ForegroundColor Red
    }
    Write-LogMessage ''

    # Set Powerplan
    $powerPlanGuids = @{
        'High performance' = '8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c'
        'Balanced'         = '381b4222-f694-41f0-9685-ff5bb260df2e'
        'Power saver'      = 'a1841308-3541-4fab-bc81-f71556f20b4a'
    }
    $activePowerPlanGuid = Get-ActivePowerPlanGuid
    Write-LogMessage "Changing the power saving scheme to 'High Performance': " -NoNewline
    if ($activePowerPlanGuid -eq $powerPlanGuids['Balanced'] -or $activePowerPlanGuid -eq $powerPlanGuids['Power saver']) {
        & powercfg /S $powerPlanGuids['High performance'] | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-LogMessage 'Done' -ForegroundColor Green
        }
        else {
            Write-LogMessage "Not Done (powercfg exit code $LASTEXITCODE)" -ForegroundColor Red
        }
    }
    else {
        $powerScheme = Get-CimInstance -Namespace root\cimv2\power -ClassName Win32_PowerPlan -Filter "IsActive='true'" -ErrorAction SilentlyContinue
        if (-not $activePowerPlanGuid) {
            Write-LogMessage 'Unable to determine the active power plan.' -ForegroundColor Yellow
        }
        elseif ($activePowerPlanGuid -eq $powerPlanGuids['High performance']) {
            Write-LogMessage 'The High Performance scheme is already active - ' -ForegroundColor Yellow -NoNewline
        }
        else {
            Write-LogMessage 'The scheme has not been changed because a custom/non-default scheme is active - ' -ForegroundColor Yellow -NoNewline
        }
        if ($activePowerPlanGuid) {
            Write-LogMessage $(if ($powerScheme) { $powerScheme.ElementName } else { $activePowerPlanGuid }) -ForegroundColor Yellow
        }
    }

    # Apply performance-related DWORDs and verify the resulting values.
    Write-LogMessage ''
    $performanceSystemPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile'
    Write-LogMessage 'Improve input responsiveness and network throughput: ' -NoNewline
    try {
        Set-VerifiedRegistryDword -Path $performanceSystemPath -Name 'NetworkThrottlingIndex' -Value 20
        Set-VerifiedRegistryDword -Path $performanceSystemPath -Name 'SystemResponsiveness' -Value 10
        Write-LogMessage 'Done' -ForegroundColor Green
    }
    catch {
        Write-LogMessage "Not Done ($($_.Exception.Message))" -ForegroundColor Red
    }

    # Enable Windows Game Mode only if it is not enabled already.
    $gameModeRegistryPath = 'HKCU:\Software\Microsoft\GameBar'
    $gameModeValue = (Get-ItemProperty -Path $gameModeRegistryPath -Name 'AutoGameModeEnabled' -ErrorAction SilentlyContinue).AutoGameModeEnabled
    Write-LogMessage ''
    Write-LogMessage 'Game Mode: ' -NoNewline
    if ($gameModeValue -eq 1) {
        Write-LogMessage 'ALREADY ENABLED' -ForegroundColor Green
    }
    else {
        try {
            Set-VerifiedRegistryDword -Path $gameModeRegistryPath -Name 'AutoGameModeEnabled' -Value 1
            Write-LogMessage 'ENABLED (reboot may be required)' -ForegroundColor Green
        }
        catch {
            Write-LogMessage "Not Done ($($_.Exception.Message))" -ForegroundColor Red
        }
    }

    # Set the user GameDVR preference and machine policy as requested.
    $gameDvrUserPath = 'HKCU:\System\GameConfigStore'
    $gameDvrPolicyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR'
    $gameDvrEnabled = (Get-ItemProperty -Path $gameDvrUserPath -Name 'GameDVR_Enabled' -ErrorAction SilentlyContinue).GameDVR_Enabled
    $gameDvrPolicy = (Get-ItemProperty -Path $gameDvrPolicyPath -Name 'AllowGameDVR' -ErrorAction SilentlyContinue).AllowGameDVR
    $gameDvrState = Get-GameDvrState -UserValue $gameDvrEnabled -PolicyValue $gameDvrPolicy

    Write-LogMessage ''
    Write-LogMessage 'GameDVR can affect performance; disable it if screen recording is unnecessary.' -ForegroundColor Yellow
    Write-LogMessage "GameDVR registry configuration: $gameDvrState" -ForegroundColor Green
    $question = if ($gameDvrState -eq 'Off') { 'Want to enable GameDVR? (Y - Yes / Any - No)' } else { 'Want to disable GameDVR? (Y - Yes / Any - No)' }
    if ((Read-Host $question) -eq 'Y') {
        $targetValue = if ($gameDvrState -eq 'Off') { 1 } else { 0 }
        try {
            Set-VerifiedRegistryDword -Path $gameDvrUserPath -Name 'GameDVR_Enabled' -Value $targetValue
            Set-VerifiedRegistryDword -Path $gameDvrPolicyPath -Name 'AllowGameDVR' -Value $targetValue
            $actualUser = (Get-ItemProperty -Path $gameDvrUserPath -Name 'GameDVR_Enabled' -ErrorAction Stop).GameDVR_Enabled
            $actualPolicy = (Get-ItemProperty -Path $gameDvrPolicyPath -Name 'AllowGameDVR' -ErrorAction Stop).AllowGameDVR
            Write-LogMessage "GameDVR registry configuration: $(Get-GameDvrState -UserValue $actualUser -PolicyValue $actualPolicy)" -ForegroundColor Green
        }
        catch {
            Write-LogMessage "Failed to change GameDVR registry configuration: $($_.Exception.Message)" -ForegroundColor Red
        }
    }

    # Check CPU instruction support and Intel 13th/14th Gen microcode status.
    Write-LogMessage ''
    Write-LogMessage 'CPU Info...'
    $processor = Get-CimInstance -ClassName Win32_Processor -ErrorAction SilentlyContinue | Select-Object -First 1
    $processorName = if ($processor) { [string]$processor.Name } else { 'Unknown' }
    Write-LogMessage "Name CPU: $processorName"
    Write-LogMessage 'AVX support: ' -NoNewline
    if (Test-AvxSupported) {
        Write-LogMessage 'Yes' -ForegroundColor Green
    }
    else {
        Write-LogMessage 'No' -ForegroundColor Red
        Write-LogMessage ''
        Write-LogMessage 'Unfortunately, your processor does not support the AVX instruction set, the game will not be able to start without this set.' -ForegroundColor Red
    }

    $intelCategory = Get-IntelVminProcessorClassification -ProcessorName $processorName -Manufacturer ([string]$processor.Manufacturer)
    if ($intelCategory.Category -in @('Affected', 'Review')) {
        $intelRevision = Get-IntelMicrocodeRevision
        $intelAssessment = Get-IntelVminAssessment -ProcessorName $processorName -Manufacturer ([string]$processor.Manufacturer) -MicrocodeRevision $intelRevision
        $bios = Get-CimInstance -ClassName Win32_BIOS -ErrorAction SilentlyContinue | Select-Object -First 1
        $baseBoard = Get-CimInstance -ClassName Win32_BaseBoard -ErrorAction SilentlyContinue | Select-Object -First 1
        Write-IntelVminAssessment -Assessment $intelAssessment -Bios $bios -BaseBoard $baseBoard
    }

    # Checking the parameters of the paging file
    $gameLogPath = Join-Path -Path $gameDirectory -ChildPath 'enshrouded.log'
    $outOfMemoryFound = $null
    if (Test-Path -LiteralPath $gameLogPath) {
        $gameLogContent = Get-Content -LiteralPath $gameLogPath
        $outOfMemoryFound = [bool]($gameLogContent -like '*Could not allocate new memory block, error: out of memory*')
    }

    Write-LogMessage ''
    try {
        $systemManagedPaging = Get-SystemManagedPageFile
    }
    catch {
        Write-LogMessage "Unable to determine automatic paging file management: $($_.Exception.Message)" -ForegroundColor Red
        $systemManagedPaging = $null
    }
    $pageFileAssessment = Get-PageFileAssessment -SystemManaged $systemManagedPaging -OutOfMemoryFound $outOfMemoryFound

    switch ($pageFileAssessment) {
        'Unknown' {
            Write-LogMessage 'Auto-selection of the paging file size: Unknown' -ForegroundColor Yellow
        }
        'SystemManagedWithOutOfMemory' {
            Write-LogMessage 'Auto-selection of the paging file size: ' -NoNewline
            Write-LogMessage 'Yes' -ForegroundColor Green
            Write-LogMessage "The message 'Out of memory' was found in the log file." -ForegroundColor Yellow
        }
        'ManualWithoutOutOfMemory' {
            Write-LogMessage 'Auto-selection of the paging file size: ' -NoNewline
            Write-LogMessage 'No' -ForegroundColor Yellow
            Write-LogMessage "The message 'Out of memory' was not found in the log file." -ForegroundColor Yellow
        }
        'SystemManaged' {
            Write-LogMessage 'Auto-selection of the paging file size: ' -NoNewline
            Write-LogMessage 'Yes' -ForegroundColor Green
        }
        'ManualWithOutOfMemory' {
            Write-LogMessage 'Auto-selection of the paging file size: ' -NoNewline
            Write-LogMessage 'No' -ForegroundColor Yellow
            Write-LogMessage "The message 'Out of memory' was found in the log file." -ForegroundColor Yellow
            Write-LogMessage 'If your game crashes immediately, it is advisable to set the auto-selection of the paging file size by the system.' -ForegroundColor Yellow
            $answer = Read-Host 'Do you want to do this? (Y - Yes / Any - No)'
            if ($answer -eq 'Y') {
                SystemPropertiesPerformance.exe /pagefile
                Write-LogMessage ''
                Write-LogMessage '- Click the ' -NoNewline
                Write-LogMessage "'Change'" -NoNewline -ForegroundColor Green
                Write-LogMessage ' button'
                Write-LogMessage '- Select the disk on which you have a paging file'
                Write-LogMessage '- Specify ' -NoNewline
                Write-LogMessage "'System managed size'" -NoNewline -ForegroundColor Green
                Write-LogMessage ', then click the ' -NoNewline
                Write-LogMessage "'Set'" -NoNewline -ForegroundColor Green
                Write-LogMessage ' button'
                Write-LogMessage '- After that, check the box ' -NoNewline
                Write-LogMessage "'Automatically manage paging file size for all drives'" -ForegroundColor Green
                Write-LogMessage '- Click ' -NoNewline
                Write-LogMessage "'Ok'" -ForegroundColor Green
                Write-LogMessage 'The system will ask you to reboot for the changes to take effect, postpone this process and exit this script, after which you can reboot the system.' -ForegroundColor Yellow
                Read-Host -Prompt 'Press Enter to Continue' | Out-Null
            }
        }
    }

    # Check RAM
    Write-LogMessage ''
    $ramGb = [Math]::Round((Get-CimInstance -ClassName Win32_ComputerSystem).TotalPhysicalMemory / 1GB)
    Write-LogMessage 'RAM: ' -NoNewline
    if ($ramGb -lt 16) {
        Write-LogMessage "$ramGb GB" -ForegroundColor Red
        Write-LogMessage 'Attention: the amount of RAM is less than 16 GB' -ForegroundColor Yellow
        Write-LogMessage 'It is very likely that the game will show you a warning that your system does not meet the minimum requirements. You can acknowledge this message and proceed at your own risk.' -ForegroundColor Yellow
    }
    else {
        Write-LogMessage "$ramGb GB" -ForegroundColor Green
    }

    # Report GPU memory only when a matching adapter and reliable registry value exist.
    Write-LogMessage ''
    $videoCard = Get-VideoControllerForRegistryPath -VideoRegistryPath $videoRegistryPath
    $vramGb = $null
    $driverName = $null
    if ($videoRegistryPath -and $videoCard) {
        $videoProperties = Get-ItemProperty -Path $videoRegistryPath -ErrorAction SilentlyContinue
        $driverName = [string]$videoProperties.DriverDesc
        if ($driverName -eq [string]$videoCard.Name) {
            $dxPath = $videoRegistryPath -split '\\'
            $directXVideoPath = Get-ItemProperty -Path ('HKLM:\SOFTWARE\Microsoft\DirectX\' + $dxPath[-2]) -ErrorAction SilentlyContinue
            if ($directXVideoPath -and $null -ne $directXVideoPath.DedicatedVideoMemory) {
                $memoryBytes = [uint64]$directXVideoPath.DedicatedVideoMemory
                if ($memoryBytes -gt 0) { $vramGb = [Math]::Round($memoryBytes / 1GB) }
            }
        }
    }
    $displayName = if ($videoCard) { [string]$videoCard.Name } else { 'Unknown' }
    Write-LogMessage 'Video Card: ' -NoNewline
    if ($null -eq $vramGb) {
        Write-LogMessage "$displayName (VRAM unknown)" -ForegroundColor Yellow
    }
    elseif ($vramGb -lt 6) {
        Write-LogMessage "$displayName ($vramGb GB)" -ForegroundColor Red
        Write-LogMessage 'Attention: the amount of video memory is less than 6 GB' -ForegroundColor Yellow
    }
    else {
        Write-LogMessage "$displayName ($vramGb GB)" -ForegroundColor Green
    }

    if ($videoRegistryPath -and $videoCard -and $driverName -eq [string]$videoCard.Name) {
        $driverVersion = (Get-ItemProperty -Path $videoRegistryPath -Name 'DriverVersion' -ErrorAction SilentlyContinue).DriverVersion
        $driverDate = (Get-ItemProperty -Path $videoRegistryPath -Name 'DriverDate' -ErrorAction SilentlyContinue).DriverDate
        if ($driverName -like '*NVIDIA*' -and $driverVersion) {
            $displayVersion = Convert-GpuDriverVersionForDisplay -Vendor NVIDIA -DriverVersion $driverVersion
            Write-LogMessage "GPU driver version: $displayVersion ($driverDate)" -ForegroundColor Green
        }
        elseif ($driverName -like '*AMD*') {
            $radeonVersion = (Get-ItemProperty -Path $videoRegistryPath -Name 'RadeonSoftwareVersion' -ErrorAction SilentlyContinue).RadeonSoftwareVersion
            if ($radeonVersion) { Write-LogMessage "GPU driver version: $radeonVersion ($driverDate)" -ForegroundColor Green }
        }
        elseif ($driverName -like '*Intel*' -and $driverVersion) {
            $displayVersion = Convert-GpuDriverVersionForDisplay -Vendor Intel -DriverVersion $driverVersion
            Write-LogMessage "GPU driver version: $displayVersion ($driverDate)" -ForegroundColor Green
        }
    }

    Write-LogMessage ''
    Write-LogMessage 'The Texture Resolution setting affects the amount of video memory consumed by the game:' -ForegroundColor Yellow
    Write-LogMessage 'Performance (~5 GB), Balanced (~5.5 GB), Quality (~6.5 GB), Max.Quality (~8.5 GB)' -ForegroundColor Yellow
    Write-LogMessage ''
    Write-LogMessage "It's recommended to update your video card drivers if you have an older version and a newer one is available." -ForegroundColor Yellow
    Write-LogMessage 'After that, you must run this utility again to check the Vulkan API version.' -ForegroundColor Yellow
    Write-LogMessage ''

    if ($videoCard.Name -like '*nvidia*') {
        Write-LogMessage 'Link to the latest video driver: ' -NoNewline
        Write-LogMessage '(https://www.nvidia.com/Download/index.aspx)' -ForegroundColor Green
        Write-LogMessage 'You can also try the beta driver for Vulkan: ' -NoNewline
        Write-LogMessage '(https://developer.nvidia.com/vulkan-driver)' -ForegroundColor Green
    }
    elseif ($videoCard.Name -like '*radeon*' -or $videoCard.Name -like '*amd*') {
        Write-LogMessage 'Link to the latest video driver: ' -NoNewline
        Write-LogMessage '(https://www.amd.com/en/support)' -ForegroundColor Green
    }
    elseif ($videoCard.Name -like '*intel*' -or $videoCard.Name -like '*arc*' -or $videoCard.Name -like '*iris*') {
        Write-LogMessage 'Link to the latest video driver: ' -NoNewline
        Write-LogMessage '(https://www.techpowerup.com/download/intel-graphics-drivers/)' -ForegroundColor Green
    }
    else {
        Write-LogMessage 'Video card not recognized.'
    }

    # Completing script execution
    Write-LogMessage ''
    Write-LogMessage 'Even if after all the corrections you have made, the game continues to crash after some time, most likely the problem is in the game itself. Either you have a very large and complex "castle", or you have a large number of crops. (This problem seems to be known to developers and it remains only to wait for patches.)' -ForegroundColor Yellow
    Write-LogMessage ''
    Write-LogMessage 'The computer must be restarted for the changes to take effect.' -ForegroundColor Yellow
    Write-LogMessage ''

    # Write data to log file
    $dateTime = Get-Date -Format 'yyyy-MM-ddTHH-mm-ss'
    $logDirectory = Join-Path -Path $gameDirectory -ChildPath 'Enshrouded_Tool_Fix'
    if (-not (Test-Path -LiteralPath $logDirectory)) {
        New-Item -Path $logDirectory -ItemType Directory -Force | Out-Null
    }

    $destinationLog = Join-Path -Path $logDirectory -ChildPath "Enshrouded_Tool_Fix_$dateTime.log"
    Copy-Item -LiteralPath $script:LogFilePath -Destination $destinationLog
    Remove-Item -LiteralPath $script:LogFilePath -Force
    Start-Process -FilePath $logDirectory
    Read-Host -Prompt 'Press Enter to Exit' | Out-Null
}

if ($MyInvocation.InvocationName -ne '.') {
    Invoke-EnshroudedToolFix
}
