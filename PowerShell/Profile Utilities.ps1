Add-Type -AssemblyName UIAutomationClient

# Variables
$CustomVariables = @{
    "google" = "www.google.com"
}


# Set variables
foreach ($item in $CustomVariables.GetEnumerator()) {
	$alias = $item.Key
	$path = $item.Value
	iex "`$$($alias) = '$($path)'"
}


# Use psreadline when defaulted
if($host.Name -eq 'ConsoleHost') {
    if (-not (Get-Module -ListAvailable -Name PSReadLine)) {
        Install-Module PSReadLine -Force
    }
     Import-Module PSReadLine
}


# Notepad++ Alias
if (Test-Path "C:\Program Files (x86)\Notepad++\notepad++.exe") {
    Set-Alias notepad++ "C:\Program Files (x86)\Notepad++\notepad++.exe"
}


# Install Choco
function Install-AppManagers {
    winget install choco -y
}


# Edit the hosts file
function Open-Hosts {
    Start-Process "notepad++.exe" -ArgumentList "$env:windir\system32\drivers\etc\hosts" -Verb RunAs
}


# Find a window by its title
function Find-Window {
    param(
        [string]$title
    )
    $condition = New-Object System.Windows.Automation.PropertyCondition ([System.Windows.Automation.AutomationElement]::NameProperty, $title)
    $element = [System.Windows.Automation.AutomationElement]::RootElement.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $condition)
    return $element
}


# Text To Speech (Google)
function Send-TTS {
    param (
        [Parameter(ValueFromPipeline=$true)]
        [string]$textToSpeak=""
    )
	try {
		if (([string]$textToSpeak).trim() -eq "") {
			return
		}
		$hasInternet = Test-Connection -ComputerName google.com -Count 1 -Quiet
		if ($hasInternet) {
			$ProgressPreference = 'SilentlyContinue'
			$encodedText = [System.Web.HttpUtility]::UrlEncode($textToSpeak)
			$tempFile = [System.IO.Path]::GetTempFileName() + ".mp3"
			$url = "http://translate.google.com/translate_tts?ie=UTF-8&total=1&idx=0&textlen=$(($textToSpeak.Length))&client=tw-ob&q=$encodedText&tl=En-gb"
			Invoke-WebRequest -Uri $url -OutFile $tempFile
			$process = Start-Process -FilePath "vlc" -ArgumentList "--intf dummy $tempFile vlc://quit" -PassThru
			$process | Wait-Process
			Remove-Item -Path $tempFile
			$ProgressPreference = 'Continue'
		}else{
			$synthesizer = New-Object -TypeName System.Speech.Synthesis.SpeechSynthesizer
			$synthesizer.Speak($textToSpeak)
		}
	}catch{
		Write-Output "An error occured."
	}
}


# Find a file using its name
function Get-File {
    param(
        [string]$name
    )
    Write-Host ""    
    Get-ChildItem -Path C:\ -include $name -Recurse -ErrorAction SilentlyContinue | Select-Object -expandproperty FullName
    Write-Host ""
}


# Get a system report
function Get-SystemReport {
    $report = @()

    $computerInfo = Get-ComputerInfo
    $report += "Computer Information:"
    $report += "-------------------------------------"
    $report += "Computer Name: $($computerInfo.CsName)"
    $report += "Manufacturer: $($computerInfo.CsManufacturer)"
    $report += "Model: $($computerInfo.CsModel)"
    $report += "Operating System: $($computerInfo.WindowsProductName) $($computerInfo.WindowsVersion) $($computerInfo.OsHardwareAbstractionLayer)"
    $report += ""

    $processor = Get-WmiObject -Class Win32_Processor
    $report += "Processor Information:"
    $report += "-------------------------------------"
    $report += "Name: $($processor.Name)"
    $report += "Description: $($processor.Description)"
    $report += "Manufacturer: $($processor.Manufacturer)"
    $report += "Number of Cores: $($processor.NumberOfCores)"
    $report += ""

    $bios = Get-WmiObject -Class Win32_BIOS
    $report += "BIOS Information:"
    $report += "-------------------------------------"
    $report += "Manufacturer: $($bios.Manufacturer)"
    $report += "SMBIOS Version: $($bios.SMBIOSBIOSVersion)"
    $report += "Version: $($bios.Version)"
    $report += ""

    $report | Out-String
}


# Find duplicate files (Hash based)
function Find-DuplicateFiles {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Directory,
        [switch]$RemoveDuplicates
    )

    $fileHashes = @{}
    Get-ChildItem -Path $Directory -File -Recurse | ForEach-Object {
        $hash = (Get-FileHash $_.FullName).Hash
        if ($fileHashes.ContainsKey($hash)) {
            $fileHashes[$hash] += $_.FullName
        } else {
            $fileHashes[$hash] = @($_.FullName)
        }
    }

    $duplicates = $fileHashes.Values | Where-Object { $_.Count -gt 1 }
    foreach ($dup in $duplicates) {
        Write-Output "Duplicate Files: "
        $dup | ForEach-Object { Write-Output $_ }
        if ($RemoveDuplicates.IsPresent) {
            # Keep the first file, remove the rest
            $dup | Select-Object -Skip 1 | ForEach-Object {
                Remove-Item $_ -Force
                Write-Output "Removed $_"
            }
        }
    }
}


# Search for text inside files
function Search-Text {
    param (
        [string]$path,
        [string]$pattern
    )
    Get-ChildItem $path -Recurse | Select-String -Pattern $pattern
}


# Securely wipe a file
function Wipe-File {
    param (
        [Parameter(Mandatory = $true)]
        [string]$FilePath,
        [int]$Passes = 3
    )
    
    for ($i = 0; $i -lt $Passes; $i++) {
        $fileContent = Get-Content -Path $FilePath -Raw
        $randomData = -join ((1..$fileContent.Length) | ForEach-Object { Get-Random -Maximum 256 -Minimum 0 | ForEach-Object { [char]$_ } })
        Set-Content -Path $FilePath -Value $randomData
    }
    
    Remove-Item -Path $FilePath
}


# Convert images to another format
function Convert-ImageFormat {
    param (
        [Parameter(Mandatory = $true)]
        [string]$SourcePath,
        [Parameter(Mandatory = $true)]
        [string]$DestinationPath,
        [Parameter(Mandatory = $true)]
        [string]$Format # e.g., "jpeg", "png", "bmp", "gif"
    )

    Add-Type -AssemblyName System.Drawing
    $image = [System.Drawing.Image]::FromFile($SourcePath)
    $formatType = [System.Drawing.Imaging.ImageFormat]::jpeg.GetType()
    $imageFormat = $formatType.GetProperty($Format, [System.Reflection.BindingFlags]::Static -bor [System.Reflection.BindingFlags]::IgnoreCase -bor [System.Reflection.BindingFlags]::GetProperty).GetValue($null, $null)
    $image.Save($DestinationPath, $imageFormat)
    $image.Dispose()
}


# Merge text files
function Merge-TextFiles {
    param (
        [Parameter(Mandatory = $true)]
        [string]$SourceDirectory,
        [Parameter(Mandatory = $true)]
        [string]$DestinationFile
    )
    Get-ChildItem -Path $SourceDirectory -Filter *.txt |
    Get-Content |
    Set-Content -Path $DestinationFile
}


# Quickly edit your profile
function Edit-Profile {
    if (!Test-Path $PROFILE) {
        $Parent = Split-Path -path $PROFILE
        if (!Test-Path $Parent) {
            New-Item -Type Directory -Path $Parent
        }
        New-Item -Type Item -Path $PROFILE
    }
    if (Test-Path "C:\Program Files (x86)\Notepad++\notepad++.exe") {
        & "C:\Program Files (x86)\Notepad++\notepad++.exe" $PROFILE
        return
    }
    notepad $PROFILE
}


# Monitor a file or folder for changes in real time
function Start-Monitor {
    param (
        [string]$Path
    )
    $watcher = New-Object System.IO.FileSystemWatcher
    $watcher.Path = $Path
    $watcher.IncludeSubdirectories = $true
    $watcher.EnableRaisingEvents = $true
    Register-ObjectEvent $watcher "Changed" -Action { Write-Host "Changed: $($Event.SourceEventArgs.FullPath)" }
    Register-ObjectEvent $watcher "Created" -Action { Write-Host "Created: $($Event.SourceEventArgs.FullPath)" }
    Register-ObjectEvent $watcher "Deleted" -Action { Write-Host "Deleted: $($Event.SourceEventArgs.FullPath)" }
    Register-ObjectEvent $watcher "Renamed" -Action { Write-Host "Renamed: $($Event.SourceEventArgs.OldFullPath) to $($Event.SourceEventArgs.FullPath)" }
}


# Do a network speed test
function Test-NetworkSpeed {
    if (-not (Get-Module -ListAvailable -Name SpeedTest)) {
        Install-Module SpeedTest -Force
    }
    Import-Module SpeedTest
    Start-SpeedTest
}


# YT-DLP
function Get-YTDLP {
    param (
        [string]$url,
        [switch]$playlist
    )
    $Location = (Get-Location).Path
    $Command = "yt-dlp --external-downloader 'aria2c' --cookies-from-browser firefox --windows-filenames --external-downloader-args '--min-split-size=1M --max-connection-per-server=16 --max-concurrent-downloads=16 --split=16' --throttled-rate 100K  --embed-thumbnail --embed-metadata"
    if ($playlist) {
        $Command += " --output ""$Location\%(playlist)s\%(title)s.%(ext)s"""
    }else{
        $Command += " --output ""$Location\%(title)s.%(ext)s"""
    }
    $Command += $url
    iex $Command
}


# Update all PowerShell Modules
function Update-AllModules {
    Get-Module -ListAvailable | ForEach-Object { Update-Module $_.Name -Force }
}


# Sort objects numerically
function Sort-STNumerical {
    [CmdletBinding()]
    Param(
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineBypropertyName = $True)]
        [System.Object[]]
        $InputObject,
        
        [ValidateRange(2, 100)]
        [Byte]
        $MaximumDigitCount = 100,

        [Switch] $Descending
    )
    
    Begin {
        [System.Object[]] $InnerInputObject = @()

        [Bool] $SortDescending = $False
        if ($Descending) {
            $SortDescending = $True
        }
    }
    
    Process {
        $InnerInputObject += $InputObject
    }

    End {
        $InnerInputObject |
            Sort-Object -Property `
                @{ Expression = {
                    [Regex]::Replace($_, '(\d+)', {
                        "{0:D$MaximumDigitCount}" -f [Int] $Args[0].Value })
                    }
                },
                @{ Expression = { $_ } } -Descending:$SortDescending
    }
}


# Unzip all files in dir
function Start-Unzip{
    param(
        [string] $dir
    )
    if ($dir -ne $null) {
            $directory = $($dir -replace "\.*.zip$", "")
            $null = New-Item -Force -ItemType directory -Path $directory
            $null = expand-archive $dir -DestinationPath $directory    
    }else{
        $Compressed = Get-ChildItem | where-object {$_.FullName -match (".*\.zip.*")} | ForEach-Object -Process { $_ | Select-Object -ExpandProperty name }
        foreach($file in $Compressed) {
            $dir = $(get-location | select-object -expandproperty path) + "\" + (($file).split("\")[-1].split(".")[0])
            $null = New-Item -Force -ItemType directory -Path $dir
            $null = expand-archive $file -DestinationPath $dir
        }
    }
}


# Delete all files by their extension
function Remove-FilesByExtension {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Extension,
        [Parameter(Mandatory=$false)]
        [bool]$Recurse = $false
    )
    if($Recurse) { 
        Get-ChildItem -Path "./" -Recurse -Filter "*.$Extension" | Remove-Item -Force 
    } else {
        Get-ChildItem -Path "./" -Filter "*.$Extension" | Remove-Item -Force 
    }

}


# Minimize Window
function Minimize-Window {
    param(
        [string] $TITLE
    )
	$SW_MINIMIZE = 6
	Get-Process | Where-Object {$_.MainWindowTitle -like "*$TITLE*"} | ForEach-Object {
		$handle = $_.MainWindowHandle
		if ($handle -ne [IntPtr]::Zero) {
			[void] [User32]::ShowWindow($handle, $SW_MINIMIZE)
		}
	}
}


# Consolidate all files in a directory to the parent directory
function Consolidate-Files {
    param(
        [string] $type
    )
	$type = $type -split "," | ForEach-Object { "*$($_)" }
    $scriptPath = Split-Path -Parent $profile
    $logFile = Join-Path $scriptPath "MoveFilesLog.csv"
    Get-ChildItem -Path . -Recurse -Include $type | ForEach-Object {
        $originalPath = $_.FullName
        $destinationFileName = [System.IO.Path]::GetFileName($originalPath)
        $destinationPath = Join-Path .\ $destinationFileName
        if (-not [String]::IsNullOrWhiteSpace($destinationPath) -and -not (Test-Path $destinationPath)) {
            Move-Item $originalPath -Destination $destinationPath
            Add-Content -Path $logFile -Value "$($originalPath),$($destinationPath)"
        }
    }
}


# Undo the consolidation
function Undo-Consolidation {
    $scriptPath = Split-Path -Parent $profile
    $logFile = Join-Path $scriptPath "MoveFilesLog.csv"
    if (Test-Path $logFile) {
        Import-Csv $logFile -Header OriginalPath, DestinationPath | ForEach-Object {
            $destinationPath = $_.DestinationPath
            if (Test-Path $destinationPath) {
                Move-Item $destinationPath -Destination $_.OriginalPath
            }
        }
        Remove-Item $logFile
    } else {
        Write-Output "No history found."
    }
}


# Export powershell command history
function Export-PSHistory {
    param (
        [Parameter(Mandatory = $true)]
        [string]$ExportFilePath
    )

    Get-History | Select-Object -Property CommandLine | Export-Csv -Path $ExportFilePath -NoTypeInformation
}


# Cleanup temp files
function Clean-TemporaryFiles {
    $tempPaths = @(
        $env:TEMP,
        "$env:WINDIR\Temp"
    )

    foreach ($path in $tempPaths) {
        try {
            Get-ChildItem -Path $path -Recurse | Remove-Item -Force -Recurse
            Write-Output "Cleaned temporary files in $path"
        } catch {
            Write-Error "Failed to clean $path. Error: $_"
        }
    }
}


# Check if console is running as admin
function Test-IsAdmin {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $windowsPrincipal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    $adminRole = [Security.Principal.WindowsBuiltInRole]::Administrator

    return $windowsPrincipal.IsInRole($adminRole)
}


# Get your local IP
function Get-LocalIPAddress {
    Get-NetIPAddress | Where-Object { $_.AddressFamily -eq 'IPv4' -and $_.AddressState -eq 'Preferred' } | Select-Object IPAddress
}


# Get a list of installed applications
function Export-InstalledPrograms {
    param (
        [Parameter(Mandatory = $true)]
        [string]$ExportPath
    )

    $installedPrograms = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* |
    Select-Object DisplayName, DisplayVersion, Publisher, InstallDate |
    Where-Object { $_.DisplayName -ne $null } |
    Sort-Object DisplayName

    $installedPrograms | Export-Csv -Path $ExportPath -NoTypeInformation
}


# Remove empty folders
function Remove-EmptyDirectories {
    param (
        [Parameter(Mandatory = $true)]
        [string]$StartDirectory
    )

    Get-ChildItem -Path $StartDirectory -Directory -Recurse | 
    Where-Object { $_.GetFileSystemInfos().Count -eq 0 } | 
    ForEach-Object { Remove-Item $_.FullName -Force }
}


# Encrypt a file
function Encrypt-File {
    param (
        [Parameter(Mandatory = $true)]
        [string]$FilePath
    )

    $content = Get-Content -Path $FilePath -Raw
    $encryptedContent = [System.Security.Cryptography.ProtectedData]::Protect([System.Text.Encoding]::UTF8.GetBytes($content), $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
    [System.IO.File]::WriteAllBytes($FilePath, $encryptedContent)
}


# Decrypt a file
function Decrypt-File {
    param (
        [Parameter(Mandatory = $true)]
        [string]$FilePath
    )

    $encryptedContent = [System.IO.File]::ReadAllBytes($FilePath)
    $decryptedContent = [System.Security.Cryptography.ProtectedData]::Unprotect($encryptedContent, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
    [System.IO.File]::WriteAllText($FilePath, [System.Text.Encoding]::UTF8.GetString($decryptedContent))
}


# Rename a lot of files at once
function Batch-RenameFiles {
    param (
        [Parameter(Mandatory = $true)]
        [string]$DirectoryPath,
        [Parameter(Mandatory = $true)]
        [string]$Pattern,
        [Parameter(Mandatory = $true)]
        [string]$Replacement
    )

    Get-ChildItem -Path $DirectoryPath -File | ForEach-Object {
        $newName = $_.Name -replace $Pattern, $Replacement
        Rename-Item $_.FullName -NewName $newName
    }
}


# Generate a secure password
function Generate-SecurePassword {
    param (
        [int]$Length = 12,
        [switch]$IncludeSpecialCharacters,
        [switch]$IncludeNumbers,
        [switch]$IncludeUppercase,
        [switch]$IncludeLowercase
    )

    $passwordChars = @()
    if ($IncludeSpecialCharacters) { $passwordChars += '!@#$%^&*()-_=+[]{}|;:,.<>/?' -split '' }
    if ($IncludeNumbers) { $passwordChars += '0123456789' -split '' }
    if ($IncludeUppercase) { $passwordChars += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' -split '' }
    if ($IncludeLowercase) { $passwordChars += 'abcdefghijklmnopqrstuvwxyz' -split '' }

    $password = -join (1..$Length | ForEach-Object { Get-Random -InputObject $passwordChars })
    return $password
}


# Mount an ISO to a drive
function Mount-ISO {
    param (
        [Parameter(Mandatory = $true)]
        [string]$IsoPath,
        [string]$DriveLetter
    )

    $mountResult = Mount-DiskImage -ImagePath $IsoPath -PassThru
    $volume = $mountResult | Get-Volume

    if ($DriveLetter) {
        $volume | Set-Partition -NewDriveLetter $DriveLetter[0]
    }

    Write-Output "ISO mounted to $(if ($DriveLetter) { $DriveLetter } else { $volume.DriveLetter })"
}


# Expand recursively
function Expand-ZIPRecursively {
    param (
        [Parameter(Mandatory = $true)]
        [string]$SourceDirectory
    )

    Get-ChildItem -Path $SourceDirectory -Recurse -Filter "*.zip" | ForEach-Object {
        $destination = $_.DirectoryName
        Expand-Archive -Path $_.FullName -DestinationPath $destination -Force
        Remove-Item -Path $_.FullName
    }
}


# Compare folder contents to each other
function Compare-FolderContents {
    param (
        [Parameter(Mandatory = $true)]
        [string]$FolderA,
        [Parameter(Mandatory = $true)]
        [string]$FolderB
    )

    $folderAFiles = Get-ChildItem -Path $FolderA -Recurse | Select-Object -ExpandProperty FullName | Sort-Object
    $folderBFiles = Get-ChildItem -Path $FolderB -Recurse | Select-Object -ExpandProperty FullName | Sort-Object

    $compareResult = Compare-Object -ReferenceObject $folderAFiles -DifferenceObject $folderBFiles

    foreach ($result in $compareResult) {
        if ($result.SideIndicator -eq "<=") {
            Write-Output "Missing in Folder B: $($result.InputObject.Replace($FolderA,''))"
        } else {
            Write-Output "Missing in Folder A: $($result.InputObject.Replace($FolderB,''))"
        }
    }
}


# Sync up two directories
function Sync-Directories {
    param (
        [Parameter(Mandatory = $true)]
        [string]$SourceDirectory,
        [Parameter(Mandatory = $true)]
        [string]$DestinationDirectory
    )

    robocopy $SourceDirectory $DestinationDirectory /MIR
    Write-Output "Synchronized $DestinationDirectory with $SourceDirectory"
}


# Compress all folders in a directory
function Compress-Folders {
    param (
        [Parameter(Mandatory=$true)]
        [string]$SourceDirectory
    )

    Get-ChildItem -Path $SourceDirectory -Directory | ForEach-Object {
        $zipFilePath = "$($_.FullName).zip"
        Compress-Archive -Path $_.FullName -DestinationPath $zipFilePath
        Write-Output "Compressed $($_.Name) to $zipFilePath"
    }
}


# Download all files from a list
function Download-Files {
    param (
        [Parameter(Mandatory=$true)]
        [string[]]$Urls,
        [Parameter(Mandatory=$true)]
        [string]$DestinationDirectory
    )

    foreach ($url in $Urls) {
        $fileName = [System.IO.Path]::GetFileName($url)
        $destinationPath = Join-Path -Path $DestinationDirectory -ChildPath $fileName
        Invoke-WebRequest -Uri $url -OutFile $destinationPath
        Write-Output "Downloaded $($url) to $(destinationPath)"
    }
}


# Get a hash for files
function Generate-FileHashes {
    param (
        [Parameter(Mandatory=$true)]
        [string]$DirectoryPath,
        [ValidateSet("MD5", "SHA1", "SHA256", "SHA384", "SHA512")]
        [string]$Algorithm = "SHA256"
    )

    Get-ChildItem -Path $DirectoryPath -File | ForEach-Object {
        $hash = Get-FileHash -Path $_.FullName -Algorithm $Algorithm
        Write-Output "$($_.Name): $($hash.Hash)"
    }
}


# Helps resolve issues with win update
function Clean-SoftwareDistribution {
    Stop-Service -Name wuauserv -Force
    Remove-Item -Path C:\Windows\SoftwareDistribution\Download -Recurse -Force
    Start-Service -Name wuauserv
    Write-Output "SoftwareDistribution folder cleaned."
}


# Get the file encoding of a text file
function Analyze-TextFileEncoding {
    param (
        [Parameter(Mandatory = $true)]
        [string]$FilePath
    )

    $bytes = [System.IO.File]::ReadAllBytes($FilePath)
    $encoding = [System.Text.Encoding]::Default

    if ($bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE) {
        $encoding = 'Unicode'
    } elseif ($bytes[0] -eq 0xFE -and $bytes[1] -eq 0xFF) {
        $encoding = 'BigEndianUnicode'
    } elseif ($bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
        $encoding = 'UTF8'
    }

    Write-Output "$FilePath is encoded in $encoding."
}


# Set wallpaper to an image file
function Set-Wallpaper {
    param (
        [Parameter(Mandatory = $true)]
        [string]$ImagePath
    )

    Add-Type -TypeDefinition @"
    using System;
    using System.Runtime.InteropServices;

    public class Wallpaper {
        [DllImport("user32.dll", CharSet = CharSet.Auto)]
        public static extern int SystemParametersInfo(int uAction, int uParam, string lpvParam, int fuWinIni);
    }
"@

    $SPI_SETDESKWALLPAPER = 0x0014
    $SPIF_UPDATEINIFILE = 0x01
    $SPIF_SENDCHANGE = 0x02

    [Wallpaper]::SystemParametersInfo($SPI_SETDESKWALLPAPER, 0, $ImagePath, $SPIF_UPDATEINIFILE -bor $SPIF_SENDCHANGE)
    Write-Output "Wallpaper set to $ImagePath"
}


# Check if you have a connection
function Test-InternetConnection {
    try {
        $ping = Test-Connection -ComputerName "google.com" -Count 1 -ErrorAction Stop
        Write-Output "Internet Connection: Available"
    } catch {
        Write-Output "Internet Connection: Unavailable"
    }
}


# Get a health check of the network
function Perform-NetworkHealthCheck {
    $report = @()
    $destinations = @("google.com","8.8.8.8", "1.1.1.1")
    foreach ($destination in $destinations) {
        try {
            $pingTest = Test-Connection -ComputerName $destination -Count 3 -ErrorAction Stop
            $avgResponseTime = ($pingTest | Measure-Object ResponseTime -Average).Average
            $report += "Ping to $($destination): SUCCESS, Average Response Time: $avgResponseTime ms"
        } catch {
            $report += "Ping to $($destination): FAILED"
        }

        try {
            $dnsTest = Resolve-DnsName $destination -ErrorAction Stop
            $report += "DNS Resolution for $($destination): SUCCESS, Resolved IP: $($dnsTest.IPAddress)"
        } catch {
            $report += "DNS Resolution for $($destination): FAILED"
        }
    }

    # Check default gateway reachability
    $gateway = (Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway -ne $null }).IPv4DefaultGateway.NextHop
    if ($gateway) {
        try {
            $gatewayPing = Test-Connection -ComputerName $gateway -Count 1 -ErrorAction Stop
            $report += "Default Gateway ($gateway): REACHABLE"
        } catch {
            $report += "Default Gateway ($gateway): UNREACHABLE"
        }
    } else {
        $report += "Default Gateway: NOT CONFIGURED"
    }

    # Write the report to a file
    Write-Host $report | Out-String
}


# Scan open ports
function Scan-NetworkPort {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Target,
        [int[]]$PortRange = 1..1024
    )

    foreach ($port in $PortRange) {
        try {
            $tcpClient = New-Object System.Net.Sockets.TcpClient
            $tcpClient.Connect($Target, $port)
            if ($tcpClient.Connected) {
                Write-Output "Port $port is open."
            }
            $tcpClient.Close()
        } catch {
            # Port is closed, no action required
        }
    }
}


# Create a new system restore point
function Create-SystemRestorePoint {
    param (
        [Parameter(Mandatory = $true)]
        [string]$RestorePointName
    )

    Checkpoint-Computer -Description $RestorePointName -RestorePointType "MODIFY_SETTINGS"
    Write-Output "System restore point created: $RestorePointName"
}


# Put all files into their own folder by extension
function Organize-FilesByExtension {
    param (
        [Parameter(Mandatory = $true)]
        [string]$TargetDirectory
    )

    Get-ChildItem -Path $TargetDirectory -File | ForEach-Object {
        $extension = $_.Extension
        $destFolder = Join-Path -Path $TargetDirectory -ChildPath $extension.TrimStart('.')

        if (-not (Test-Path -Path $destFolder)) {
            New-Item -Path $destFolder -ItemType Directory | Out-Null
        }

        Move-Item -Path $_.FullName -Destination $destFolder
    }
    Write-Output "Files in $TargetDirectory have been organized by extension."
}


# Encrypt text using AES
function Encrypt-Text {
    param (
        [Parameter(Mandatory = $true)]
        [string]$PlainText,
        [Parameter(Mandatory = $true)]
        [string]$Password
    )

    $aes = New-Object System.Security.Cryptography.AesCryptoServiceProvider
    $aes.Key = [System.Text.Encoding]::UTF8.GetBytes($Password.PadRight(32).Substring(0, 32))
    $aes.IV = [System.Text.Encoding]::UTF8.GetBytes($Password.PadRight(16).Substring(0, 16))

    $encryptor = $aes.CreateEncryptor($aes.Key, $aes.IV)
    $ms = New-Object System.IO.MemoryStream
    $cs = New-Object System.Security.Cryptography.CryptoStream $ms, $encryptor, [System.Security.Cryptography.CryptoStreamMode]::Write
    $sw = New-Object System.IO.StreamWriter $cs

    $sw.WriteLine($PlainText)
    $sw.Close()
    $cs.Close()
    $ms.Close()

    return [Convert]::ToBase64String($ms.ToArray())
}


# Decrypt text using AES
function Decrypt-Text {
    param (
        [Parameter(Mandatory = $true)]
        [string]$CipherText,
        [Parameter(Mandatory = $true)]
        [string]$Password
    )

    $aes = New-Object System.Security.Cryptography.AesCryptoServiceProvider
    $aes.Key = [System.Text.Encoding]::UTF8.GetBytes($Password.PadRight(32).Substring(0, 32))
    $aes.IV = [System.Text.Encoding]::UTF8.GetBytes($Password.PadRight(16).Substring(0, 16))

    $decryptor = $aes.CreateDecryptor($aes.Key, $aes.IV)
    $ms = New-Object System.IO.MemoryStream ([Convert]::FromBase64String($CipherText))
    $cs = New-Object System.Security.Cryptography.CryptoStream $ms, $decryptor, [System.Security.Cryptography.CryptoStreamMode]::Read
    $sr = New-Object System.IO.StreamReader $cs

    $plaintext = $sr.ReadToEnd()
    $sr.Close()
    $cs.Close()
    $ms.Close()

    return $plaintext
}


# Monitor a web page for any changes
function Monitor-WebPageChange {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Url,
        [Parameter(Mandatory = $true)]
        [string]$ChecksumFilePath,
        [int]$IntervalSeconds = 300
    )

    # Function to calculate the MD5 hash of the webpage content
    function Get-WebContentHash {
        param (
            [string]$Content
        )

        $md5 = New-Object -TypeName System.Security.Cryptography.MD5CryptoServiceProvider
        $utf8 = New-Object -TypeName System.Text.UTF8Encoding
        $hash = [System.BitConverter]::ToString($md5.ComputeHash($utf8.GetBytes($Content)))
        return $hash.Replace("-", "")
    }

    while ($true) {
        $currentContent = (Invoke-WebRequest -Uri $Url).Content
        $currentHash = Get-WebContentHash -Content $currentContent

        if (Test-Path -Path $ChecksumFilePath) {
            $previousHash = Get-Content -Path $ChecksumFilePath

            if ($currentHash -ne $previousHash) {
                Write-Host "Change detected on $Url at $(Get-Date)"
                # Optionally, trigger an action here, such as sending an email or notification
            }
        }

        Set-Content -Path $ChecksumFilePath -Value $currentHash
        Start-Sleep -Seconds $IntervalSeconds
    }
}


# Advanced diagnostics
function Perform-AdvancedSystemDiagnostics {
    $report = @()

    # Disk Health Check
    $disks = Get-Disk
    foreach ($disk in $disks) {
        $healthStatus = "OK"
        if ($disk.OperationalStatus -ne "Online" -or $disk.HealthStatus -ne "Healthy") {
            $healthStatus = "Attention Needed"
        }
        $report += "Disk $($disk.Number): $($disk.FriendlyName) is $($healthStatus)"
    }

    # Critical Windows Services Check
    $criticalServices = @("wuauserv", "bits", "Dnscache", "LanmanServer")
    foreach ($service in $criticalServices) {
        $serviceStatus = Get-Service -Name $service | Select-Object Status
        if ($serviceStatus.Status -ne "Running") {
            $report += "Critical Service $service is not running"
        } else {
            $report += "Critical Service $service is running"
        }
    }

    # Output the report
    $report | Out-String
}


# Restore the system using a snapshot
function Restore-SystemFromSnapshot {
    $restorePoints = Get-ComputerRestorePoint | Sort-Object -Property CreationTime -Descending
    $restorePoints | ForEach-Object { Write-Output "$($_.SequenceNumber): $($_.Description), Created on $($_.CreationTime)" }

    $selectedNumber = Read-Host "Enter the Sequence Number of the Restore Point you want to use"
    $selectedRestorePoint = $restorePoints | Where-Object { $_.SequenceNumber -eq $selectedNumber }

    if ($selectedRestorePoint) {
        Restore-Computer -RestorePoint $selectedRestorePoint.SequenceNumber
        Write-Output "System restore initiated to: $($selectedRestorePoint.Description)"
    } else {
        Write-Error "Invalid Restore Point selected."
    }
}


# Validate filesystem
function Validate-SystemFilesIntegrity {
    sfc /scannow
}


# Get the exchange rate of a currency
function Get-ExchangeRate {
    param (
        [string]$FromCurrency,
        [string]$ToCurrency
    )

    $url = "https://api.exchangerate-api.com/v4/latest/$FromCurrency"
    $response = Invoke-RestMethod -Uri $url -Method Get
    $exchangeRate = $response.rates.$ToCurrency
    return $exchangeRate
}


# Get public ip address
function Get-PublicIPAddress {
    $url = "https://api.ipify.org?format=json"
    $response = Invoke-RestMethod -Uri $url -Method Get
    $ipAddress = $response.ip
    return $ipAddress
}


# Check if a website is up
function Get-WebsiteStatus {
    param (
        [string]$Url
    )

    $webRequest = [System.Net.WebRequest]::Create($Url)
    $webResponse = $webRequest.GetResponse()

    return $webResponse.StatusCode
}


# Get DNS records of a domain
function Get-DNSRecords {
    param (
        [string]$Domain
    )

    Resolve-DnsName -Name $Domain -Type ANY
}


# Convert time and date to unix
function ConvertTo-UnixTimestamp {
    param (
        [datetime]$DateTime
    )

    return [int]($DateTime.ToUniversalTime() - (Get-Date "1970-01-01")).TotalSeconds
}


# Convert numbers to hex
function ConvertTo-Hexadecimal {
    param (
        [int]$Number
    )

    return $Number.ToString("X")
}


# Get the perms on a file
function Get-FilePermissions {
    param (
        [string]$Path
    )

    $acl = Get-Acl -Path $Path
    $permissions = $acl.Access | Select-Object IdentityReference, FileSystemRights, AccessControlType
    return $permissions
}


# Unlock/unblock any items
function Unlock-Item {
    param (
        [string]$Path
    )

    if (!Test-IsAdmin) {
        Write-Output "This must be run as administrator."
        return
    }

    if (Test-Path $Path) {
        try {
            $item = Get-Item $Path
            if ($item.Attributes -band [System.IO.FileAttributes]::ReadOnly) {
                $item.Attributes = $item.Attributes -bxor [System.IO.FileAttributes]::ReadOnly
                Write-Host "File/Folder unlocked successfully: $Path"
            } else {
                Write-Warning "File/Folder is not locked: $Path"
            }

            # Change owner to current user
            $acl = Get-Acl $Path
            $acl.SetOwner([System.Security.Principal.NTAccount]::New($env:USERNAME))
            Set-Acl -Path $Path -AclObject $acl

            # Terminate processes using the file/folder
            $lockedProcesses = Get-Process | Where-Object { $_.Modules.FileName -eq $Path }
            if ($lockedProcesses) {
                $lockedProcesses | ForEach-Object {
                    Write-Host "Terminating process $($_.ProcessName) (PID: $($_.Id))"
                    Stop-Process -Id $_.Id -Force
                }
            }
        } catch {
            Write-Error "Failed to unlock file/folder: $_"
        }
    } else {
        Write-Error "File/Folder not found: $Path"
    }
}


# Random filename
function Get-RandomFileName {
    param (
        [string]$Directory,
        [string]$Extension
    )

    $files = Get-ChildItem -Path $Directory
    $randomFile = $files | Get-Random
    if ($Extension) {
        Write-Output "$($randomFile.Name)$($Extension)"
    } else {
        Write-Output "$($randomFile.Name)"
    }
   
}


# Convert number to binary
function Convert-ToBinary {
    param (
        [int]$Number
    )
    [Convert]::ToString($Number, 2)
}


# List all local admins
function Get-LocalAdmins {
    $group = [ADSI]"WinNT://./Administrators"
    $members = $group.Invoke("Members")
    $members | ForEach-Object {
        $_.GetType().InvokeMember("Name", 'GetProperty', $null, $_, $null)
    }
}


# Reload the profile
function Reload {
    & $PROFILE
}


# Grep some text
function grep($regex, $dir) {
    if ( $dir ) {
        ls $dir | select-string $regex
        return
    }
    $input | select-string $regex
}
