# Function to check if the path is valid
function Validate-Path($path) {
    return Test-Path -Path $path
}

# Function to get video duration
function Get-VideoDuration($file) {
    $shell = New-Object -ComObject Shell.Application
    $folder = $shell.Namespace((Get-Item $file).DirectoryName)
    $item = $folder.ParseName((Get-Item $file).Name)
    return $folder.GetDetailsOf($item, 27)
}

# Load configuration from JSON
$Config = Get-Content ".\Config.json" | ConvertFrom-Json

# Assign variables from config
$Max_Size = $Config.MaxSize
$Delete_Method = $Config.DeleteMethod
$Delete_Short_Enabled = $Config.DeleteShort.Enabled.ToLower()
$Delete_Short_Minimum = $Config.DeleteShort.MinimumLength
$Logging_Enabled = $Config.Logging.Enabled.ToLower()
$Logging_File = $Config.Logging.Path
$Content_Directory = $Config.ContentDirectory
$Successful_Removals = 0
$Unsuccessful_Removals = 0

# Verify max size is correct
if ([int]$Max_Size -le 0) {
    $message = "Your max size must be a number and larger than 0."
    Write-Host $message -ForegroundColor Red
    if ($Logging_Enabled -eq "true") { $message | Out-File -Append -FilePath $Logging_File }
    exit
}

# Validate Video directory
if (-not (Validate-Path $Content_Directory)) {
    Write-Host "Invalid video directory: $Content_Directory." -ForegroundColor Red
    exit
}

# Get video files excluding ignored videos
$Video_Files = Get-ChildItem -Path $Content_Directory -Directory | Where-Object { -not (Get-ChildItem $_.FullName | Where-Object { $Config.IgnoredVideos -contains $_.Name }) }


# Filter out items containing ignored files
$Video_Files = $Video_Files | Where-Object {
    $item = $_
    -not ($Config.IgnoreIfFiles | Where-Object { Test-Path -Path (Join-Path -Path $item.FullName -ChildPath $_) })
}

# Delete videos that are too short
if ($Delete_Short_Enabled -eq "true") {
    if ([int]$Delete_Short_Minimum -le 0) {
        $message = "You can't have a 0 or negative minimum time. If required, disable it in the configuration file by changing 'true' to 'false'."
        Write-Host $message -ForegroundColor Red
        if ($Logging_Enabled -eq "true") { $message | out-file -Append -FilePath $Logging_File }
        exit
    }
    foreach ($File in $Video_Files) {
        $VideoFiles = Get-ChildItem -Path $File -File | Where-Object { $_.Extension -match '\.(mp4|avi|mkv|mov)$' }
        foreach ($Video_File in $VideoFiles) {
            $duration = Get-VideoDuration $Video_File.FullName

            # Convert time to minutes
            $Minimum_Deletion_Time = if ($Delete_Short_Minimum -contains "h") {
                [int]$Delete_Short_Minimum.ToLower().replace("h", "") * 60
            } else {
                [int]$Delete_Short_Minimum.ToLower().Replace("m", "")
            }

            if ($duration -match '^\d+:\d+:\d+$') {
                $durationParts = $duration -split ':'
                $totalMinutes = $durationParts[0] * 60 + $durationParts[1]
                if ($totalMinutes -lt $Minimum_Deletion_Time) {
                    $ParentFolder = Split-Path -Path $Video_File.FullName -Parent
                    Remove-Item $ParentFolder -Recurse -Force -ErrorAction SilentlyContinue -ErrorVariable DeleteError

                    if ($DeleteError) {
                        if ($Logging_Enabled -eq "true") { "$(Get-Date) - Unable to Delete $($ParentFolder.Name)\n\nERROR\n\n$DeleteError\n\n" | Out-File -Append -FilePath $Logging_File }
                        Write-Host "Unable to Delete $($ParentFolder.Name)." -ForegroundColor Red
                        $Unsuccessful_Removals++
                    } else {
                        if ($Logging_Enabled -eq "true") { "$(Get-Date) - Deleted $($ParentFolder.Name)" | Out-File -Append -FilePath $Logging_File }
                        Write-Host "Successfully Deleted $($ParentFolder.Name)." -ForegroundColor Green
                        $Successful_Removals++
                    }
                }
            }
        }
    }
}

# Delete extra files based on the method provided
$Amount_To_Remove = (Get-ChildItem -Path $Content_Directory).Count - $Max_Size
for($i = 0; $i -lt $Amount_To_Remove; $i++) {
    $Removed_File = $null
    $Error = ""
    $Video_Files = if ($Delete_Method.ToLower() -eq "oldest") {
        $Video_Files | Sort-Object CreationTime
    } else {
        $Video_Files | Sort-Object CreationTime -Descending
    }
    $Removed_File = $Video_Files[0]
    Remove-Item -Path $Removed_File.FullName -Force -Recurse -ErrorAction SilentlyContinue -ErrorVariable DeleteError
    if ($DeleteError) {
        if ($Logging_Enabled -eq "true") { "$(Get-Date) - Unable to Delete $($Removed_File.Name)\n\nERROR\n\n$DeleteError\n\n" | Out-File -Append -FilePath $Logging_File }
        Write-Host "Unable to Delete $($Removed_File.Name)." -ForegroundColor Red
        $Unsuccessful_Removals++
    } else {
        if ($Logging_Enabled -eq "true") { "$(Get-Date) - Deleted $($Removed_File.Name)" | Out-File -Append -FilePath $Logging_File}
        Write-Host "Successfully Deleted $($Removed_File.Name)." -ForegroundColor Green
        $Successful_Removals++
    }
    $Video_Files = $Video_Files | Where-Object { $_.Name -ne $Removed_File.Name }
}

# Log and display results
if ($Successful_Removals -gt 0) {
    $message = "Successfully Removed $Successful_Removals videos."
    Write-Host $message -ForegroundColor Green
    if ($Logging_Enabled -eq "true") { $message | out-file -Append -FilePath $Logging_File }
}

if ($Unsuccessful_Removals -gt 0) {
    $message = "Encountered $Unsuccessful_Removals error(s) when attempting removal. Check the logs for details."
    Write-Host $message -ForegroundColor Red
    if ($Logging_Enabled -eq "true") { $message | out-file -Append -FilePath $Logging_File }
}

if ($Successful_Removals -eq 0 -and $Unsuccessful_Removals -eq 0) {
    $message = "No files were removed, and there were no errors."
    Write-Host $message -ForegroundColor Green
    if ($Logging_Enabled -eq "true") { $message | out-file -Append -FilePath $Logging_File }
}
