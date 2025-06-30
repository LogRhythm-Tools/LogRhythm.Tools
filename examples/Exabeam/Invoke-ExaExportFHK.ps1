using namespace System.Collections.Generic
using namespace System
Import-Module LogRhythm.Tools

$RootFolderPath = "C:\TEMP\Exabeam\FHK"
$RowLimit = 500000
$FilePrefix = "fhk_$($(get-date).ToString('MMyyyy'))"
$CurMonth = (Get-Date).ToString("MM")
$SearchDays = 5
$HoursPerIncrement = 4  # Search in 4-hour increments

# Find all files for current month
$MonthFiles = Get-ChildItem -Path $RootFolderPath -Filter "${FilePrefix}_*.csv" | Sort-Object Name

# Initialize variables
$LastLogDate = $null
$LastLogHour = 0

# If there are no files, start at 1
if (-not $MonthFiles) {
    Write-Verbose "No existing files found. Starting new file."
    $CurFileNum = 1
    $EventPath = Join-Path $RootFolderPath "$FilePrefix`_1.csv"
    $FHK = [list[object]]::new()
    $DaysBetween = $SearchDays
} else {
    # Use last file for this month
    $LastFile = $MonthFiles | Select-Object -Last 1
    $CurFileNum = [int]($LastFile.BaseName -replace '.*_(\d+)$','$1')
    $EventPath = $LastFile.FullName
    Write-Verbose "Using existing file: $EventPath"

    # Import existing rows and check row count
    try {
        $CSV = Import-Csv -Path $EventPath -ErrorAction Stop
        $FHK = [list[object]]::new()
        $FHK.AddRange(@($CSV))

        # Calculate how many days to look back
        if ($FHK.Count -gt 0) {
            # Get the latest timestamp to determine how far back to search
            $LastTimestamps = $FHK.timestamp | Where-Object { $_ } | ForEach-Object {[datetime]::Parse($_)}
            if ($LastTimestamps.Count -gt 0) {
                # Store the last timestamp and its hour for optimization
                $LastTimestamp = $LastTimestamps | Sort-Object -Descending | Select-Object -First 1
                $LastLogDate = $LastTimestamp.Date
                $LastLogHour = $LastTimestamp.Hour
                $Timespan = New-TimeSpan -Start $LastTimestamp -End (Get-Date)
                $DaysBetween = [math]::Max($Timespan.Days, 1)
                Write-Verbose "Found last timestamp: $LastTimestamp (Hour: $LastLogHour), Days between: $DaysBetween"
            } else {
                $DaysBetween = $SearchDays
                Write-Verbose "No valid timestamps found. Using default search days: $DaysBetween"
            }
        } else {
            $DaysBetween = $SearchDays
            Write-Verbose "Empty file found. Using default search days: $DaysBetween"
        }
    } catch {
        Write-Warning "Error reading existing file: $_"
        $FHK = [list[object]]::new()
        $DaysBetween = $SearchDays
    }

    # If current file is full, create a new one
    if ($FHK.Count -ge $RowLimit) {
        $CurFileNum++
        $EventPath = Join-Path $RootFolderPath "$FilePrefix`_${CurFileNum}.csv"
        $FHK = [list[object]]::new()  # New file = new list
        Write-Verbose "Current file is full. Creating new file: $EventPath"
    }
}

# Create directory if it doesn't exist
if (-not (Test-Path $RootFolderPath)) {
    try {
        $null = New-Item -Path $RootFolderPath -ItemType Directory -Force
        Write-Verbose "Created directory: $RootFolderPath"
    } catch {
        Write-Error "Failed to create directory $RootFolderPath: $_"
        return
    }
}

# Set up the HashSet for duplicate checking
$existingSha1 = [System.Collections.Generic.HashSet[string]]::new()
foreach ($item in $FHK) {
    if ($item.sha1) { [void]$existingSha1.Add($item.sha1) }
}

# Combined new rows will go here
$AddRows = [list[object]]::new()

# Current date for reference
$CurrentDate = Get-Date

# Get each day to process
for ($day = $DaysBetween; $day -ge 0; $day--) {
    $ProcessDate = $CurrentDate.AddDays(-$day).Date
    Write-Verbose "Processing date: $($ProcessDate.ToString('yyyy-MM-dd'))"
    
    # Determine starting hour based on if this is the first day with the last timestamp
    $skipToHour = 0
    $skipRemainingTimeBlocks = $false
    
    # If this is the same day as our last log, start from that hour's block
    # This optimization prevents redundant queries for time we've already processed
    if ($LastLogDate -and $ProcessDate.Date -eq $LastLogDate.Date) {
        # Calculate which block the last hour belongs to
        $skipToHour = [Math]::Floor($LastLogHour / $HoursPerIncrement) * $HoursPerIncrement
        Write-Verbose "Optimizing: Starting from hour block $skipToHour on $($ProcessDate.ToString('yyyy-MM-dd')) based on last timestamp"
    }
    # If we're looking at dates before the last log, skip them entirely
    elseif ($LastLogDate -and $ProcessDate.Date -lt $LastLogDate.Date) {
        Write-Verbose "Optimizing: Skipping date $($ProcessDate.ToString('yyyy-MM-dd')) as it's earlier than last timestamp"
        $skipRemainingTimeBlocks = $true
    }
    
    # Skip this date if it's before our last timestamp
    if ($skipRemainingTimeBlocks) {
        continue
    }
    
    # Process each 4-hour increment in the day, starting from the optimized hour
    for ($startHour = $skipToHour; $startHour -lt 24; $startHour += $HoursPerIncrement) {
        $endHour = [Math]::Min($startHour + $HoursPerIncrement - 1, 23)
        Write-Verbose "Processing time block: $startHour:00 to $endHour:59"
        
        # Get data for this time block
        $SearchResults = Get-LrtExaFHKResults -Days 1 -StartHour $startHour -Verbose
        
        if ($SearchResults.rows) {
            $Rows = $SearchResults.rows | Sort-Object approxLogTime
            Write-Verbose "Retrieved $($Rows.Count) rows from Exabeam for $startHour:00 to $endHour:59"
            
            foreach ($Row in $Rows) {
                try {
                    # Check if timestamp is within our date range 
                    $rowDate = Get-Date $($Row.timestamp) -ErrorAction Stop
                    
                    # Only records for the current month & no duplicate sha1 & within the right day
                    if (($rowDate.ToString("MM") -eq $CurMonth) -and 
                        ($rowDate.Date -eq $ProcessDate.Date) -and
                        ($rowDate.Hour -ge $startHour) -and 
                        ($rowDate.Hour -le $endHour)) {
                        
                        if (-not $existingSha1.Contains($Row.sha1)) {
                            $AddRows.Add($Row)
                            [void]$existingSha1.Add($Row.sha1) # Add to HashSet to prevent duplicates
                        }
                    }
                } catch {
                    Write-Warning "Error processing row: $_"
                }
            }
        }
    }
}

Write-Verbose "Found $($AddRows.Count) total new unique rows for the current month"

# Append rows—if we cross the row limit, spill into next file(s)
while ($AddRows.Count -gt 0) {
    $SpaceLeft = $RowLimit - $FHK.Count
    $Chunk = $AddRows | Select-Object -First $SpaceLeft
    $FHK.AddRange($Chunk)
    $AddRows.RemoveRange(0, $Chunk.Count)

    # Write the file
    $FHK | Export-Csv -Path $EventPath -NoTypeInformation

    # If more rows left, bump to next file, reset buffer
    if ($AddRows.Count -gt 0) {
        $CurFileNum++
        $EventPath = Join-Path $RootFolderPath "$FilePrefix`_${CurFileNum}.csv"
        $FHK = [list[object]]::new()
    }
}

# If no new rows and file is empty (brand new run), still create the file (optional)
if (($FHK.Count -eq 0) -and !(Test-Path $EventPath)) {
    $FHK | Export-Csv -Path $EventPath -NoTypeInformation
}
