using namespace System.Collections.Generic
Import-Module LogRhythm.Tools

$RootFolderPath = "C:\TEMP\Exabeam\FHK"
$RowLimit = 500000
$FilePrefix = "fhk_$($(get-date).ToString('MMyyyy'))"
$CurMonth = (Get-Date).ToString("MM")
$SearchDays = 5
$DefaultStartHour = 0  # Default start hour if no previous logs found

# Find all files for current month
$MonthFiles = Get-ChildItem -Path $RootFolderPath -Filter "${FilePrefix}_*.csv" | Sort-Object Name

# Initialize variables
$LastHour = $DefaultStartHour

# If there are no files, start at 1 with default hour
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
            # Get the latest timestamp and extract its hour
            $LastTimestamps = $FHK.timestamp | Where-Object { $_ } | ForEach-Object {[datetime]::Parse($_)}
            if ($LastTimestamps.Count -gt 0) {
                $LastTimestamp = $LastTimestamps | Sort-Object -Descending | Select-Object -First 1
                $LastHour = $LastTimestamp.Hour
                $Timespan = New-TimeSpan -Start $LastTimestamp -End (Get-Date)
                $DaysBetween = [math]::Max($Timespan.Days, 1)
                Write-Verbose "Found last timestamp: $LastTimestamp (Hour: $LastHour), Days between: $DaysBetween"
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

# Fetch and filter new data
Write-Verbose "Fetching data with Days: $DaysBetween, StartHour: $LastHour"
$SearchResults = Get-LrtExaFHKResults -Days $DaysBetween -StartHour $LastHour -Verbose

$AddRows = [list[object]]::new()
if ($SearchResults.rows) {
    $Rows = $SearchResults.rows | Sort-Object approxLogTime
    Write-Verbose "Retrieved $($Rows.Count) rows from Exabeam"
    
    # Use a faster approach with a HashSet for duplicate checking
    $existingSha1 = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($item in $FHK) {
        if ($item.sha1) { [void]$existingSha1.Add($item.sha1) }
    }
    
    foreach ($Row in $Rows) {
        try {
            # Only records for the current month & no duplicate sha1
            if ((Get-Date $($Row.timestamp) -ErrorAction Stop).ToString("MM") -eq $CurMonth) {
                if (-not $existingSha1.Contains($Row.sha1)) {
                    $AddRows.Add($Row)
                    [void]$existingSha1.Add($Row.sha1) # Add to HashSet to prevent duplicates in current batch
                }
            }
        } catch {
            Write-Warning "Error processing row: $_"
        }
    }
    
    Write-Verbose "Found $($AddRows.Count) new unique rows for the current month"
}

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
