using namespace System.Collections.Generic
Import-Module LogRhythm.Tools

$RootFolderPath = "C:\TEMP\Exabeam\FHK"
$RowLimit = 500000
$FilePrefix = "fhk_$($(get-date).ToString('MMyyyy'))"
$CurMonth = (Get-Date).ToString("MM")
$SearchDays = 5

# Find all files for current month
$MonthFiles = Get-ChildItem -Path $RootFolderPath -Filter "${FilePrefix}_*.csv" | Sort-Object Name

# If there are no files, start at 1
if (-not $MonthFiles) {
    $CurFileNum = 1
    $EventPath = Join-Path $RootFolderPath "$FilePrefix`_1.csv"
    $FHK = [list[object]]::new()
    $DaysBetween = $SearchDays
}
else {
    # Use last file for this month
    $LastFile = $MonthFiles | Select-Object -Last 1
    $CurFileNum = [int]($LastFile.BaseName -replace '.*_(\d+)$','$1')
    $EventPath = $LastFile.FullName

    # Import existing rows and check row count
    $CSV = Import-Csv -Path $EventPath
    $FHK = [list[object]]::new()
    $FHK.AddRange(@($CSV))

    # Calculate how many days to look back
    if ($FHK) {
        $LastDate = $FHK.timestamp | ForEach-Object {[datetime]$_} | Sort-Object -Descending | Select-Object -First 1
        $Timespan = New-TimeSpan -Start $LastDate -End (Get-Date)
        $DaysBetween = [math]::Max($Timespan.Days, 1)
    }
    else {
        $DaysBetween = $SearchDays
    }

    # If current file is full, create a new one
    if ($FHK.Count -ge $RowLimit) {
        $CurFileNum++
        $EventPath = Join-Path $RootFolderPath "$FilePrefix`_${CurFileNum}.csv"
        $FHK = [list[object]]::new()  # New file = new list
    }
}

# Fetch and filter new data
$SearchResults = Get-LrtExaFHKResults -RouteId 'GOV' -Days $DaysBetween
$AddRows = [list[object]]::new()
if ($SearchResults.rows) {
    foreach ($Row in $SearchResults.rows) {
        # Only records for the current month & no duplicate sha1
        if ((Get-Date $($Row.timestamp)).ToString("MM") -eq $CurMonth) {
            if ($FHK.sha1 -notcontains $Row.sha1) {
                $AddRows.Add($Row)
            }
        }
    }
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
