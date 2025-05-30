using namespace System.Collections.Generic
Import-Module LogRhythm.Tools
# Set home folder for Sync to read/write content to.
$RootFolderPath = "C:\TEMP\Exabeam\FHK"
$ExportFile = "fhk_$($(get-date).ToString("MMyyyy")).csv"

# Cleanup Alert entries older than 90 days from the SecEventSyncLog
$SearchDays = 5

#####
# Log Path
$EventPath = (Join-Path $RootFolderPath -ChildPath $ExportFile)

if (Test-Path $EventPath -PathType Leaf) {
    # Load in existing data
    $FHK = Import-Csv -Path $EventPath
    if ($FHK) {
        $LastDate = $FHK.timestamp | ForEach-Object {[datetime]$_} | Sort-Object -Descending | Select-Object -First 1
        $Timespan = New-TimeSpan -Start $LastDate -End $(get-date)
        $DaysBetween = [math]::Max($Timespan.Days, 1)
    }
} else {
    $DaysBetween = $SearchDays
}

$CurMonth = $($(get-date).ToString("MM"))

$SearchResults = Get-LrtExaFHKResults -RouteId 'GOV' -Days $DaysBetween
$AddRows = [list[object]]::new()
if ($SearchResults.rows) {
    foreach ($Row in $SearchResults.rows) {
        # Logic that ensures each CSV only contains records for the current month.
        if ((Get-Date $($Row.timestamp)).ToString("MM") -eq $CurMonth) { 
            if ($FHK.sha1 -notcontains $Row.sha1) {
                $AddRows.add($Row)
            }
        } else { 
            continue
        }
    }
}


if ($AddRows.Count -gt 0) {
    # Convert $AddRows to an array and append to $FHK
    $FHK += $AddRows.ToArray()
    $FHK | Export-Csv -Path $EventPath -NoTypeInformation
}