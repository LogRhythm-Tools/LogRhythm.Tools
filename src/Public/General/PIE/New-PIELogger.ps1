<#
    .SYNOPSIS
        Provides PIE the capability to write the PIE Run log.
    .NOTES
        PIE      
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
#>
function New-PIELogger {
    Param(
        [Parameter(Mandatory = $false, Position = 0)]
        $logLevel = "debug",

        [Parameter(Mandatory = $true, Position = 1)]
        $logSev,

        [Parameter(Mandatory = $true, Position = 2)]
        $Message,

        [Parameter(Mandatory = $true, Position = 3)]
        $LogFile
    )
    $cTime = "[{0:MM/dd/yy} {0:HH:mm:ss}]" -f (Get-Date)
    #Create phishLog if file does not exist.
    if ( $(Test-Path $LogFile -PathType Leaf) -eq $false ) {
        Set-Content $LogFile -Value "PIE Powershell Runlog for $date"
        Write-Output "$cTime ALERT - No runLog detected.  Created new $runLog" | Out-File $LogFile
    }
    if ($LogLevel -like "info" -Or $LogLevel -like "debug") {
        if ($logSev -like "s") {
            Write-Output "$cTime STATUS - $Message" | Out-File $LogFile -Append
        } elseif ($logSev -like "a") {
            Write-Output "$cTime ALERT - $Message" | Out-File $LogFile -Append
        } elseif ($logSev -like "e") {
            Write-Output "$cTime ERROR - $Message" | Out-File $LogFile -Append
        }
    }
    if ($LogSev -like "i") {
        Write-Output "$cTime INFO - $Message" | Out-File $LogFile -Append
    }
    if ($LogSev -like "d") {
        Write-Output "$cTime DEBUG - $Message" | Out-File $LogFile -Append
    }
    Switch ($logSev) {
        e {$logSev = "ERROR"}
        s {$logSev = "STATUS"}
        a {$logSev = "ALERT"}
        i {$logSev = "INFO"}
        d {$logSev = "DEBUG"}
        default {$logSev = "LOGGER ERROR"}
    }
}