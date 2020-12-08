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
        [ValidateSet('info','debug', ignorecase=$true)]
        $logLevel = "info",

        [Parameter(Mandatory = $true, Position = 1)]
        [ValidateSet('e', 's', 'a', 'i', 'd', ignorecase=$true)]
        [string] $logSev,

        [Parameter(Mandatory = $true, Position = 2)]
        [string] $Message,

        [Parameter(Mandatory = $true, Position = 3)]
        $LogFile,

        [Parameter(Mandatory = $false, Position = 4)]
        [switch] $PassThru
    )
    $cTime = "[{0:MM/dd/yy} {0:HH:mm:ss}]" -f (Get-Date)
    #Create phishLog if file does not exist.
    if ( $(Test-Path $LogFile -PathType Leaf) -eq $false ) {
        Set-Content $LogFile -Value "PIE Powershell Runlog for $date"
        Write-Output "$cTime ALERT - No runLog detected.  Created new $runLog" | Out-File $LogFile
    }

    Switch ($logSev) {
        e {$LogOutput = "$cTime ERROR - $Message"}
        s {$LogOutput = "$cTime STATUS - $Message"}
        a {$LogOutput = "$cTime ALERT - $Message"}
        i {$LogOutput = "$cTime INFO - $Message"}
        d {$LogOutput = "$cTime DEBUG - $Message"}
        default {$logSev = "LOGGER ERROR"}
    }

    if ($logLevel -like "info") {

    }

    # If Debug mode, write out all log messages
    if ($LogLevel -like "debug") {
        Write-Output $LogOutput | Out-File $LogFile -Append
        if ($PassThru) {
            Write-Host $LogOutput
        }
    } else {
        # Write to file all but debug logs
        if ($LogSev -notlike "d") {
            Write-Output $LogOutput | Out-File $LogFile -Append
            if ($PassThru) {
                Write-Host $LogOutput
            }
        }
    }
}