$RootFolderPath = "\home\logrhythm\AzureSecurityAlerts"
#$RootFolderPath = "C:\Users\eric\Documents\GitHub\LogRhythm.Tools"
$SecEventSyncLog = "azure_synclog.csv"

# FileBeat File Names
# AzureATP
$FB_AzureATP = "FB_AzureATP.log"
$FB_AzureATP_Path = (Join-Path $RootFolderPath -ChildPath $FB_AzureATP)

# AzureSecurityCenter
$FB_AzureSecurityCenter = "FB_AzureSecurityCenter.log"
$FB_AzureSecurityCenter_Path = (Join-Path $RootFolderPath -ChildPath $AzureSecurityCenter)


# MCAS
$FB_MCAS = "FB_MCAS.log"
$FB_MCAS_Path = (Join-Path $RootFolderPath -ChildPath $FB_MCAS)


# AzureADIdentityProtection
$FB_AzureADIdentityProtection = "FB_AzureADIdentityProtection.log"
$FB_AzureADIdentityProtection_Path = (Join-Path $RootFolderPath -ChildPath $FB_AzureADIdentityProtection)


# AzureSentinel
$FB_AzureSentinel = "FB_AzureSentinel.log"
$FB_AzureSentinel_Path = (Join-Path $RootFolderPath -ChildPath $FB_AzureSentinel)

# DefenderATP
$FB_DefenderATP = "FB_DefenderATP.log"
$FB_DefenderATP_Path = (Join-Path $RootFolderPath -ChildPath $FB_DefenderATP)

#####
# Log Path
$SecEventSyncLogPath = (Join-Path $RootFolderPath -ChildPath $SecEventSyncLog)

if (!(Test-Path $SecEventSyncLogPath -PathType Leaf)) {
    $SecEventSyncTemplate = [PSCustomObject]@{
        log_timestamp = (get-date -Format yyyy-MM-ddTHH:mm:ss:ffffffK)
        event_timestamp = (get-date -Format MMddyyyy-HH:mm:ss:ffffff)
        type = "AzureATP"
        id = "55555555555555555555555555531d4c83000b728848d87cc1a18b3e2ad838fc"
        azureTenantId = "55555555-5555-5555-5555-555555555555"
        severity = "medium"
    }
    $SecEventSyncTemplate | Export-Csv -Path $SecEventSyncLogPath -NoTypeInformation
} else {
    $SecEventLogs = Import-Csv -Path $SecEventSyncLogPath
}

# Begin Section - AzureATP
$AzureATP_SecEvents = Get-LrtAzSecurityAlerts -AzureATP -Status 'newAlert'
$AzureATP_LoggedEvents = $SecEventLogs | Where-Object -Property "type" -like "AzureATP"

# Loop through results and proceed to process identified new events
ForEach ($SecurityEvent in $AzureATP_SecEvents) {
    if ($AzureATP_LoggedEvents.Id -notcontains $SecurityEvent.Id) {
        # New Event
        # Establish Log Entry
        $SecEvent = [PSCustomObject]@{
            log_timestamp = (get-date -Format yyyy-MM-ddTHH:mm:ss:ffffffK)
            event_timestamp = $SecurityEvent.createdDateTime
            type = "AzureATP"
            id = $SecurityEvent.id
            azureTenantId = $SecurityEvent.azureTenantId
            severity = $SecurityEvent.severity
        }

        # Write out JSON event for FileBeat
        Try {
            if (!(Test-Path $FB_AzureATP_Path -PathType Leaf)) {
                $SecurityEvent | ConvertTo-Json | Out-File -FilePath $FB_AzureATP_Path
            } else {
                $SecurityEvent | ConvertTo-Json | Out-File -FilePath $FB_AzureATP_Path -Append
            }
            
            # Record Log Entry
            Try {
                $SecEvent | Export-Csv -Path $SecEventSyncLogPath -NoTypeInformation -Append
            } Catch {
                Write-Host $_
            }
        } Catch {
            Write-Host $_
        }
    }
}

# End Section - AzureATP

# Begin Section - AzureSecurityCenter
$AzureSecurityCenter_SecEvents = Get-LrtAzSecurityAlerts -AzureSecurityCenter -Status 'newAlert'
$AzureSecurityCenter_LoggedEvents = $SecEventLogs | Where-Object -Property "type" -like "AzureSecurityCenter"

# Loop through results and proceed to process identified new events
ForEach ($SecurityEvent in $AzureSecurityCenter_SecEvents) {
    if ($AzureSecurityCenter_LoggedEvents.Id -notcontains $SecurityEvent.Id) {
        # New Event
        # Establish Log Entry
        $SecEvent = [PSCustomObject]@{
            log_timestamp = (get-date -Format yyyy-MM-ddTHH:mm:ss:ffffffK)
            event_timestamp = $SecurityEvent.createdDateTime
            type = "AzureSecurityCenter"
            id = $SecurityEvent.id
            azureTenantId = $SecurityEvent.azureTenantId
            severity = $SecurityEvent.severity
        }

        # Write out JSON event for FileBeat
        Try {
            if (!(Test-Path $FB_AzureSecurityCenter_Path -PathType Leaf)) {
                $SecurityEvent | ConvertTo-Json | Out-File -FilePath $FB_AzureSecurityCenter_Path
            } else {
                $SecurityEvent | ConvertTo-Json | Out-File -FilePath $FB_AzureSecurityCenter_Path -Append
            }
            
            # Record Log Entry
            Try {
                $SecEvent | Export-Csv -Path $SecEventSyncLogPath -NoTypeInformation -Append
            } Catch {
                Write-Host $_
            }
        } Catch {
            Write-Host $_
        }
    }
}
# End Section - AzureSecurityCenter

# Begin Section - MCAS
$MCAS_SecEvents = Get-LrtAzSecurityAlerts -MCAS -Status 'newAlert'
$MCAS_LoggedEvents = $SecEventLogs | Where-Object -Property "type" -like "MCAS"

# Loop through results and proceed to process identified new events
ForEach ($SecurityEvent in $MCAS_SecEvents) {
    if ($MCAS_LoggedEvents.Id -notcontains $SecurityEvent.Id) {
        # New Event
        # Establish Log Entry
        $SecEvent = [PSCustomObject]@{
            log_timestamp = (get-date -Format yyyy-MM-ddTHH:mm:ss:ffffffK)
            event_timestamp = $SecurityEvent.createdDateTime
            type = "MCAS"
            id = $SecurityEvent.id
            azureTenantId = $SecurityEvent.azureTenantId
            severity = $SecurityEvent.severity
        }

        # Write out JSON event for FileBeat
        Try {
            if (!(Test-Path $FB_MCAS_Path -PathType Leaf)) {
                $SecurityEvent | ConvertTo-Json | Out-File -FilePath $FB_MCAS_Path
            } else {
                $SecurityEvent | ConvertTo-Json | Out-File -FilePath $FB_MCAS_Path -Append
            }
            
            # Record Log Entry
            Try {
                $SecEvent | Export-Csv -Path $SecEventSyncLogPath -NoTypeInformation -Append
            } Catch {
                Write-Host $_
            }
        } Catch {
            Write-Host $_
        }
    }
}
# End Section - MCAS

# Begin Section - AzureADIdentityProtection
$AzureADIdentityProtection_SecEvents = Get-LrtAzSecurityAlerts -AzureADIdentityProtection -Status 'newAlert'
$AzureADIdentityProtection_LoggedEvents = $SecEventLogs | Where-Object -Property "type" -like "AzureADIdentityProtection"

# Loop through results and proceed to process identified new events
ForEach ($SecurityEvent in $AzureADIdentityProtection_SecEvents) {
    if ($AzureADIdentityProtection_LoggedEvents.Id -notcontains $SecurityEvent.Id) {
        # New Event
        # Establish Log Entry
        $SecEvent = [PSCustomObject]@{
            log_timestamp = (get-date -Format yyyy-MM-ddTHH:mm:ss:ffffffK)
            event_timestamp = $SecurityEvent.createdDateTime
            type = "AzureADIdentityProtection"
            id = $SecurityEvent.id
            azureTenantId = $SecurityEvent.azureTenantId
            severity = $SecurityEvent.severity
        }

        # Write out JSON event for FileBeat
        Try {
            if (!(Test-Path $FB_AzureADIdentityProtection_Path -PathType Leaf)) {
                $SecurityEvent | ConvertTo-Json | Out-File -FilePath $FB_AzureADIdentityProtection_Path
            } else {
                $SecurityEvent | ConvertTo-Json | Out-File -FilePath $FB_AzureADIdentityProtection_Path -Append
            }
            
            # Record Log Entry
            Try {
                $SecEvent | Export-Csv -Path $SecEventSyncLogPath -NoTypeInformation -Append
            } Catch {
                Write-Host "Unable to append to file: $SecEventSyncLogPath"
            }
        } Catch {
            Write-Host $_
        }
    }
}

# End Section - AzureADIdentityProtection

# Begin Section - AzureSentinel
$AzureSentinel_SecEvents = Get-LrtAzSecurityAlerts -MCAS -Status 'newAlert'
$AzureSentinel_LoggedEvents = $SecEventLogs | Where-Object -Property "type" -like "MCAS"

# Loop through results and proceed to process identified new events
ForEach ($SecurityEvent in $AzureSentinel_SecEvents) {
    if ($AzureSentinel_LoggedEvents.Id -notcontains $SecurityEvent.Id) {
        # New Event
        # Establish Log Entry
        $SecEvent = [PSCustomObject]@{
            log_timestamp = (get-date -Format yyyy-MM-ddTHH:mm:ss:ffffffK)
            event_timestamp = $SecurityEvent.createdDateTime
            type = "AzureSentinel"
            id = $SecurityEvent.id
            azureTenantId = $SecurityEvent.azureTenantId
            severity = $SecurityEvent.severity
        }

        # Write out JSON event for FileBeat
        Try {
            if (!(Test-Path $FB_AzureSentinel_Path -PathType Leaf)) {
                $SecurityEvent | ConvertTo-Json | Out-File -FilePath $FB_AzureSentinel_Path
            } else {
                $SecurityEvent | ConvertTo-Json | Out-File -FilePath $FB_AzureSentinel_Path -Append
            }
            
            # Record Log Entry
            Try {
                $SecEvent | Export-Csv -Path $SecEventSyncLogPath -NoTypeInformation -Append
            } Catch {
                Write-Host $_
            }
        } Catch {
            Write-Host $_
        }
    }
}
# End Section - AzureSentinel

# Begin Section - DefenderATP
$DefenderATP_SecEvents = Get-LrtAzSecurityAlerts -DefenderATP -Status 'newAlert'
$DefenderATP_LoggedEvents = $SecEventLogs | Where-Object -Property "type" -like "DefenderATP"

# Loop through results and proceed to process identified new events
ForEach ($SecurityEvent in $DefenderATP_SecEvents) {
    if ($DefenderATP_LoggedEvents.Id -notcontains $SecurityEvent.Id) {
        # New Event
        # Establish Log Entry
        $SecEvent = [PSCustomObject]@{
            log_timestamp = (get-date -Format yyyy-MM-ddTHH:mm:ss:ffffffK)
            event_timestamp = $SecurityEvent.createdDateTime
            type = "DefenderATP"
            id = $SecurityEvent.id
            azureTenantId = $SecurityEvent.azureTenantId
            severity = $SecurityEvent.severity
        }

        # Write out JSON event for FileBeat
        Try {
            if (!(Test-Path $FB_DefenderATP_Path -PathType Leaf)) {
                $SecurityEvent | ConvertTo-Json | Out-File -FilePath $FB_DefenderATP_Path
            } else {
                $SecurityEvent | ConvertTo-Json | Out-File -FilePath $FB_DefenderATP_Path -Append
            }
            
            # Record Log Entry
            Try {
                $SecEvent | Export-Csv -Path $SecEventSyncLogPath -NoTypeInformation -Append
            } Catch {
                Write-Host $_
            }
        } Catch {
            Write-Host $_
        }
    }
}
# End Section - DefenderATP