using namespace System.Collections.Generic
Import-Module LogRhythm.Tools
# Set home folder for Sync to read/write content to.
#$RootFolderPath = "/opt/logrhythm/lrtools_azure_securityevents"
$RootFolderPath = "C:\LogRhythm\Tools\AzureSecEvents"
$SecEventSyncLog = "azure_synclog.csv"


# Cleanup Alert entries older than 90 days from the SecEventSyncLog
$CleanupDate = (Get-Date).AddDays(-90).Date


# OpenCollector Webhook Endpoint
$OCEndpoint = 'http://172.17.5.20:8080/webhook'


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
}

# Load in Security Events Log
$SecEventLogs = Import-Csv -Path $SecEventSyncLogPath

# Begin Section - AzureATP
$AzureATP_SecEvents = Get-LrtAzSecurityAlerts -AzureATP -Status 'newAlert'
$AzureATP_LoggedEvents = $SecEventLogs | Where-Object -Property "type" -like "AzureATP"


# Loop through results and proceed to process identified new events
ForEach ($AZAtpSecurityEvent in $AzureATP_SecEvents) {
    if ($AzureATP_LoggedEvents.Id -notcontains $AZAtpSecurityEvent.Id) {
        # New Event
        # Establish Log Entry
        $SecEvent = [PSCustomObject]@{
            log_timestamp = (get-date -Format yyyy-MM-ddTHH:mm:ss:ffffffK)
            event_timestamp = $AZAtpSecurityEvent.createdDateTime
            type = "AzureATP"
            id = $AZAtpSecurityEvent.id
            azureTenantId = $AZAtpSecurityEvent.azureTenantId
            severity = $AZAtpSecurityEvent.severity
        }

        # Write out JSON event for FileBeat
        Try {
            Invoke-RestMethod -Method 'post' -uri $OCendpoint -Headers @{'Content-Type' = 'application/json; charset=utf-8'} -Body $($AZAtpSecurityEvent | ConvertTo-Json -Depth 50 -Compress)
             
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
ForEach ($AzSecCenSecurityEvent in $AzureSecurityCenter_SecEvents) {
    if ($AzureSecurityCenter_LoggedEvents.Id -notcontains $AzSecCenSecurityEvent.Id) {
        # New Event
        # Establish Log Entry
        $SecEvent = [PSCustomObject]@{
            log_timestamp = (get-date -Format yyyy-MM-ddTHH:mm:ss:ffffffK)
            event_timestamp = $AzSecCenSecurityEvent.createdDateTime
            type = "AzureSecurityCenter"
            id = $AzSecCenSecurityEvent.id
            azureTenantId = $AzSecCenSecurityEvent.azureTenantId
            severity = $AzSecCenSecurityEvent.severity
        }

        # Write out JSON event for FileBeat
        Try {
            Invoke-RestMethod -Method 'post' -uri $OCendpoint -Headers @{'Content-Type' = 'application/json; charset=utf-8'} -Body $($AzSecCenSecurityEvent | ConvertTo-Json -Depth 50 -Compress)
            
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
ForEach ($MCASSecurityEvent in $MCAS_SecEvents) {
    if ($MCAS_LoggedEvents.Id -notcontains $MCASSecurityEvent.Id) {
        # New Event
        # Establish Log Entry
        $SecEvent = [PSCustomObject]@{
            log_timestamp = (get-date -Format yyyy-MM-ddTHH:mm:ss:ffffffK)
            event_timestamp = $MCASSecurityEvent.createdDateTime
            type = "MCAS"
            id = $MCASSecurityEvent.id
            azureTenantId = $MCASSecurityEvent.azureTenantId
            severity = $MCASSecurityEvent.severity
        }

        $MCASSecurityEvent | Add-Member -MemberType NoteProperty -Name "tag" -Value "AZURE_MCAS" -Force

        # Write out JSON event for FileBeat
        Try {
            Invoke-RestMethod -Method 'post' -uri $OCendpoint -Headers @{'Content-Type' = 'application/json; charset=utf-8'} -Body $($MCASSecurityEvent | ConvertTo-Json -Depth 50 -Compress)
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
ForEach ($AZADIdProtSecurityEvent in $AzureADIdentityProtection_SecEvents) {
    if ($AzureADIdentityProtection_LoggedEvents.Id -notcontains $AZADIdProtSecurityEvent.Id) {
        # New Event
        # Establish Log Entry
        $SecEvent = [PSCustomObject]@{
            log_timestamp = (get-date -Format yyyy-MM-ddTHH:mm:ss:ffffffK)
            event_timestamp = $AZADIdProtSecurityEvent.createdDateTime
            type = "AzureADIdentityProtection"
            id = $AZADIdProtSecurityEvent.id
            azureTenantId = $AZADIdProtSecurityEvent.azureTenantId
            severity = $AZADIdProtSecurityEvent.severity
        }

        # Write out JSON event for FileBeat
        Try {
            Invoke-RestMethod -Method 'post' -uri $OCendpoint -Headers @{'Content-Type' = 'application/json; charset=utf-8'} -Body $($AZADIdProtSecurityEvent | ConvertTo-Json -Depth 50 -Compress)

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
$AzureSentinel_SecEvents = Get-LrtAzSecurityAlerts -AzureSentinel -Status 'newAlert'
$AzureSentinel_LoggedEvents = $SecEventLogs | Where-Object -Property "type" -like "AzureSentinel"

# Loop through results and proceed to process identified new events
ForEach ($AZSentSecurityEvent in $AzureSentinel_SecEvents) {
    if ($AzureSentinel_LoggedEvents.Id -notcontains $AZSentSecurityEvent.Id) {
        # New Event
        # Establish Log Entry
        $SecEvent = [PSCustomObject]@{
            log_timestamp = (get-date -Format yyyy-MM-ddTHH:mm:ss:ffffffK)
            event_timestamp = $AZSentSecurityEvent.createdDateTime
            type = "AzureSentinel"
            id = $AZSentSecurityEvent.id
            azureTenantId = $AZSentSecurityEvent.azureTenantId
            severity = $AZSentSecurityEvent.severity
        }

        # Write out JSON event for FileBeat
        Try {
            Invoke-RestMethod -Method 'post' -uri $OCendpoint -Headers @{'Content-Type' = 'application/json; charset=utf-8'} -Body $($AZSentSecurityEvent | ConvertTo-Json -Depth 50 -Compress)
            
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
ForEach ($DefSecurityEvent in $DefenderATP_SecEvents) {
    if ($DefenderATP_LoggedEvents.Id -notcontains $DefSecurityEvent.Id) {
        # New Event
        # Establish Log Entry
        $SecEvent = [PSCustomObject]@{
            log_timestamp = (get-date -Format yyyy-MM-ddTHH:mm:ss:ffffffK)
            event_timestamp = $DefSecurityEvent.createdDateTime
            type = "DefenderATP"
            id = $DefSecurityEvent.id
            azureTenantId = $DefSecurityEvent.azureTenantId
            severity = $DefSecurityEvent.severity
        }

        # Write out JSON event for FileBeat
        Try {
            Invoke-RestMethod -Method 'post' -uri $OCendpoint -Headers @{'Content-Type' = 'application/json; charset=utf-8'} -Body $($DefSecurityEvent | ConvertTo-Json -Depth 50 -Compress)
            
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
