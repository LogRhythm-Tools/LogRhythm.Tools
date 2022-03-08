using namespace System.Collections.Generic
Import-Module LogRhythm.Tools
# Set home folder for Sync to read/write content to.
#$RootFolderPath = "/opt/logrhythm/lrtools_azure_securityevents"
$RootFolderPath = "C:\LogRhythm\Tools\AzureSecEvents"
$SecEventSyncLog = "azure_synclog.csv"


# Cleanup Alert entries older than 90 days from the SecEventSyncLog
$CleanupDate = (Get-Date).AddDays(-90).Date


# OpenCollector Webhook Endpoint
$OCEndpoint = 'http://172.17.5.20:8085/webhook'

# Enable Azure Alert Providers
$AZAlertProviders = [List[string]]::new()
$AZAlertProviders.add('AzureATP')
$AZAlertProviders.add('AzureSecurityCenter')
$AZAlertProviders.add('MCAS')
$AZAlertProviders.add('AzureADIdentityProtection')
$AZAlertProviders.add('DefenderATP')
$AZAlertProviders.add('AzureSentinel')


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

ForEach ($AZAlertProvider in $AZAlertProviders) {
    write-host "Processing: $AZAlertProvider"
    switch ($AZAlertProvider) {
        'AzureATP' { $SecEvents = Get-LrtAzSecurityAlerts -AzureATP -Status 'newAlert' }
        'AzureSecurityCenter' { $SecEvents = Get-LrtAzSecurityAlerts -AzureSecurityCenter -Status 'newAlert' }
        'MCAS' { $SecEvents = Get-LrtAzSecurityAlerts -MCAS -Status 'newAlert' }
        'AzureADIdentityProtection' { $SecEvents = Get-LrtAzSecurityAlerts -AzureADIdentityProtection -Status 'newAlert' }
        'DefenderATP' { $SecEvents = Get-LrtAzSecurityAlerts -DefenderATP -Status 'newAlert' }
        'AzureSentinel' { $SecEvents = Get-LrtAzSecurityAlerts -AzureSentinel -Status 'newAlert' }
    }

    $LoggedEvents = $SecEventLogs | Where-Object -Property "type" -like $AZAlertProvider 

    ForEach ($SecEvent in $SecEvents) {
        if ($LoggedEvents.Id -notcontains $SecEvent.Id) {
            # Establish log entry.
            $LoggedEvent = [PSCustomObject]@{
                log_timestamp = (get-date -Format yyyy-MM-ddTHH:mm:ss:ffffffK)
                event_timestamp = $SecEvent.createdDateTime
                type = $AZAlertProvider
                id = $SecEvent.id
                azureTenantId = $SecEvent.azureTenantId
                severity = $SecEvent.severity
            }

            # Global alert parsing
            $OCLog = [PSCustomObject]@{
                tag1 = $SecEvent.vendorInformation.provider
                tag2 = $SecEvent.category
                object = $SecEvent.vendorInformation.provider
                severity = $SecEvent.severity
                policy = $SecEvent.category
                vmid = $SecEvent.azureSubscriptionId
                serialnumber = $SecEvent.azureTenantId
                session = $SecEvent.id
                reason = $SecEvent.description
                status = $SecEvent.status
                threatname = $SecEvent.title
                # These properties change as the objecttype shifts from BaseAlert to the other alert elements
                # The updates to these metadata values align to the same usecase and purpose of the values set on the BaseAlert.
                objecttype = 'BaseAlert'
                size = $SecEvent.riskScore
                vendorinfo = 'https://docs.microsoft.com/en-us/graph/api/resources/alert?view=graph-rest-1.0'
                
                dname = $null
                domainorigin = $null
                domainimpacted = $null
                account = $null
                action = $null
                amount = $null
                dip = $null
                dnatip = $null
                dport = $null
                hash = $null
                login = $null
                objectname = $null
                process = $null
                processid = $null
                parentprocessname = $null
                parentprocesspath = $null
                parentprocessid = $null
                quantity = $null
                sessiontype = $null
                sip = $null
                snatip = $null
                sname = $null
                subject = $null
                sport = $null
                threatid = $null
                url = $null
                useragent = $null   
                "timestamp.iso8601" = $('{0:yyyy-MM-ddTHH:mm:ssZ}' -f $($([DateTime]$SecEvent.createdDateTime).ToUniversalTime()))
                original_message = $SecEvent
                whsdp = $true
                fullyqualifiedbeatname = "webhookbeat_AzureGraph-$($SecEvent.vendorInformation.provider.replace(' ',''))"
            }
            # (get-date -Format yyyy-MM-ddTHH:mm:ssZ) 
            Try {
                Invoke-RestMethod -Method 'post' -uri $OCendpoint -Headers @{'Content-Type' = 'application/json; charset=utf-8'} -Body $($OCLog | ConvertTo-Json -Depth 10 -Compress) | Out-Null
            } Catch {
                Write-Host $_
            }

            if ($null -ne $SecEvent.cloudAppStates) {
                $EventCurrent = 0
                $OCLog.quantity = $SecEvent.cloudAppStates.count
                $OCLog.objecttype = 'CloudAppState'
                ForEach ($CloudAppState in $SecEvent.cloudAppStates) {
                    $EventCurrent++
                    $OCLog.amount = $EventCurrent

                    # Capture Destination Service IP
                    if ($CloudAppState.destinationServiceIp) {
                        $OCLog.dip = $CloudAppState.destinationServiceIp
                    }

                    # Capture DestinationServiceName 
                    if ($CloudAppState.destinationServiceName) {
                        $OCLog.process = $CloudAppState.destinationServiceName
                    }

                    # Capture CloudAppState Risk Score
                    if ($CloudAppState.riskScore) {
                        $OCLog.size = $CloudAppState.riskScore
                    }

                    $OCLog.vendorinfo = 'https://docs.microsoft.com/en-us/graph/api/resources/cloudappsecuritystate?view=graph-rest-1.0'

                    Try {
                        Invoke-RestMethod -Method 'post' -uri $OCendpoint -Headers @{'Content-Type' = 'application/json; charset=utf-8'} -Body $($OCLog | ConvertTo-Json -Depth 10 -Compress) | Out-Null
                    } Catch {
                        Write-Host $_
                    }
                    $OCLog.dip = $null
                    $OCLog.process = $null
                    $OCLog.size = $null
                    $OCLog.vendorinfo = $null
                }
                $OCLog.quantity = $null
                $OCLog.objecttype = $null
            }

            if ($SecEvent.sourceMaterials) {
                $EventCurrent = 0
                $OCLog.quantity = $($SecEvent.sourceMaterials | Sort-Object -Unique).count
                $OCLog.objecttype = 'SourceMaterials'
                ForEach ($SourceMaterial in $($SecEvent.sourceMaterials | Sort-Object -Unique)) {
                    $EventCurrent++
                    $OCLog.amount = $EventCurrent

                    $OCLog.url = $SourceMaterial

                    $OCLog.vendorinfo = 'https://docs.microsoft.com/en-us/graph/api/resources/alert?view=graph-rest-1.0'

                    Try {
                        Invoke-RestMethod -Method 'post' -uri $OCendpoint -Headers @{'Content-Type' = 'application/json; charset=utf-8'} -Body $($OCLog | ConvertTo-Json -Depth 10 -Compress) | Out-Null
                    } Catch {
                        Write-Host $_
                    }
                    $OCLog.vendorinfo = $null
                    $OCLog.url = $null
                }
                $OCLog.quantity = $null
                $OCLog.objecttype = $null
            }

            # File States
            if ($null -ne $SecEvent.fileStates) {
                $EventCurrent = 0
                $OCLog.quantity = $SecEvent.fileStates.count
                $OCLog.objecttype = 'FileState'
                ForEach ($FileState in $SecEvent.fileStates) {
                    $EventCurrent++
                    $OCLog.amount = $EventCurrent

                    # Capture File Names
                    if ($FileState.fileHash.hashValue) {
                        $OCLog.hash = $FileState.fileHash.hashValue
                    }

                    # Capture File Hashes
                    if ($FileState.fileHash.hashType) {
                        $OCLog.objectname = $FileState.fileHash.hashType
                    }

                    if ($FileState.name) {
                        $OCLog.process = $FileState.name
                    }

                    if ($FileState.riskScore) {
                        $OCLog.size = $FileState.riskScore
                    }

                    $OCLog.vendorinfo = 'https://docs.microsoft.com/en-us/graph/api/resources/filesecuritystate?view=graph-rest-1.0'

                    Try {
                        Invoke-RestMethod -Method 'post' -uri $OCendpoint -Headers @{'Content-Type' = 'application/json; charset=utf-8'} -Body $($OCLog | ConvertTo-Json -Depth 10 -Compress) | Out-Null
                    } Catch {
                        Write-Host $_
                    }
                    $OCLog.process = $null
                    $OCLog.hash = $null
                    $OCLog.size = $null
                    $OCLog.objectname = $null
                    $OCLog.vendorinfo = $null
                }
                $OCLog.quantity = $null
                $OCLog.objecttype = $null
            }

            # Process States
            if ($null -ne $SecEvent.processes) {
                $EventCurrent = 0
                $OCLog.quantity = $SecEvent.processes.count
                $OCLog.objecttype = 'Process'
                ForEach ($Process in $SecEvent.processes) {
                    $EventCurrent++
                    $OCLog.amount = $EventCurrent

                    # Capture File Names
                    if ($Process.accountName) {
                        $OCLog.login = $Process.accountName
                    }

                    # Capture File Hashes
                    if ($Process.name) {
                        $OCLog.process = $Process.name
                    }

                    if ($Process.processId) {
                        $OCLog.processid = $Process.processId
                    }

                    if ($Process.commandLine) {
                        $OCLog.process = $Process.commandLine
                    }

                    if ($Process.parentProcessName) {
                        $OCLog.parentprocessname = $Process.parentProcessName
                    }

                    if ($Process.parentProcessId) {
                        $OCLog.parentprocessid = $Process.parentProcessId
                    }

                    if ($Process.fileHash.hashValue) {
                        $OCLog.hash = $Process.fileHash.hashValue
                    }

                    if ($Process.fileHash.hashType) {
                        $OCLog.subject = $Process.fileHash.hashType
                    }


                    $OCLog.vendorinfo = 'https://docs.microsoft.com/en-us/graph/api/resources/process?view=graph-rest-1.0'

                    Try {
                        Invoke-RestMethod -Method 'post' -uri $OCendpoint -Headers @{'Content-Type' = 'application/json; charset=utf-8'} -Body $($OCLog | ConvertTo-Json -Depth 10 -Compress) | Out-Null
                    } Catch {
                        Write-Host $_
                    }
                    $OCLog.process = $null
                    $OCLog.hash = $null
                    $OCLog.size = $null
                    $OCLog.objectname = $null
                    $OCLog.vendorinfo = $null
                }
                $OCLog.quantity = $null
                $OCLog.objecttype = $null
            }


            # Security Resources
            if ($null -ne $SecEvent.securityResources) {
                $EventCurrent = 0
                $OCLog.quantity = $SecEvent.securityResources.count
                $OCLog.objecttype = 'SecurityResource'
                ForEach ($SecResource in $SecEvent.securityResources) {
                    $EventCurrent++
                    $OCLog.amount = $EventCurrent

                    if ($SecResource.resource) {
                        $OCLog.objectname = $SecResource.resource
                    }
                    
                    if ($SecResource.resourceType) {
                        switch ($SecResource.resourceType) {
                            1 {$OCLog.subject = "The resource was attacked in the alert."}
                            2 {$OCLog.subject = "The resource is related to the alert, though not directly attacked."}
                            'attacked' {$OCLog.subject = "The resource was attacked in the alert."}
                            'related' {$OCLog.subject = "The resource is related to the alert, though not directly attacked."}
                            default {
                                $OCLog.subject = "The resource has not been defined as being attacked or related to the attack."
                            }
                        }
                        
                    }

                    $OCLog.vendorinfo = 'https://docs.microsoft.com/en-us/graph/api/resources/securityresource?view=graph-rest-1.0'

                    Try {
                        Invoke-RestMethod -Method 'post' -uri $OCendpoint -Headers @{'Content-Type' = 'application/json; charset=utf-8'} -Body $($OCLog | ConvertTo-Json -Depth 10 -Compress) | Out-Null
                    } Catch {
                        Write-Host $_
                    }

                    $OCLog.objectname = $null
                    $OCLog.subject = $null
                    $OCLog.vendorinfo = $null
                }
                $OCLog.quantity = $null
                $OCLog.objecttype = $null
            }



            # NetworkConnections
            if ($null -ne $SecEvent.networkConnections) {
                $EventCurrent = 0
                $OCLog.quantity = $SecEvent.networkConnections.count
                $OCLog.objecttype = 'NetworkConnection'
                ForEach ($NetConn in $SecEvent.networkConnections) {
                    $EventCurrent++
                    $OCLog.amount = $EventCurrent

                    if ($NetConn.sourceAddress) {
                        $OCLog.sip = $NetConn.sourceAddress
                    }

                    if ($NetConn.destinationAddress) {
                        $OCLog.dip = $NetConn.destinationAddress
                    }

                    if ($NetConn.sourcePort) {
                        $OCLog.sport = $NetConn.sourceAddress
                    }

                    if ($NetConn.destinationPort) {
                        $OCLog.dport = $NetConn.destinationPort
                    }

                    if ($NetConn.natSourceAddress) {
                        $OCLog.snatip = $NetConn.natSourceAddress
                    }

                    if ($NetConn.natDestinationAddress) {
                        $OCLog.dnatip = $NetConn.natDestinationAddress
                    }

                    if ($NetConn.destinationUrl) {
                        $OCLog.url = $NetCon.destinationUrl
                    }

                    if ($NetConn.riskScore) {
                        $OCLog.size = $NetConn.riskScore
                    }

                    $OCLog.vendorinfo = 'https://docs.microsoft.com/en-us/graph/api/resources/networkconnection?view=graph-rest-1.0'

                    Try {
                        Invoke-RestMethod -Method 'post' -uri $OCendpoint -Headers @{'Content-Type' = 'application/json; charset=utf-8'} -Body $($OCLog | ConvertTo-Json -Depth 10 -Compress) | Out-Null
                    } Catch {
                        Write-Host $_
                    }
                    $OCLog.sip = $null
                    $OCLog.dip = $null
                    $OCLog.hash = $null
                    $OCLog.url = $null
                    $OCLog.dnatip = $null
                    $OCLog.snatip = $null
                    $OCLog.dport = $null
                    $OCLog.sport = $null
                    $OCLog.size = $null
                    $OCLog.vendorinfo = $null
                }
                $OCLog.quantity = $null
                $OCLog.objecttype = $null
            }



            if ($null -ne $SecEvent.malwareStates) {
                $EventCurrent = 0
                $OCLog.quantity = $SecEvent.malwareStates.count
                $OCLog.objecttype = 'MalwareState'
                ForEach ($MalwareState in $SecEvent.malwareStates) {
                    $EventCurrent++
                    $OCLog.amount = $EventCurrent

                    # Capture Malware Name as ThreatID 
                    if ($MalwareState.name) {
                        $OCLog.threatid = $MalwareState.name
                    }

                    if ($MalwareState.category) {
                        $OCLog.objectname = $MalwareState.category
                    }

                    if ($MalwareStates.family) {
                        $OCLog.process = $MalwareState.family
                    }

                    if ($MalwareStates.severity) {
                        $OCLog.subject = $MalwareStates.severity
                    }

                    if ($MalwareStates.wasRunning) {
                        $OCLog.sessiontype = "Malware reported as running at the time of detection."
                    } else {
                        $OCLog.sessiontype = "Malware reported as not running at the time of detection."
                    }

                    $OCLog.vendorinfo = 'https://docs.microsoft.com/en-us/graph/api/resources/malwarestate?view=graph-rest-1.0'

                    Try {
                        Invoke-RestMethod -Method 'post' -uri $OCendpoint -Headers @{'Content-Type' = 'application/json; charset=utf-8'} -Body $($OCLog | ConvertTo-Json -Depth 10 -Compress)  | Out-Null
                    } Catch {
                        Write-Host $_
                    }
                    $OCLog.threatid = $null
                    $OCLog.process = $null
                    $OCLog.subject = $null
                    $OCLog.objectname = $null
                    $OCLog.sessiontype = $null
                    $OCLog.vendorinfo = $null
                }
                $OCLog.quantity = $null
                $OCLog.objecttype = $null
            }


            if ($null -ne $SecEvent.hostStates) {
                $EventCurrent = 0
                $OCLog.quantity = $SecEvent.hostStates.count
                ForEach ($HostState in $SecEvent.hostStates) {
                    $EventCurrent++
                    $OCLog.amount = $EventCurrent
                    $OCLog.objecttype = 'HostState'

                    if ($HostState.fqdn) {
                        $OCLog.sname = $HostState.fqdn
                    } elseif ($HostState.netBiosName) {
                        Try {
                            $netBNtoIP = [IPAddress] $HostState.netBiosName
                            if ($null -eq $HostState.privateIpAddress) {
                                $OCLog.sip = $netBNtoIP.IPAddressToString
                            }
                        } Catch {
                            $OCLog.sname = $HostState.netBiosName
                        }
                        
                    }
    
                    if ($HostState.isAzureAdJoined) {
                        $OCLog.sessiontype = "AzureAdJoined"
                    }
    
                    if ($HostState.isAzureAdRegistered) {
                        $OCLog.objectname = "AzureAdRegistered"
                    }

                    if ($HostState.isHybridAzureDomainJoined) {
                        $OCLog.subject = "HybridAzureDomainJoined"
                    }
    
                    if ($HostState.os) {
                        $OCLog.useragent = $HostState.os
                    }
    
                    if ($HostState.privateIpAddress) {
                        $OCLog.sip = $HostState.privateIpAddress
                    } 
                    
                    if ($HostState.publicIpAddress) {
                        $OCLog.snatip = $HostState.publicIpAddress
                    }
    
                    if ($HostState.riskScore) {
                        $OCLog.size = $HostState.riskScore
                    }

                    $OCLog.vendorinfo = 'https://docs.microsoft.com/en-us/graph/api/resources/hostsecuritystate?view=graph-rest-1.0'

                    Try {
                        Invoke-RestMethod -Method 'post' -uri $OCendpoint -Headers @{'Content-Type' = 'application/json; charset=utf-8'} -Body $($OCLog | ConvertTo-Json -Depth 10 -Compress)  | Out-Null
                    } Catch {
                        Write-Host $_
                    }
                    $OCLog.size = $null
                    $OCLog.snatip = $null
                    $OCLog.sip = $null
                    $OCLog.useragent = $null
                    $OCLog.sname = $null
                    $OCLog.subject = $null
                    $OCLog.objectname = $null
                    $OCLog.sessiontype = $null
                    $OCLog.vendorinfo = $null
                }
                $OCLog.quantity = $null
                $OCLog.objecttype = $null
            }

            
            # Submit one log for each UserState entry
            if ($null -ne $SecEvent.userStates) {
                $EventCurrent = 0
                $OCLog.quantity = $SecEvent.userStates.count
                $OCLog.objecttype = 'UserStates'
                ForEach ($UserState in $SecEvent.userStates) {
                    $EventCurrent++
                    $OCLog.amount = $EventCurrent

                    # Preference to userPrincipalName as this will be username+domainName 
                    if ($UserState.userPrincipalName) {
                        $OCLog.login = $UserState.userPrincipalName
                    } elseif ($UserState.accountName) {
                        $OCLog.login = $UserState.accountName
                    }

                    if ($UserState.aadUserId) {
                        $OCLog.subject = $UserState.aadUserId
                    }
    
                    if ($UserState.logonIp) {
                        $OCLog.sip = $UserState.logonIp
                    }

                    if ($UserState.isVpn) {
                        $OCLog.sessiontype = "VPN"
                    } elseif ($UserState.logonType) {
                        $OCLog.sessiontype = $UserState.logonType
                    }

                    if ($UserState.userAccountType) {
                        $OCLog.objectname = $UserState.userAccountType
                    }
    
                    if ($UserState.domainName) {
                        $OCLog.domainorigin = $UserState.domainName
                    }

                    if ($UserState.riskScore) {
                        $OCLog.size = $UserState.riskScore
                    }

                    $OCLog.vendorinfo = 'https://docs.microsoft.com/en-us/graph/api/resources/usersecuritystate?view=graph-rest-1.0'

                    Try {
                        Invoke-RestMethod -Method 'post' -uri $OCendpoint -Headers @{'Content-Type' = 'application/json; charset=utf-8'} -Body $($OCLog | ConvertTo-Json -Depth 10 -Compress)  | Out-Null
                    } Catch {
                        Write-Host $_
                    }
                    # Reset variables before proceeding to next state
                    $OCLog.amount = $null
                    $OCLog.login = $null
                    $OCLog.sip = $null
                    $OCLog.domainorigin = $null
                    $OCLog.size = $null
                    $OCLog.objectname = $null
                    $OCLog.sessiontype = $null
                    $OCLog.subject = $null
                    $OCLog.vendorinfo = $null
                }
                $OCLog.quantity = $null
                $OCLog.objecttype = $null
            }

            # Record Log Entry
            Try {
                $LoggedEvent | Export-Csv -Path $SecEventSyncLogPath -NoTypeInformation -Append
            } Catch {
                Write-Host $_
            }
        }
    }
    
}


# Refresh the $State variable from the appended CSV content.
$State = Import-Csv -Path $SecEventSyncLogPath
$StateCleanup = [list[object]]::new()
ForEach ($StateEntry in $State) {
    Try {
        $AlertDate = [DateTime]$StateEntry.event_timestamp
    } Catch {
        continue
    }
    if ($AlertDate -ge $CleanupDate) {
        $StateCleanup.add($StateEntry)
    }
}

# Overwrite the CSV State File representing only the entries that are valid within the script's configured $eventLookBack time period.
$StateCleanup | Export-Csv -Path $SecEventSyncLogPath -NoTypeInformation -Force