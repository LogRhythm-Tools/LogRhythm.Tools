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
            
            # User States
            if ($null -ne $SecEvent.userStates) {
                $UserStates = [list[object]]::new()
                ForEach ($UserState in $SecEvent.userStates) {
                    if ($UserStates -notcontains $UserState) {
                        $UserStates.add($UserState)
                        
                    }
                }
                $UserStateCount = $UserStates.count
            }
            
            # Host States
            if ($null -ne $SecEvent.hostStates) {
                $HostStates = [list[object]]::new()
                ForEach ($HostState in $SecEvent.hostStates) {
                    if ($HostStates -notcontains $HostState) {
                        $HostStates.add($HostState)
                    }
                }
                $HostStateCount = $HostStates.count
            }

            # VulnerabilityStates
            if ($null -ne $SecEvent.vulnerabilityStates) {
                $VulnStates = [list[object]]::new()
                ForEach ($VulnState in $SecEvent.vulnerabilityStates) {
                    if ($VulnStates -notcontains $VulnState) {
                        $VulnStates.add($VulnState)
                    }
                }
                $VulnStateCount = $VulnStates.count
            }

            # UserClickSecurityStates

            # CloudAppStates
            if ($null -ne $SecEvent.cloudAppStates) {
                $AppStates = [list[object]]::new()
                ForEach ($AppState in $SecEvent.cloudAppStates) {
                    if ($AppStates -notcontains $AppState) {
                        $AppStates.add($AppState)
                    }
                }
                $AppStateCount = $AppStates.count
            }

            # FileStates
            if ($null -ne $SecEvent.fileStates) {
                $FileStates = [list[object]]::new()
                ForEach ($FileState in $SecEvent.fileStates) {
                    if ($FileStates -notcontains $FileState) {
                        $FileStates.add($FileState)
                    }
                }
                $FileStateCount = $FileStates.count
            }

            # InvestigationSecurityStates

            # MalwareStates
            if ($null -ne $SecEvent.malwareStates) {
                $MalwareStates = [list[object]]::new()
                ForEach ($MalwareState in $SecEvent.malwareStates) {
                    if ($MalwareStates -notcontains $MalwareState) {
                        $MalwareStates.add($MalwareState)
                    }
                }
                $MalwareStateCount = $MalwareStates.count
            }

            # MessageSecurityStates
            if ($null -ne $SecEvent.messageSecurityStates) {
                $MsgSecStates = [list[object]]::new()
                ForEach ($MsgSecState in $SecEvent.messageSecurityStates) {
                    if ($MsgSecStates -notcontains $MsgSecState) {
                        $MsgSecStates.add($MsgSecState)
                    }
                }
                $MsgSecStateCount = $MsgSecStates.count
            }

            # NetworkConnections
            if ($null -ne $SecEvent.networkConnections) {
                $NetConStates = [list[object]]::new()
                ForEach ($NetConState in $SecEvent.networkConnections) {
                    if ($NetConStates -notcontains $NetConState) {
                        $NetConStates.add($NetConState)
                    }
                }
                $NetConStateCount = $NetConStates.count
            }

            # Processes
            if ($null -ne $SecEvent.processes) {
                $ProcessesStates = [list[object]]::new()
                ForEach ($ProcessesState in $SecEvent.processes) {
                    if ($ProcessesStates -notcontains $ProcessesState) {
                        $ProcessesStates.add($ProcessesState)
                    }
                }
                $ProcessesStateCount = $ProcessesStates.count
            }

            # RegistryKeyStates

            # Security Resources

            # Triggers

            # Processes
            if ($null -ne $SecEvent.recommendedActions) {
                $RecommendedActions = [list[object]]::new()
                ForEach ($RecommendedAction in $SecEvent.recommendedActions) {
                    if ($RecommendedActions -notcontains $RecommendedAction) {
                        $RecommendedActions.add($RecommendedAction)
                    }
                }
                $RecommendedActionCount = $RecommendedActions.count
            }

            # 
            # Global alert parsing
            $OCLog = [PSCustomObject]@{
                tag1 = $SecEvent.vendorInformation.provider
                tag2 = $SecEvent.category
                object = $SecEvent.vendorInformation.provider
                objecttype = 'BaseAlert'
                severity = $SecEvent.severity
                vmid = $SecEvent.azureSubscriptionId
                policy = $SecEvent.category
                serialnumber = $SecEvent.azureTenantId
                session = $SecEvent.id
                reason = $SecEvent.description
                status = $SecEvent.status
                quantity = $null
                amount = $null
                threatname = $SecEvent.title
                threatid = $null
                dname = $null
                sname = $null
                hash = $null
                account = $null
                login = $null
                sip = $null
                dip = $null
                snatip = $null
                dnatip = $null
                process = $null
                useragent = $null
                size = $null
                domainorigin = $null
                domainimpacted = $null
                action = $null
                vendorinfo = $null
                url = $null
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

            # Seen in MCAS
            if ($SecEvent.cloudAppStates.destinationServiceIp) {
                $OCLog | Add-Member -MemberType NoteProperty -Name 'dip' -Value $SecEVent.cloudAppStates.destinationServiceIp -Force
            }

            if ($SecEvent.sourceMaterials) {
                $EventCurrent = 0
                $OCLog.quantity = $($SecEvent.sourceMaterials | Sort-Object -Unique).count
                $OCLog.objecttype = 'SourceMaterials'
                ForEach ($SourceMaterial in $($SecEvent.sourceMaterials | Sort-Object -Unique)) {
                    $EventCurrent++
                    $OCLog.amount = $EventCurrent

                    $OCLog.vendorinfo = $SourceMaterial
                    $OCLog.url = $SourceMaterial

                    Try {
                        Invoke-RestMethod -Method 'post' -uri $OCendpoint -Headers @{'Content-Type' = 'application/json; charset=utf-8'} -Body $($OCLog | ConvertTo-Json -Depth 10 -Compress) | Out-Null
                    } Catch {
                        Write-Host $_
                    }
                    $OCLog.vendorinfo = $null
                    $OCLog.url = $null
                }

            }

            # File States
            if ($FileStates) {
                $EventCurrent = 0
                $OCLog.quantity = $FileStateCount
                $OCLog.objecttype = 'FileState'
                ForEach ($FileState in $FileStates) {
                    $EventCurrent++
                    $OCLog.amount = $EventCurrent

                    # Capture File Names
                    if ($FileState.name) {
                        $OCLog.process = $FileState.name
                    }

                    # Capture File Hashes
                    if ($FileState.fileHash) {
                        $OCLog.hash = $FileState.fileHash
                    }

                    Try {
                        Invoke-RestMethod -Method 'post' -uri $OCendpoint -Headers @{'Content-Type' = 'application/json; charset=utf-8'} -Body $($OCLog | ConvertTo-Json -Depth 10 -Compress) | Out-Null
                    } Catch {
                        Write-Host $_
                    }
                    $OCLog.process = $null
                    $OCLog.hash = $null
                }
            }


            if ($MalwareStates) {
                $EventCurrent = 0
                $OCLog.quantity = $MalwareStateCount
                $OCLog.objecttype = 'MalwareState'
                ForEach ($MalwareState in $MalwareStates) {
                    $EventCurrent++
                    $OCLog.amount = $EventCurrent

                    # Capture Malware Name as ThreatID 
                    if ($MalwareState.name) {
                        $OCLog.threatid = $MalwareState.name
                    }


                    Try {
                        Invoke-RestMethod -Method 'post' -uri $OCendpoint -Headers @{'Content-Type' = 'application/json; charset=utf-8'} -Body $($OCLog | ConvertTo-Json -Depth 10 -Compress)  | Out-Null
                    } Catch {
                        Write-Host $_
                    }
                    $OCLog.threatid = $null
                }
                
            }


            if ($HostStates) {
                $EventCurrent = 0
                $OCLog.quantity = $HostStateCount
                ForEach ($HostState in $HostStates) {
                    $EventCurrent++
                    $OCLog.amount = $EventCurrent
                    $OCLog.objecttype = 'HostState'
                    if ($HostState.fqdn) {
                        $OCLog.sname = $HostState.fqdn
                    } elseif ($HostState.netBiosName) {
                        $OCLog.sname = $HostState.fqdn
                    }
    
                    if ($HostState.isAzureAdJoined) {
    
                    }
    
                    if ($HostState.isAzureAdRegistered) {
    
                    }
    
                    if ($HostState.isHybridAzureDomainJoined) {
    
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
                }
            }
            
            # Submit one log for each UserState entry
            if ($UserStates) {
                $EventCurrent = 0
                $OCLog.quantity = $UserStateCount
                $OCLog.objecttype = 'UserStates'
                ForEach ($UserState in $UserStates) {
                    $EventCurrent++
                    $OCLog.amount = $EventCurrent
                    if ($UserState.userPrincipalName) {
                        $OCLog.login = $UserState.userPrincipalName
                    }
    
                    if ($UserState.logonIp) {
                        $OCLog.sip = $UserState.logonIp
                    }
    
                    if ($UserState.domainName) {
                        $OCLog.domainorigin = $UserState.domainName
                    }
                    Try {
                        Invoke-RestMethod -Method 'post' -uri $OCendpoint -Headers @{'Content-Type' = 'application/json; charset=utf-8'} -Body $($OCLog | ConvertTo-Json -Depth 10 -Compress)  | Out-Null
                    } Catch {
                        Write-Host $_
                    }
                    $OCLog.login = $null
                    $OCLog.sip = $null
                    $OCLog.domainorigin = $null
                }
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