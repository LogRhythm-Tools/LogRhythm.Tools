using namespace System.Collections.Generic

## Manual Config Begin
# Array of Log Sources Names we want to Automatically Add
$LogSourceAdds = [list[object]]::new()
$LogSourceAdds.add([PSCustomObject]@{
    Name = "MS Windows Event Logging - Firewall With Advanced Security"
    Path = 'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall'
}) 

$LogSourceAdds.add([PSCustomObject]@{
    Name = "MS Windows Event Logging XML - Security"
    Path = 'Security'
})

$LogSourceAdds.add([PSCustomObject]@{
    Name = "MS Windows Event Logging XML - System"
    Path = 'System'
})

$LogSourceAdds.add([PSCustomObject]@{
    Name = "MS Windows Event Logging XML - Application"
    Path = 'Application'
})

$LogSourceRemoves = @("MS Windows Event Logging - System", "MS Windows Event Logging - Security", "MS Windows Event Logging - Application")

# Defines the amount of messages the LR Agent will retrieve per cycle
$MaxMsgCount = 2000

# Set log sources to LSO 2.0 policy where applicable 
$MPEv2 = $true
## Manual Config End

## Automation Begin
# Generate the Log Source IDs based on the LogSourceReqs defined
$LogSourceAddIds = [list[object]]::new()
ForEach ($LogSourceReq in $LogSourceAdds) {
    $LogSourceReqDetails = Get-LrLogSourceTypes -Name $($LogSourceReq.name)
    if (($LogSourceAddIds -notcontains $LogSourceReqDetails) -and ($null -ne $LogSourceReqDetails) -and ($null -eq $LogSourceDetails.Error)) {
        $LogSourceReqDetails | Add-Member -MemberType NoteProperty -Name 'Path' -Value $($LogSourceReq.Path)
        Write-Host "$(Get-TimeStamp) | Add Log Sources | Adding Request | Log Source Name: $($LogSourceReqDetails.name)"
        $LogSourceAddIds.add($LogSourceReqDetails)
    } else {
        if ($null -eq $LogSourceDetails.Error) {
            Write-Host "$(Get-TimeStamp) | Add Log Sources | Skipped Request | Log Source Name: $($LogSourceReq.name)"
        } else {
            Write-Host "$(Get-TimeStamp) | Add Log Sources | Request Error | Log Source Name: $($LogSourceReq.name)"
            write-host $LogSourceReqDetails.Error
        }
    }
}

$LogSourceRemIds = [list[object]]::new()
ForEach ($LogSourceReq in $LogSourceRemoves) {
    $LogSourceReqDetails = Get-LrLogSourceTypes -Name $LogSourceReq
    if (($LogSourceRemIds -notcontains $LogSourceReqDetails) -and ($null -ne $LogSourceReqDetails) -and ($null -eq $LogSourceDetails.Error)) {
        Write-Host "$(Get-TimeStamp) | Remove Log Sources | Adding Request | Log Source Name: $($LogSourceReqDetails.name)"
        $LogSourceRemIds.add($LogSourceReqDetails)
    } else {
        if ($null -eq $LogSourceDetails.Error) {
            Write-Host "$(Get-TimeStamp) | Remove Log Sources | Skipped Request | Log Source Name: $($LogSourceReq)"
        } else {
            Write-Host "$(Get-TimeStamp) | Remove Log Sources | Request Error | Log Source Name: $($LogSourceReq)"
            write-host $LogSourceReqDetails.Error
        }
    }
}

# Get Log Source IDs for the Log Source Types I want to automatically add
Write-Host "$(Get-TimeStamp) | Retrieving Active Agents | Begin"
$Agents = Get-LrAgentsAccepted -RecordStatus 'active' -AgentType 'Windows'
Write-Host "$(Get-TimeStamp) | Retrieving Active Agents | End"
$Counters = [PSCustomObject]@{
    TotalAgents = 0
    Add = 0
    Remove = 0
    AddError = 0
    RemoveError = 0
    AddSkip = 0
    RemoveSkip = 0
}
ForEach ($Agent in $Agents[500..$($Agents.count)]) {
    Write-Host "$(Get-TimeStamp) | Automation Runtime | Begin | Agent: $($Agent.hostName)"
    $Counters.TotalAgents += 1
    $LogSources = Get-LrAgentLogSources -Id $Agent.Id -RecordStatus active
    
    # Adds
    ForEach ($LogSourceAddId in $LogSourceAddIds) {
        if ($LogSources.logSourceType.id -notcontains $LogSourceAddId.id) {
            $AgentHost = Get-LrHostDetails -Id $Agent.hostId
            $LogSourceMPEPolicies = Get-LrMpePolicies -msgSourceTypeId $LogSourceAddId.id

            if ($MPEv2 -eq $true -and $LogSourceMPEPolicies.name -match ".*?V2\.0") {
                $MPEPolicy = $LogSourceMPEPolicies | Where-Object -FilterScript {$_.name -match ".*?V2\.0"}
            } else {
                $MPEPolicy = $LogSourceMPEPolicies | Where-Object -FilterScript {$_.name -match "LogRhythm Default"}
            }

            # Define $LogFilePath
            $LogFilePath = "$($Agent.hostname):$($LogSourceAddId.path)"
            $AddResult = Add-LrLogSource -systemMonitorId $Agent.id -name "$($Agent.hostName) | $($LogSourceAddId.abbreviation)" -hostId $($Agent.hostId) -entityId $($AgentHost.entity.id) -logSourceTypeId $($LogSourceAddId.id) -mpePolicyId $($MPEPolicy.id) -mpeProcessingMode 'EventForwardingEnabled' -maxMsgCount $MaxMsgCount -longDescription "$(Get-TimeStamp) | Log Source Added through automation from $($env:computername)" -filePath $LogFilePath -RecordStatus Active -Status Enabled
            if (($null -ne $AddResult.Error) -and ($AddResult.Error -eq $true)) {
                write-host $AddResult
                $Counters.AddError += 1
            } else {
                $Counters.Add += 1
                Write-Host "$(Get-TimeStamp) | Automation Runtime | Adding Logsource | Success | Agent: $($Agent.hostName) Log Source: $($LogSourceAddId.name)"
            }
            # Add it
        } else {
            $Counters.AddSkip += 1
            Write-Host "$(Get-TimeStamp) | Automation Runtime | Adding Logsource | Skip | Agent: $($Agent.hostName) Log Source: $($LogSourceAddId.name)"
        }
    }

    # Removes
    ForEach ($LogSource in $LogSources) {

        # Removals
        if ($LogSourceRemIds.id -contains $LogSource.logSourceType.id) {
            if ($LogSource.systemMonitorName -like $LogSource.host.name) {
                #Update-LrLogSource -Id $LogSource.id
                $UpdateResult = Update-LrLogSource -Id $($LogSource.id) -RecordStatus Retired
                if (($null -ne $UpdateResult.Error) -and ($UpdateResult.Error -eq $true)) {
                    write-host $UpdateResult
                    $Counters.RemoveError += 1
                } else {
                    $Counters.Remove += 1
                    Write-Host "$(Get-TimeStamp) | Automation Runtime | Retire Logsource | Success | Agent: $($Agent.hostName) Log Source: $($LogSource.name)"
                }                
                # Remove it
            } else {
                $Counters.RemoveSkip += 1
                Write-Host "$(Get-TimeStamp) | Automation Runtime | Retire Logsource | Skip | Agent: $($Agent.hostName) Log Source: $($LogSource.name) | Remote Collection"
            }

        } else {
            $Counters.RemoveSkip += 1
            Write-Host "$(Get-TimeStamp) | Automation Runtime | Retire Logsource | Skip | Agent: $($Agent.hostName) Log Source: $($LogSource.name) | Criteria Miss"
        }
    }
    Write-Host "$(Get-TimeStamp) | Automation Runtime | End | Agent: $($Agent.hostName)"
}
write-host "$(Get-TimeStamp) | Automation Complete | Summary | Agent Total: $($Counters.TotalAgents)  Added Sources: $($Counters.Add)  Add Errors: $($Counters.AddError)  Removes: $($Counters.Remove)  Remove Errors: $($Counters.RemoveError)"

# Set all Windows Security Event Logs to same Policy
$WinSecLogSources = $(get-lrlogsources -RecordStatus 'active' -MessageSourceTypeId $(Get-LrLogSourceTypes -Name "MS Windows Event Logging XML - Security" | Select-Object -ExpandProperty id)) | Where-Object -FilterScript {$_.mpePolicy.name -notlike 'LogRhythm Default v2.0'}
ForEach ($WinSecSource in $WinSecLogSources) {
    $Results = Update-LrLogSource -Id $WinSecSource.id -MpePolicyId -1000000020 -PassThru
    if (($null -ne $Results.Error) -and ($Results.Error -eq $true)) {
        write-host $Results
    }
    write-host "$(Get-TimeStamp) | MPE Set | Log Source: $($Results.name) Policy: $($Results.mpePolicy.Name) Log Source: $($Results.logSourceType.Name)"
}
## Automation End