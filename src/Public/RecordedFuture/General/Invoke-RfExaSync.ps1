using namespace System.Collections.Generic
Function Invoke-RfExaSync {
    <#
    .SYNOPSIS
        RfSync serves as an application-like service to enable synchronizing Recorded Future Threat Lists into the LogRhythm SIEM
        environment without need to directly interact with PowerShell.  

        LogRhythm List's are established to support the complete control of which threat lists are synchronized and determining
        Confidence High as compared to Confidence Low thresholds as related to the Recorded Future Risk Level assigned to each entry.
    .DESCRIPTION
        Upon first invocation the Invoke-RfSync function will establish configuration lists to enable the control of Recorded Future
        to LogRhythm SIEM Lists.  There are four risk types supported: Hash, IP, Url, Domain.  For each risk type there are three
        configuration files:
        
        RF : Conf : (RiskType) : Available Risk Lists
        RF : Conf : (RiskType) : Enabled Risk Lists
        RF : Conf : (RiskType) : Confidence Threshold

        All lists created by Invoke-RfSync follow a naming convention.  
        Configuration Lists:
        ListPrefix : Conf : (RiskType) : Configuration Name

        ListPrefex  - Manually set by the PowerShell variable $ListPrefix.  Default value to "RF :"
        Conf        - Designates the list is a configuration List.
        Configuration Name - Designates the list's configuration purpose.
        
        ShortDescription - Contains details associated with the list, including instructions on how to use.

        Threat Lists:
        ListPrefix : RiskType : ConfLevel : RecordedFutureRiskListName

        ListPrefex  - Manually set by the PowerShell variable $ListPrefix.  Default value to "RF :"
        RiskType    - Auto populated based on the Risk List Type: Hash, IP, Url, Domain
        ConfLevel   - Auto set to ConfHi or ConfLo.  Each ThreatList Value's Risk Value is compared against the configured RiskType's Confidence Threshold.
                      If the ThreatList Value's Risk Value < Confidence Threshold the value is populated in the ConfLo LogRhythm List.
                      If the ThreatList Value's Risk Value >= Confidence Threshold the value is populated in the ConfHi LogRhythm list.
        RecordedFutureRiskListName - Auto populated with the original Threat List name as provided by Recorded Future.

        ShortDescription - Contains details associated with the list.  List will always contain a timestamp for last synchronization. 
    .PARAMETER SyncScope
        This parameter is utilized as part of the manual control/invocation through LogRhythm via SmartResponse.  The default Synchronization Scope is All list types.

        Valid Synchronization Scopes:
            All - Default
            Vulnerability
            IP
            HASH
            URL
            Domain

        This value supports submission of multiple types as an array.
    .EXAMPLE
        This script is intended to be established on a dedicated system with the LogRhyhtm Powershell Module installed.  A scheduled task should be established
        that appropriately imports the LogRhythm PowerShell Module.  Once imported the Invoke-RfSync function can be called.

        Invoke-RfSync will syncrhonize contente between Recorded Future and the LogRhyhtm SIEM based on the LogRhythm Lists: RF : Conf : (RiskType) : Enabled Risk Lists.
    .NOTES
        RecordedFuture-API
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false, Position = 0)]
        [ValidateSet('all','vulnerability','ip','url','domain', 'hash', ignorecase=$true)]
        [ValidateNotNull()]
        [string[]] $SyncScope = "all",

        [Parameter(Mandatory = $false, Position = 1)]
        [ValidateNotNull()]
        [string] $EntityName = "Primary Site",

        [Parameter(Mandatory = $false, Position = 2)]
        [ValidateNotNull()]
        [int32] $MaxListSize = 30000,

        [Parameter(Mandatory = $false, Position = 3)]
        [ValidateNotNull()]
        [int32] $VulnDefaultConfThreshold = 90,

        [Parameter(Mandatory = $false, Position = 4)]
        [ValidateNotNull()]
        [int32] $IPDefaultConfThreshold = 80,

        [Parameter(Mandatory = $false, Position = 5)]
        [ValidateNotNull()]
        [int32] $UrlDefaultConfThreshold = 80,

        [Parameter(Mandatory = $false, Position = 6)]
        [ValidateNotNull()]
        [int32] $DomainDefaultConfThreshold = 80,

        [Parameter(Mandatory = $false, Position = 7)]
        [ValidateNotNull()]
        [int32] $HashDefaultConfThreshold = 80,

        [Parameter(Mandatory = $false, Position = 8)]
        [ValidateNotNull()]
        [string] $ListPrefix = "RF :"
    )

    # End Section - General Setup
    #---------------------------------------
    # Begin Section - Hash Setup & Control
    # Determine if LR List exists
    # TODO FIX
    $ListNameHash = 'Recorded Future - Hash Lists'
    $ListStatusHash = Get-ExaContextTables -Name $ListNameHash -Exact

    # Create the list if it does not exist
    if (!$ListStatusHash) {
        $Attributes = [list[object]]::new()
        $Attributes.add([PSCustomObject]@{
            id = 'value'
            isKey = $true
        })
        $Attributes.add([PSCustomObject]@{
            id = 'enabled'
            isKey = $false
        })
        New-ExaContextTable -Name $ListNameHash -ContextType 'Other' -Source 'Custom' -Attributes $Attributes

    } else {
        Write-Verbose "$(Get-TimeStamp) - List Verification: $ListNameHash exists.  Synchronizing contents between Recorded Future and this Exabeam list."
    }

    # Sync Items
    Try {
        $RfHashRiskLists = Get-RfHashRiskLists      
    } Catch {
        Write-Host "$(Get-TimeStamp) - Unable to retrieve Recorded Future Hash Threat Lists.  See Get-RfHashRiskLists"
    }

    $RfHashRiskDescriptions = [list[object]]::new()
    $NonFunctionalHashLists = @('linkedToMalware', 'positiveMalwareVerdict')
    foreach ($RfHashRiskList in $RfHashRiskLists) {
        if (($NonFunctionalHashLists -notcontains $($RfHashRiskList.name)) -and ($RfHashRiskList.criticality -ge 2)) {
            $RfHashRiskDescriptions.add([PSCustomObject]@{
                Value = $RfHashRiskList.Description
                Enabled = 'true'
            })
        }
    }

    Add-ExaContextRecords -ContextId $ListStatusHash.id -Data $RfHashRiskDescriptions -Operation 'append' -verbose


    # User Enabled URL List
    $ListStatusHashEnabled = Get-ExaContextRecords -Id $ListStatusHash.id


    # End Section - Setup & Control - Hash
    # -----------------------------------
    # Begin Section - Setup & Control - URL
    # Establish LR List of available URL Threat Lists
    $RfUrlConfThreatList = "$ListPrefix Conf : URL : Available Risk Lists"
    $RfUrlConfConfidenceThreshold = "$ListPrefix Conf : URL : Confidence Threshold"
    $RfUrlEnabledThreatList = "$ListPrefix Conf : URL : Enabled Risk Lists"

    # Determine if LR List exists
    $ListStatusUrlThreatList = Get-LrLists -Name $RfUrlConfThreatList -Exact

    # Create the list if it does not exist
    if (!$ListStatusUrlThreatList) {
        New-LrList -Name $RfUrlConfThreatList -ListType "generalvalue" -UseContext "message" -ShortDescription "List of avaialable Recorded Future URL Risk Lists.  Do not modify this list manually." -ReadAccess $ListReadAccess -WriteAccess $ListWriteAccess  -EntityName $EntityName
    } else {
        Write-Verbose "$(Get-TimeStamp) - List Verification: $RfUrlConfThreatList exists.  Synchronizing contents between Recorded Future and this LogRhythm list."
    }

    # Sync Items
    Try {
        $RfUrlRiskLists = Get-RfUrlRiskLists
        $RfUrlRiskDescriptions = [list[string]]::new()
        $NonFunctionalUrlLists = @('recentMaliciousSiteDetected','maliciousSiteDetected','phishingSiteDetected','malwareSiteDetected',`
            'recentMalwareSiteDetected','recentPhishingSiteDetected')
        foreach ($RfUrlRiskList in $RfUrlRiskLists) {
            if (($NonFunctionalUrlLists -notcontains $RfUrlRiskList.name) -and ($RfUrlRiskList.criticality -ge 2)) {
                $RfUrlRiskDescriptions.add($($RfUrlRiskList.Description))
            }
        }
    } Catch {
        Write-Host "$(Get-TimeStamp) - Unable to retrieve Recorded Future Url Threat Lists.  See Get-RfUrlRiskLists"
    }
    Sync-LrListItems -name $RfUrlConfThreatList -Value $RfUrlRiskDescriptions

    # User Enabled URL List
    $ListStatusUrlEnabled = Get-LrLists -Name $RfUrlEnabledThreatList -Exact

    # Create the list if it does not exist
    if (!$ListStatusUrlEnabled) {
        New-LrList -Name $RfUrlEnabledThreatList -ListType "generalvalue" -UseContext "message" -ShortDescription "List of enabled Recorded Future URL Threat Lists.  Modify this list manually with values from $RfUrlConfThreatList." -ReadAccess $ListReadAccess -WriteAccess $ListWriteAccess -EntityName $EntityName
    } else {
        Write-Verbose "$(Get-TimeStamp) - List Verification: $RfUrlEnabledThreatList exists."
    }

    # Risk Threshold Management List
    $UrlListStatusConfidenceThreshold = Get-LrLists -Name $RfUrlConfConfidenceThreshold -Exact

    # Create the list if it does not exist
    if (!$UrlListStatusConfidenceThreshold) {
        $UrlConfidenceList = New-LrList -Name $RfUrlConfConfidenceThreshold -ListType "generalvalue" -UseContext "message" -ShortDescription "Single Integer value to signify minimum value for Confidence High qualification.  Reference Additional Settings/Additional Additional Details for more information." -LongDescription "Results from Risk Lists with a Confidence score lower than the value populated on this list will be categorized as ConfLo.  Results from Risk Lists with a Confidence score equal to or greater than the value populated on this list will be categorized as ConfHi.  Note this list should never contain more than a single integer value between 1-99 with a recommendation being greater than 65 due to Recorded Future lists typically not providing risk scores lower than 65." -ReadAccess $ListReadAccess -WriteAccess $ListWriteAccess -PassThru -EntityName $EntityName
        
        Sync-LrListItems -Name $UrlConfidenceList.Guid -Value $UrlDefaultConfThreshold
    } else {
        Write-Verbose "$(Get-TimeStamp) - List Verification: $RfUrlConfConfidenceThreshold exists."
        # Verify a threshold value is set
        if ($UrlListStatusConfidenceThreshold.entryCount -le 0) {
            Sync-LrListItems -Name $UrlListStatusConfidenceThreshold.Guid -Value $UrlDefaultConfThreshold
        } elseif ($UrlListStatusConfidenceThreshold.entryCount -ge 2) {
            Sync-LrListItems -Name $UrlListStatusConfidenceThreshold.Guid -Value $UrlDefaultConfThreshold
        }
    }



    # End Section - Setup & Control - URL
    # -----------------------------------
    # Begin Section - Setup & Control - Domain
    # Establish LR List of available Domain Threat Lists
    $RfDomainConfThreatList = "$ListPrefix Conf : Domain : Available Risk Lists"
    $RfDomainConfConfidenceThreshold = "$ListPrefix Conf : Domain : Confidence Threshold"
    $RfDomainEnabledThreatList = "$ListPrefix Conf : Domain : Enabled Risk Lists"

    # Determine if LR List exists
    $ListStatusDomain = Get-LrLists -Name $RfDomainConfThreatList -Exact

    # Create the list if it does not exist
    if (!$ListStatusDomain) {
        New-LrList -Name $RfDomainConfThreatList -ListType "generalvalue" -UseContext "message" -ShortDescription "List of avaialable Recorded Future Domain Risk Lists.  Do not modify this list manually." -ReadAccess $ListReadAccess -WriteAccess $ListWriteAccess -EntityName $EntityName
    } else {
        Write-Verbose "$(Get-TimeStamp) - List Verification: $RfDomainConfThreatList exists.  Synchronizing contents between Recorded Future and this LogRhythm list."
    }

    # Sync Items
    Try {
        $RfDomainRiskLists = Get-RfDomainRiskLists
        $RfDomainRiskDescriptions = [list[string]]::new()
        foreach ($RfDomainRiskList in $RfDomainRiskLists) {
            if ($RfDomainRiskList.criticality -ge 2) {
                $RfDomainRiskDescriptions.add($($RfDomainRiskList.Description))
            }
        }
        #$RfDomainRiskDescriptions = $RfDomainRiskLists | Select-Object -ExpandProperty description
    } Catch {
        Write-Host "$(Get-TimeStamp) - Unable to retrieve Recorded Future Domain Threat Lists.  See Get-RfDomainRiskLists"
    }
    Sync-LrListItems -name $RfDomainConfThreatList -Value $RfDomainRiskDescriptions

    # User Enabled URL List
    $ListStatusDomainEnabled = Get-LrLists -Name $RfDomainEnabledThreatList -Exact

    # Create the list if it does not exist
    if (!$ListStatusDomainEnabled) {
        New-LrList -Name $RfDomainEnabledThreatList -ListType "generalvalue" -UseContext "message" -ShortDescription "List of enabled Recorded Future Domain Threat Lists.  Modify this list manually with values from $RfDomainConfThreatList." -ReadAccess $ListReadAccess -WriteAccess $ListWriteAccess -EntityName $EntityName
    } else {
        Write-Verbose "$(Get-TimeStamp) - List Verification: $RfDomainEnabledThreatList exists."
    }

    # Risk Threshold Management List
    $ListStatusDomainConfidence = Get-LrLists -Name $RfDomainConfConfidenceThreshold -Exact

    # Create the list if it does not exist
    if (!$ListStatusDomainConfidence) {
        $DomainConfidenceList = New-LrList -Name $RfDomainConfConfidenceThreshold -ListType "generalvalue" -UseContext "message" -ShortDescription "Single Integer value to signify minimum value for Confidence High qualification.  Reference Additional Settings/Additional Additional Details for more information." -LongDescription "Results from Risk Lists with a Confidence score lower than the value populated on this list will be categorized as ConfLo.  Results from Risk Lists with a Confidence score equal to or greater than the value populated on this list will be categorized as ConfHi.  Note this list should never contain more than a single integer value between 1-99 with a recommendation being greater than 65 due to Recorded Future lists typically not providing risk scores lower than 65." -ReadAccess $ListReadAccess -WriteAccess $ListWriteAccess -PassThru -EntityName $EntityName
        
        Sync-LrListItems -Name $DomainConfidenceList.Guid -Value $DomainDefaultConfThreshold
    } else {
        Write-Verbose "$(Get-TimeStamp) - List Verification: $RfDomainConfConfidenceThreshold exists."
        # Verify a threshold value is set
        if ($ListStatusDomainConfidence.entryCount -le 0) {
            Sync-LrListItems -Name $ListStatusDomainConfidence.Guid -Value $DomainDefaultConfThreshold
        } elseif ($ListStatusDomainConfidence.entryCount -ge 2) {
            Sync-LrListItems -Name $ListStatusDomainConfidence.Guid -Value $DomainDefaultConfThreshold
        }
    }


    # End Section - Setup & Control - Domain
    #---------------------------------------
    # Begin Section - Setup & Control - IP 
    # Establish LR List of available IP Threat Lists
    $RfIPConfThreatList = "$ListPrefix Conf : IP : Available Risk Lists"
    $RfIPConfConfidenceThreshold = "$ListPrefix Conf : IP : Confidence Threshold"
    $RfIPEnabledThreatList = "$ListPrefix Conf : IP : Enabled Risk Lists"

    # Determine if LR List exists
    $ListStatusIP = Get-LrLists -Name $RfIPConfThreatList -Exact

    # Create the list if it does not exist
    if (!$ListStatusIP) {
        New-LrList -Name $RfIPConfThreatList -ListType "generalvalue" -UseContext "message" -ShortDescription "List of avaialable Recorded Future IP Risk Lists.  Do not modify this list manually." -ReadAccess $ListReadAccess -WriteAccess $ListWriteAccess -EntityName $EntityName
    } else {
        Write-Verbose "$(Get-TimeStamp) - List Verification: $RfIPConfThreatList exists.  Synchronizing contents between Recorded Future and this LogRhythm list."
    }

    # Sync Items
    Try {
        $RfIPRiskLists = Get-RfIPRiskLists
        $RfIPRiskDescriptions = [list[string]]::new()
        foreach ($RfIPRiskList in $RfIPRiskLists) {
            if ($RfIPRiskList.criticality -ge 2) {
                $RfIPRiskDescriptions.add($($RfIPRiskList.Description))
            }
        }
        #$RfIPRiskDescriptions = $RfIPRiskLists | Select-Object -ExpandProperty description
    } Catch {
        Write-Host "$(Get-TimeStamp) - Unable to retrieve Recorded Future IP Threat Lists.  See Get-RfIPRiskLists"
    }
    Sync-LrListItems -name $RfIPConfThreatList -Value $RfIPRiskDescriptions

    # User Enabled URL List
    $ListStatusIPEnabled = Get-LrLists -Name $RfIPEnabledThreatList -Exact

    # Create the list if it does not exist
    if (!$ListStatusIPEnabled) {
        New-LrList -Name $RfIPEnabledThreatList -ListType "generalvalue" -UseContext "message" -ShortDescription "List of enabled Recorded Future IP Threat Lists.  Modify this list manually with values from $RfIPConfThreatList." -ReadAccess $ListReadAccess -WriteAccess $ListWriteAccess -EntityName $EntityName
    } else {
        Write-Verbose "$(Get-TimeStamp) - List Verification: $RfIPEnabledThreatList exists."
    }

    # Risk Threshold Management List
    $ListStatusIPConfidence = Get-LrLists -Name $RfIPConfConfidenceThreshold -Exact

    # Create the list if it does not exist
    if (!$ListStatusIPConfidence) {
        $IPConfidenceList = New-LrList -Name $RfIPConfConfidenceThreshold -ListType "generalvalue" -UseContext "message" -ShortDescription "Single Integer value to signify minimum value for Confidence High qualification.  Reference Additional Settings/Additional Additional Details for more information." -LongDescription "Results from Risk Lists with a Confidence score lower than the value populated on this list will be categorized as ConfLo.  Results from Risk Lists with a Confidence score equal to or greater than the value populated on this list will be categorized as ConfHi.  Note this list should never contain more than a single integer value between 1-99 with a recommendation being greater than 65 due to Recorded Future lists typically not providing risk scores lower than 65." -ReadAccess $ListReadAccess -WriteAccess $ListWriteAccess -PassThru -EntityName $EntityName
        
        Sync-LrListItems -Name $IPConfidenceList.Guid -Value $IPDefaultConfThreshold
    } else {
        Write-Verbose "$(Get-TimeStamp) - List Verification: $RfIPConfConfidenceThreshold exists."
        # Verify a threshold value is set
        if ($ListStatusIPConfidence.entryCount -le 0) {
            Sync-LrListItems -Name $ListStatusIPConfidence.Guid -Value $IPDefaultConfThreshold
        } elseif ($ListStatusIPConfidence.entryCount -ge 2) {
            Sync-LrListItems -Name $ListStatusIPConfidence.Guid -Value $IPDefaultConfThreshold
        }
    }

    # End Section - Setup & Control - IP
    # Begin Section - Vulnerability Setup & Control
    # Establish LR List of available Vulnerability Threat Lists
    $RfVulnerabilityConfThreatList = "$ListPrefix Conf : Vuln : Available Risk Lists"
    $RfVulnerabilityConfConfidenceThreshold = "$ListPrefix Conf : Vuln : Confidence Threshold"
    $RfVulnerabilityEnabledThreatList = "$ListPrefix Conf : Vuln : Enabled Risk Lists"

    # Determine if LR List exists
    $ListStatusVulnerability = Get-LrLists -Name $RfVulnerabilityConfThreatList -Exact

    # Create the list if it does not exist
    if (!$ListStatusVulnerability) {
        New-LrList -Name $RfVulnerabilityConfThreatList -ListType "generalvalue" -UseContext "message" -ShortDescription "List of avaialable Recorded Future Vulnerability Risk Lists.  Do not modify this list manually." -ReadAccess $ListReadAccess -WriteAccess $ListWriteAccess -EntityName $EntityName
    } else {
        Write-Verbose "$(Get-TimeStamp) - List Verification: $RfVulnerabilityConfThreatList exists.  Synchronizing contents between Recorded Future and this LogRhythm list."
    }

    # Sync Items
    Try {
        $RfVulnerabilityRiskLists = Get-RfVulnerabilityRiskLists
        $RfVulnerabilityRiskDescriptions = [list[string]]::new()
        foreach ($RfVulnerabilityRiskList in $RfVulnerabilityRiskLists) {
            if ($RfVulnerabilityRiskList.criticality -ge 2) {
                $RfVulnerabilityRiskDescriptions.add($($RfVulnerabilityRiskList.Description))
            }
        }
        #$RfVulnerabilityRiskDescriptions = $RfVulnerabilityRiskLists | Select-Object -ExpandProperty description
    } Catch {
        Write-Host "$(Get-TimeStamp) - Unable to retrieve Recorded Future Vulnerability Threat Lists.  See Get-RfVulnerabilityRiskLists"
    }
    Sync-LrListItems -name $RfVulnerabilityConfThreatList -Value $RfVulnerabilityRiskDescriptions

    # User Enabled Vulnerability List
    $ListStatusVulnerabilityEnabled = Get-LrLists -Name $RfVulnerabilityEnabledThreatList -Exact

    # Create the list if it does not exist
    if (!$ListStatusVulnerabilityEnabled) {
        New-LrList -Name $RfVulnerabilityEnabledThreatList -ListType "generalvalue" -UseContext "message" -ShortDescription "List of enabled Recorded Future Vulnerability Threat Lists.  Modify this list manually with values from $RfVulnerabilityConfThreatList." -ReadAccess $ListReadAccess -WriteAccess $ListWriteAccess -EntityName $EntityName
    } else {
        Write-Verbose "$(Get-TimeStamp) - List Verification: $RfVulnerabilityEnabledThreatList exists."
    }

    # Risk Threshold Management List
    $ListStatusVulnerabilityConfidence = Get-LrLists -Name $RfVulnerabilityConfConfidenceThreshold -Exact

    # Create the list if it does not exist
    if (!$ListStatusVulnerabilityConfidence) {
        $VulnConfidenceList = New-LrList -Name $RfVulnerabilityConfConfidenceThreshold -ListType "generalvalue" -UseContext "message" -ShortDescription "Single Integer value to signify minimum value for Confidence High qualification.  Reference Additional Settings/Additional Additional Details for more information." -LongDescription "Results from Risk Lists with a Confidence score lower than the value populated on this list will be categorized as ConfLo.  Results from Risk Lists with a Confidence score equal to or greater than the value populated on this list will be categorized as ConfHi.  Note this list should never contain more than a single integer value between 1-99 with a recommendation being greater than 65 due to Recorded Future lists typically not providing risk scores lower than 65." -ReadAccess $ListReadAccess -WriteAccess $ListWriteAccess -PassThru -EntityName $EntityName
        
        Sync-LrListItems -Name $VulnConfidenceList.Guid -Value $VulnDefaultConfThreshold
    } else {
        Write-Verbose "$(Get-TimeStamp) - List Verification: $RfVulnerabilityConfConfidenceThreshold exists."
        # Verify a threshold value is set
        if ($ListStatusVulnerabilityConfidence.entryCount -le 0) {
            Sync-LrListItems -Name $ListStatusVulnerabilityConfidence.Guid -Value $VulnDefaultConfThreshold
        } elseif ($ListStatusVulnerabilityConfidence.entryCount -ge 2) {
            Sync-LrListItems -Name $ListStatusVulnerabilityConfidence.Guid -Value $VulnDefaultConfThreshold
        }
    }
    # End Section - Setup & Control - Vulnerability
    #-----------------------------
    # Begin Section - Value Sync - Hash
    # Create Hash Threat Lists based on enabled Threat List(s)
    if (($SyncScope -contains "all") -or ($SyncScope -contains "hash")) {
        if ($ListStatusHashEnabled) {
            Write-Host "$(Get-TimeStamp) - Begin - Recorded Future Hash Threat List Sync"
            ForEach ($ThreatListHash in $ListStatusHashEnabled.records) {
                if ($ThreatListHash.enabled -like 'False') {
                    continue
                }
                # Fork each RiskList into two Lists
                Write-Host "$(Get-TimeStamp) - Working: $($ThreatListHash.value)"

                # Map list Description to List Name
                Try {
                    Write-Host "$(Get-TimeStamp) - Mapping RecordedFuture Threat List Description to Name"
                    $HashListName = $RfHashRiskLists.Where({($_.description -like $($ThreatListHash.value))}).name
                    $HashListResultQuantity = $($RfHashRiskLists.Where({($_.description -like $($ThreatListHash.value))}) | Select-Object -ExpandProperty count)
                } Catch {
                    Write-Host "$(Get-TimeStamp) - Pulled list: $($ThreatListHash.value) is not a valid list."
                }

                # Update capitilization for RiskList Value
                $HashThreatListName = "RF Hash: $((Get-Culture).TextInfo.ToTitleCase($ThreatListHash.value))"


                # Check if list exists - Change to Get-LRListGuidByName
                Write-Host "$(Get-TimeStamp) - Testing List Status"
                $HashListStatus = Get-ExaContextTables -name $HashThreatListName -Exact

                # If the list exists then update it.  Else create it.
                if ($HashListStatus) {
                    Write-Host "$(Get-TimeStamp) - Updating List: $HashThreatListName"
                } else {
                    Write-Host "$(Get-TimeStamp) - Creating List: $HashThreatListName"
                    $Attributes = [list[object]]::new()
                    $Attributes.add([PSCustomObject]@{
                        id = 'value'
                        isKey = $true
                    })
                    $Attributes.add([PSCustomObject]@{
                        id = 'risk_level'
                        isKey = $false
                    })
                    $HashListStatus = New-ExaContextTable -Name $HashThreatListName -ContextType 'Other' -Source 'Custom' -Attributes $Attributes
                    # If successful, reset the status to reflect the same result schema as a Get-ExaContextTables
                    if ($HashListStatus.table) {
                        $HashListStatus = $HashListStatus.table
                    }
                }


                # Pull list values
                Write-Host "$(Get-TimeStamp) - Running: Get-RfHashRiskList -List $HashThreatListName"

                Write-Host "$(Get-TimeStamp) - Retrieving List to process. List: $HashThreatListName RecordCount: $HashListResultQuantity"
                $ListResults = Get-RfHashRiskList -List $HashListName

                # Determin lowest confidence score provided in list.
                if ($ListResults.Risk) {
                    $Data = [list[object]]::new()
                    ForEach ($Entry in $ListResults) {
                        if ($Entry.Risk -ge 85) {
                            $rlevel = 'High'
                        } elseif ($Entry.Risk -ge 60) {
                            $rlevel = 'Medium'
                        } else {
                            $rlevel = 'Low'
                        }
                        $Data.add([PSCustomObject]@{
                            value = $Entry.name
                            risk_level = $rlevel
                        })
                    }

                    Add-ExaContextRecords -ContextId $HashListStatus.id -Data $($Data | Sort-Object risk_level ) -Operation 'append' -verbose
                }
                
                Write-Host "$(Get-TimeStamp) - Clearing Variables: Hash*"
                Clear-Variable -Name Hash* -ErrorAction SilentlyContinue
                Clear-Variable -Name ListResults -ErrorAction SilentlyContinue
                Clear-Variable -Name Data -ErrorAction SilentlyContinue
                Clear-Variable -Name MinimumConfidenceScore -ErrorAction SilentlyContinue
                [GC]::Collect()
            }
            Write-Host "$(Get-TimeStamp) - End - Recorded Future Hash Risk List Sync"
        }
    }
    # End Section - Value Sync - Hash
    # -----------------------------------
    # Begin Section - Value Sync - Url
    # Create URL Threat Lists based on RfUrlEnabledThreatList values
    if (($SyncScope -contains "all") -or ($SyncScope -contains "url")) {
        $EnabledThreatListUrl = Get-LrListItems -Name $RfUrlEnabledThreatList -Exact -ValuesOnly

        if ($EnabledThreatListUrl) {
            Write-Host "$(Get-TimeStamp) - Begin - Recorded Future URL Threat List Sync"
            $RiskCutoffUrl = Get-LrListItems -Name $RfUrlConfConfidenceThreshold -Exact -ValuesOnly

            ForEach ($ThreatListUrl in $EnabledThreatListUrl) {
                # Fork each RiskList into two Lists
                Write-Host "$(Get-TimeStamp) - Working: $ThreatListUrl"

                # Map list Description to List Name
                Try {
                    Write-Host "$(Get-TimeStamp) - Mapping RecordedFuture Threat List Description to Name"
                    $UrlListName = $RfUrlRiskLists.Where({($_.description -like $ThreatListUrl)}).name
                    $UrlListResultQuantity = $($RfUrlRiskLists.Where({($_.description -like $ThreatListUrl)}) | Select-Object -ExpandProperty count)
                } Catch {
                    Write-Host "$(Get-TimeStamp) - Pulled list: $ThreatListUrl is not a valid list."
                }

                # Update capitilization for RiskList Value
                $UrlThreatListName = (Get-Culture).TextInfo.ToTitleCase($ThreatListUrl)

                # High Risk
                # Set High Risk name Schema
                $UrlConfHiList = "$($ListPrefix) URL : ConfHi : $UrlThreatListName"

                # Check if list exists - Change to Get-LRListGuidByName
                Write-Host "$(Get-TimeStamp) - Testing ConfHi Status"
                $UrlConfHiStatus = Get-LrLists -name $UrlConfHiList -Exact

                # If the list exists then update it.  Else create it.
                if ($UrlConfHiStatus) {
                    Write-Host "$(Get-TimeStamp) - Updating List: $UrlConfHiList"
                    Update-LrList -Guid $UrlConfHiStatus.Guid -Name $UrlConfHiList -ListType "generalvalue" -UseContext "url" -ShortDescription "Recorded Future list of URLs for $ThreatListUrl.  Confidence score between $RiskCutoffUrl and 100.  Sync Time: $(Get-TimeStamp)" -ReadAccess $ListReadAccess -WriteAccess $ListWriteAccess 
                } else {
                    Write-Host "$(Get-TimeStamp) - Creating List: $UrlConfHiList"
                    New-LrList -Name $UrlConfHiList -ListType "generalvalue" -UseContext "url" -ShortDescription "Recorded Future list of URLs for $ThreatListUrl.  Confidence score between $RiskCutoffUrl and 100.  Sync Time: $(Get-TimeStamp)" -ReadAccess $ListReadAccess -WriteAccess $ListWriteAccess -EntityName $EntityName
                }

                # Suspicious Risk
                # Set Suspicious Risk name Schema
                $UrlConfLoList = "$($ListPrefix) URL : ConfLo : $UrlThreatListName"

                Write-Host "$(Get-TimeStamp) - Testing ConfLo Status"
                $UrlConfLoStatus = Get-LrLists -name $UrlConfLoList -Exact

                # If the list exists then update it.  Else create it.
                if ($UrlConfLoStatus) {
                    Write-Host "$(Get-TimeStamp) - Updating List: $UrlConfLoList"
                    Update-LrList -Guid $UrlConfLoStatus.Guid -Name $UrlConfLoList -ListType "generalvalue" -UseContext "url" -ShortDescription "Recorded Future list of URLs for $ThreatListUrl.  Confidence score between 65 and $RiskCutoffUrl.  Sync Time: $(Get-TimeStamp)" -ReadAccess $ListReadAccess -WriteAccess $ListWriteAccess 
                } else {
                    Write-Host "$(Get-TimeStamp) - Creating List: $UrlConfLoList"
                    New-LrList -Name $UrlConfLoList -ListType "generalvalue" -UseContext "url" -ShortDescription "Recorded Future list of URLs for $ThreatListUrl.  Confidence score score between 65 and $RiskCutoffUrl.  Sync Time: $(Get-TimeStamp)" -ReadAccess $ListReadAccess -WriteAccess $ListWriteAccess -EntityName $EntityName
                }

                # Pull list values
                Write-Host "$(Get-TimeStamp) - Running: Get-RfUrlRiskList -List $UrlListName"
                # Determine if compressed download required
                if ($UrlListResultQuantity -ge 200000000) {
                    #$ListResults = Get-RfUrlRiskList -List $UrlListName -Compressed $true
                    Write-Host "$(Get-TimeStamp) - Error - List Quantity too large to process. List: $UrlListName RecordCount: $UrlListResultQuantity"
                    $ListResults = "http://Error.ListOver2millionEntries.com"
                } else {
                    Write-Host "$(Get-TimeStamp) - Retrieving List to process. List: $UrlListName RecordCount: $UrlListResultQuantity"
                    $ListResults = Get-RfUrlRiskList -List $UrlListName

                    # Determin lowest confidence score provided in list.
                    if ($ListResults.Risk) {
                        $MinimumConfidenceScore = $($ListResults | Measure-Object -Property Risk -Minimum | Select-Object -ExpandProperty Minimum)
                    }

                    # If the list has values with a Risk Score less than the default 65, update the list description to reflect the minimum.
                    if (($MinimumConfidenceScore -lt 65) -and ($Null -ne $MinimumConfidenceScore)) {
                        Write-Host "$(Get-TimeStamp) - Updating List: $UrlConfLoList"
                        Update-LrList -Guid $UrlConfLoStatus.Guid -Name $UrlConfLoList -ListType "generalvalue" -UseContext "url" -ShortDescription "Recorded Future list of URLs for $ThreatListUrl.  Confidence score between $MinimumConfidenceScore and $RiskCutoffUrl.  Sync Time: $(Get-TimeStamp)" -ReadAccess $ListReadAccess -WriteAccess $ListWriteAccess 
                    }

                    # Splitting results by Risk
                    Try {
                        Write-Host "$(Get-TimeStamp) - Splitting results where Risk is greater than or equal to $RiskCutoffUrl"
                        $UrlConfHiResults = $ListResults.Where({([int32]$_.Risk -ge $RiskCutoffUrl)})
                        Write-Host "$(Get-TimeStamp) - Splitting results where Risk is less than $RiskCutoffUrl"
                        $UrlConfLoResults = $ListResults.Where({([int32]$_.Risk -lt $RiskCutoffUrl)})
                    } Catch {
                        Write-Host "$(Get-TimeStamp) - Error trying to split UrlHighResults and UrlSuspiciousResults"
                        Write-Host "$(Get-TimeStamp) - Current List: $UrlListName"
                    }

                    # Populate Lists
                    # High Risk
                    if ($UrlConfHiResults.count -gt 0) {
                        $ConfHiResults = $UrlConfHiResults | Sort-Object -Property Risk -Descending | Select-Object -ExpandProperty Name -First $MaxListSize
                        Write-Host "$(Get-TimeStamp) - Syncing Quantity: $($ConfHiResults.count)  ConfHi to list $UrlConfHiList"
                        Sync-LrListItems -Value $ConfHiResults -name $UrlConfHiList
                    } else {
                        Write-Host "$(Get-TimeStamp) - ConfHi Quantity: $($UrlConfHiResults.count)"
                    }

                    # Suspicious Risks
                    if ($UrlConfLoResults.count -gt 0) {
                        $ConfLoResults = $UrlConfLoResults | Sort-Object -Property Risk -Descending | Select-Object -ExpandProperty Name -First $MaxListSize
                        Write-Host "$(Get-TimeStamp) - Syncing Quantity: $($ConfLoResults.count)  ConfLo to list $UrlConfLoList"
                        Sync-LrListItems -Value $ConfLoResults -name $UrlConfLoList
                    }  else {
                        Write-Host "$(Get-TimeStamp) - ConfLo Quantity: $($UrlConfLoResults.count)"
                    }
                }
                Write-Host "$(Get-TimeStamp) - Clearing Variables: Url*"
                Clear-Variable -Name Url* -ErrorAction SilentlyContinue
                Clear-Variable -Name Conf -ErrorAction SilentlyContinue
                Clear-Variable -Name ListResults -ErrorAction SilentlyContinue
                Clear-Variable -Name MinimumConfidenceScore -ErrorAction SilentlyContinue
                [GC]::Collect()
            }
            Write-Host "$(Get-TimeStamp) - End - Recorded Future URL Risk List Sync"
        }
    }
    # End Section - Value Sync - Url
    # -----------------------------------
    # Begin Section - Value Sync - Domain
    # Create Domain Threat Lists based on RfDomainEnabledThreatList values
    if (($SyncScope -contains "all") -or ($SyncScope -contains "domain")) {
        $EnabledThreatListDomain = Get-LrListItems -Name $RfDomainEnabledThreatList -Exact -ValuesOnly

        if ($EnabledThreatListDomain) {
            Write-Host "$(Get-TimeStamp) - Begin - Recorded Future Domain Threat List Sync"
            $RiskCutoffDomain = Get-LrListItems -Name $RfDomainConfConfidenceThreshold -Exact -ValuesOnly

            ForEach ($ThreatListDomain in $EnabledThreatListDomain) {
                $ConfNull = 0

                # Fork each RiskList into two Lists
                Write-Host "$(Get-TimeStamp) - Working: $ThreatListDomain"

                # Map list Description to List Name
                Try {
                    Write-Host "$(Get-TimeStamp) - Mapping RecordedFuture Threat List Description to Name"
                    $DomainListName = $RfDomainRiskLists.Where({($_.description -like $ThreatListDomain)}).name
                    $DomainListResultQuantity = $($RfDomainRiskLists.Where({($_.description -like $ThreatListDomain)}) | Select-Object -ExpandProperty count)
                } Catch {
                    Write-Host "$(Get-TimeStamp) - Pulled list: $ThreatListDomain is not a valid list."
                }

                # Update capitilization for RiskList Value
                $DomainThreatListName = (Get-Culture).TextInfo.ToTitleCase($ThreatListDomain)

                # Shorten up that long name
                if ($DomainThreatListName -like "Recent Typosquat Similarity - Dns Sandwich") {
                    $DomainThreatListName = $DomainThreatListName -replace 'Recent Typosquat Similarity - Dns Sandwich','Recent Typosquat'
                }

                # High Risk
                # Set High Risk name Schema
                $DomainConfHiList = "$($ListPrefix) Domain : ConfHi : $DomainThreatListName"

                # Check if list exists - Change to Get-LRListGuidByName
                Write-Host "$(Get-TimeStamp) - Testing ConfHi Status"
                $DomainConfHiStatus = Get-LrLists -name $DomainConfHiList -Exact

                # If the list exists then update it.  Else create it.
                if ($DomainConfHiStatus) {
                    Write-Host "$(Get-TimeStamp) - Updating List: $DomainConfHiList"
                    Update-LrList -Guid $DomainConfHiStatus.Guid -Name $DomainConfHiList -ListType "generalvalue" -UseContext "url" -ShortDescription "Recorded Future list of Domains for $ThreatListDomain.  Confidence score between $RiskCutoffDomain and 100.  Sync Time: $(Get-TimeStamp)" -ReadAccess $ListReadAccess -WriteAccess $ListWriteAccess 
                } else {
                    Write-Host "$(Get-TimeStamp) - Creating List: $DomainConfHiList"
                    New-LrList -Name $DomainConfHiList -ListType "generalvalue" -UseContext "url" -ShortDescription "Recorded Future list of Domains for $ThreatListDomain.  Confidence score between $RiskCutoffDomain and 100.  Sync Time: $(Get-TimeStamp)" -ReadAccess $ListReadAccess -WriteAccess $ListWriteAccess -EntityName $EntityName
                }

                # Suspicious Risk
                # Set Suspicious Risk name Schema
                $DomainConfLoList = "$($ListPrefix) Domain : ConfLo : $DomainThreatListName"
                Write-Host "$(Get-TimeStamp) - Testing ConfLo Status"
                $DomainConfLoStatus = Get-LrLists -name $DomainConfLoList -Exact
                # If the list exists then update it.  Else create it.
                if ($DomainConfLoStatus) {
                    Write-Host "$(Get-TimeStamp) - Updating List: $DomainConfLoList"
                    Update-LrList -Guid $DomainConfLoStatus.Guid -Name $DomainConfLoList -ListType "generalvalue" -UseContext "url" -ShortDescription "Recorded Future list of Domains for $ThreatListDomain.  Confidence score between 65 and $RiskCutoffDomain.  Sync Time: $(Get-TimeStamp)" -ReadAccess $ListReadAccess -WriteAccess $ListWriteAccess 
                } else {
                    Write-Host "$(Get-TimeStamp) - Creating List: $DomainConfLoList"
                    New-LrList -Name $DomainConfLoList -ListType "generalvalue" -UseContext "url" -ShortDescription "Recorded Future list of Domains for $ThreatListDomain.  Confidence score score between 65 and $RiskCutoffDomain.  Sync Time: $(Get-TimeStamp)" -ReadAccess $ListReadAccess -WriteAccess $ListWriteAccess -EntityName $EntityName
                }

                # Pull list values
                Write-Host "$(Get-TimeStamp) - Running: Get-RfDomainRiskList -List $DomainListName"
                # Determine if compressed download required
                if ($DomainListResultQuantity -ge 2000000000) {
                    #$ListResults = Get-RfDomainRiskList -List $DomainListName -Compressed $true
                    Write-Host "$(Get-TimeStamp) - Error - List Quantity too large to process. List: $DomainListName RecordCount: $DomainListResultQuantity"
                    $ListResults = "http://Error.ListOver2millionEntries.com"
                } else {
                    Write-Host "$(Get-TimeStamp) - Retrieving List to process. List: $DomainListName RecordCount: $DomainListResultQuantity"
                    $ListResults = Get-RfDomainRiskList -List $DomainListName

                    # Determin lowest confidence score provided in list.
                    if ($ListResults.Risk) {
                        $MinimumConfidenceScore = $($ListResults | Measure-Object -Property Risk -Minimum | Select-Object -ExpandProperty Minimum)
                    }

                    # If the list has values with a Risk Score less than the default 65, update the list description to reflect the minimum.
                    if (($MinimumConfidenceScore -lt 65) -and ($Null -ne $MinimumConfidenceScore)) {
                        Write-Host "$(Get-TimeStamp) - Updating List: $DomainConfLoList"
                        Update-LrList -Guid $DomainConfLoStatus.Guid -Name $DomainConfLoList -ListType "generalvalue" -UseContext "url" -ShortDescription "Recorded Future list of Domains for $ThreatListDomain.  Confidence score between $MinimumConfidenceScore and $RiskCutoffDomain.  Sync Time: $(Get-TimeStamp)" -ReadAccess $ListReadAccess -WriteAccess $ListWriteAccess 
                    }
                    # Splitting results by Risk
                    Try {
                        Write-Host "$(Get-TimeStamp) - Splitting results where Risk is greater than or equal to $RiskCutoffDomain"
                        $DomainConfHiResults = $ListResults.Where({([int32]$_.Risk -ge $RiskCutoffDomain)})
                        Write-Host "$(Get-TimeStamp) - Splitting results where Risk is less than $RiskCutoffDomain"
                        $DomainConfLoResults = $ListResults.Where({([int32]$_.Risk -lt $RiskCutoffDomain)})
                    } Catch {
                        Write-Host "$(Get-TimeStamp) - Error trying to split DomainHighResults and DomainSuspiciousResults"
                        Write-Host "$(Get-TimeStamp) - Current List: $DomainListName"
                    }

                    # Populate Lists
                    # High Risk
                    if ($DomainConfHiResults.count -gt 0) {
                        $ConfHiResults = $DomainConfHiResults | Sort-Object -Property Risk -Descending | Select-Object -ExpandProperty Name -First $MaxListSize
                        Write-Host "$(Get-TimeStamp) - Syncing Quantity: $($ConfHiResults.count)  ConfHi to list $DomainConfHiList"
                        Sync-LrListItems -Value $ConfHiResults -name $DomainConfHiList
                    } else {
                        Write-Host "$(Get-TimeStamp) - ConfHi Quantity: $($DomainConfHiResults.count)"
                    }

                    # Suspicious Risks
                    if ($DomainConfLoResults.count -gt 0) {
                        $ConfLoResults = $DomainConfLoResults | Sort-Object -Property Risk -Descending | Select-Object -ExpandProperty Name -First $MaxListSize
                        Write-Host "$(Get-TimeStamp) - Syncing Quantity: $($ConfLoResults.count)  ConfLo to list $DomainConfLoList"
                        Sync-LrListItems -Value $ConfLoResults -name $DomainConfLoList
                    }  else {
                        Write-Host "$(Get-TimeStamp) - ConfLo Quantity: $($DomainConfLoResults.count)"
                    }
                }
                Write-Host "$(Get-TimeStamp) - Clearing Variables: Domain*"
                Clear-Variable -Name Domain* -ErrorAction SilentlyContinue
                Clear-Variable -Name ConfHiResults -ErrorAction SilentlyContinue
                Clear-Variable -Name ConfLoResults -ErrorAction SilentlyContinue
                Clear-Variable -Name ListResults -ErrorAction SilentlyContinue
                Clear-Variable -Name MinimumConfidenceScore -ErrorAction SilentlyContinue
                [GC]::Collect()
            }
            Write-Host "$(Get-TimeStamp) - End - Recorded Future Domain Risk List Sync"
        }
    }
    # End Section - Value Sync - Domain
    # -----------------------------------
    # Begin Section - Value Sync - IP
    # Create IP Threat Lists based on RfIPEnabledThreatList values
    if (($SyncScope -contains "all") -or ($SyncScope -contains "ip")) {
        $EnabledThreatListIP = Get-LrListItems -Name $RfIPEnabledThreatList -Exact -ValuesOnly

        if ($EnabledThreatListIP) {
            Write-Host "$(Get-TimeStamp) - Begin - Recorded Future IP Threat List Sync"
            $RiskCutoffIP = Get-LrListItems -Name $RfIPConfConfidenceThreshold -Exact -ValuesOnly

            ForEach ($ThreatListIP in $EnabledThreatListIP) {
                $ConfNull = 0

                # Fork each RiskList into two Lists
                Write-Host "$(Get-TimeStamp) - Working: $ThreatListIP"

                # Map list Description to List Name
                Try {
                    Write-Host "$(Get-TimeStamp) - Mapping RecordedFuture Threat List Description to Name"
                    $IPListName = $RfIPRiskLists.Where({($_.description -like $ThreatListIP)}).name
                    $IPListResultQuantity = $($RfIPRiskLists.Where({($_.description -like $ThreatListIP)}) | Select-Object -ExpandProperty count)
                } Catch {
                    Write-Host "$(Get-TimeStamp) - Pulled list: $ThreatListIP is not a valid list."
                }

                # Update capitilization for RiskList Value
                $IPThreatListName = (Get-Culture).TextInfo.ToTitleCase($ThreatListIP)

                # High Risk
                # Set High Risk name Schema
                $IPConfHiList = "$($ListPrefix) IP : ConfHi : $IPThreatListName"

                # Check if list exists - Change to Get-LRListGuidByName
                Write-Host "$(Get-TimeStamp) - Testing ConfHi Status"
                $IPConfHiStatus = Get-LrLists -name $IPConfHiList -Exact

                # If the list exists then update it.  Else create it.
                if ($IPConfHiStatus) {
                    Write-Host "$(Get-TimeStamp) - Updating List: $IPConfHiList"
                    Update-LrList -Guid $IPConfHiStatus.Guid -Name $IPConfHiList -ListType "ip" -ShortDescription "Recorded Future list of IPs for $ThreatListIP.  Confidence score between $RiskCutoffIP and 100.  Sync Time: $(Get-TimeStamp)" -ReadAccess $ListReadAccess -WriteAccess $ListWriteAccess 
                } else {
                    Write-Host "$(Get-TimeStamp) - Creating List: $IPConfHiList"
                    New-LrList -Name $IPConfHiList -ListType "ip" -ShortDescription "Recorded Future list of IPs for $ThreatListIP.  Confidence score between $RiskCutoffIP and 100.  Sync Time: $(Get-TimeStamp)" -ReadAccess $ListReadAccess -WriteAccess $ListWriteAccess -EntityName $EntityName
                }

                # Suspicious Risk
                # Set Suspicious Risk name Schema
                $IPConfLoList = "$($ListPrefix) IP : ConfLo : $IPThreatListName"

                Write-Host "$(Get-TimeStamp) - Testing ConfLo Status"
                $IPConfLoStatus = Get-LrLists -name $IPConfLoList -Exact

                # If the list exists then update it.  Else create it.
                if ($IPConfLoStatus) {
                    Write-Host "$(Get-TimeStamp) - Updating List: $IPConfLoList"
                    Update-LrList -Guid $IPConfLoStatus.Guid -Name $IPConfLoList -ListType "ip" -ShortDescription "Recorded Future list of IPs for $ThreatListIP.  Confidence score between 65 and $RiskCutoffIP.  Sync Time: $(Get-TimeStamp)" -ReadAccess $ListReadAccess -WriteAccess $ListWriteAccess 
                } else {
                    Write-Host "$(Get-TimeStamp) - Creating List: $IPConfLoList"
                    New-LrList -Name $IPConfLoList -ListType "ip" -ShortDescription "Recorded Future list of IPs for $ThreatListIP.  Confidence score score between 65 and $RiskCutoffIP.  Sync Time: $(Get-TimeStamp)" -ReadAccess $ListReadAccess -WriteAccess $ListWriteAccess -EntityName $EntityName
                }

                # Pull list values
                Write-Host "$(Get-TimeStamp) - Running: Get-RfIPRiskList -List $IPListName"
                # Determine if compressed download required
                if ($IPListResultQuantity -ge 2000000000) {
                    #$ListResults = Get-RfIPRiskList -List $IPListName -Compressed $true
                    Write-Host "$(Get-TimeStamp) - Error - List Quantity too large to process. List: $IPListName RecordCount: $IPListResultQuantity"
                    $ListResults = "http://Error.ListOver2millionEntries.com"
                } else {
                    Write-Host "$(Get-TimeStamp) - Retrieving List to process. List: $IPListName RecordCount: $IPListResultQuantity"
                    $ListResults = Get-RfIPRiskList -List $IPListName -IPv4

                    # Determin lowest confidence score provided in list.
                    if ($ListResults.Risk) {
                        $MinimumConfidenceScore = $($ListResults | Measure-Object -Property Risk -Minimum | Select-Object -ExpandProperty Minimum)
                    }

                    # If the list has values with a Risk Score less than the default 65, update the list description to reflect the minimum.
                    if (($MinimumConfidenceScore -lt 65) -and ($Null -ne $MinimumConfidenceScore)) {
                        Write-Host "$(Get-TimeStamp) - Updating List: $IPConfLoList"
                        Update-LrList -Guid $IPConfLoStatus.Guid -Name $IPConfLoList -ListType "ip" -ShortDescription "Recorded Future list of IPs for $ThreatListIP.  Confidence score between $MinimumConfidenceScore and $RiskCutoffIP.  Sync Time: $(Get-TimeStamp)" -ReadAccess $ListReadAccess -WriteAccess $ListWriteAccess 
                    }

                    # Splitting results by Risk
                    Try {
                        Write-Host "$(Get-TimeStamp) - Splitting results where Risk is greater than or equal to $RiskCutoffIP"
                        $IPConfHiResults = $ListResults.Where({([int32]$_.Risk -ge $RiskCutoffIP)})
                        Write-Host "$(Get-TimeStamp) - Splitting results where Risk is less than $RiskCutoffIP"
                        $IPConfLoResults = $ListResults.Where({([int32]$_.Risk -lt $RiskCutoffIP)})
                    } Catch {
                        Write-Host "$(Get-TimeStamp) - Error trying to split IPHighResults and IPSuspiciousResults"
                        Write-Host "$(Get-TimeStamp) - Current List: $IPListName"
                    }

                    # Populate Lists
                    # High Risk
                    if ($IPConfHiResults.count -gt 0) {
                        $ConfHiResults = $IPConfHiResults | Sort-Object -Property Risk -Descending | Select-Object -ExpandProperty Name -First $MaxListSize
                        Write-Host "$(Get-TimeStamp) - Syncing Quantity: $($ConfHiResults.count)  ConfHi to list $IPConfHiList"
                        Sync-LrListItems -Value $ConfHiResults -name $IPConfHiList
                    } else {
                        Write-Host "$(Get-TimeStamp) - ConfHi Quantity: $($IPConfHiResults.count)"
                    }

                    # Suspicious Risks
                    if ($IPConfLoResults.count -gt 0) {
                        $ConfLoResults = $IPConfLoResults | Sort-Object -Property Risk -Descending | Select-Object -ExpandProperty Name -First $MaxListSize
                        Write-Host "$(Get-TimeStamp) - Syncing Quantity: $($ConfLoResults.count)  ConfLo to list $IPConfLoList"
                        Sync-LrListItems -Value $ConfLoResults -name $IPConfLoList
                    }  else {
                        Write-Host "$(Get-TimeStamp) - ConfLo Quantity: $($IPConfLoResults.count)"
                    }
                }
                Write-Host "$(Get-TimeStamp) - Clearing Variables: IP*"
                Clear-Variable -Name IP* -ErrorAction SilentlyContinue
                Clear-Variable -Name ConfHiResults -ErrorAction SilentlyContinue
                Clear-Variable -Name ConfLoResults -ErrorAction SilentlyContinue
                Clear-Variable -Name ListResults -ErrorAction SilentlyContinue
                Clear-Variable -Name MinimumConfidenceScore -ErrorAction SilentlyContinue
                [GC]::Collect()
            }
            Write-Host "$(Get-TimeStamp) - End - Recorded Future IP Risk List Sync"
        }
    }
    # End Section - Value Sync - IP
    # -----------------------------------
    # Begin Section - Value Sync - Vulnerability
    # Create Vulnerability Threat Lists based on RfVulnerabilityEnabledThreatList values
    

    
    if (($SyncScope -contains "all") -or ($SyncScope -contains "vulnerability")) {
        $EnabledThreatListVulnerability = Get-LrListItems -Name $RfVulnerabilityEnabledThreatList -Exact -ValuesOnly

        if ($EnabledThreatListVulnerability) {
            Write-Host "$(Get-TimeStamp) - Begin - Recorded Future Vulnerability Threat List Sync"
            $RiskCutoffVulnerability = Get-LrListItems -Name $RfVulnerabilityConfConfidenceThreshold -Exact -ValuesOnly

            ForEach ($ThreatListVulnerability in $EnabledThreatListVulnerability) {
                $ConfNull = 0

                # Fork each RiskList into two Lists
                Write-Host "$(Get-TimeStamp) - Working: $ThreatListVulnerability"

                # Map list Description to List Name
                Try {
                    Write-Host "$(Get-TimeStamp) - Mapping RecordedFuture Threat List Description to Name"
                    $VulnerabilityListName = $RfVulnerabilityRiskLists.Where({($_.description -like $ThreatListVulnerability)}).name
                    $VulnerabilityListResultQuantity = $($RfVulnerabilityRiskLists.Where({($_.description -like $ThreatListVulnerability)}) | Select-Object -ExpandProperty count)
                } Catch {
                    Write-Host "$(Get-TimeStamp) - Pulled list: $ThreatListVulnerability is not a valid list."
                }

                # Update capitilization for RiskList Value
                $VulnerabilityThreatListName = (Get-Culture).TextInfo.ToTitleCase($ThreatListVulnerability)

                # Shorten up that long name
                if ($VulnerabilityThreatListName -like "*Proof Of Concept*") {
                    $VulnerabilityThreatListName = $VulnerabilityThreatListName -replace 'Proof Of Concept','PoC'
                }

                # High Risk
                # Set High Risk name Schema
                $VulnerabilityConfHiList = "$($ListPrefix) Vuln : ConfHi : $VulnerabilityThreatListName"

                # Check if list exists - Change to Get-LRListGuidByName
                Write-Host "$(Get-TimeStamp) - Testing ConfHi Status"
                $VulnerabilityConfHiStatus = Get-LrLists -name $VulnerabilityConfHiList -Exact

                # If the list exists then update it.  Else create it.
                if ($VulnerabilityConfHiStatus) {
                    Write-Host "$(Get-TimeStamp) - Updating List: $VulnerabilityConfHiList"
                    Update-LrList -Guid $VulnerabilityConfHiStatus.Guid -Name $VulnerabilityConfHiList -ListType "generalvalue" -UseContext "cve" -ShortDescription "Recorded Future list of Vulnerabilitys for $ThreatListVulnerability.  Confidence score between $RiskCutoffVulnerability and 100.  Sync Time: $(Get-TimeStamp)" -ReadAccess $ListReadAccess -WriteAccess $ListWriteAccess 
                } else {
                    Write-Host "$(Get-TimeStamp) - Creating List: $VulnerabilityConfHiList"
                    New-LrList -Name $VulnerabilityConfHiList -ListType "generalvalue" -UseContext "cve" -ShortDescription "Recorded Future list of Vulnerabilitys for $ThreatListVulnerability.  Confidence score between $RiskCutoffVulnerability and 100.  Sync Time: $(Get-TimeStamp)" -ReadAccess $ListReadAccess -WriteAccess $ListWriteAccess -EntityName $EntityName
                }

                # Suspicious Risk
                # Set Suspicious Risk name Schema
                $VulnerabilityConfLoList = "$($ListPrefix) Vuln : ConfLo : $VulnerabilityThreatListName"

                Write-Host "$(Get-TimeStamp) - Testing ConfLo Status"
                $VulnerabilityConfLoStatus = Get-LrLists -name $VulnerabilityConfLoList -Exact

                # If the list exists then update it.  Else create it.
                if ($VulnerabilityConfLoStatus) {
                    Write-Host "$(Get-TimeStamp) - Updating List: $VulnerabilityConfLoList"
                    Update-LrList -Guid $VulnerabilityConfLoStatus.Guid -Name $VulnerabilityConfLoList -ListType "generalvalue" -UseContext "cve" -ShortDescription "Recorded Future list of Vulnerabilitys for $ThreatListVulnerability.  Confidence score between 65 and $RiskCutoffVulnerability.  Sync Time: $(Get-TimeStamp)" -ReadAccess $ListReadAccess -WriteAccess $ListWriteAccess 
                } else {
                    Write-Host "$(Get-TimeStamp) - Creating List: $VulnerabilityConfLoList"
                    New-LrList -Name $VulnerabilityConfLoList -ListType "generalvalue" -UseContext "cve" -ShortDescription "Recorded Future list of Vulnerabilitys for $ThreatListVulnerability.  Confidence score score between 65 and $RiskCutoffVulnerability.  Sync Time: $(Get-TimeStamp)" -ReadAccess $ListReadAccess -WriteAccess $ListWriteAccess -EntityName $EntityName
                }

                # Pull list values
                Write-Host "$(Get-TimeStamp) - Running: Get-RfVulnerabilityRiskList -List $VulnerabilityListName"
                # Determine if compressed download required
                if ($VulnerabilityListResultQuantity -ge 2000000000) {
                    #$ListResults = Get-RfVulnerabilityRiskList -List $VulnerabilityListName -Compressed $true
                    Write-Host "$(Get-TimeStamp) - Error - List Quantity too large to process. List: $VulnerabilityListName RecordCount: $VulnerabilityListResultQuantity"
                    $ListResults = "http://Error.ListOver2millionEntries.com"
                } else {
                    Write-Host "$(Get-TimeStamp) - Retrieving List to process. List: $VulnerabilityListName RecordCount: $VulnerabilityListResultQuantity"
                    $ListResults = Get-RfVulnerabilityRiskList -List $VulnerabilityListName -CVE

                    # Determin lowest confidence score provided in list.
                    if ($ListResults.Risk) {
                        $MinimumConfidenceScore = $($ListResults | Measure-Object -Property Risk -Minimum | Select-Object -ExpandProperty Minimum)
                    }

                    # If the list has values with a Risk Score less than the default 65, update the list description to reflect the minimum.
                    if (($MinimumConfidenceScore -lt 65) -and ($Null -ne $MinimumConfidenceScore)) {
                        Write-Host "$(Get-TimeStamp) - Updating List: $VulnerabilityConfLoList"
                        Update-LrList -Guid $VulnerabilityConfLoStatus.Guid -Name $VulnerabilityConfLoList -ListType "generalvalue" -UseContext "cve" -ShortDescription "Recorded Future list of Vulnerabilitys for $ThreatListVulnerability.  Confidence score between $MinimumConfidenceScore and $RiskCutoffVulnerability.  Sync Time: $(Get-TimeStamp)" -ReadAccess $ListReadAccess -WriteAccess $ListWriteAccess 
                    }

                    # Splitting results by Risk
                    Try {
                        Write-Host "$(Get-TimeStamp) - Splitting results where Risk is greater than or equal to $RiskCutoffVulnerability"
                        $VulnerabilityConfHiResults = $ListResults.Where({([int32]$_.Risk -ge $RiskCutoffVulnerability)})
                        Write-Host "$(Get-TimeStamp) - Splitting results where Risk is less than $RiskCutoffVulnerability"
                        $VulnerabilityConfLoResults = $ListResults.Where({([int32]$_.Risk -lt $RiskCutoffVulnerability)})
                    } Catch {
                        Write-Host "$(Get-TimeStamp) - Error trying to split VulnerabilityHighResults and VulnerabilitySuspiciousResults"
                        Write-Host "$(Get-TimeStamp) - Current List: $VulnerabilityListName"
                    }

                    # Populate Lists
                    # High Risk
                    if ($VulnerabilityConfHiResults.count -gt 0) {
                        $ConfHiResults = $VulnerabilityConfHiResults | Sort-Object -Property Risk -Descending | Select-Object -ExpandProperty Name -First $MaxListSize
                        Write-Host "$(Get-TimeStamp) - Syncing Quantity: $($ConfHiResults.count)  ConfHi to list $VulnerabilityConfHiList"
                        Sync-LrListItems -Value $ConfHiResults -name $VulnerabilityConfHiList
                    } else {
                        Write-Host "$(Get-TimeStamp) - ConfHi Quantity: $($VulnerabilityConfHiResults.count)"
                    }

                    # Suspicious Risks
                    if ($VulnerabilityConfLoResults.count -gt 0) {
                        $ConfLoResults = $VulnerabilityConfLoResults | Sort-Object -Property Risk -Descending | Select-Object -ExpandProperty Name -First $MaxListSize
                        Write-Host "$(Get-TimeStamp) - Syncing Quantity: $($ConfLoResults.count)  ConfLo to list $VulnerabilityConfLoList"
                        Sync-LrListItems -Value $ConfLoResults -name $VulnerabilityConfLoList
                    }  else {
                        Write-Host "$(Get-TimeStamp) - ConfLo Quantity: $($VulnerabilityConfLoResults.count)"
                    }
                }
                Write-Host "$(Get-TimeStamp) - Clearing Variables: Vulnerability*"
                Clear-Variable -Name Vulnerability* -ErrorAction SilentlyContinue
                Clear-Variable -Name ConfHiResults -ErrorAction SilentlyContinue
                Clear-Variable -Name ConfLoResults -ErrorAction SilentlyContinue
                Clear-Variable -Name ListResults -ErrorAction SilentlyContinue
                Clear-Variable -Name MinimumConfidenceScore -ErrorAction SilentlyContinue
                [GC]::Collect()
            }
            Write-Host "$(Get-TimeStamp) - End - Recorded Future Vulnerability Risk List Sync"
        }
    }
    # Begin Section - Value Sync - Vulnerability
    # Cleanup memory.
    [GC]::Collect()
}