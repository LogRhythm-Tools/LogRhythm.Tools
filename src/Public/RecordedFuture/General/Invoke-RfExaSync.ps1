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
        $Results = New-ExaContextTable -Name $ListNameHash -ContextType 'Other' -Source 'Custom' -Attributes $Attributes
        $ListStatusHash = Get-ExaContextTables -Name $ListNameHash -Exact
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

    $Results = Add-ExaContextRecords -ContextId $ListStatusHash.id -Data $RfHashRiskDescriptions -Operation 'append'

    Start-Sleep -Seconds 30
    # User Enabled Hash List
    $ListStatusHashEnabled = Get-ExaContextRecords -Id $ListStatusHash.id


    # End Section - Setup & Control - Hash
    # -----------------------------------
    # Begin Section - Setup & Control - URL
    # Establish LR List of available URL Threat Lists
    $ListNameUrl = 'Recorded Future - Url Lists'
    $ListStatusUrl = Get-ExaContextTables -Name $ListNameUrl -Exact


    # Create the list if it does not exist
    if (!$ListStatusUrl) {
        $Attributes = [list[object]]::new()
        $Attributes.add([PSCustomObject]@{
            id = 'value'
            isKey = $true
        })
        $Attributes.add([PSCustomObject]@{
            id = 'enabled'
            isKey = $false
        })
        New-ExaContextTable -Name $ListNameUrl -ContextType 'Other' -Source 'Custom' -Attributes $Attributes

        $ListStatusUrl = Get-ExaContextTables -Name $ListNameUrl -Exact
    } else {
        Write-Verbose "$(Get-TimeStamp) - List Verification: $ListNameUrl exists.  Synchronizing contents between Recorded Future and this Exabeam list."
    }

    # Sync Items
    Try {
        $RfUrlRiskLists = Get-RfUrlRiskLists    
    } Catch {
        Write-Host "$(Get-TimeStamp) - Unable to retrieve Recorded Future Url Threat Lists.  See Get-RfUrlRiskLists"
    }

    $RfUrlRiskDescriptions = [list[object]]::new()
    $NonFunctionalUrlLists = @()
    foreach ($RfUrlRiskList in $RfUrlRiskLists) {
        if (($NonFunctionalUrlLists -notcontains $($RfUrlRiskList.name)) -and ($RfUrlRiskList.criticality -ge 2)) {
            $RfUrlRiskDescriptions.add([PSCustomObject]@{
                Value = $RfUrlRiskList.Description
                Enabled = 'true'
            })
        }
    }

    $Results = Add-ExaContextRecords -ContextId $ListStatusUrl.id -Data $RfUrlRiskDescriptions -Operation 'append'

    Start-Sleep -Seconds 30
    # User Enabled URL List
    $ListStatusUrlEnabled = Get-ExaContextRecords -Id $ListStatusUrl.id


    # End Section - Setup & Control - URL
    # -----------------------------------
    # Begin Section - Setup & Control - Domain
    # Establish LR List of available Domain Threat Lists
    $ListNameDomain = 'Recorded Future - Domain Lists'
    $ListStatusDomain = Get-ExaContextTables -Name $ListNameDomain -Exact


    # Create the list if it does not exist
    if (!$ListStatusDomain) {
        $Attributes = [list[object]]::new()
        $Attributes.add([PSCustomObject]@{
            id = 'value'
            isKey = $true
        })
        $Attributes.add([PSCustomObject]@{
            id = 'enabled'
            isKey = $false
        })
        $Results = New-ExaContextTable -Name $ListNameDomain -ContextType 'Other' -Source 'Custom' -Attributes $Attributes

        $ListStatusDomain = Get-ExaContextTables -Name $ListNameDomain -Exact
    } else {
        Write-Verbose "$(Get-TimeStamp) - List Verification: $ListNameDomain exists.  Synchronizing contents between Recorded Future and this Exabeam list."
    }

    # Sync Items
    Try {
        $RfDomainRiskLists = Get-RfDomainRiskLists   
    } Catch {
        Write-Host "$(Get-TimeStamp) - Unable to retrieve Recorded Future Domain Threat Lists.  See Get-RfDomainRiskLists"
    }

    $RfDomainRiskDescriptions = [list[object]]::new()
    $NonFunctionalDomainLists = @()
    foreach ($RfDomainRiskList in $RfDomainRiskLists) {
        if (($NonFunctionalDomainLists -notcontains $($RfDomainRiskList.name)) -and ($RfDomainRiskList.criticality -ge 2)) {
            $RfDomainRiskDescriptions.add([PSCustomObject]@{
                Value = $RfDomainRiskList.Description
                Enabled = 'true'
            })
        }
    }

    $Results = Add-ExaContextRecords -ContextId $ListStatusDomain.id -Data $RfDomainRiskDescriptions -Operation 'append'

    Start-Sleep -Seconds 30
    # User Enabled URL List
    $ListStatusDomainEnabled = Get-ExaContextRecords -Id $ListStatusDomain.id


    # End Section - Setup & Control - Domain
    #---------------------------------------
    # Begin Section - Setup & Control - IP 
    # Establish LR List of available IP Threat Lists
    $ListNameIP = 'Recorded Future - IP Lists'
    $ListStatusIP = Get-ExaContextTables -Name $ListNameIP -Exact


    # Create the list if it does not exist
    if (!$ListStatusIP) {
        $Attributes = [list[object]]::new()
        $Attributes.add([PSCustomObject]@{
            id = 'value'
            isKey = $true
        })
        $Attributes.add([PSCustomObject]@{
            id = 'enabled'
            isKey = $false
        })
        $Results = New-ExaContextTable -Name $ListNameIP -ContextType 'Other' -Source 'Custom' -Attributes $Attributes

        $ListStatusIP = Get-ExaContextTables -Name $ListNameIP -Exact
    } else {
        Write-Verbose "$(Get-TimeStamp) - List Verification: $ListNameIP exists.  Synchronizing contents between Recorded Future and this Exabeam list."
    }

    # Sync Items
    Try {
        $RfIPRiskLists = Get-RfIPRiskLists   
    } Catch {
        Write-Host "$(Get-TimeStamp) - Unable to retrieve Recorded Future IP Threat Lists.  See Get-RfIPRiskLists"
    }

    $RfIPRiskDescriptions = [list[object]]::new()
    $NonFunctionalIPLists = @()
    foreach ($RfIPRiskList in $RfIPRiskLists) {
        if (($NonFunctionalIPLists -notcontains $($RfIPRiskList.name)) -and ($RfIPRiskList.criticality -ge 2)) {
            $RfIPRiskDescriptions.add([PSCustomObject]@{
                Value = $RfIPRiskList.Description
                Enabled = 'true'
            })
        }
    }

    $Results = Add-ExaContextRecords -ContextId $ListStatusIP.id -Data $RfIPRiskDescriptions -Operation 'append'

    Start-Sleep -Seconds 30
    # User Enabled URL List
    $ListStatusIPEnabled = Get-ExaContextRecords -Id $ListStatusIP.id


    # End Section - Setup & Control - IP
    # Begin Section - Vulnerability Setup & Control
    # Establish LR List of available Vulnerability Threat Lists
    $ListNameVuln = 'Recorded Future - Vulnerability Lists'
    $ListStatusVuln = Get-ExaContextTables -Name $ListNameVuln -Exact


    # Create the list if it does not exist
    if (!$ListStatusVuln) {
        $Attributes = [list[object]]::new()
        $Attributes.add([PSCustomObject]@{
            id = 'value'
            isKey = $true
        })
        $Attributes.add([PSCustomObject]@{
            id = 'enabled'
            isKey = $false
        })
        $Results = New-ExaContextTable -Name $ListNameVuln -ContextType 'Other' -Source 'Custom' -Attributes $Attributes

        $ListStatusVuln = Get-ExaContextTables -Name $ListNameVuln -Exact
    } else {
        Write-Verbose "$(Get-TimeStamp) - List Verification: $ListNameVuln exists.  Synchronizing contents between Recorded Future and this Exabeam list."
    }

    # Sync Items
    Try {
        $RfVulnRiskLists = Get-RfVulnerabilityRiskLists   
    } Catch {
        Write-Host "$(Get-TimeStamp) - Unable to retrieve Recorded Future Vulnerability Threat Lists.  See Get-RfVulnerabilityRiskLists"
    }

    $RfVulnRiskDescriptions = [list[object]]::new()
    $NonFunctionalVulnLists = @()
    foreach ($RfVulnRiskList in $RfVulnRiskLists) {
        if (($NonFunctionalVulnLists -notcontains $($RfVulnRiskList.name)) -and ($RfVulnRiskList.criticality -ge 2)) {
            $RfVulnRiskDescriptions.add([PSCustomObject]@{
                Value = $RfVulnRiskList.Description
                Enabled = 'true'
            })
        }
    }

    $Results = Add-ExaContextRecords -ContextId $ListStatusVuln.id -Data $RfVulnRiskDescriptions -Operation 'append'

    Start-Sleep -Seconds 30
    # User Enabled URL List
    $ListStatusVulnEnabled = Get-ExaContextRecords -Id $ListStatusVuln.id


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

                    $Results = Add-ExaContextRecords -ContextId $HashListStatus.id -Data $($Data | Sort-Object risk_level ) -Operation 'append'
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

        if ($ListStatusUrlEnabled) {
            Write-Host "$(Get-TimeStamp) - Begin - Recorded Future URL Threat List Sync"
            ForEach ($ThreatListUrl in $ListStatusUrlEnabled.records) {
                if ($ThreatListUrl.enabled -like 'False') {
                    continue
                }
                # Fork each RiskList into two Lists
                Write-Host "$(Get-TimeStamp) - Working: $($ThreatListUrl.value)"

                # Map list Description to List Name
                Try {
                    Write-Host "$(Get-TimeStamp) - Mapping RecordedFuture Threat List Description to Name"
                    $UrlListName = $RfUrlRiskLists.Where({($_.description -like $($ThreatListUrl.value))}).name
                    $UrlListResultQuantity = $($RfUrlRiskLists.Where({($_.description -like $($ThreatListUrl.value))}) | Select-Object -ExpandProperty count)
                } Catch {
                    Write-Host "$(Get-TimeStamp) - Pulled list: $($ThreatListUrl.value) is not a valid list."
                }

                # Update capitilization for RiskList Value
                $UrlThreatListName = "RF URL: $((Get-Culture).TextInfo.ToTitleCase($ThreatListUrl.value))"

                # Check if list exists - Change to Get-ExaContextTables
                Write-Host "$(Get-TimeStamp) - Testing List Status"
                $UrlListStatus = Get-ExaContextTables -name $UrlThreatListName -Exact
                

                # If the list exists then update it.  Else create it.
                if ($UrlListStatus) {
                    Write-Host "$(Get-TimeStamp) - Updating List: $UrlThreatListName"
                } else {
                    Write-Host "$(Get-TimeStamp) - Creating List: $UrlThreatListName"
                    $Attributes = [list[object]]::new()
                    $Attributes.add([PSCustomObject]@{
                        id = 'value'
                        isKey = $true
                    })
                    $Attributes.add([PSCustomObject]@{
                        id = 'risk_level'
                        isKey = $false
                    })
                    $UrlListStatus = New-ExaContextTable -Name $UrlThreatListName -ContextType 'Other' -Source 'Custom' -Attributes $Attributes
                    # If successful, reset the status to reflect the same result schema as a Get-ExaContextTables
                    if ($UrlListStatus.table) {
                        $UrlListStatus = $UrlListStatus.table
                    }
                }

                # Pull list values
                Write-Host "$(Get-TimeStamp) - Running: Get-RfUrlRiskList -List $UrlThreatListName"

                Write-Host "$(Get-TimeStamp) - Retrieving List to process. List: $UrlThreatListName RecordCount: $UrlListResultQuantity"
                $ListResults = Get-RfUrlRiskList -List $UrlListName

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

                    $Results = Add-ExaContextRecords -ContextId $UrlListStatus.id -Data $($Data | Sort-Object risk_level ) -Operation 'append'
                }
                Write-Host "$(Get-TimeStamp) - Clearing Variables: Url*"
                Clear-Variable -Name Url* -ErrorAction SilentlyContinue
                Clear-Variable -Name ListResults -ErrorAction SilentlyContinue
                Clear-Variable -Name Data -ErrorAction SilentlyContinue
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
        if ($ListStatusDomainEnabled) {
            Write-Host "$(Get-TimeStamp) - Begin - Recorded Future Domain Threat List Sync"
            ForEach ($ThreatList in $ListStatusDomainEnabled.records) {
                if ($ThreatList.enabled -like 'False') {
                    continue
                }
                # Fork each RiskList into two Lists
                Write-Host "$(Get-TimeStamp) - Working: $($ThreatList.value)"

                # Map list Description to List Name
                Try {
                    Write-Host "$(Get-TimeStamp) - Mapping RecordedFuture Threat List Description to Name"
                    $DomainListName = $RfDomainRiskLists.Where({($_.description -like $($ThreatList.value))}).name
                    $DomainListResultQuantity = $($RfDomainRiskLists.Where({($_.description -like $($ThreatList.value))}) | Select-Object -ExpandProperty count)
                } Catch {
                    Write-Host "$(Get-TimeStamp) - Pulled list: $($ThreatList.value) is not a valid list."
                }

                
                # Update capitilization for RiskList Value
                $DomainThreatListName = "RF Domain: $((Get-Culture).TextInfo.ToTitleCase($ThreatList.value))"


                # Check if list exists - Change to Get-LRListGuidByName
                Write-Host "$(Get-TimeStamp) - Testing List Status"
                $DomainListStatus = Get-ExaContextTables -name $DomainThreatListName -Exact

                # If the list exists then update it.  Else create it.
                if ($DomainListStatus) {
                    Write-Host "$(Get-TimeStamp) - Updating List: $DomainThreatListName"
                } else {
                    Write-Host "$(Get-TimeStamp) - Creating List: $DomainThreatListName"
                    $Attributes = [list[object]]::new()
                    $Attributes.add([PSCustomObject]@{
                        id = 'value'
                        isKey = $true
                    })
                    $Attributes.add([PSCustomObject]@{
                        id = 'risk_level'
                        isKey = $false
                    })
                    $DomainListStatus = New-ExaContextTable -Name $DomainThreatListName -ContextType 'Other' -Source 'Custom' -Attributes $Attributes
                    # If successful, reset the status to reflect the same result schema as a Get-ExaContextTables
                    if ($DomainListStatus.table) {
                        $DomainListStatus = $DomainListStatus.table
                    }
                }

                # Pull list values
                Write-Host "$(Get-TimeStamp) - Running: Get-RfDomainRiskList -List $($ThreatList.value)"

                Write-Host "$(Get-TimeStamp) - Retrieving List to process. List: $($ThreatList.value) RecordCount: $DomainListResultQuantity"
                $ListResults = Get-RfDomainRiskList -List $DomainListName

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

                    $Results = Add-ExaContextRecords -ContextId $DomainListStatus.id -Data $($Data | Sort-Object risk_level ) -Operation 'append'
                }
                
                Write-Host "$(Get-TimeStamp) - Clearing Variables: Domain*"
                Clear-Variable -Name Hash* -ErrorAction SilentlyContinue
                Clear-Variable -Name ListResults -ErrorAction SilentlyContinue
                Clear-Variable -Name Data -ErrorAction SilentlyContinue
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
        if ($ListStatusIPEnabled) {
            Write-Host "$(Get-TimeStamp) - Begin - Recorded Future IP Threat List Sync"
            ForEach ($ThreatList in $ListStatusIPEnabled.records) {
                if ($ThreatList.enabled -like 'False') {
                    continue
                }
                # Fork each RiskList into two Lists
                Write-Host "$(Get-TimeStamp) - Working: $($ThreatList.value)"

                # Map list Description to List Name
                Try {
                    Write-Host "$(Get-TimeStamp) - Mapping RecordedFuture Threat List Description to Name"
                    $IPListName = $RfIPRiskLists.Where({($_.description -like $($ThreatList.value))}).name
                    $IPListResultQuantity = $($RfIPRiskLists.Where({($_.description -like $($ThreatList.value))}) | Select-Object -ExpandProperty count)
                } Catch {
                    Write-Host "$(Get-TimeStamp) - Pulled list: $($ThreatList.value) is not a valid list."
                }

                
                # Update capitilization for RiskList Value
                $IPThreatListName = "RF IP: $((Get-Culture).TextInfo.ToTitleCase($ThreatList.value))"


                # Check if list exists - Change to Get-LRListGuidByName
                Write-Host "$(Get-TimeStamp) - Testing List Status"
                $IPListStatus = Get-ExaContextTables -name $IPThreatListName -Exact

                # If the list exists then update it.  Else create it.
                if ($IPListStatus) {
                    Write-Host "$(Get-TimeStamp) - Updating List: $IPThreatListName"
                } else {
                    Write-Host "$(Get-TimeStamp) - Creating List: $IPThreatListName"
                    $Attributes = [list[object]]::new()
                    $Attributes.add([PSCustomObject]@{
                        id = 'value'
                        isKey = $true
                    })
                    $Attributes.add([PSCustomObject]@{
                        id = 'risk_level'
                        isKey = $false
                    })
                    $IPListStatus = New-ExaContextTable -Name $IPThreatListName -ContextType 'Other' -Source 'Custom' -Attributes $Attributes
                    # If successful, reset the status to reflect the same result schema as a Get-ExaContextTables
                    if ($IPListStatus.table) {
                        $IPListStatus = $IPListStatus.table
                    }
                }

                # Pull list values
                Write-Host "$(Get-TimeStamp) - Running: Get-RfIPRiskList -List $IPListName"

                Write-Host "$(Get-TimeStamp) - Retrieving List to process. List: $IPListName RecordCount: $IPListResultQuantity"
                $ListResults = Get-RfIPRiskList -List $IPListName

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

                    $Results = Add-ExaContextRecords -ContextId $IPListStatus.id -Data $($Data | Sort-Object risk_level ) -Operation 'append'
                }
                
                Write-Host "$(Get-TimeStamp) - Clearing Variables: IP*"
                Clear-Variable -Name Hash* -ErrorAction SilentlyContinue
                Clear-Variable -Name ListResults -ErrorAction SilentlyContinue
                Clear-Variable -Name Data -ErrorAction SilentlyContinue
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
        if ($ListStatusVulnEnabled) {
            Write-Host "$(Get-TimeStamp) - Begin - Recorded Future Vuln Threat List Sync"
            ForEach ($ThreatList in $ListStatusVulnEnabled.records) {
                if ($ThreatList.enabled -like 'False') {
                    continue
                }
                # Fork each RiskList into two Lists
                Write-Host "$(Get-TimeStamp) - Working: $($ThreatList.value)"

                # Map list Description to List Name
                Try {
                    Write-Host "$(Get-TimeStamp) - Mapping RecordedFuture Threat List Description to Name"
                    $VulnListName = $RfVulnRiskLists.Where({($_.description -like $($ThreatList.value))}).name
                    $VulnListResultQuantity = $($RfVulnRiskLists.Where({($_.description -like $($ThreatList.value))}) | Select-Object -ExpandProperty count)
                } Catch {
                    Write-Host "$(Get-TimeStamp) - Pulled list: $($ThreatList.value) is not a valid list."
                }

                
                # Update capitilization for RiskList Value
                $VulnThreatListName = "RF Vuln: $((Get-Culture).TextInfo.ToTitleCase($ThreatList.value))"


                # Check if list exists - Change to Get-LRListGuidByName
                Write-Host "$(Get-TimeStamp) - Testing List Status"
                $VulnListStatus = Get-ExaContextTables -name $VulnThreatListName -Exact

                # If the list exists then update it.  Else create it.
                if ($VulnListStatus) {
                    Write-Host "$(Get-TimeStamp) - Updating List: $VulnThreatListName"
                } else {
                    Write-Host "$(Get-TimeStamp) - Creating List: $VulnThreatListName"
                    $Attributes = [list[object]]::new()
                    $Attributes.add([PSCustomObject]@{
                        id = 'value'
                        isKey = $true
                    })
                    $Attributes.add([PSCustomObject]@{
                        id = 'risk_level'
                        isKey = $false
                    })
                    $VulnListStatus = New-ExaContextTable -Name $VulnThreatListName -ContextType 'Other' -Source 'Custom' -Attributes $Attributes
                    # If successful, reset the status to reflect the same result schema as a Get-ExaContextTables
                    if ($VulnListStatus.table) {
                        $VulnListStatus = $VulnListStatus.table
                    }
                }

                # Pull list values
                Write-Host "$(Get-TimeStamp) - Running: Get-RfIPRiskList -List $VulnListName"

                Write-Host "$(Get-TimeStamp) - Retrieving List to process. List: $VulnListName RecordCount: $VulnListResultQuantity"
                $ListResults = Get-RfVulnerabilityRiskList -List $VulnListName

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

                    $Results = Add-ExaContextRecords -ContextId $VulnListStatus.id -Data $($Data | Sort-Object risk_level ) -Operation 'append'
                }
                
                Write-Host "$(Get-TimeStamp) - Clearing Variables: Vuln*"
                Clear-Variable -Name Hash* -ErrorAction SilentlyContinue
                Clear-Variable -Name ListResults -ErrorAction SilentlyContinue
                Clear-Variable -Name Data -ErrorAction SilentlyContinue
                Clear-Variable -Name MinimumConfidenceScore -ErrorAction SilentlyContinue
                [GC]::Collect()
            }
            Write-Host "$(Get-TimeStamp) - End - Recorded Future Vuln Risk List Sync"
        }
    }
    # Begin Section - Value Sync - Vulnerability
    # Cleanup memory.
    [GC]::Collect()
}