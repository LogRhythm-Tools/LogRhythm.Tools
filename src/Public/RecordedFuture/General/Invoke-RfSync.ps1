Function Invoke-RfSync {
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
        [ValidateSet('all','vulnerability','ip','url','domain', ignorecase=$true)]
        [ValidateNotNull()]
        [string[]] $SyncScope = "all"
    )

    $ListPrefix = "F1 RF :"
    $ListReadAccess = "PublicRestrictedAdmin"
    $ListWriteAccess = "PublicRestrictedAdmin"

    # End Section - General Setup
    #---------------------------------------
    # Begin Section - Hash Setup & Control
    # Establish LR List of available Hash Threat Lists
    $RfHashConfThreatList = "$ListPrefix Conf : Hash : Available Risk Lists"
    $RfHashConfConfidenceThreshold = "$ListPrefix Conf : Hash : Confidence Threshold"
    $RfHashEnabledThreatList = "$ListPrefix Conf : Hash : Enabled Risk Lists"

    # Determine if LR List exists
    $ListStatusHash = Get-LrList -Name $RfHashConfThreatList

    # Create the list if it does not exist
    if (!$ListStatusHash) {
        New-LrList -Name $RfHashConfThreatList -ListType "generalvalue" -UseContext "message" -ShortDescription "List of avaialable Recorded Future Hash Risk Lists.  Do not modify this list manually." -ReadAccess $ListReadAccess -WriteAccess $ListWriteAccess 
    } else {
        Write-Verbose "$(Get-TimeStamp) - List Verification: $RfHashConfThreatList exists.  Synchronizing contents between Recorded Future and this LogRhythm list."
    }

    # Sync Items
    Try {
        $RfHashRiskLists = Get-RfHashRiskLists
        $RfHashRiskDescriptions = $RfHashRiskLists | Select-Object -ExpandProperty description
    } Catch {
        Write-Host "$(Get-TimeStamp) - Unable to retrieve Recorded Future Hash Threat Lists.  See Get-RfHashRiskLists"
    }
    Sync-LrListItems -name $RfHashConfThreatList -ItemType "generalvalue" -UseContext "message" -Value $RfHashRiskDescriptions

    # User Enabled URL List
    $ListStatusHashEnabled = Get-LrList -Name $RfHashEnabledThreatList

    # Create the list if it does not exist
    if (!$ListStatusHashEnabled) {
        New-LrList -Name $RfHashEnabledThreatList -ListType "generalvalue" -UseContext "message" -ShortDescription "List of enabled Recorded Future Hash Threat Lists.  Modify this list manually with values from $RfHashConfThreatList." -ReadAccess $ListReadAccess -WriteAccess $ListWriteAccess 
    } else {
        Write-Verbose "$(Get-TimeStamp) - List Verification: $RfHashEnabledThreatList exists."
    }

    # Risk Threshold Management List
    $ListStatusHashConfidence = Get-LrList -Name $RfHashConfConfidenceThreshold

    # Create the list if it does not exist
    if (!$ListStatusHashConfidence) {
        New-LrList -Name $RfHashConfConfidenceThreshold -ListType "generalvalue" -UseContext "message" -ShortDescription "Single Integer value to signify minimum value for Confidence High qualification.  Results from Risk Lists with a Confidence score lower than the value populated on this list will be categorized as ConfLo.  Results from Risk Lists with a Confidence score equal to or greater than the value populated on this list will be categorized as ConfHi" -ReadAccess $ListReadAccess -WriteAccess $ListWriteAccess 
        Add-LrListItem -Name $RfHashConfConfidenceThreshold -Value 90 -ItemType "generalvalue"
    } else {
        Write-Verbose "$(Get-TimeStamp) - List Verification: $RfHashConfConfidenceThreshold exists."
    }
    # End Section - Setup & Control - Hash
    # -----------------------------------
    # Begin Section - Setup & Control - URL
    # Establish LR List of available URL Threat Lists
    $RfUrlConfThreatList = "$ListPrefix Conf : URL : Available Risk Lists"
    $RfUrlConfConfidenceThreshold = "$ListPrefix Conf : URL : Confidence Threshold"
    $RfUrlEnabledThreatList = "$ListPrefix Conf : URL : Enabled Risk Lists"

    # Determine if LR List exists
    $ListStatusUrlThreatList = Get-LrList -Name $RfUrlConfThreatList

    # Create the list if it does not exist
    if (!$ListStatusUrlThreatList) {
        New-LrList -Name $RfUrlConfThreatList -ListType "generalvalue" -UseContext "message" -ShortDescription "List of avaialable Recorded Future URL Risk Lists.  Do not modify this list manually." -ReadAccess $ListReadAccess -WriteAccess $ListWriteAccess 
    } else {
        Write-Verbose "$(Get-TimeStamp) - List Verification: $RfUrlConfThreatList exists.  Synchronizing contents between Recorded Future and this LogRhythm list."
    }

    # Sync Items
    Try {
        $RfUrlRiskLists = Get-RfUrlRiskLists
        $RfUrlRiskDescriptions = $RfUrlRiskLists | Select-Object -ExpandProperty description
    } Catch {
        Write-Host "$(Get-TimeStamp) - Unable to retrieve Recorded Future Url Threat Lists.  See Get-RfUrlRiskLists"
    }
    Sync-LrListItems -name $RfUrlConfThreatList -ItemType "generalvalue" -UseContext "message" -Value $RfUrlRiskDescriptions

    # User Enabled URL List
    $ListStatusUrlEnabled = Get-LrList -Name $RfUrlEnabledThreatList

    # Create the list if it does not exist
    if (!$ListStatusUrlEnabled) {
        New-LrList -Name $RfUrlEnabledThreatList -ListType "generalvalue" -UseContext "message" -ShortDescription "List of enabled Recorded Future URL Threat Lists.  Modify this list manually with values from $RfUrlConfThreatList." -ReadAccess $ListReadAccess -WriteAccess $ListWriteAccess 
    } else {
        Write-Verbose "$(Get-TimeStamp) - List Verification: $RfUrlEnabledThreatList exists."
    }

    # Risk Threshold Management List
    $ListStatusConfidenceThreshold = Get-LrList -Name $RfUrlConfConfidenceThreshold

    # Create the list if it does not exist
    if (!$ListStatusConfidenceThreshold) {
        New-LrList -Name $RfUrlConfConfidenceThreshold -ListType "generalvalue" -UseContext "message" -ShortDescription "Single Integer value to signify minimum value for Confidence High qualification.  Results from Risk Lists with a Confidence score lower than the value populated on this list will be categorized as ConfLo.  Results from Risk Lists with a Confidence score equal to or greater than the value populated on this list will be categorized as ConfHi" -ReadAccess $ListReadAccess -WriteAccess $ListWriteAccess 
        Add-LrListItem -Name $RfUrlConfConfidenceThreshold -Value 85 -ItemType "generalvalue"
    } else {
        Write-Verbose "$(Get-TimeStamp) - List Verification: $RfUrlConfConfidenceThreshold exists."
    }
    # End Section - Setup & Control - URL
    # -----------------------------------
    # Begin Section - Setup & Control - Domain
    # Establish LR List of available Domain Threat Lists
    $RfDomainConfThreatList = "$ListPrefix Conf : Domain : Available Risk Lists"
    $RfDomainConfConfidenceThreshold = "$ListPrefix Conf : Domain : Confidence Threshold"
    $RfDomainEnabledThreatList = "$ListPrefix Conf : Domain : Enabled Risk Lists"

    # Determine if LR List exists
    $ListStatusDomain = Get-LrList -Name $RfDomainConfThreatList

    # Create the list if it does not exist
    if (!$ListStatusDomain) {
        New-LrList -Name $RfDomainConfThreatList -ListType "generalvalue" -UseContext "message" -ShortDescription "List of avaialable Recorded Future Domain Risk Lists.  Do not modify this list manually." -ReadAccess $ListReadAccess -WriteAccess $ListWriteAccess 
    } else {
        Write-Verbose "$(Get-TimeStamp) - List Verification: $RfDomainConfThreatList exists.  Synchronizing contents between Recorded Future and this LogRhythm list."
    }

    # Sync Items
    Try {
        $RfDomainRiskLists = Get-RfDomainRiskLists
        $RfDomainRiskDescriptions = $RfDomainRiskLists | Select-Object -ExpandProperty description
    } Catch {
        Write-Host "$(Get-TimeStamp) - Unable to retrieve Recorded Future Domain Threat Lists.  See Get-RfDomainRiskLists"
    }
    Sync-LrListItems -name $RfDomainConfThreatList -ItemType "generalvalue" -UseContext "message" -Value $RfDomainRiskDescriptions

    # User Enabled URL List
    $ListStatusDomainEnabled = Get-LrList -Name $RfDomainEnabledThreatList

    # Create the list if it does not exist
    if (!$ListStatusDomainEnabled) {
        New-LrList -Name $RfDomainEnabledThreatList -ListType "generalvalue" -UseContext "message" -ShortDescription "List of enabled Recorded Future Domain Threat Lists.  Modify this list manually with values from $RfDomainConfThreatList." -ReadAccess $ListReadAccess -WriteAccess $ListWriteAccess 
    } else {
        Write-Verbose "$(Get-TimeStamp) - List Verification: $RfDomainEnabledThreatList exists."
    }

    # Risk Threshold Management List
    $ListStatusDomainConfidence = Get-LrList -Name $RfDomainConfConfidenceThreshold

    # Create the list if it does not exist
    if (!$ListStatusDomainConfidence) {
        New-LrList -Name $RfDomainConfConfidenceThreshold -ListType "generalvalue" -UseContext "message" -ShortDescription "Single Integer value to signify minimum value for Confidence High qualification.  Results from Risk Lists with a Confidence score lower than the value populated on this list will be categorized as ConfLo.  Results from Risk Lists with a Confidence score equal to or greater than the value populated on this list will be categorized as ConfHi" -ReadAccess $ListReadAccess -WriteAccess $ListWriteAccess 
        Add-LrListItem -Name $RfDomainConfConfidenceThreshold -Value 90 -ItemType "generalvalue"
    } else {
        Write-Verbose "$(Get-TimeStamp) - List Verification: $RfDomainConfConfidenceThreshold exists."
    }
    # End Section - Setup & Control - Domain
    #---------------------------------------
    # Begin Section - Setup & Control - IP 
    # Establish LR List of available IP Threat Lists
    $RfIPConfThreatList = "$ListPrefix Conf : IP : Available Risk Lists"
    $RfIPConfConfidenceThreshold = "$ListPrefix Conf : IP : Confidence Threshold"
    $RfIPEnabledThreatList = "$ListPrefix Conf : IP : Enabled Risk Lists"

    # Determine if LR List exists
    $ListStatusIP = Get-LrList -Name $RfIPConfThreatList

    # Create the list if it does not exist
    if (!$ListStatusIP) {
        New-LrList -Name $RfIPConfThreatList -ListType "generalvalue" -UseContext "message" -ShortDescription "List of avaialable Recorded Future IP Risk Lists.  Do not modify this list manually." -ReadAccess $ListReadAccess -WriteAccess $ListWriteAccess 
    } else {
        Write-Verbose "$(Get-TimeStamp) - List Verification: $RfIPConfThreatList exists.  Synchronizing contents between Recorded Future and this LogRhythm list."
    }

    # Sync Items
    Try {
        $RfIPRiskLists = Get-RfIPRiskLists
        $RfIPRiskDescriptions = $RfIPRiskLists | Select-Object -ExpandProperty description
    } Catch {
        Write-Host "$(Get-TimeStamp) - Unable to retrieve Recorded Future IP Threat Lists.  See Get-RfIPRiskLists"
    }
    Sync-LrListItems -name $RfIPConfThreatList -ItemType "generalvalue" -UseContext "message" -Value $RfIPRiskDescriptions

    # User Enabled URL List
    $ListStatusIPEnabled = Get-LrList -Name $RfIPEnabledThreatList

    # Create the list if it does not exist
    if (!$ListStatusIPEnabled) {
        New-LrList -Name $RfIPEnabledThreatList -ListType "generalvalue" -UseContext "message" -ShortDescription "List of enabled Recorded Future IP Threat Lists.  Modify this list manually with values from $RfIPConfThreatList." -ReadAccess $ListReadAccess -WriteAccess $ListWriteAccess 
    } else {
        Write-Verbose "$(Get-TimeStamp) - List Verification: $RfIPEnabledThreatList exists."
    }

    # Risk Threshold Management List
    $ListStatusIPConfidence = Get-LrList -Name $RfIPConfConfidenceThreshold

    # Create the list if it does not exist
    if (!$ListStatusIPConfidence) {
        New-LrList -Name $RfIPConfConfidenceThreshold -ListType "generalvalue" -UseContext "message" -ShortDescription "Single Integer value to signify minimum value for Confidence High qualification.  Results from Risk Lists with a Confidence score lower than the value populated on this list will be categorized as ConfLo.  Results from Risk Lists with a Confidence score equal to or greater than the value populated on this list will be categorized as ConfHi" -ReadAccess $ListReadAccess -WriteAccess $ListWriteAccess 
        Add-LrListItem -Name $RfIPConfConfidenceThreshold -Value 90 -ItemType "generalvalue"
    } else {
        Write-Verbose "$(Get-TimeStamp) - List Verification: $RfIPConfConfidenceThreshold exists."
    }
    # End Section - Setup & Control - IP
    # Begin Section - Vulnerability Setup & Control
    # Establish LR List of available Vulnerability Threat Lists
    $RfVulnerabilityConfThreatList = "$ListPrefix Conf : Vulnerability : Available Risk Lists"
    $RfVulnerabilityConfConfidenceThreshold = "$ListPrefix Conf : Vulnerability : Confidence Threshold"
    $RfVulnerabilityEnabledThreatList = "$ListPrefix Conf : Vulnerability : Enabled Risk Lists"

    # Determine if LR List exists
    $ListStatusVulnerability = Get-LrList -Name $RfVulnerabilityConfThreatList

    # Create the list if it does not exist
    if (!$ListStatusVulnerability) {
        New-LrList -Name $RfVulnerabilityConfThreatList -ListType "generalvalue" -UseContext "message" -ShortDescription "List of avaialable Recorded Future Vulnerability Risk Lists.  Do not modify this list manually." -ReadAccess $ListReadAccess -WriteAccess $ListWriteAccess 
    } else {
        Write-Verbose "$(Get-TimeStamp) - List Verification: $RfVulnerabilityConfThreatList exists.  Synchronizing contents between Recorded Future and this LogRhythm list."
    }

    # Sync Items
    Try {
        $RfVulnerabilityRiskLists = Get-RfVulnerabilityRiskLists
        $RfVulnerabilityRiskDescriptions = $RfVulnerabilityRiskLists | Select-Object -ExpandProperty description
    } Catch {
        Write-Host "$(Get-TimeStamp) - Unable to retrieve Recorded Future Vulnerability Threat Lists.  See Get-RfVulnerabilityRiskLists"
    }
    Sync-LrListItems -name $RfVulnerabilityConfThreatList -ItemType "generalvalue" -UseContext "message" -Value $RfVulnerabilityRiskDescriptions

    # User Enabled URL List
    $ListStatusVulnerabilityEnabled = Get-LrList -Name $RfVulnerabilityEnabledThreatList

    # Create the list if it does not exist
    if (!$ListStatusVulnerabilityEnabled) {
        New-LrList -Name $RfVulnerabilityEnabledThreatList -ListType "generalvalue" -UseContext "message" -ShortDescription "List of enabled Recorded Future Vulnerability Threat Lists.  Modify this list manually with values from $RfVulnerabilityConfThreatList." -ReadAccess $ListReadAccess -WriteAccess $ListWriteAccess 
    } else {
        Write-Verbose "$(Get-TimeStamp) - List Verification: $RfVulnerabilityEnabledThreatList exists."
    }

    # Risk Threshold Management List
    $ListStatusVulnerabilityConfidence = Get-LrList -Name $RfVulnerabilityConfConfidenceThreshold

    # Create the list if it does not exist
    if (!$ListStatusVulnerabilityConfidence) {
        New-LrList -Name $RfVulnerabilityConfConfidenceThreshold -ListType "generalvalue" -UseContext "message" -ShortDescription "Single Integer value to signify minimum value for Confidence High qualification.  Results from Risk Lists with a Confidence score lower than the value populated on this list will be categorized as ConfLo.  Results from Risk Lists with a Confidence score equal to or greater than the value populated on this list will be categorized as ConfHi" -ReadAccess $ListReadAccess -WriteAccess $ListWriteAccess 
        Add-LrListItem -Name $RfVulnerabilityConfConfidenceThreshold -Value 90 -ItemType "generalvalue"
    } else {
        Write-Verbose "$(Get-TimeStamp) - List Verification: $RfVulnerabilityConfConfidenceThreshold exists."
    }
    # End Section - Setup & Control - Vulnerability
    #-----------------------------
    # Begin Section - Value Sync - Hash
    # Create Hash Threat Lists based on enabled Threat List(s)
    if (($SyncScope -contains "all") -or ($SyncScope -contains "hash")) {
        $EnabledThreatListHash = Get-LrListItems -Name $RfHashEnabledThreatList -ValuesOnly

        if ($EnabledThreatListHash) {
            Write-Host "$(Get-TimeStamp) - Begin - Recorded Future Hash Threat List Sync"
            $RiskCutoffHash = Get-LrListItems -Name $RfHashConfConfidenceThreshold -ValuesOnly
            ForEach ($ThreatListHash in $EnabledThreatListHash) {
                # Fork each RiskList into two Lists
                Write-Host "$(Get-TimeStamp) - Working: $ThreatListHash"

                # Map list Description to List Name
                Try {
                    Write-Host "$(Get-TimeStamp) - Mapping RecordedFuture Threat List Description to Name"
                    $HashListName = $RfHashRiskLists.Where({($_.description -like $ThreatListHash)}).name
                    $HashListResultQuantity = $($RfHashRiskLists.Where({($_.description -like $ThreatListHash)}) | Select-Object -ExpandProperty count)
                } Catch {
                    Write-Host "$(Get-TimeStamp) - Pulled list: $ThreatListHash is not a valid list."
                }

                # Update capitilization for RiskList Value
                $HashThreatListName = (Get-Culture).TextInfo.ToTitleCase($ThreatListHash)

                # High Risk
                # Set High Risk name Schema
                $HashConfHiList = "$($ListPrefix) Hash : ConfHi : $HashThreatListName"

                # Check if list exists - Change to Get-LRListGuidByName
                Write-Host "$(Get-TimeStamp) - Testing ConfHi Status"
                $HashConfHiStatus = Get-LrLists -name $HashConfHiList -Exact

                # If the list exists then update it.  Else create it.
                if ($HashConfHiStatus) {
                    Write-Host "$(Get-TimeStamp) - Updating List: $HashConfHiList"
                    New-LrList -Name $HashConfHiList -ListType "generalvalue" -UseContext "hash" -ShortDescription "Recorded Future list of Hashes for $ThreatListHash.  Confidence score between $RiskCutoffHash and 99.  Sync Time: $(Get-TimeStamp)" -ReadAccess $ListReadAccess -WriteAccess $ListWriteAccess 
                } else {
                    Write-Host "$(Get-TimeStamp) - Creating List: $HashConfHiList"
                    New-LrList -Name $HashConfHiList -ListType "generalvalue" -UseContext "hash" -ShortDescription "Recorded Future list of Hashes for $ThreatListHash.  Confidence score between $RiskCutoffHash and 99.  Sync Time: $(Get-TimeStamp)" -ReadAccess $ListReadAccess -WriteAccess $ListWriteAccess 
                }

                # Suspicious Risk
                # Set Suspicious Risk name Schema
                $HashConfLoList = "$($ListPrefix) Hash : ConfLo : $HashThreatListName"

                Write-Host "$(Get-TimeStamp) - Testing ConfLo Status"
                $HashConfLoStatus = Get-LrLists -name $HashConfLoList -Exact

                # If the list exists then update it.  Else create it.
                if ($HashConfLoStatus) {
                    Write-Host "$(Get-TimeStamp) - Updating List: $HashConfLoList"
                    New-LrList -Name $HashConfLoList -ListType "generalvalue" -UseContext "hash" -ShortDescription "Recorded Future list of Hashes for $ThreatListHash.  Confidence score between 65 and $RiskCutoffHash.  Sync Time: $(Get-TimeStamp)" -ReadAccess $ListReadAccess -WriteAccess $ListWriteAccess 
                } else {
                    Write-Host "$(Get-TimeStamp) - Creating List: $HashConfLoList"
                    New-LrList -Name $HashConfLoList -ListType "generalvalue" -UseContext "hash" -ShortDescription "Recorded Future list of Hashes for $ThreatListHash.  Confidence score score between 65 and $RiskCutoffHash.  Sync Time: $(Get-TimeStamp)" -ReadAccess $ListReadAccess -WriteAccess $ListWriteAccess 
                }

                # Pull list values
                Write-Host "$(Get-TimeStamp) - Running: Get-RfHashRiskList -List $HashListName"
                # Determine if compressed download required
                if ($HashListResultQuantity -ge 2000000) {
                    #$ListResults = Get-RfUrlRiskList -List $UrlListName -Compressed $true
                    Write-Host "$(Get-TimeStamp) - Error - List Quantity too large to process. List: $HashListName RecordCount: $HashListResultQuantity"
                    $ListResults = "http://Error.ListOver2millionEntries.com"
                } else {
                    Write-Host "$(Get-TimeStamp) - Retrieving List to process. List: $HashListName RecordCount: $HashListResultQuantity"
                    $ListResults = Get-RfHashRiskList -List $HashListName

                    # Determin lowest confidence score provided in list.
                    $MinimumConfidenceScore = $($ListResults | Measure-Object -Property Risk -Minimum | Select-Object -ExpandProperty Minimum)

                    # If the list has values with a Risk Score less than the default 65, update the list description to reflect the minimum.
                    if (($MinimumConfidenceScore -lt 65) -and ($Null -ne $MinimumConfidenceScore)) {
                        Write-Host "$(Get-TimeStamp) - Updating List: $HashConfLoList"
                        New-LrList -Name $HashConfLoList -ListType "generalvalue" -UseContext "hash" -ShortDescription "Recorded Future list of Hashes for $ThreatListHash.  Confidence score between $MinimumConfidenceScore and $RiskCutoffHash.  Sync Time: $(Get-TimeStamp)" -ReadAccess $ListReadAccess -WriteAccess $ListWriteAccess 
                    }

                    # Splitting results by Risk
                    Try {
                        Write-Host "$(Get-TimeStamp) - Splitting results where Risk is greater than or equal to $RiskCutoffHash"
                        $HashConfHiResults = $ListResults.Where({([int32]$_.Risk -ge $RiskCutoffHash)}).Name
                        Write-Host "$(Get-TimeStamp) - Splitting results where Risk is less than $RiskCutoffHash"
                        $HashConfLoResults = $ListResults.Where({([int32]$_.Risk -lt $RiskCutoffHash)}).Name
                    } Catch {
                        Write-Host "$(Get-TimeStamp) - Error trying to split ConfHi and ConfLo"
                        Write-Host "$(Get-TimeStamp) - Current List: $HashListName"
                    }

                    # Populate Lists
                    # High Risk
                    if ($HashConfHiResults.count -gt 0) {
                        Write-Host "$(Get-TimeStamp) - Syncing Quantity: $($HashConfHiResults.count)  Hash ConfHi to list $HashConfHiList"
                        Sync-LrListItems -Value $HashConfHiResults -name $HashConfHiList -ItemType "generalvalue"
                    } else {
                        Write-Host "$(Get-TimeStamp) - ConfHi Quantity: $($HashConfHiResults.count)"
                    }

                    # Suspicious Risks
                    if ($HashConfLoResults.count -gt 0) {
                        Write-Host "$(Get-TimeStamp) - Syncing Quantity: $($HashConfLoResults.count)  Hash ConfLo to list $HashConfLoList"
                        Sync-LrListItems -Value $HashConfLoResults -name $HashConfLoList -ItemType "generalvalue"
                    }  else {
                        Write-Host "$(Get-TimeStamp) - ConfLo Quantity: $($HashConfLoResults.count)"
                    }
                }
                Write-Host "$(Get-TimeStamp) - Clearing Variables: Hash*"
                Clear-Variable -Name Hash*
            }
            Write-Host "$(Get-TimeStamp) - End - Recorded Future Hash Risk List Sync"
        }
    }
    # End Section - Value Sync - Hash
    # -----------------------------------
    # Begin Section - Value Sync - Url
    # Create URL Threat Lists based on RfUrlEnabledThreatList values
    if (($SyncScope -contains "all") -or ($SyncScope -contains "url")) {
        $EnabledThreatListUrl = Get-LrListItems -Name $RfUrlEnabledThreatList -ValuesOnly

        if ($EnabledThreatListUrl) {
            Write-Host "$(Get-TimeStamp) - Begin - Recorded Future URL Threat List Sync"
            $RiskCutoffUrl = Get-LrListItems -Name $RfUrlConfConfidenceThreshold -ValuesOnly

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
                    New-LrList -Name $UrlConfHiList -ListType "generalvalue" -UseContext "url" -ShortDescription "Recorded Future list of URLs for $ThreatListUrl.  Confidence score between $RiskCutoffUrl and 99.  Sync Time: $(Get-TimeStamp)" -ReadAccess $ListReadAccess -WriteAccess $ListWriteAccess 
                } else {
                    Write-Host "$(Get-TimeStamp) - Creating List: $UrlConfHiList"
                    New-LrList -Name $UrlConfHiList -ListType "generalvalue" -UseContext "url" -ShortDescription "Recorded Future list of URLs for $ThreatListUrl.  Confidence score between $RiskCutoffUrl and 99.  Sync Time: $(Get-TimeStamp)" -ReadAccess $ListReadAccess -WriteAccess $ListWriteAccess 
                }

                # Suspicious Risk
                # Set Suspicious Risk name Schema
                $UrlConfLoList = "$($ListPrefix) URL : ConfLo : $UrlThreatListName"

                Write-Host "$(Get-TimeStamp) - Testing ConfLo Status"
                $UrlConfLoStatus = Get-LrLists -name $UrlConfLoList -Exact

                # If the list exists then update it.  Else create it.
                if ($UrlConfLoStatus) {
                    Write-Host "$(Get-TimeStamp) - Updating List: $UrlConfLoList"
                    New-LrList -Name $UrlConfLoList -ListType "generalvalue" -UseContext "url" -ShortDescription "Recorded Future list of URLs for $ThreatListUrl.  Confidence score between 65 and $RiskCutoffUrl.  Sync Time: $(Get-TimeStamp)" -ReadAccess $ListReadAccess -WriteAccess $ListWriteAccess 
                } else {
                    Write-Host "$(Get-TimeStamp) - Creating List: $UrlConfLoList"
                    New-LrList -Name $UrlConfLoList -ListType "generalvalue" -UseContext "url" -ShortDescription "Recorded Future list of URLs for $ThreatListUrl.  Confidence score score between 65 and $RiskCutoffUrl.  Sync Time: $(Get-TimeStamp)" -ReadAccess $ListReadAccess -WriteAccess $ListWriteAccess 
                }

                # Pull list values
                Write-Host "$(Get-TimeStamp) - Running: Get-RfUrlRiskList -List $UrlListName"
                # Determine if compressed download required
                if ($UrlListResultQuantity -ge 2000000) {
                    #$ListResults = Get-RfUrlRiskList -List $UrlListName -Compressed $true
                    Write-Host "$(Get-TimeStamp) - Error - List Quantity too large to process. List: $UrlListName RecordCount: $UrlListResultQuantity"
                    $ListResults = "http://Error.ListOver2millionEntries.com"
                } else {
                    Write-Host "$(Get-TimeStamp) - Retrieving List to process. List: $UrlListName RecordCount: $UrlListResultQuantity"
                    $ListResults = Get-RfUrlRiskList -List $UrlListName

                    # Determin lowest confidence score provided in list.
                    $MinimumConfidenceScore = $($ListResults | Measure-Object -Property Risk -Minimum | Select-Object -ExpandProperty Minimum)

                    # If the list has values with a Risk Score less than the default 65, update the list description to reflect the minimum.
                    if (($MinimumConfidenceScore -lt 65) -and ($Null -ne $MinimumConfidenceScore)) {
                        Write-Host "$(Get-TimeStamp) - Updating List: $UrlConfLoList"
                        New-LrList -Name $UrlConfLoList -ListType "generalvalue" -UseContext "url" -ShortDescription "Recorded Future list of URLs for $ThreatListUrl.  Confidence score between $MinimumConfidenceScore and $RiskCutoffUrl.  Sync Time: $(Get-TimeStamp)" -ReadAccess $ListReadAccess -WriteAccess $ListWriteAccess 
                    }

                    # Splitting results by Risk
                    Try {
                        Write-Host "$(Get-TimeStamp) - Splitting results where Risk is greater than or equal to $RiskCutoffUrl"
                        $UrlConfHiResults = $ListResults.Where({([int32]$_.Risk -ge $RiskCutoffUrl)}).Name
                        Write-Host "$(Get-TimeStamp) - Splitting results where Risk is less than $RiskCutoffUrl"
                        $UrlConfLoResults = $ListResults.Where({([int32]$_.Risk -lt $RiskCutoffUrl)}).Name
                    } Catch {
                        Write-Host "$(Get-TimeStamp) - Error trying to split UrlHighResults and UrlSuspiciousResults"
                        Write-Host "$(Get-TimeStamp) - Current List: $UrlListName"
                    }

                    # Populate Lists
                    # High Risk
                    if ($UrlConfHiResults.count -gt 0) {
                        Write-Host "$(Get-TimeStamp) - Syncing Quantity: $($UrlConfHiResults.count)  ConfHi to list $UrlConfHiList"
                        Sync-LrListItems -Value $UrlConfHiResults -name $UrlConfHiList -ItemType "generalvalue"
                    } else {
                        Write-Host "$(Get-TimeStamp) - ConfHi Quantity: $($UrlConfHiResults.count)"
                    }

                    # Suspicious Risks
                    if ($UrlConfLoResults.count -gt 0) {
                        Write-Host "$(Get-TimeStamp) - Syncing Quantity: $($UrlConfLoResults.count)  ConfLo to list $UrlConfLoList"
                        Sync-LrListItems -Value $UrlConfLoResults -name $UrlConfLoList -ItemType "generalvalue"
                    }  else {
                        Write-Host "$(Get-TimeStamp) - ConfLo Quantity: $($UrlConfLoResults.count)"
                    }
                }
                Write-Host "$(Get-TimeStamp) - Clearing Variables: Url*"
                Clear-Variable -Name Url*
            }
            Write-Host "$(Get-TimeStamp) - End - Recorded Future URL Risk List Sync"
        }
    }
    # End Section - Value Sync - Url
    # -----------------------------------
    # Begin Section - Value Sync - Domain
    # Create Domain Threat Lists based on RfDomainEnabledThreatList values
    if (($SyncScope -contains "all") -or ($SyncScope -contains "domain")) {
        $EnabledThreatListDomain = Get-LrListItems -Name $RfDomainEnabledThreatList -ValuesOnly

        if ($EnabledThreatListDomain) {
            Write-Host "$(Get-TimeStamp) - Begin - Recorded Future Domain Threat List Sync"
            $RiskCutoffDomain = Get-LrListItems -Name $RfDomainConfConfidenceThreshold -ValuesOnly

            ForEach ($ThreatListDomain in $EnabledThreatListDomain) {
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

                # High Risk
                # Set High Risk name Schema
                $DomainConfHiList = "$($ListPrefix) Domain : ConfHi : $DomainThreatListName"

                # Check if list exists - Change to Get-LRListGuidByName
                Write-Host "$(Get-TimeStamp) - Testing ConfHi Status"
                $DomainConfHiStatus = Get-LrLists -name $DomainConfHiList -Exact

                # If the list exists then update it.  Else create it.
                if ($DomainConfHiStatus) {
                    Write-Host "$(Get-TimeStamp) - Updating List: $DomainConfHiList"
                    New-LrList -Name $DomainConfHiList -ListType "generalvalue" -UseContext "url" -ShortDescription "Recorded Future list of Domains for $ThreatListDomain.  Confidence score between $RiskCutoffDomain and 99.  Sync Time: $(Get-TimeStamp)" -ReadAccess $ListReadAccess -WriteAccess $ListWriteAccess 
                } else {
                    Write-Host "$(Get-TimeStamp) - Creating List: $DomainConfHiList"
                    New-LrList -Name $DomainConfHiList -ListType "generalvalue" -UseContext "url" -ShortDescription "Recorded Future list of Domains for $ThreatListDomain.  Confidence score between $RiskCutoffDomain and 99.  Sync Time: $(Get-TimeStamp)" -ReadAccess $ListReadAccess -WriteAccess $ListWriteAccess 
                }

                # Suspicious Risk
                # Set Suspicious Risk name Schema
                $DomainConfLoList = "$($ListPrefix) Domain : ConfLo : $DomainThreatListName"

                Write-Host "$(Get-TimeStamp) - Testing ConfLo Status"
                $DomainConfLoStatus = Get-LrLists -name $DomainConfLoList -Exact

                # If the list exists then update it.  Else create it.
                if ($DomainConfLoStatus) {
                    Write-Host "$(Get-TimeStamp) - Updating List: $DomainConfLoList"
                    New-LrList -Name $DomainConfLoList -ListType "generalvalue" -UseContext "url" -ShortDescription "Recorded Future list of Domains for $ThreatListDomain.  Confidence score between 65 and $RiskCutoffDomain.  Sync Time: $(Get-TimeStamp)" -ReadAccess $ListReadAccess -WriteAccess $ListWriteAccess 
                } else {
                    Write-Host "$(Get-TimeStamp) - Creating List: $DomainConfLoList"
                    New-LrList -Name $DomainConfLoList -ListType "generalvalue" -UseContext "url" -ShortDescription "Recorded Future list of Domains for $ThreatListDomain.  Confidence score score between 65 and $RiskCutoffDomain.  Sync Time: $(Get-TimeStamp)" -ReadAccess $ListReadAccess -WriteAccess $ListWriteAccess 
                }

                # Pull list values
                Write-Host "$(Get-TimeStamp) - Running: Get-RfDomainRiskList -List $DomainListName"
                # Determine if compressed download required
                if ($DomainListResultQuantity -ge 2000000) {
                    #$ListResults = Get-RfDomainRiskList -List $DomainListName -Compressed $true
                    Write-Host "$(Get-TimeStamp) - Error - List Quantity too large to process. List: $DomainListName RecordCount: $DomainListResultQuantity"
                    $ListResults = "http://Error.ListOver2millionEntries.com"
                } else {
                    Write-Host "$(Get-TimeStamp) - Retrieving List to process. List: $DomainListName RecordCount: $DomainListResultQuantity"
                    $ListResults = Get-RfDomainRiskList -List $DomainListName

                    # Determin lowest confidence score provided in list.
                    $MinimumConfidenceScore = $($ListResults | Measure-Object -Property Risk -Minimum | Select-Object -ExpandProperty Minimum)

                    # If the list has values with a Risk Score less than the default 65, update the list description to reflect the minimum.
                    if (($MinimumConfidenceScore -lt 65) -and ($Null -ne $MinimumConfidenceScore)) {
                        Write-Host "$(Get-TimeStamp) - Updating List: $DomainConfLoList"
                        New-LrList -Name $DomainConfLoList -ListType "generalvalue" -UseContext "url" -ShortDescription "Recorded Future list of Domains for $ThreatListDomain.  Confidence score between $MinimumConfidenceScore and $RiskCutoffDomain.  Sync Time: $(Get-TimeStamp)" -ReadAccess $ListReadAccess -WriteAccess $ListWriteAccess 
                    }

                    # Splitting results by Risk
                    Try {
                        Write-Host "$(Get-TimeStamp) - Splitting results where Risk is greater than or equal to $RiskCutoffDomain"
                        $DomainConfHiResults = $ListResults.Where({([int32]$_.Risk -ge $RiskCutoffDomain)}).Name
                        Write-Host "$(Get-TimeStamp) - Splitting results where Risk is less than $RiskCutoffDomain"
                        $DomainConfLoResults = $ListResults.Where({([int32]$_.Risk -lt $RiskCutoffDomain)}).Name
                    } Catch {
                        Write-Host "$(Get-TimeStamp) - Error trying to split DomainHighResults and DomainSuspiciousResults"
                        Write-Host "$(Get-TimeStamp) - Current List: $DomainListName"
                    }

                    # Populate Lists
                    # High Risk
                    if ($DomainConfHiResults.count -gt 0) {
                        Write-Host "$(Get-TimeStamp) - Syncing Quantity: $($DomainConfHiResults.count)  ConfHi to list $DomainConfHiList"
                        Sync-LrListItems -Value $DomainConfHiResults -name $DomainConfHiList -ItemType "generalvalue"
                    } else {
                        Write-Host "$(Get-TimeStamp) - ConfHi Quantity: $($DomainConfHiResults.count)"
                    }

                    # Suspicious Risks
                    if ($DomainConfLoResults.count -gt 0) {
                        Write-Host "$(Get-TimeStamp) - Syncing Quantity: $($DomainConfLoResults.count)  ConfLo to list $DomainConfLoList"
                        Sync-LrListItems -Value $DomainConfLoResults -name $DomainConfLoList -ItemType "generalvalue"
                    }  else {
                        Write-Host "$(Get-TimeStamp) - ConfLo Quantity: $($DomainConfLoResults.count)"
                    }
                }
                Write-Host "$(Get-TimeStamp) - Clearing Variables: Domain*"
                Clear-Variable -Name Domain*
            }
            Write-Host "$(Get-TimeStamp) - End - Recorded Future Domain Risk List Sync"
        }
    }
    # End Section - Value Sync - Domain
    # -----------------------------------
    # Begin Section - Value Sync - IP
    # Create IP Threat Lists based on RfIPEnabledThreatList values
    if (($SyncScope -contains "all") -or ($SyncScope -contains "ip")) {
        $EnabledThreatListIP = Get-LrListItems -Name $RfIPEnabledThreatList -ValuesOnly

        if ($EnabledThreatListIP) {
            Write-Host "$(Get-TimeStamp) - Begin - Recorded Future IP Threat List Sync"
            $RiskCutoffIP = Get-LrListItems -Name $RfIPConfConfidenceThreshold -ValuesOnly

            ForEach ($ThreatListIP in $EnabledThreatListIP) {
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
                    New-LrList -Name $IPConfHiList -ListType "ip" -ShortDescription "Recorded Future list of IPs for $ThreatListIP.  Confidence score between $RiskCutoffIP and 99.  Sync Time: $(Get-TimeStamp)" -ReadAccess $ListReadAccess -WriteAccess $ListWriteAccess 
                } else {
                    Write-Host "$(Get-TimeStamp) - Creating List: $IPConfHiList"
                    New-LrList -Name $IPConfHiList -ListType "ip" -ShortDescription "Recorded Future list of IPs for $ThreatListIP.  Confidence score between $RiskCutoffIP and 99.  Sync Time: $(Get-TimeStamp)" -ReadAccess $ListReadAccess -WriteAccess $ListWriteAccess 
                }

                # Suspicious Risk
                # Set Suspicious Risk name Schema
                $IPConfLoList = "$($ListPrefix) IP : ConfLo : $IPThreatListName"

                Write-Host "$(Get-TimeStamp) - Testing ConfLo Status"
                $IPConfLoStatus = Get-LrLists -name $IPConfLoList -Exact

                # If the list exists then update it.  Else create it.
                if ($IPConfLoStatus) {
                    Write-Host "$(Get-TimeStamp) - Updating List: $IPConfLoList"
                    New-LrList -Name $IPConfLoList -ListType "ip" -ShortDescription "Recorded Future list of IPs for $ThreatListIP.  Confidence score between 65 and $RiskCutoffIP.  Sync Time: $(Get-TimeStamp)" -ReadAccess $ListReadAccess -WriteAccess $ListWriteAccess 
                } else {
                    Write-Host "$(Get-TimeStamp) - Creating List: $IPConfLoList"
                    New-LrList -Name $IPConfLoList -ListType "ip" -ShortDescription "Recorded Future list of IPs for $ThreatListIP.  Confidence score score between 65 and $RiskCutoffIP.  Sync Time: $(Get-TimeStamp)" -ReadAccess $ListReadAccess -WriteAccess $ListWriteAccess 
                }

                # Pull list values
                Write-Host "$(Get-TimeStamp) - Running: Get-RfIPRiskList -List $IPListName"
                # Determine if compressed download required
                if ($IPListResultQuantity -ge 2000000) {
                    #$ListResults = Get-RfIPRiskList -List $IPListName -Compressed $true
                    Write-Host "$(Get-TimeStamp) - Error - List Quantity too large to process. List: $IPListName RecordCount: $IPListResultQuantity"
                    $ListResults = "http://Error.ListOver2millionEntries.com"
                } else {
                    Write-Host "$(Get-TimeStamp) - Retrieving List to process. List: $IPListName RecordCount: $IPListResultQuantity"
                    $ListResults = Get-RfIPRiskList -List $IPListName -IPv4

                    # Determin lowest confidence score provided in list.
                    $MinimumConfidenceScore = $($ListResults | Measure-Object -Property Risk -Minimum | Select-Object -ExpandProperty Minimum)

                    # If the list has values with a Risk Score less than the default 65, update the list description to reflect the minimum.
                    if (($MinimumConfidenceScore -lt 65) -and ($Null -ne $MinimumConfidenceScore)) {
                        Write-Host "$(Get-TimeStamp) - Updating List: $IPConfLoList"
                        New-LrList -Name $IPConfLoList -ListType "ip" -ShortDescription "Recorded Future list of IPs for $ThreatListIP.  Confidence score between $MinimumConfidenceScore and $RiskCutoffIP.  Sync Time: $(Get-TimeStamp)" -ReadAccess $ListReadAccess -WriteAccess $ListWriteAccess 
                    }

                    # Splitting results by Risk
                    Try {
                        Write-Host "$(Get-TimeStamp) - Splitting results where Risk is greater than or equal to $RiskCutoffIP"
                        $IPConfHiResults = $ListResults.Where({([int32]$_.Risk -ge $RiskCutoffIP)}).Name
                        Write-Host "$(Get-TimeStamp) - Splitting results where Risk is less than $RiskCutoffIP"
                        $IPConfLoResults = $ListResults.Where({([int32]$_.Risk -lt $RiskCutoffIP)}).Name
                    } Catch {
                        Write-Host "$(Get-TimeStamp) - Error trying to split IPHighResults and IPSuspiciousResults"
                        Write-Host "$(Get-TimeStamp) - Current List: $IPListName"
                    }

                    # Populate Lists
                    # High Risk
                    if ($IPConfHiResults.count -gt 0) {
                        Write-Host "$(Get-TimeStamp) - Syncing Quantity: $($IPConfHiResults.count)  ConfHi to list $IPConfHiList"
                        Sync-LrListItems -Value $IPConfHiResults -name $IPConfHiList -ItemType "generalvalue"
                    } else {
                        Write-Host "$(Get-TimeStamp) - ConfHi Quantity: $($IPConfHiResults.count)"
                    }

                    # Suspicious Risks
                    if ($IPConfLoResults.count -gt 0) {
                        Write-Host "$(Get-TimeStamp) - Syncing Quantity: $($IPConfLoResults.count)  ConfLo to list $IPConfLoList"
                        Sync-LrListItems -Value $IPConfLoResults -name $IPConfLoList -ItemType "generalvalue"
                    }  else {
                        Write-Host "$(Get-TimeStamp) - ConfLo Quantity: $($IPConfLoResults.count)"
                    }
                }
                Write-Host "$(Get-TimeStamp) - Clearing Variables: IP*"
                Clear-Variable -Name IP*
            }
            Write-Host "$(Get-TimeStamp) - End - Recorded Future IP Risk List Sync"
        }
    }
    # End Section - Value Sync - IP
    # -----------------------------------
    # Begin Section - Value Sync - Vulnerability
    # Create Vulnerability Threat Lists based on RfVulnerabilityEnabledThreatList values
    

    
    if (($SyncScope -contains "all") -or ($SyncScope -contains "vulnerability")) {
        $EnabledThreatListVulnerability = Get-LrListItems -Name $RfVulnerabilityEnabledThreatList -ValuesOnly

        if ($EnabledThreatListVulnerability) {
            Write-Host "$(Get-TimeStamp) - Begin - Recorded Future Vulnerability Threat List Sync"
            $RiskCutoffVulnerability = Get-LrListItems -Name $RfVulnerabilityConfConfidenceThreshold -ValuesOnly

            ForEach ($ThreatListVulnerability in $EnabledThreatListVulnerability) {
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
                $VulnerabilityConfHiList = "$($ListPrefix) Vulnerability : ConfHi : $VulnerabilityThreatListName"

                # Check if list exists - Change to Get-LRListGuidByName
                Write-Host "$(Get-TimeStamp) - Testing ConfHi Status"
                $VulnerabilityConfHiStatus = Get-LrLists -name $VulnerabilityConfHiList -Exact

                # If the list exists then update it.  Else create it.
                if ($VulnerabilityConfHiStatus) {
                    Write-Host "$(Get-TimeStamp) - Updating List: $VulnerabilityConfHiList"
                    New-LrList -Name $VulnerabilityConfHiList -ListType "generalvalue" -UseContext "cve" -ShortDescription "Recorded Future list of Vulnerabilitys for $ThreatListVulnerability.  Confidence score between $RiskCutoffVulnerability and 99.  Sync Time: $(Get-TimeStamp)" -ReadAccess $ListReadAccess -WriteAccess $ListWriteAccess 
                } else {
                    Write-Host "$(Get-TimeStamp) - Creating List: $VulnerabilityConfHiList"
                    New-LrList -Name $VulnerabilityConfHiList -ListType "generalvalue" -UseContext "cve" -ShortDescription "Recorded Future list of Vulnerabilitys for $ThreatListVulnerability.  Confidence score between $RiskCutoffVulnerability and 99.  Sync Time: $(Get-TimeStamp)" -ReadAccess $ListReadAccess -WriteAccess $ListWriteAccess 
                }

                # Suspicious Risk
                # Set Suspicious Risk name Schema
                $VulnerabilityConfLoList = "$($ListPrefix) Vulnerability : ConfLo : $VulnerabilityThreatListName"

                Write-Host "$(Get-TimeStamp) - Testing ConfLo Status"
                $VulnerabilityConfLoStatus = Get-LrLists -name $VulnerabilityConfLoList -Exact

                # If the list exists then update it.  Else create it.
                if ($VulnerabilityConfLoStatus) {
                    Write-Host "$(Get-TimeStamp) - Updating List: $VulnerabilityConfLoList"
                    New-LrList -Name $VulnerabilityConfLoList -ListType "generalvalue" -UseContext "cve" -ShortDescription "Recorded Future list of Vulnerabilitys for $ThreatListVulnerability.  Confidence score between 65 and $RiskCutoffVulnerability.  Sync Time: $(Get-TimeStamp)" -ReadAccess $ListReadAccess -WriteAccess $ListWriteAccess 
                } else {
                    Write-Host "$(Get-TimeStamp) - Creating List: $VulnerabilityConfLoList"
                    New-LrList -Name $VulnerabilityConfLoList -ListType "generalvalue" -UseContext "cve" -ShortDescription "Recorded Future list of Vulnerabilitys for $ThreatListVulnerability.  Confidence score score between 65 and $RiskCutoffVulnerability.  Sync Time: $(Get-TimeStamp)" -ReadAccess $ListReadAccess -WriteAccess $ListWriteAccess 
                }

                # Pull list values
                Write-Host "$(Get-TimeStamp) - Running: Get-RfVulnerabilityRiskList -List $VulnerabilityListName"
                # Determine if compressed download required
                if ($VulnerabilityListResultQuantity -ge 2000000) {
                    #$ListResults = Get-RfVulnerabilityRiskList -List $VulnerabilityListName -Compressed $true
                    Write-Host "$(Get-TimeStamp) - Error - List Quantity too large to process. List: $VulnerabilityListName RecordCount: $VulnerabilityListResultQuantity"
                    $ListResults = "http://Error.ListOver2millionEntries.com"
                } else {
                    Write-Host "$(Get-TimeStamp) - Retrieving List to process. List: $VulnerabilityListName RecordCount: $VulnerabilityListResultQuantity"
                    $ListResults = Get-RfVulnerabilityRiskList -List $VulnerabilityListName -CVE

                    # Determin lowest confidence score provided in list.
                    $MinimumConfidenceScore = $($ListResults | Measure-Object -Property Risk -Minimum | Select-Object -ExpandProperty Minimum)

                    # If the list has values with a Risk Score less than the default 65, update the list description to reflect the minimum.
                    if (($MinimumConfidenceScore -lt 65) -and ($Null -ne $MinimumConfidenceScore)) {
                        Write-Host "$(Get-TimeStamp) - Updating List: $VulnerabilityConfLoList"
                        New-LrList -Name $VulnerabilityConfLoList -ListType "generalvalue" -UseContext "cve" -ShortDescription "Recorded Future list of Vulnerabilitys for $ThreatListVulnerability.  Confidence score between $MinimumConfidenceScore and $RiskCutoffVulnerability.  Sync Time: $(Get-TimeStamp)" -ReadAccess $ListReadAccess -WriteAccess $ListWriteAccess 
                    }

                    # Splitting results by Risk
                    Try {
                        Write-Host "$(Get-TimeStamp) - Splitting results where Risk is greater than or equal to $RiskCutoffVulnerability"
                        $VulnerabilityConfHiResults = $ListResults.Where({([int32]$_.Risk -ge $RiskCutoffVulnerability)}).Name
                        Write-Host "$(Get-TimeStamp) - Splitting results where Risk is less than $RiskCutoffVulnerability"
                        $VulnerabilityConfLoResults = $ListResults.Where({([int32]$_.Risk -lt $RiskCutoffVulnerability)}).Name
                    } Catch {
                        Write-Host "$(Get-TimeStamp) - Error trying to split VulnerabilityHighResults and VulnerabilitySuspiciousResults"
                        Write-Host "$(Get-TimeStamp) - Current List: $VulnerabilityListName"
                    }

                    # Populate Lists
                    # High Risk
                    if ($VulnerabilityConfHiResults.count -gt 0) {
                        Write-Host "$(Get-TimeStamp) - Syncing Quantity: $($VulnerabilityConfHiResults.count)  ConfHi to list $VulnerabilityConfHiList"
                        Sync-LrListItems -Value $VulnerabilityConfHiResults -name $VulnerabilityConfHiList -ItemType "generalvalue"
                    } else {
                        Write-Host "$(Get-TimeStamp) - ConfHi Quantity: $($VulnerabilityConfHiResults.count)"
                    }

                    # Suspicious Risks
                    if ($VulnerabilityConfLoResults.count -gt 0) {
                        Write-Host "$(Get-TimeStamp) - Syncing Quantity: $($VulnerabilityConfLoResults.count)  ConfLo to list $VulnerabilityConfLoList"
                        Sync-LrListItems -Value $VulnerabilityConfLoResults -name $VulnerabilityConfLoList -ItemType "generalvalue"
                    }  else {
                        Write-Host "$(Get-TimeStamp) - ConfLo Quantity: $($VulnerabilityConfLoResults.count)"
                    }
                }
                Write-Host "$(Get-TimeStamp) - Clearing Variables: Vulnerability*"
                Clear-Variable -Name Vulnerability*
            }
            Write-Host "$(Get-TimeStamp) - End - Recorded Future Vulnerability Risk List Sync"
        }
    }
    # Begin Section - Value Sync - Vulnerability
    # Cleanup memory.
    [GC]::Collect()
}