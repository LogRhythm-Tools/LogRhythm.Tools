using namespace System
using namespace System.IO
using namespace System.Collections.Generic
Function New-LrCaseHelper {
    <#
    .SYNOPSIS
        Add-LrNoteToCase
    .DESCRIPTION
        Add-LrNoteToCase
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
        Note: You can bypass the need to provide a Credential by setting
        the preference variable $LrtConfig.LogRhythm.ApiKey
        with a valid Api Token.
    .PARAMETER Id
        The Id of the case for which to add a note.
    .PARAMETER Text
        Text of note to add   
    .INPUTS
        Type -> Parameter
    .OUTPUTS
        PSCustomObject representing the (new|modified) LogRhythm object.
    .EXAMPLE
        PS C:\> New-LrCaseHelper -AlarmID 1 -CaseSummary "Someone broke in.. who could it have been?" -DefaultCaseTag "Tech_PhysicalSecurity" -TagOriginUsers -BindAlarmToExistingCase "userorigin" -Playbook "Unauthorized Access" -TagImpactedHosts -PassThru
        ---
        AlarmID         : 1
        DrilldownStatus : True
        Drilldown       : @{AlarmID=1; AlarmGuid=b65a202b-60f1-415b-aef1-85ab185e2f96; Priority=39; AIERuleName=Physical Access - Attempted to Forced Entry; Status=4;
                        Logs=System.Collections.Generic.List`1[System.Object]; SummaryFields=System.Collections.Generic.List`1[System.Collections.Generic.Dictionary`2[System.String,System.String]];
                        NotificationSent=True; EventID=2993; NormalMessageDate=2020-11-09T18:54:56.743; AIEMsgXml=<aie v="1"><_0 FactCount="1" Login="beth.nickels" MsgSourceID="29" NormalMsgDate="2020-11-09  
                        18:54:00" NormalMsgDateLower="2020-11-09 18:54:00" NormalMsgDateUpper="2020-11-09 18:55:00" RuleBlockType="1" /><_1 FactCount="1" MsgSourceID="29" NormalMsgDate="2020-11-09 18:54:00"  
                        NormalMsgDateLower="2020-11-09 18:54:00" NormalMsgDateUpper="2020-11-09 18:58:00" RuleBlockType="1" VendorMsg="forced door" /><_ AIERuleID="1000000001" DateEdited="2020-11-09
                        18:53:29" /></aie>}
        CaseNumber      : 5
        Case            : {CasePlaybook, CaseObject, CaseTags, Note}
        Playbook        : @{id=6D980445-F31D-4FF6-AC67-2F0D992C8D4E; name=Unauthorized Access; description=Use this Playbook when successful unauthorized access occurs accessing either systems or data.;        
                        permissions=; owner=; retired=False; entities=System.Object[]; dateCreated=2020-11-09T19:52:31.9261409Z; dateUpdated=2020-11-09T19:57:52.3675841Z; lastUpdatedBy=;
                        tags=System.Object[]}
    .NOTES
        LogRhythm-API
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]

    param( 
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
        [int32]$AlarmID,


        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 1)]
        [string]$CaseSummary,


        [Parameter(Mandatory = $false, ValueFromPipeline = $true, Position = 2)]
        [int32]$CaseDefaultPriority = 3,


        [Parameter(Mandatory = $false, Position = 3)]
        [string]$DefaultCaseTag,


        [Parameter(Mandatory = $false, Position = 4)]
        [switch]$TagOriginUsers,


        [Parameter(Mandatory = $false, Position = 5)]
        [switch]$TagImpactedUsers,


        [Parameter(Mandatory = $false, Position = 6)]
        [switch]$TagOriginHosts,


        [Parameter(Mandatory = $false, Position = 7)]
        [switch]$TagImpactedHosts,


        [Parameter(Mandatory = $false, Position = 8)]
        [ValidateSet('userorigin', 'userimpacted', 'impactedhost','originhost', ignorecase=$true)]
        [String]$BindAlarmToExistingCase="userorigin",


        [Parameter(Mandatory = $false, Position = 9)]
        [String]$Playbook,


        [Parameter(Mandatory = $false, Position = 10)]
        [switch]$PassThru
    )

    Begin {
        Write-Verbose "$(Get-Timestamp) - Begin New-LrCaseHelper"
        Write-Verbose "$(Get-Timestamp) - Initializing cmdlet list variables"
        # List of Unique User Login accounts identified within the Alarm Log results from the AIE Drilldown results.
        $Logins = [list[string]]::new()

        # List of True Identity Records assocaited with Login accounts identified within the Alarm Log results from the AIE Drilldown results.
        $TrueIdentities = [list[string]]::new()

        # Impacted TrueIdentities
        $ImpactedIdentities = [list[string]]::new()

        # Impacted Logins
        $ImpactedLogins = [list[string]]::new()

        # Origin TrueIdentities
        $OriginIdentities = [list[string]]::new()

        # Origin Logins
        $OriginLogins = [list[string]]::new()

        # Senders
        $Senders = [list[string]]::new()

        # Recipients
        $Recipients = [list[string]]::new()


        # List of Unique Countries identified within the Alarm Log results from the AIE Drilldown results.
        $ImpactedCountries = [list[string]]::new()

        # List of Unique Cities identified within the Alarm Log results from the AIE Drilldown results.
        $ImpactedCities = [list[string]]::new()


        # List of Unique External IP Addresses identified within the Alarm Log results from the AIE Drilldown results.
        $ImpactedIPs = [list[string]]::new()

        # List of Unique Hosts within the Alarm Log results from the AIE Drilldown results.
        $ImpactedHosts = [list[string]]::new()

        # Internal ImpactedKnownHosts
        $ImpactedInternalIDs = [list[string]]::new()

        # External ImpactedKnownHosts
        $ImpactedExternalIDs = [list[string]]::new()

        # Internal ImpactedIPs
        $ImpactedInternalIPs = [list[string]]::new()

        # External ImpactedIPs
        $ImpactedExternalIPs = [list[string]]::new()

        # Internal ImpactedHosts
        $ImpactedInternalHosts = [list[string]]::new()

        # External ImpactedHosts
        $ImpactedExternalHosts = [list[string]]::new()

        # Internal OriginKnownHosts
        $OriginInternalIDs = [list[string]]::new()

        # External OriginKnownHosts
        $OriginExternalIDs = [list[string]]::new()

        # Internal OriginIPs
        $OriginInternalIPs = [list[string]]::new()

        # External OriginIPs
        $OriginExternalIPs = [list[string]]::new()

        # Internal OriginHosts
        $OriginInternalHosts = [list[string]]::new()

        # External OriginHosts
        $OriginExternalHosts = [list[string]]::new()

        # List of Unique Internal IP Addresses identified within the Alarm Log results from the AIE Drilldown results.
        $OriginIPs = [list[string]]::new()

        # List of Unique Hosts identified within the Alarm Log results from the AIE Drilldown results.
        $OriginHosts = [list[string]]::new()

        # List of Unique Common Events identified within the Alarm Log results from the AIE Drilldown results.
        $CommonEvents = [list[string]]::new()

        # List of UnknownDirection Known Origin Hosts
        $OriginHostIds = [list[string]]::new()

        # List of Direction Unknown Origin IPs
        $OriginHostIPs = [list[string]]::new()

        # List of Direction Unknown Origin Hosts
        $OriginHostNames = [list[string]]::new()

        # List of Known Impacted Hosts
        $ImpactedHostIds = [list[string]]::new()

        # List of Direction Unknown Impacted IPs
        $ImpactedHostIPs = [list[string]]::new()

        # List of Direction Unknown Impacted Hosts
        $ImpactedHostNames = [list[string]]::new()

        # List of Case Taxonomy Tags
        $CaseTags = [list[object]]::new()

        # Timestamp for the Earliest log within the Alarm Log results from the AIE Drilldown results.
        $EarliestEvent

        # Timestamp for the Earliest log within the Alarm Log results from the AIE Drilldown results.
        $LatestEvent

        # List of LogRhythm API response for Tag automation
        #$ResultsTags = [list[object]]::new()

        # Define list for new tags identified
        $ScreenNewTags = [list[object]]::new()

        # Set standard API Relief to prevent API rate limit
        $APISleep = 0.3

        Write-Verbose "$(Get-Timestamp) - Initilization complete for cmdlet list variables"
    }

    Process{
        # Define Output Object
        $OutObject = [PSCustomObject]@{
            AlarmID         = $AlarmId
            DrilldownStatus = $null
            Drilldown       = $null
            CaseNumber      = $null
            Case            = @{
                CaseObject      = $null
                CaseTags        = $null
                CasePlaybook    = $null
                Note            = $null
            }
            Playbook        = $null
        }

        # Retrieve Alarm AIE data and logs
        Write-Verbose "$(Get-Timestamp) - Begin - Get-LrAieDrilldown for Alarm: $($AlarmId)"
        Try {
            $AlarmDetails = Get-LrAieDrilldown -AlarmId $AlarmId
            $OutObject.DrilldownStatus   = $true
            $OutObject.Drilldown = $AlarmDetails
            Write-Verbose "$(Get-Timestamp) - Info - Successful drilldown retrieval for Alarm: $($AlarmId)"
        } Catch {
            Write-Verbose "$(Get-Timestamp) - Info - Unsuccessful drilldown retrieval for Alarm: $($AlarmId)"
            $OutObject.DrilldownStatus = $false
        }
        Write-Verbose "$(Get-Timestamp) - End - Get-LrAieDrilldown for Alarm: $($AlarmId)"
        

        # Set Case Priority based on Alarm Priority
        
        if ($AlarmDetails) {
            Write-Verbose "$(Get-Timestamp) - Begin - CasePriority by AlarmRisk"
            Switch ($AlarmDetails.Priority) {
                {0..59 -contains $_} {$CasePriority = 5}
                {60..69 -contains $_} {$CasePriority = 4}
                {70..79 -contains $_} {$CasePriority = 3}
                {80..89 -contains $_}  {$CasePriority = 2}
                {90..100 -contains $_} {$CasePriority = 1}
                default {$CasePriority = $CaseDefaultPriority}
            }
            Write-Verbose "$(Get-Timestamp) - Info - AlarmRisk: $($AlarmDetails.Priority) CasePriority: $($CasePriority)"
            Write-Verbose "$(Get-Timestamp) - End - CasePriority by AlarmRisk"
        }

        # Retrieve Case Playbook
        if ($Playbook) {
            $CasePlaybook = Get-LrPlaybooks -Name $Playbook -Exact
            if ($CasePlaybook) {
                $OutObject.Playbook = $CasePlaybook
            }
        }
        

        # Collect evidence markers from AIE Drilldown
        if ($OutObject.Drilldown.Logs) {
            Write-Verbose "$(Get-Timestamp) - Begin - Populate cmdlet lists based on Drilldown"
            ForEach ($Log in $OutObject.Drilldown.Logs) {
                # Establish unique Users Origin
                if ($Log.login) {
                    if ($OriginLogins -notcontains $Log.login) {
                        $OriginLogins.add($Log.login)
                    }
                }

                # Establish unique Users Impacted
                if ($Log.Account) {
                    if ($ImpactedLogins -notcontains $Log.Account) {
                        $ImpactedLogins.add($Log.Account)
                    }
                }

                # Establish True Identity IDs - Origin
                if ($Log.userOriginIdentityId) {
                    if ($OriginIdentities -notcontains $Log.userOriginIdentityId) {
                        $OriginIdentities.add($Log.userOriginIdentityId)
                    }
                }

                # Establish True Identity IDs - Impacted
                if ($Log.userImpactedIdentityId) {
                    if ($ImpactedIdentities -notcontains $Log.userImpactedIdentityId) {
                        $ImpactedIdentities.add($Log.userImpactedIdentityId)
                    }
                }


                # Establish Unique Senders
                if ($Log.sender) {
                    if ($Senders -notcontains $Log.sender) {
                        $Senders.add($Log.sender)
                    }
                }

                # Establish Unique Recipients
                if ($Log.recipient) {
                    if ($Recipients -notcontains $Log.recipient) {
                        $Recipients.add($Log.recipient)
                    }
                }

                # Origin Resources
                if ($Log.originZoneName -eq "Internal") {
                    # originHostId = If the originHostID is in the KnownHost Record
                    if ($Log.originHostId -ne -1) {
                        if ($OriginInternalIDs -notcontains $Log.originHostId) {
                            # Internal OriginKnownHosts
                            $OriginInternalIDs.add($Log.originHostId)
                        }
                        # If there is no knownHost record data associated with the log, proceed to parse the originHost data
                    } else {
                        # Add unique origin Hostnames
                        if ($Log.originHostname) {
                            # Verify if hostname parses as ValidIPv4Address
                            $HostnameIPv4Status = Test-ValidIPv4Address -IP $($Log.originhostname)
                            # Test if the OriginHostname value is an IPv4 Address, if it is, add the IPAddress to the InternalIPs list
                            if ($HostnameIPv4Status.IsValid -eq $true) {
                                if ($OriginInternalIPs -notcontains $Log.originhostname) {
                                    # Hostname Validates as IPv4 Address, adding entry to Origin IPv4 list
                                    $OriginInternalIPs.add($Log.originhostname)
                                }
                            } else {
                                if ($OriginInternalHosts -notcontains $Log.originhostname) {
                                    # Add Hostname to InternalHosts list
                                    $OriginInternalHosts.add($Log.originhostname)                        
                                }
                            }
                        }

                        # Add unique origin IP Addresses
                        if ($Log.originIp) {
                            if ($OriginInternalIPs -notcontains $Log.originIp) {
                                # Hostname Validates as IPv4 Address, adding entry to Origin IPv4 list
                                $OriginInternalIPs.add($Log.originIp)
                            }
                        }
                    }
                } elseif ($Log.originZoneName -eq "External") {
                    # originHostId = If the originHostID is in the KnownHost Record
                    if ($Log.originHostId -ne -1) {
                        if ($OriginExternalIDs -notcontains $Log.originHostId) {
                            # External OriginKnownHosts
                            $OriginExternalIDs.add($Log.originHostId)
                        }
                        # If there is no knownHost record data associated with the log, proceed to parse the originHost data
                    } else {
                        if ($Log.originHostname) {
                            # Verify if hostname parses as ValidIPv4Address
                            $HostnameIPv4Status = Test-ValidIPv4Address -IP $($Log.originhostname)
                            # Test if the OriginHostname value is an IPv4 Address, if it is, add the IPAddress to the ExternalIPs list
                            if ($HostnameIPv4Status.IsValid -eq $true) {
                                if ($OriginExternalIPs -notcontains $Log.originhostname) {
                                    # Hostname Validates as IPv4 Address, adding entry to Origin IPv4 list
                                    $OriginExternalIPs.add($Log.originhostname)
                                }
                            } else {
                                if ($OriginExternalHosts -notcontains $Log.originhostname) {
                                    # Add Hostname to InternalHosts list
                                    $OriginExternalHosts.add($Log.originhostname)                        
                                }
                            }
                        }

                        # Add unique impacted IP Addresses
                        if ($Log.originIp) {
                            if ($OriginExternalIPs -notcontains $Log.originIp) {
                                # Hostname Validates as IPv4 Address, adding entry to Origin IPv4 list
                                $OriginExternalIPs.add($Log.originIp)
                            }
                        }
                    }
                } else {
                    # originHostId = If the originHostID is in the KnownHost Record
                    if ($Log.originHostId -ne -1) {
                        if ($OriginHostIds -notcontains $Log.originHostId) {
                            # External OriginKnownHosts
                            $OriginHostIds.add($Log.originHostId)
                        }
                        # If there is no knownHost record data associated with the log, proceed to parse the originHost data
                    } else {
                        if ($Log.originHostname) {
                            # Verify if hostname parses as ValidIPv4Address
                            $HostnameIPv4Status = Test-ValidIPv4Address -IP $($Log.originhostname)
                            # Test if the OriginHostname value is an IPv4 Address, if it is, add the IPAddress to the ExternalIPs list
                            if ($HostnameIPv4Status.IsValid -eq $true) {
                                if ($OriginHostIPs -notcontains $Log.originhostname) {
                                    # Hostname Validates as IPv4 Address, adding entry to Origin IPv4 list
                                    $OriginHostIPs.add($Log.originhostname)
                                }
                            } else {
                                if ($OriginHostNames -notcontains $Log.originhostname) {
                                    # Add Hostname to InternalHosts list
                                    $OriginHostNames.add($Log.originhostname)                        
                                }
                            }
                        }

                        # Add unique impacted IP Addresses
                        if ($Log.originIp) {
                            if ($OriginHostIPs -notcontains $Log.originIp) {
                                # Hostname Validates as IPv4 Address, adding entry to Origin IPv4 list
                                $OriginHostIPs.add($Log.originIp)
                            }
                        }

                    } 
                }

                # Impacted Resources
                if ($Log.impactedZoneName -eq "Internal") {
                    # ImpactedHostId = If the ImpactedHostId is in the KnownHost Record
                    if ($Log.impactedHostId -ne -1) {
                        if ($ImpactedInternalIDs -notcontains $Log.impactedHostId) {
                            # Internal OriginKnownHosts
                            $ImpactedInternalIDs.add($Log.impactedHostId)
                        }
                        # If there is no knownHost record data associated with the log, proceed to parse the originHost data
                    } else {
                        if ($Log.impactedHostname) {
                            # Verify if hostname parses as ValidIPv4Address
                            $HostnameIPv4Status = Test-ValidIPv4Address -IP $($Log.impactedhostname)
                            # Test if the impactedHostname value is an IPv4 Address, if it is, add the IPAddress to the InternalIPs list
                            if ($HostnameIPv4Status.IsValid -eq $true) {
                                if ($impactedInternalIPs -notcontains $Log.impactedhostname) {
                                    # Hostname Validates as IPv4 Address, adding entry to impacted IPv4 list
                                    $impactedInternalIPs.add($Log.impactedhostname)
                                }
                            } else {
                                if ($impactedInternalHosts -notcontains $Log.impactedhostname) {
                                    # Add Hostname to InternalHosts list
                                    $impactedInternalHosts.add($Log.impactedhostname)                        
                                }
                            }
                        }

                        # Add unique origin IP Addresses
                        if ($Log.impactedIp) {
                            if ($ImpactedInternalIPs -notcontains $Log.impactedIp) {
                                # Hostname Validates as IPv4 Address, adding entry to Origin IPv4 list
                                $ImpactedInternalIPs.add($Log.impactedIp)
                            }
                        }
                    }
                } elseif ($Log.impactedZoneName -eq "External") {
                    # impactedHostId = If the impactedHostID is in the KnownHost Record
                    if ($Log.impactedHostId -ne -1) {
                        if ($impactedExternalIDs -notcontains $Log.impactedHostId) {
                            # External impactedKnownHosts
                            $impactedExternalIDs.add($Log.impactedHostId)
                        }
                        # If there is no knownHost record data associated with the log, proceed to parse the impactedHost data
                    } else {
                        if ($Log.impactedHostname) {
                            # Verify if hostname parses as ValidIPv4Address
                            $HostnameIPv4Status = Test-ValidIPv4Address -IP $($Log.impactedhostname)
                            # Test if the impactedHostname value is an IPv4 Address, if it is, add the IPAddress to the ExternalIPs list
                            if ($HostnameIPv4Status.IsValid -eq $true) {
                                if ($impactedExternalIPs -notcontains $Log.impactedhostname) {
                                    # Hostname Validates as IPv4 Address, adding entry to impacted IPv4 list
                                    $impactedExternalIPs.add($Log.impactedhostname)
                                }
                            } else {
                                if ($impactedExternalHosts -notcontains $Log.impactedhostname) {
                                    # Add Hostname to InternalHosts list
                                    $impactedExternalHosts.add($Log.impactedhostname)                        
                                }
                            }
                        }

                        # Add unique origin IP Addresses
                        if ($Log.impactedIp) {
                            if ($impactedExternalIPs -notcontains $Log.impactedIp) {
                                # Hostname Validates as IPv4 Address, adding entry to Origin IPv4 list
                                $impactedExternalIPs.add($Log.impactedIp)
                            }
                        }
                    }
                } else {
                    # impactedHostId = If the impactedHostID is in the KnownHost Record
                    if ($Log.impactedHostId -ne -1) {
                        if ($ImpactedHostIds -notcontains $Log.impactedHostId) {
                            # Unknown impactedKnownHosts
                            $ImpactedHostIds.add($Log.impactedHostId)
                        }
                        # If there is no knownHost record data associated with the log, proceed to parse the impactedHost data
                    } else {
                        if ($Log.impactedHostname) {
                            # Verify if hostname parses as ValidIPv4Address
                            $HostnameIPv4Status = Test-ValidIPv4Address -IP $($Log.impactedhostname)
                            # Test if the impactedHostname value is an IPv4 Address, if it is, add the IPAddress to the ExternalIPs list
                            if ($HostnameIPv4Status.IsValid -eq $true) {
                                if ($ImpactedHostIPs -notcontains $Log.impactedhostname) {
                                    # Hostname Validates as IPv4 Address, adding entry to impacted IPv4 list
                                    $ImpactedHostIPs.add($Log.impactedhostname)
                                }
                            } else {
                                if ($ImpactedHostNames -notcontains $Log.impactedhostname) {
                                    # Add Hostname to InternalHosts list
                                    $ImpactedHostNames.add($Log.impactedhostname)                        
                                }
                            }
                        }

                        # Add unique impacted IP Addresses
                        if ($Log.impactedIp) {
                            if ($ImpactedHostIPs -notcontains $Log.impactedIp) {
                                # Hostname Validates as IPv4 Address, adding entry to impacted IPv4 list
                                $ImpactedHostIPs.add($Log.impactedIp)
                            }
                        }
                    } 
                }

                # Internal Resources - City & Country
                if ($Log.originCity) {
                    if ($OriginCities -notcontains $Log.originCity) {
                        $OriginCities.add($Log.originCity)
                    }
                    if ($OriginCountries -notcontains $Log.OriginCountry) {
                        $OriginCountries.add($Log.OriginCountry)
                    }
                }

                # External Resources - City & Country
                if ($Log.impactedCountry) {
                    if ($ImpactedCities -notcontains $Log.impactedCity) {
                        $ImpactedCities.add($Log.impactedCity)
                    }
                    if ($ImpactedCountries -notcontains $Log.impactedCountry) {
                        $ImpactedCountries.add($Log.impactedCountry)
                    }
                }

                # Establish unique Common Events
                if ($CommonEvents -notcontains $Log.commonEventName) {
                    $CommonEvents.add($Log.commoneventname)
                }
            }
            Write-Verbose "$(Get-Timestamp) - End - Populate cmdlet lists based on Drilldown"
        }

        # No AIE Drilldown results have been collected.  Create case based on Alarm.  Add Playbook, analysts, and update automation procedure status.
        if (($OutObject.DrilldownStatus -eq $false) -or ($OutObject.DrilldownStatus -like "false")) {
            Write-Verbose "$(Get-Timestamp) - Begin - Create Case - No drilldown"
            $OutObject.Case.CaseObject = New-LrCase -Name $AlarmDetails.AIERuleName -Priority $CasePriority -Summary $CaseSummary -AlarmNumbers $AlarmDetails.AlarmId -PassThru
            $OutObject.CaseNumber = $OutObject.Case.CaseObject.number
            Write-Verbose "$(Get-Timestamp) - Begin - Created Case: $($OutObject.CaseNumber)"
            $OutObject.Case.Note = "New case created without Drilldown enrichment."
            
            # Add CasePlaybook if Defined and lookup was successful
            if ($OutObject.Playbook.Id) {
                Write-Verbose "$(Get-Timestamp) - Begin - Adding playbook: $($OutObject.Playbook.Name) to Case: $($OutObject.CaseNumber)"
                $OutObject.Case.CasePlaybook = Add-LrCasePlaybook -Id $OutObject.CaseNumber -Playbook $($OutObject.Playbook.Id) -PassThru
            }
            

            Write-Verbose "$(Get-Timestamp) - End - Create Case - No drilldown"
            return $OutObject
        }


        Write-Verbose "$(Get-Timestamp) - Begin - Generate Case Tags - Origin Hosts"
        # Create tags for Origin Internal KnownHosts
        if ($OriginInternalIDs) {
            ForEach ($OriginInternalID in $OriginInternalIDs) {
                $HostDetails = Get-LrHostDetails -Id $OriginInternalID
                Start-Sleep $APISleep

                # Pull Origin Host Windows Hostname, IP Address, DNS Names
                $OrigHostname = $HostDetails.hostidentifiers | Where-Object -Property type -eq "WindowsName" | Select-Object -ExpandProperty Value
                $OrigIPAddress = $HostDetails.hostidentifiers | Where-Object -Property type -eq "IPAddress" | Select-Object -ExpandProperty Value
                $OrigDNSName = $HostDetails.hostidentifiers | Where-Object -Property type -eq "DNSName" | Select-Object -ExpandProperty Value

                # 
                if ($OrigHostname) {
                    foreach ($OHostname in $OrigHostname) {
                        $Tag = New-LrTagTaxObject -Primary "HOST" -Secondary "Int" -Value $OHostname -Note "Origin"
                        if ($CaseTags -notcontains $Tag) {
                            Write-Verbose "$(Get-Timestamp) - Info - Adding: $($Tag.Value) to list CaseTags"
                            $CaseTags.add($Tag)
                        }	
                    }
                }

                if ($OrigIPAddress) {
                    foreach ($OIPAddress in $OrigIPAddress) {
                        $Tag = New-LrTagTaxObject -Primary "IP" -Secondary "Int" -Value $OIPAddress -Note "Origin"
                        if ($CaseTags -notcontains $Tag) {
                            Write-Verbose "$(Get-Timestamp) - Info - Adding: $($Tag.Value) to list CaseTags"
                            $CaseTags.add($Tag)
                        }
                    }
                }

                if ($OrigDNSName) {
                    Foreach ($ODNSName in $OrigDNSName) {
                        $Tag = New-LrTagTaxObject -Primary "DNS" -Secondary "Int" -Value $ODNSName -Note "Origin"
                        if ($CaseTags -notcontains $Tag) {
                            Write-Verbose "$(Get-Timestamp) - Info - Adding: $($Tag.Value) to list CaseTags"
                            $CaseTags.add($Tag)
                        }
                    }
                }
            }
        }

        # Create tags for Origin External KnownHosts
        if ($OriginExternalIDs) {
            ForEach ($OriginExternalID in $OriginExternalIDs) {
                $HostDetails = Get-LrHostDetails -Id $OriginExternalID
                Start-Sleep $APISleep

                # Pull Origin Host Windows Hostname, IP Address, DNS Names
                $OrigHostname = $HostDetails.hostidentifiers | Where-Object -Property type -eq "WindowsName" | Select-Object -ExpandProperty Value
                $OrigIPAddress = $HostDetails.hostidentifiers | Where-Object -Property type -eq "IPAddress" | Select-Object -ExpandProperty Value
                $OrigDNSName = $HostDetails.hostidentifiers | Where-Object -Property type -eq "DNSName" | Select-Object -ExpandProperty Value

                # 
                if ($OrigHostname) {
                    foreach ($OHostname in $OrigHostname) {
                        $Tag = New-LrTagTaxObject -Primary "HOST" -Secondary "Ext" -Value $OHostname -Note "Origin"
                        if ($CaseTags -notcontains $Tag) {
                            Write-Verbose "$(Get-Timestamp) - Info - Adding: $($Tag.Value) to list CaseTags"
                            $CaseTags.add($Tag)
                        }
                    }
                }

                if ($OrigIPAddress) {
                    foreach ($OIPAddress in $OrigIPAddress) {
                        $Tag = New-LrTagTaxObject -Primary "IP" -Secondary "Ext" -Value $OIPAddress -Note "Origin"
                        if ($CaseTags -notcontains $Tag) {
                            Write-Verbose "$(Get-Timestamp) - Info - Adding: $($Tag.Value) to list CaseTags"
                            $CaseTags.add($Tag)
                        }
                    }
                }

                if ($OrigDNSName) {
                    ForEach ($ODNSName in $OrigDNSName) {
                        $Tag = New-LrTagTaxObject -Primary "DNS" -Secondary "Ext" -Value $ODNSName -Note "Origin"
                        if ($CaseTags -notcontains $Tag) {
                            Write-Verbose "$(Get-Timestamp) - Info - Adding: $($Tag.Value) to list CaseTags"
                            $CaseTags.add($Tag)
                        }
                    }
                }
            }
        }

        # Create tags for Origin Unknown-Direction-Origin KnownHosts
        if ($OriginHostIds) {
            ForEach ($OriginHostId in $OriginHostIds) {
                $HostDetails = Get-LrHostDetails -Id $OriginHostId
                Start-Sleep $APISleep

                # Pull Origin Host Windows Hostname, IP Address, DNS Names
                $OrigHostname = $HostDetails.hostidentifiers | Where-Object -Property type -eq "WindowsName" | Select-Object -ExpandProperty Value
                $OrigIPAddress = $HostDetails.hostidentifiers | Where-Object -Property type -eq "IPAddress" | Select-Object -ExpandProperty Value
                $OrigDNSName = $HostDetails.hostidentifiers | Where-Object -Property type -eq "DNSName" | Select-Object -ExpandProperty Value

                if ($OrigHostname) {
                    foreach ($OHostname in $OrigHostname) {
                        $Tag = New-LrTagTaxObject -Primary "HOST" -Secondary "Unk" -Value $OHostname -Note "Origin"
                        if ($CaseTags -notcontains $Tag) {
                            Write-Verbose "$(Get-Timestamp) - Info - Adding: $($Tag.Value) to list CaseTags"
                            $CaseTags.add($Tag)
                        }
                    }
                }

                if ($OrigIPAddress) {
                    foreach ($OIPAddress in $OrigIPAddress) {
                        $Tag = New-LrTagTaxObject -Primary "IP" -Secondary "Unk" -Value $OIPAddress -Note "Origin"
                        if ($CaseTags -notcontains $Tag) {
                            Write-Verbose "$(Get-Timestamp) - Info - Adding: $($Tag.Value) to list CaseTags"
                            $CaseTags.add($Tag)
                        }
                    }
                }

                if ($OrigDNSName) {
                    ForEach ($ODNSName in $OrigDNSName) {
                        $Tag = New-LrTagTaxObject -Primary "DNS" -Secondary "Unk" -Value $ODNSName -Note "Origin"
                        if ($CaseTags -notcontains $Tag) {
                            Write-Verbose "$(Get-Timestamp) - Info - Adding: $($Tag.Value) to list CaseTags"
                            $CaseTags.add($Tag)
                        }
                    }
                }
            }
        }

        # Internal direction but not a known hostname
        if ($OriginInternalHosts) {
            ForEach ($OriginInternalHost in $OriginInternalHosts) {
                $Tag = New-LrTagTaxObject -Primary "HOST" -Secondary "Int" -Value $OriginInternalHost -Note "Origin"
                if ($CaseTags -notcontains $Tag) {
                    Write-Verbose "$(Get-Timestamp) - Info - Adding: $($Tag.Value) to list CaseTags"
                    $CaseTags.add($Tag)
                }
            }
        }

        # Internal direction but not a known IP
        if ($OriginInternalIPs) {
            ForEach ($OriginInternalIP in $OriginInternalIPs) {
                $Tag = New-LrTagTaxObject -Primary "IP" -Secondary "Int" -Value $OriginInternalIP -Note "Origin"
                if ($CaseTags -notcontains $Tag) {
                    Write-Verbose "$(Get-Timestamp) - Info - Adding: $($Tag.Value) to list CaseTags"
                    $CaseTags.add($Tag)
                }
            }
        }

        # External direction but not a known hostname
        if ($OriginExternalHosts) {
            ForEach ($OriginExternalHost in $OriginExternalHosts) {
                $Tag = New-LrTagTaxObject -Primary "HOST" -Secondary "Ext" -Value $OriginExternalHost -Note "Origin"
                if ($CaseTags -notcontains $Tag) {
                    Write-Verbose "$(Get-Timestamp) - Info - Adding: $($Tag.Value) to list CaseTags"
                    $CaseTags.add($Tag)
                }
            }
        }

        # Origin direction but not a known IP
        if ($OriginExternalIPs) {
            ForEach ($OriginExternalIP in $OriginExternalIPs) {
                $Tag = New-LrTagTaxObject -Primary "IP" -Secondary "Ext" -Value $OriginExternalIP -Note "Origin"
                if ($CaseTags -notcontains $Tag) {
                    Write-Verbose "$(Get-Timestamp) - Info - Adding: $($Tag.Value) to list CaseTags"
                    $CaseTags.add($Tag)
                }
            }
        }

        # Unknown direction but not a known IP
        if ($OriginIPs) {
            ForEach ($OriginIP in $OriginIPs) {
                $Tag = New-LrTagTaxObject -Primary "IP" -Secondary "Unk" -Value $OriginIP -Note "Origin"
                if ($CaseTags -notcontains $Tag) {
                    Write-Verbose "$(Get-Timestamp) - Info - Adding: $($Tag.Value) to list CaseTags"
                    $CaseTags.add($Tag)
                }
            }
        }

        # Unknown direction but not a known hostname
        if ($OriginHosts) {
            ForEach ($OriginHost in $OriginHosts) {
                $Tag = New-LrTagTaxObject -Primary "HOST" -Secondary "Unk" -Value $OriginHost -Note "Origin"
                if ($CaseTags -notcontains $Tag) {
                    Write-Verbose "$(Get-Timestamp) - Info - Adding: $($Tag.Value) to list CaseTags"
                    $CaseTags.add($Tag)
                }
            }
        }
        Write-Verbose "$(Get-Timestamp) - End - Generate Case Tags - Origin Hosts"

        
        # Create tags for Impacted Hosts
        Write-Verbose "$(Get-Timestamp) - Begin - Generate Case Tags - Impacted Hosts"
        # Build out Case Tags
        if ($ImpactedInternalIDs) {
            ForEach ($ImpactedInternalID in $ImpactedInternalIDs) {
                $HostDetails = Get-LrHostDetails -Id $ImpactedInternalID
                Start-Sleep $APISleep

                # Pull Impacted Host Windows Hostname, IP Address, DNS Names
                $ImpactedHostname = $HostDetails.hostidentifiers | Where-Object -Property type -eq "WindowsName" | Select-Object -ExpandProperty Value
                $ImpactedIPAddress = $HostDetails.hostidentifiers | Where-Object -Property type -eq "IPAddress" | Select-Object -ExpandProperty Value
                $ImpactedDNSName = $HostDetails.hostidentifiers | Where-Object -Property type -eq "DNSName" | Select-Object -ExpandProperty Value


                if ($ImpactedHostname) {
                    foreach ($IHostname in $ImpactedHostname) {
                        $Tag = New-LrTagTaxObject -Primary "HOST" -Secondary "Int" -Value $IHostname -Note "Impacted"
                        if ($CaseTags -notcontains $Tag) {
                            Write-Verbose "$(Get-Timestamp) - Info - Adding: $($Tag.Value) to list CaseTags"
                            $CaseTags.add($Tag)
                        }
                    }
                }

                if ($ImpactedIPAddress) {
                    foreach ($IIPAddress in $ImpactedIPAddress) {
                        $Tag = New-LrTagTaxObject -Primary "IP" -Secondary "Int" -Value $IIPAddress -Note "Impacted"
                        if ($CaseTags -notcontains $Tag) {
                            Write-Verbose "$(Get-Timestamp) - Info - Adding: $($Tag.Value) to list CaseTags"
                            $CaseTags.add($Tag)
                        }
                    }
                }

                if ($ImpactedDNSName) {
                    foreach ($IDNSName in $ImpactedDNSName) {
                        $Tag = New-LrTagTaxObject -Primary "DNS" -Secondary "Int" -Value $IDNSName -Note "Impacted"
                        if ($CaseTags -notcontains $Tag) {
                            Write-Verbose "$(Get-Timestamp) - Info - Adding: $($Tag.Value) to list CaseTags"
                            $CaseTags.add($Tag)
                        }
                    }
                }
            }
        }

        # Create tags for Impacted External KnownHosts
        if ($ImpactedExternalIDs) {
            ForEach ($ImpactedExternalID in $ImpactedExternalIDs) {
                $HostDetails = Get-LrHostDetails -Id $ImpactedExternalID
                Start-Sleep $APISleep

                # Pull Impacted Host Windows Hostname, IP Address, DNS Names
                $ImpactedHostname = $HostDetails.hostidentifiers | Where-Object -Property type -eq "WindowsName" | Select-Object -ExpandProperty Value
                $ImpactedIPAddress = $HostDetails.hostidentifiers | Where-Object -Property type -eq "IPAddress" | Select-Object -ExpandProperty Value
                $ImpactedDNSName = $HostDetails.hostidentifiers | Where-Object -Property type -eq "DNSName" | Select-Object -ExpandProperty Value

                # 
                if ($ImpactedHostname) {
                    foreach ($IHostname in $ImpactedHostname) {
                        $Tag = New-LrTagTaxObject -Primary "HOST" -Secondary "Ext" -Value $IHostname -Note "Impacted"
                        if ($CaseTags -notcontains $Tag) {
                            Write-Verbose "$(Get-Timestamp) - Info - Adding: $($Tag.Value) to list CaseTags"
                            $CaseTags.add($Tag)
                        }
                    }
                }

                if ($ImpactedIPAddress) {
                    foreach ($IIPAddress in $ImpactedIPAddress) {
                        $Tag = New-LrTagTaxObject -Primary "IP" -Secondary "Ext" -Value $IIPAddress -Note "Impacted"
                        if ($CaseTags -notcontains $Tag) {
                            Write-Verbose "$(Get-Timestamp) - Info - Adding: $($Tag.Value) to list CaseTags"
                            $CaseTags.add($Tag)
                        }
                    }
                }

                if ($ImpactedDNSName) {
                    foreach ($IDNSName in $ImpactedDNSName) {
                        $Tag = New-LrTagTaxObject -Primary "DNS" -Secondary "Ext" -Value $IDNSName -Note "Impacted"
                        if ($CaseTags -notcontains $Tag) {
                            Write-Verbose "$(Get-Timestamp) - Info - Adding: $($Tag.Value) to list CaseTags"
                            $CaseTags.add($Tag)
                        }
                    }
                }
            }
        }


        # Create tags for Impacted Unknown-Direction-Origin KnownHosts
        if ($ImpactedHostIds) {
            ForEach ($ImpactedHostId in $ImpactedHostIds) {
                $HostDetails = Get-LrHostDetails -Id $ImpactedHostId
                Start-Sleep $APISleep

                # Pull Origin Host Windows Hostname, IP Address, DNS Names
                $ImpactedHostname = $HostDetails.hostidentifiers | Where-Object -Property type -eq "WindowsName" | Select-Object -ExpandProperty Value
                $ImpactedIPAddress = $HostDetails.hostidentifiers | Where-Object -Property type -eq "IPAddress" | Select-Object -ExpandProperty Value
                $ImpactedDNSName = $HostDetails.hostidentifiers | Where-Object -Property type -eq "DNSName" | Select-Object -ExpandProperty Value


                if ($ImpactedHostname) {
                    foreach ($IHostname in $ImpactedHostname) {
                        $Tag = New-LrTagTaxObject -Primary "HOST" -Secondary "Unk" -Value $IHostname -Note "Impacted"
                        if ($CaseTags -notcontains $Tag) {
                            Write-Verbose "$(Get-Timestamp) - Info - Adding: $($Tag.Value) to list CaseTags"
                            $CaseTags.add($Tag)
                        }
                    }
                }

                if ($ImpactedIPAddress) {
                    foreach ($IIPAddress in $ImpactedIPAddress) {
                        $Tag = New-LrTagTaxObject -Primary "IP" -Secondary "Unk" -Value $IIPAddress -Note "Impacted"
                        if ($CaseTags -notcontains $Tag) {
                            Write-Verbose "$(Get-Timestamp) - Info - Adding: $($Tag.Value) to list CaseTags"
                            $CaseTags.add($Tag)
                        }
                    }
                }

                if ($ImpactedDNSName) {
                    foreach ($IDNSName in $ImpactedDNSName) {
                        $Tag = New-LrTagTaxObject -Primary "DNS" -Secondary "Unk" -Value $IDNSName -Note "Impacted"
                        if ($CaseTags -notcontains $Tag) {
                            Write-Verbose "$(Get-Timestamp) - Info - Adding: $($Tag.Value) to list CaseTags"
                            $CaseTags.add($Tag)
                        }
                    }
                }
            }
        }

        # Internal direction but not a known hostname
        if ($ImpactedInternalHosts) {
            ForEach ($ImpactedInternalHost in $ImpactedInternalHosts) {
                $Tag = New-LrTagTaxObject -Primary "HOST" -Secondary "Int" -Value $ImpactedInternalHost -Note "Impacted"
                if ($CaseTags -notcontains $Tag) {
                    Write-Verbose "$(Get-Timestamp) - Info - Adding: $($Tag.Value) to list CaseTags"
                    $CaseTags.add($Tag)
                }
            }
        }

        # Internal direction but not a known IP
        if ($ImpactedInternalIPs) {
            ForEach ($ImpactedInternalIP in $ImpactedInternalIPs) {
                $Tag = New-LrTagTaxObject -Primary "IP" -Secondary "Int" -Value $ImpactedInternalIP -Note "Impacted"
                if ($CaseTags -notcontains $Tag) {
                    Write-Verbose "$(Get-Timestamp) - Info - Adding: $($Tag.Value) to list CaseTags"
                    $CaseTags.add($Tag)
                }
            }
        }

        # External direction but not a known IP
        if ($ImpactedExternalHosts) {
            ForEach ($ImpactedExternalHost in $ImpactedExternalHosts) {
                $Tag = New-LrTagTaxObject -Primary "HOST" -Secondary "Ext" -Value $ImpactedExternalHost -Note "Impacted"
                if ($CaseTags -notcontains $Tag) {
                    Write-Verbose "$(Get-Timestamp) - Info - Adding: $($Tag.Value) to list CaseTags"
                    $CaseTags.add($Tag)
                }
            }
        }

        # External direction but not a known IP
        if ($ImpactedExternalIPs) {
            ForEach ($ImpactedExternalIP in $ImpactedExternalIPs) {
                $Tag = New-LrTagTaxObject -Primary "IP" -Secondary "Ext" -Value $ImpactedExternalIP -Note "Impacted"
                if ($CaseTags -notcontains $Tag) {
                    Write-Verbose "$(Get-Timestamp) - Info - Adding: $($Tag.Value) to list CaseTags"
                    $CaseTags.add($Tag)
                }
            }
        }

        # Unknown Direction but not a known IP
        if ($ImpactedIPs) {
            ForEach ($OriginIP in $OriginIPs) {
                $Tag = New-LrTagTaxObject -Primary "IP" -Secondary "Unk" -Value $OriginIP -Note "Impacted"
                if ($CaseTags -notcontains $Tag) {
                    Write-Verbose "$(Get-Timestamp) - Info - Adding: $($Tag.Value) to list CaseTags"
                    $CaseTags.add($Tag)
                }
            }
        }

        # Unknown direction but not a known hostname
        if ($ImpactedHosts) {
            ForEach ($ImpactedHost in $ImpactedHosts) {
                $Tag = New-LrTagTaxObject -Primary "HOST" -Secondary "Unk" -Value $ImpactedHost -Note "Impacted"
                if ($CaseTags -notcontains $Tag) {
                    Write-Verbose "$(Get-Timestamp) - Info - Adding: $($Tag.Value) to list CaseTags"
                    $CaseTags.add($Tag)
                }
            }
        }
        Write-Verbose "$(Get-Timestamp) - End - Generate Case Tags - Impacted Hosts"


        Write-Verbose "$(Get-Timestamp) - Begin - Generate Case Tags - Users"
        # Establish tags for Logins
        Write-Verbose "$(Get-Timestamp) - Begin - User Tags - Origin Logins"
        ForEach ($OrgLogin in $OriginLogins) {
            Write-Verbose "$(Get-Timestamp) - New - User Origin - Login: $OrgLogin"
            $Tag = $null
            # Add tags for Users
            $Tag = New-LrTagTaxObject -Primary "USER" -Secondary "Login" -Value $OrgLogin  -Note "Origin"

            # Add Tag to CaseTag variable
            if ($CaseTags -notcontains $Tag) {
                Write-Verbose "$(Get-Timestamp) - Info - Adding: $($Tag.Value) to list CaseTags"
                $CaseTags.add($Tag)
            }
        }
        Write-Verbose "$(Get-Timestamp) - End - User Tags - Origin Logins"

        # Establish tags and detail summaries for TrueIDs
        Write-Verbose "$(Get-Timestamp) - Begin - User Tags - Origin Identities"
        ForEach ($OrgTrueID in $OriginIdentities) {
            Write-Verbose "$(Get-Timestamp) - New - User Origin - Identity: $OrgTrueID"
            $Tag = $null

            # Add tags for each Identity
            $Tag = New-LrTagTaxObject -Primary "USER" -Secondary "TrueID" -Value $OrgTrueID -Note "Origin"

            # Add Tag to CaseTag variable
            if ($CaseTags -notcontains $Tag) {
                Write-Verbose "$(Get-Timestamp) - Info - Adding: $($Tag.Value) to list CaseTags"
                $CaseTags.add($Tag)
            }
        }
        Write-Verbose "$(Get-Timestamp) - End - User Tags - Origin Identities"


        # Establish tags for Logins
        Write-Verbose "$(Get-Timestamp) - Begin - User Tags - Impacted Logins"
        ForEach ($ImpLogin in $ImpactedLogins) {
            Write-Verbose "$(Get-Timestamp) - New - User Impacted - Login: $ImpLogin"
            $Tag = $null
            # Add tags for Users
            $Tag = New-LrTagTaxObject -Primary "USER" -Secondary "Login" -Value $ImpLogin  -Note "Impacted"

            # Add Tag to CaseTag variable
            if ($CaseTags -notcontains $Tag) {
                Write-Verbose "$(Get-Timestamp) - Info - Adding: $($Tag.Value) to list CaseTags"
                $CaseTags.add($Tag)
            }
        }
        Write-Verbose "$(Get-Timestamp) - End - User Tags - Impacted Logins"



        # Establish tags for Senders
        Write-Verbose "$(Get-Timestamp) - Begin - User Tags - Sender"
        ForEach ($Sender in $Senders) {
            Write-Verbose "$(Get-Timestamp) - New - Sender - Value: $Sender"
            $Tag = $null
            # Add tags for Users
            $Tag = New-LrTagTaxObject -Primary "USER" -Secondary "Email" -Value $Sender  -Note "Sender"

            # Add Tag to CaseTag variable
            if ($CaseTags -notcontains $Tag) {
                Write-Verbose "$(Get-Timestamp) - Info - Adding: $($Tag.Value) to list CaseTags"
                $CaseTags.add($Tag)
            }
        }
        Write-Verbose "$(Get-Timestamp) - End - User Tags - Sender"

        # Establish tags for Senders
        Write-Verbose "$(Get-Timestamp) - Begin - User Tags - Recipient"
        ForEach ($Recipient in $Recipients) {
            Write-Verbose "$(Get-Timestamp) - New - Recipient - Value: $Recipient"
            $Tag = $null
            # Add tags for Users
            $Tag = New-LrTagTaxObject -Primary "USER" -Secondary "Email" -Value $Recipient  -Note "Recipient"

            # Add Tag to CaseTag variable
            if ($CaseTags -notcontains $Tag) {
                Write-Verbose "$(Get-Timestamp) - Info - Adding: $($Tag.Value) to list CaseTags"
                $CaseTags.add($Tag)
            }
        }
        Write-Verbose "$(Get-Timestamp) - End - User Tags - Recipient"

        # Establish tags and detail summaries for TrueIDs
        Write-Verbose "$(Get-Timestamp) - Begin - User Tags - Impacted Identities"
        ForEach ($ImpTrueID in $ImpactedIdentities) {
            Write-Verbose "$(Get-Timestamp) - New - User Impacted - Identity: $ImpTrueID"
            $Tag = $null
            # Add tags for each Identity
            $Tag = New-LrTagTaxObject -Primary "USER" -Secondary "TrueID" -Value $ImpTrueID -Note "Impacted"

            # Add Tag to CaseTag variable
            if ($CaseTags -notcontains $Tag) {
                Write-Verbose "$(Get-Timestamp) - Info - Adding: $($Tag.Value) to list CaseTags"
                $CaseTags.add($Tag)
            }
        }
        Write-Verbose "$(Get-Timestamp) - End - User Tags - Impacted Identities"
        Write-Verbose "$(Get-Timestamp) - End - Generate Case Tags - Users"


        # Check if BindAlarmToExistingCase is enabled for User Case association
        Write-Verbose "$(Get-Timestamp) - Begin - Bind Alarm to Existing Case - User"
        if (($TagOriginUsers -or $TagImpactedUsers) -and ($BindAlarmToExistingCase -like "userorigin"-or $BindAlarmToExistingCase -like "userimpacted")) {
            # Build array of pending Tags associated with primary TAG:USER
            if ($BindAlarmToExistingCase -like "userorigin") {
                Write-Verbose "$(Get-Timestamp) - Info - Bind Alarm - User Origin"
                $UserTags = $($CaseTags | Where-Object -Property Primary -eq "USER" | Where-Object -Property Note -eq "Origin" | Select-Object -ExpandProperty Tag)
            }

            if ($BindAlarmToExistingCase -like "userimpacted") {
                Write-Verbose "$(Get-Timestamp) - Info - Bind Alarm - User Impacted"
                $UserTags = $($CaseTags | Where-Object -Property Primary -eq "USER" | Where-Object -Property Note -eq "Impacted" | Select-Object -ExpandProperty Tag)
            }


            # Screen for existing case, if so add new details to existing case and halt
            ForEach ($UserTag in $UserTags) {
                Write-Verbose "$(Get-Timestamp) - Info - UserTag: $($UserTag)"
                # Identify if an open case exists involving same AIE Alarm and User exists.  Valid case status:  Created, Incident, Mitigated
                $ScreenCases = Get-LrCases -Name $AlarmDetails.AIERuleName -Exact -Tags $UserTag -Status @("1", "3", "4")
                Start-Sleep $APISleep
                if ($ScreenCases) {
                    if ($ScreenCases.count -gt 1) {
                        # Update most recent case
                        $ScreenCases = $ScreenCases | Sort-Object -Property dateUpdated -Descending | Select-Object -First 1
                    }
                    # Add alarm to case
                    Add-LrAlarmToCase -Id $ScreenCases.number -AlarmNumbers $AlarmDetails.AlarmId
                    Start-Sleep $APISleep

                    # Update output Object
                    $OutObject.CaseNumber = $ScreenCases.number
                    $OutObject.Case.CaseObject = $ScreenCases
                    $OutObject.Case.Note = "Existing case updated due to matched user association with Alarm."

                    # User Tags
                    $CurUserTags = $ScreenCases.tags | Where-Object -Property text -match "User_.*" | Select-Object -ExpandProperty text

                    # Generate User Origin Tags
                    if ($TagOriginUsers) {
                        Write-Verbose "$(Get-Timestamp) - Begin - Add User Origin Tags to Case"
                        $OriginUserTags = $CaseTags | Where-Object -Property Primary -in "User" | Where-Object -Property Note -in "Origin", "Sender"

                        # Iterate through Origin Host tags
                        ForEach ($OriginUserTag in $OriginUserTags) {
                            # If the Curent Case Host Tags does not include the Origin Host Tag, add it
                            if ($CurUserTags -notcontains $OriginUserTag.Tag) {
                                $TagStatus = Get-LrTags -Name $OriginUserTag.Tag -Exact
                                if ($null -eq $TagStatus) {
                                    Write-Verbose "$(Get-Timestamp) - Info - Creating new tag: $($OriginUserTag.tag)"
                                    New-LrTag -Tag $OriginUserTag.Tag
                                    Start-Sleep $APISleep
                                }
                                Write-Verbose "$(Get-Timestamp) - Info - Adding tag: $($OriginUserTag.tag) to Case: $($OutObject.CaseNumber)"
                                Add-LrCaseTags -Id $OutObject.CaseNumber -Tags $OriginUserTag.Tag
                                $ScreenNewTags.add($OriginUserTag)
                                Start-Sleep $APISleep
                            }
                        }
                        Write-Verbose "$(Get-Timestamp) - End - Add User Origin Tags to Case"
                    }

                    # General User Impacted Tags
                    if ($TagImpactedUsers) {
                        Write-Verbose "$(Get-Timestamp) - Begin - Add User Impacted Tags to Case"
                        $ImpactUserTags = $CaseTags | Where-Object -Property Primary -in "User" | Where-Object -Property Note -in "Impacted", "Recipient"

                        # Iterate through Impacted User tags
                        ForEach ($ImpactUserTag in $ImpactUserTags) {
                            # If the Curent Case User Tags does not include the Impacted User Tag, add it
                            if ($CurUserTags -notcontains $ImpactUserTag.Tag) {
                                $TagStatus = Get-LrTags -Name $ImpactUserTag.Tag -Exact
                                if ($null -eq $TagStatus) {
                                    Write-Verbose "$(Get-Timestamp) - Info - Creating new tag: $($ImpactUserTag.tag)"
                                    New-LrTag -Tag $ImpactUserTag.Tag
                                    Start-Sleep $APISleep
                                }
                                Write-Verbose "$(Get-Timestamp) - Info - Adding tag: $($ImpactUserTag.tag) to Case: $($OutObject.CaseNumber)"
                                Add-LrCaseTags -Id $OutObject.CaseNumber -Tags $ImpactUserTag.Tag
                                $ScreenNewTags.add($ImpactUserTag)
                                Start-Sleep $APISleep
                            }
                        }
                        Write-Verbose "$(Get-Timestamp) - End - Add User Impacted Tags to Case"
                    }


                    # Host Tags
                    $CurHostTags = $ScreenCases.tags | Where-Object -Property text -Match "(HOST|IP|DNS)_.*" | Select-Object -ExpandProperty text
                    
                    # If CaseTagOriginHosts is enabled, add new CaseTagOriginHosts to Case
                    if ($TagOriginHosts -eq $true) {
                        Write-Verbose "$(Get-Timestamp) - Begin - Add Host Origin Tags to Case"
                        $OriginHostTags = $CaseTags | Where-Object -Property Primary -in "HOST","IP","DNS" | Where-Object -Property Note -eq "Origin"

                        # Iterate through Origin Host tags
                        ForEach ($OriginHostTag in $OriginHostTags) {
                            # If the Curent Case Host Tags does not include the Origin Host Tag, add it
                            if ($CurHostTags -notcontains $OriginHostTag.Tag) {
                                $TagStatus = Get-LrTags -Name $OriginHostTag.Tag -Exact
                                if ($null -eq $TagStatus) {
                                    Write-Verbose "$(Get-Timestamp) - Info - Creating new tag: $($OriginHostTag.tag)"
                                    New-LrTag -Tag $OriginHostTag.Tag
                                    Start-Sleep $APISleep
                                }
                                Write-Verbose "$(Get-Timestamp) - Info - Adding tag: $($OriginHostTag.tag) to Case: $($OutObject.CaseNumber)"
                                Add-LrCaseTags -Id $OutObject.CaseNumber -Tags $OriginHostTag.Tag
                                $ScreenNewTags.add($OriginHostTag)
                                Start-Sleep $APISleep
                            }
                        }
                        Write-Verbose "$(Get-Timestamp) - End - Add Host Origin Tags to Case"
                    }

                    if ($TagImpactedHosts -eq $true) {
                        Write-Verbose "$(Get-Timestamp) - Begin - Add Host Impacted Tags to Case"
                        $ImpactedHostTags = $CaseTags | Where-Object -Property Primary -in "HOST","IP","DNS" | Where-Object -Property Note -eq "Impacted"

                        # Iterate through Origin Host tags
                        ForEach ($ImpactedHostTag in $ImpactedHostTags) {
                            # If the Curent Case Host Tags does not include the Origin Host Tag, add it
                            if ($CurHostTags -notcontains $ImpactedHostTag.Tag) {
                                $TagStatus = Get-LrTags -Name $ImpactedHostTag.Tag -Exact
                                if ($null -eq $TagStatus) {
                                    Write-Verbose "$(Get-Timestamp) - Info - Creating new tag: $($ImpactedHostTag.Tag)"
                                    New-LrTag -Tag $ImpactedHostTag.Tag
                                    Start-Sleep $APISleep
                                }
                                Write-Verbose "$(Get-Timestamp) - Info - Adding tag: $($ImpactedHostTag.tag) to Case: $($OutObject.CaseNumber)"
                                Add-LrCaseTags -Id $OutObject.CaseNumber -Tags $ImpactedHostTag.Tag
                                $ScreenNewTags.add($ImpactedHostTag)
                                Start-Sleep $APISleep
                            }
                        }
                        Write-Verbose "$(Get-Timestamp) - End - Add Host Origin Tags to Case"
                    }

                    if ($ScreenNewTags) {
                        $ScreenTagNote += "-==- Updated Case Taxonomy Tags -==-`r`nIdenified new resources from Alarm: $($AlarmDetails.AlarmId).`r`n`r`nNew Tags:`r`n"
                        ForEach ($ScreenTag in $ScreenNewTags) {
                        # Apply Regex match approach to support future modifications to case tag listing and prevent adding non-taxonomy tags to note.
                            Switch -regex ($ScreenTag) {
                                'tech_.*' {$ScreenTagNote +="$($ScreenTag.tag)`r`n"}
                                'user_.*' {$ScreenTagNote +="$($ScreenTag.tag)`r`n"}
                                'host_.*' {$ScreenTagNote +="$($ScreenTag.tag)`r`n"}
                                'ip_*' {$ScreenTagNote +="$($ScreenTag.tag)`r`n"}
                                'dns_*' {$ScreenTagNote +="$($ScreenTag.tag)`r`n"}
                            }
                        }
                        Add-LrNoteToCase -Id $OutObject.CaseNumber -Text $ScreenTagNote
                        Start-Sleep $APISleep
                        $OutObject.Case.CaseTags = $ScreenNewTags
                    }

                    return $OutObject
                }
            }
        }
        Write-Verbose "$(Get-Timestamp) - End - Bind Alarm to Existing Case - User"


        # Check if BindAlarmToExistingCase is enabled for User Case association
        if ($CaseTagImpactedHosts -eq $true) {
            Write-Verbose "$(Get-Timestamp) - Begin - Bind Alarm to Existing Case - Host Impacted"
            if ($BindAlarmToExistingCase -like "impactedhost") {
                # Build array of pending Tags associated with primary TAG:USER
                $HostTags = $CaseTags | Where-Object -Property Primary -eq "HOST" | Where-Object -Property Note -eq "Impacted" | Select-Object -ExpandProperty Tag



                # Screen for existing case, if so add new details to existing case and halt
                ForEach ($HostTag in $HostTags) {
                    # Identify if an open case exists involving same AIE Alarm and Host exists.  Valid case status:  Created, Incident, Mitigated
                    $ScreenCases = Get-LrCases -Name $AlarmDetails.AIERuleName -Exact -Tags $HostTag -Status @("1", "3", "4")
                    Start-Sleep $APISleep
                    if ($ScreenCases) {
                        if ($ScreenCases.count -gt 1) {
                            # Update most recent case
                            $ScreenCases = $ScreenCases | Sort-Object -Property dateUpdated -Descending | Select-Object -First 1
                        }
                        # Add alarm to case
                        Add-LrAlarmToCase -Id $ScreenCases.number -AlarmNumbers $AlarmDetails.AlarmId
                        Start-Sleep $APISleep

                        $OutObject.CaseNumber = $ScreenCases.number
                        $OutObject.Case.CaseObject = $ScreenCases
                        $OutObject.Case.Note = "Existing case updated due to matched Host Impacted association with Alarm."


                        # User Tags
                        $CurUserTags = $ScreenCases.tags | Where-Object -Property text -match "User_.*" | Select-Object -ExpandProperty text

                        # Generate User Origin Tags
                        if ($TagOriginUsers) {
                            Write-Verbose "$(Get-Timestamp) - Begin - Add User Origin Tags to Case"
                            $OriginUserTags = $CaseTags | Where-Object -Property Primary -in "User" | Where-Object -Property Note -in "Origin", "Sender"

                            # Iterate through Origin Host tags
                            ForEach ($OriginUserTag in $OriginUserTags) {
                                # If the Curent Case Host Tags does not include the Origin Host Tag, add it
                                if ($CurUserTags -notcontains $OriginUserTag.Tag) {
                                    $TagStatus = Get-LrTags -Name $OriginUserTag.Tag -Exact
                                    if ($null -eq $TagStatus) {
                                        Write-Verbose "$(Get-Timestamp) - Info - Creating new tag: $($OriginUserTag.tag)"
                                        New-LrTag -Tag $OriginUserTag.Tag
                                        Start-Sleep $APISleep
                                    }
                                    Write-Verbose "$(Get-Timestamp) - Info - Adding tag: $($OriginUserTag.tag) to Case: $($OutObject.CaseNumber)"
                                    Add-LrCaseTags -Id $OutObject.CaseNumber -Tags $OriginUserTag.Tag
                                    $ScreenNewTags.add($OriginUserTag)
                                    Start-Sleep $APISleep
                                }
                            }
                            Write-Verbose "$(Get-Timestamp) - End - Add User Origin Tags to Case"
                        }

                        # General User Impacted Tags
                        if ($TagImpactedUsers) {
                            Write-Verbose "$(Get-Timestamp) - Begin - Add User Impacted Tags to Case"
                            $ImpactUserTags = $CaseTags | Where-Object -Property Primary -in "User" | Where-Object -Property Note -in "Impacted", "Recipient"

                            # Iterate through Impacted User tags
                            ForEach ($ImpactUserTag in $ImpactUserTags) {
                                # If the Curent Case User Tags does not include the Impacted User Tag, add it
                                if ($CurUserTags -notcontains $ImpactUserTag.Tag) {
                                    $TagStatus = Get-LrTags -Name $ImpactUserTag.Tag -Exact
                                    if ($null -eq $TagStatus) {
                                        Write-Verbose "$(Get-Timestamp) - Info - Creating new tag: $($ImpactUserTag.tag)"
                                        New-LrTag -Tag $ImpactUserTag.Tag
                                        Start-Sleep $APISleep
                                    }
                                    Write-Verbose "$(Get-Timestamp) - Info - Adding tag: $($ImpactUserTag.tag) to Case: $($OutObject.CaseNumber)"
                                    Add-LrCaseTags -Id $OutObject.CaseNumber -Tags $ImpactUserTag.Tag
                                    $ScreenNewTags.add($ImpactUserTag)
                                    Start-Sleep $APISleep
                                }
                            }
                            Write-Verbose "$(Get-Timestamp) - End - Add User Impacted Tags to Case"
                        }


                        # Host Tags
                        $CurHostTags = $ScreenCases.tags | Where-Object -Property text -Match "(HOST|IP|DNS)_.*" | Select-Object -ExpandProperty text
                        
                        # If CaseTagOriginHosts is enabled, add new CaseTagOriginHosts to Case
                        if ($TagOriginHosts -eq $true) {
                            Write-Verbose "$(Get-Timestamp) - Begin - Add Host Origin Tags to Case"
                            $OriginHostTags = $CaseTags | Where-Object -Property Primary -in "HOST","IP","DNS" | Where-Object -Property Note -eq "Origin"

                            # Iterate through Origin Host tags
                            ForEach ($OriginHostTag in $OriginHostTags) {
                                # If the Curent Case Host Tags does not include the Origin Host Tag, add it
                                if ($CurHostTags -notcontains $OriginHostTag.Tag) {
                                    $TagStatus = Get-LrTags -Name $OriginHostTag.Tag -Exact
                                    if ($null -eq $TagStatus) {
                                        Write-Verbose "$(Get-Timestamp) - Info - Creating new tag: $($OriginHostTag.tag)"
                                        New-LrTag -Tag $OriginHostTag.Tag
                                        Start-Sleep $APISleep
                                    }
                                    Write-Verbose "$(Get-Timestamp) - Info - Adding tag: $($OriginHostTag.tag) to Case: $($OutObject.CaseNumber)"
                                    Add-LrCaseTags -Id $OutObject.CaseNumber -Tags $OriginHostTag.Tag
                                    $ScreenNewTags.add($OriginHostTag)
                                    Start-Sleep $APISleep
                                }
                            }
                            Write-Verbose "$(Get-Timestamp) - End - Add Host Origin Tags to Case"
                        }

                        if ($TagImpactedHosts -eq $true) {
                            Write-Verbose "$(Get-Timestamp) - Begin - Add Host Impacted Tags to Case"
                            $ImpactedHostTags = $CaseTags | Where-Object -Property Primary -in "HOST","IP","DNS" | Where-Object -Property Note -eq "Impacted"

                            # Iterate through Origin Host tags
                            ForEach ($ImpactedHostTag in $ImpactedHostTags) {
                                # If the Curent Case Host Tags does not include the Origin Host Tag, add it
                                if ($CurHostTags -notcontains $ImpactedHostTag.Tag) {
                                    $TagStatus = Get-LrTags -Name $ImpactedHostTag.Tag -Exact
                                    if ($null -eq $TagStatus) {
                                        Write-Verbose "$(Get-Timestamp) - Info - Creating new tag: $($ImpactedHostTag.Tag)"
                                        New-LrTag -Tag $ImpactedHostTag.Tag
                                        Start-Sleep $APISleep
                                    }
                                    Write-Verbose "$(Get-Timestamp) - Info - Adding tag: $($ImpactedHostTag.tag) to Case: $($OutObject.CaseNumber)"
                                    Add-LrCaseTags -Id $OutObject.CaseNumber -Tags $ImpactedHostTag.Tag
                                    $ScreenNewTags.add($ImpactedHostTag)
                                    Start-Sleep $APISleep
                                }
                            }
                            Write-Verbose "$(Get-Timestamp) - End - Add Host Origin Tags to Case"
                        }

                        if ($ScreenNewTags) {
                            $ScreenTagNote += "-==- Updated Case Taxonomy Tags -==-`r`nIdenified new resources from Alarm: $($AlarmDetails.AlarmId).`r`n`r`nNew Tags:`r`n"
                            ForEach ($ScreenTag in $ScreenNewTags) {
                            # Apply Regex match approach to support future modifications to case tag listing and prevent adding non-taxonomy tags to note.
                                Switch -regex ($ScreenTag) {
                                    'tech_.*' {$ScreenTagNote +="$($ScreenTag.tag)`r`n"}
                                    'user_.*' {$ScreenTagNote +="$($ScreenTag.tag)`r`n"}
                                    'host_.*' {$ScreenTagNote +="$($ScreenTag.tag)`r`n"}
                                    'ip_*' {$ScreenTagNote +="$($ScreenTag.tag)`r`n"}
                                    'dns_*' {$ScreenTagNote +="$($ScreenTag.tag)`r`n"}
                                }
                            }
                            Add-LrNoteToCase -Id $ScreenCases.Number -Text $ScreenTagNote
                            Start-Sleep $APISleep
                        }

                        return $OutObject
                    }
                }
            }
            Write-Verbose "$(Get-Timestamp) - End - Bind Alarm to Existing Case - Host Impacted"
        }

        # Check if BindAlarmToExistingCase is enabled for User Case association
        if ($CaseTagImpactedHosts -eq $true) {
            Write-Verbose "$(Get-Timestamp) - Begin - Bind Alarm to Existing Case - Host Origin"
            if ($BindAlarmToExistingCase -like "originhost") {
                # Build array of pending Tags associated with primary TAG:USER
                $HostTags = $CaseTags | Where-Object -Property Primary -eq "HOST" | Where-Object -Property Note -eq "Origin" | Select-Object -ExpandProperty Tag

    

                # Screen for existing case, if so add new details to existing case and halt
                ForEach ($HostTag in $HostTags) {
                    # Identify if an open case exists involving same AIE Alarm and Host exists.  Valid case status:  Created, Incident, Mitigated
                    $ScreenCases = Get-LrCases -Name $AlarmDetails.AIERuleName -Exact -Tags $HostTag -Status @("1", "3", "4")
                    Start-Sleep $APISleep
                    if ($ScreenCases) {
                        if ($ScreenCases.count -gt 1) {
                            # Update most recent case
                            $ScreenCases = $ScreenCases | Sort-Object -Property dateUpdated -Descending | Select-Object -First 1
                        }
                        # Add alarm to case
                        Add-LrAlarmToCase -Id $ScreenCases.number -AlarmNumbers $AlarmDetails.AlarmId
                        Start-Sleep $APISleep

                        $OutObject.CaseNumber = $ScreenCases.number
                        $OutObject.Case.CaseObject = $ScreenCases
                        $OutObject.Case.Note = "Existing case updated due to matched Host Origin association with Alarm."


                        # User Tags
                        $CurUserTags = $ScreenCases.tags | Where-Object -Property text -match "User_.*" | Select-Object -ExpandProperty text

                        # Generate User Origin Tags
                        if ($TagOriginUsers) {
                            Write-Verbose "$(Get-Timestamp) - Begin - Add User Origin Tags to Case"
                            $OriginUserTags = $CaseTags | Where-Object -Property Primary -in "User" | Where-Object -Property Note -in "Origin", "Sender"

                            # Iterate through Origin Host tags
                            ForEach ($OriginUserTag in $OriginUserTags) {
                                # If the Curent Case Host Tags does not include the Origin Host Tag, add it
                                if ($CurUserTags -notcontains $OriginUserTag.Tag) {
                                    $TagStatus = Get-LrTags -Name $OriginUserTag.Tag -Exact
                                    if ($null -eq $TagStatus) {
                                        Write-Verbose "$(Get-Timestamp) - Info - Creating new tag: $($OriginUserTag.tag)"
                                        New-LrTag -Tag $OriginUserTag.Tag
                                        Start-Sleep $APISleep
                                    }
                                    Write-Verbose "$(Get-Timestamp) - Info - Adding tag: $($OriginUserTag.tag) to Case: $($OutObject.CaseNumber)"
                                    Add-LrCaseTags -Id $OutObject.CaseNumber -Tags $OriginUserTag.Tag
                                    $ScreenNewTags.add($OriginUserTag)
                                    Start-Sleep $APISleep
                                }
                            }
                            Write-Verbose "$(Get-Timestamp) - End - Add User Origin Tags to Case"
                        }

                        # General User Impacted Tags
                        if ($TagImpactedUsers) {
                            Write-Verbose "$(Get-Timestamp) - Begin - Add User Impacted Tags to Case"
                            $ImpactUserTags = $CaseTags | Where-Object -Property Primary -in "User" | Where-Object -Property Note -in "Impacted", "Recipient"

                            # Iterate through Impacted User tags
                            ForEach ($ImpactUserTag in $ImpactUserTags) {
                                # If the Curent Case User Tags does not include the Impacted User Tag, add it
                                if ($CurUserTags -notcontains $ImpactUserTag.Tag) {
                                    $TagStatus = Get-LrTags -Name $ImpactUserTag.Tag -Exact
                                    if ($null -eq $TagStatus) {
                                        Write-Verbose "$(Get-Timestamp) - Info - Creating new tag: $($ImpactUserTag.tag)"
                                        New-LrTag -Tag $ImpactUserTag.Tag
                                        Start-Sleep $APISleep
                                    }
                                    Write-Verbose "$(Get-Timestamp) - Info - Adding tag: $($ImpactUserTag.tag) to Case: $($OutObject.CaseNumber)"
                                    Add-LrCaseTags -Id $OutObject.CaseNumber -Tags $ImpactUserTag.Tag
                                    $ScreenNewTags.add($ImpactUserTag)
                                    Start-Sleep $APISleep
                                }
                            }
                            Write-Verbose "$(Get-Timestamp) - End - Add User Impacted Tags to Case"
                        }

                        # Host Tags
                        $CurHostTags = $ScreenCases.tags | Where-Object -Property text -Match "(HOST|IP|DNS)_.*" | Select-Object -ExpandProperty text
                        
                        # If CaseTagOriginHosts is enabled, add new CaseTagOriginHosts to Case
                        if ($TagOriginHosts -eq $true) {
                            Write-Verbose "$(Get-Timestamp) - Begin - Add Host Origin Tags to Case"
                            $OriginHostTags = $CaseTags | Where-Object -Property Primary -in "HOST","IP","DNS" | Where-Object -Property Note -eq "Origin"

                            # Iterate through Origin Host tags
                            ForEach ($OriginHostTag in $OriginHostTags) {
                                # If the Curent Case Host Tags does not include the Origin Host Tag, add it
                                if ($CurHostTags -notcontains $OriginHostTag.Tag) {
                                    $TagStatus = Get-LrTags -Name $OriginHostTag.Tag -Exact
                                    if ($null -eq $TagStatus) {
                                        Write-Verbose "$(Get-Timestamp) - Info - Creating new tag: $($OriginHostTag.tag)"
                                        New-LrTag -Tag $OriginHostTag.Tag
                                        Start-Sleep $APISleep
                                    }
                                    Write-Verbose "$(Get-Timestamp) - Info - Adding tag: $($OriginHostTag.tag) to Case: $($OutObject.CaseNumber)"
                                    Add-LrCaseTags -Id $OutObject.CaseNumber -Tags $OriginHostTag.Tag
                                    $ScreenNewTags.add($OriginHostTag)
                                    Start-Sleep $APISleep
                                }
                            }
                            Write-Verbose "$(Get-Timestamp) - End - Add Host Origin Tags to Case"
                        }

                        if ($TagImpactedHosts -eq $true) {
                            Write-Verbose "$(Get-Timestamp) - Begin - Add Host Impacted Tags to Case"
                            $ImpactedHostTags = $CaseTags | Where-Object -Property Primary -in "HOST","IP","DNS" | Where-Object -Property Note -eq "Impacted"

                            # Iterate through Origin Host tags
                            ForEach ($ImpactedHostTag in $ImpactedHostTags) {
                                # If the Curent Case Host Tags does not include the Origin Host Tag, add it
                                if ($CurHostTags -notcontains $ImpactedHostTag.Tag) {
                                    $TagStatus = Get-LrTags -Name $ImpactedHostTag.Tag -Exact
                                    if ($null -eq $TagStatus) {
                                        Write-Verbose "$(Get-Timestamp) - Info - Creating new tag: $($ImpactedHostTag.Tag)"
                                        New-LrTag -Tag $ImpactedHostTag.Tag
                                        Start-Sleep $APISleep
                                    }
                                    Write-Verbose "$(Get-Timestamp) - Info - Adding tag: $($ImpactedHostTag.tag) to Case: $($OutObject.CaseNumber)"
                                    Add-LrCaseTags -Id $OutObject.CaseNumber -Tags $ImpactedHostTag.Tag
                                    $ScreenNewTags.add($ImpactedHostTag)
                                    Start-Sleep $APISleep
                                }
                            }
                            Write-Verbose "$(Get-Timestamp) - End - Add Host Origin Tags to Case"
                        }

                        if ($ScreenNewTags) {
                            Write-Verbose "$(Get-Timestamp) - Begin - Add Updated Case Taxonomy to Case"
                            $ScreenTagNote += "-==- Updated Case Taxonomy Tags -==-`r`nIdenified new resources from Alarm: $($AlarmDetails.AlarmId).`r`n`r`nNew Tags:`r`n"
                            ForEach ($ScreenTag in $ScreenNewTags) {
                            # Apply Regex match approach to support future modifications to case tag listing and prevent adding non-taxonomy tags to note.
                                Switch -regex ($ScreenTag) {
                                    'tech_.*' {$ScreenTagNote +="$($ScreenTag.tag)`r`n"}
                                    'user_.*' {$ScreenTagNote +="$($ScreenTag.tag)`r`n"}
                                    'host_.*' {$ScreenTagNote +="$($ScreenTag.tag)`r`n"}
                                    'ip_*' {$ScreenTagNote +="$($ScreenTag.tag)`r`n"}
                                    'dns_*' {$ScreenTagNote +="$($ScreenTag.tag)`r`n"}
                                }
                            }
                            Add-LrNoteToCase -Id $ScreenCases.Number -Text $ScreenTagNote
                            Start-Sleep $APISleep
                            Write-Verbose "$(Get-Timestamp) - End - Add Updated Case Taxonomy to Case"
                        }

                        return $OutObject
                    }
                }
            }
            Write-Verbose "$(Get-Timestamp) - End - Bind Alarm to Existing Case - Host Origin"
        }


        # Establish Case
        Write-Verbose "$(Get-Timestamp) - Begin - Create New Case - Drilldown Enrichment"
        $OutObject.Case.CaseObject = $(New-LrCase -Name $AlarmDetails.AIERuleName -Priority $CasePriority -Summary $CaseSummary -AlarmNumbers $AlarmDetails.AlarmId -PassThru)
        Write-Verbose "$(Get-Timestamp) - Created new case: $($OutObject.Case.CaseObject.number)"
        $OutObject.CaseNumber = $OutObject.Case.CaseObject.number
        $OutObject.Case.Note = "Created new case with Drilldown enrichment."
        Write-Verbose "$(Get-Timestamp) - End - Create New Case - Drilldown Enrichment"
        Start-Sleep $APISleep

        # Add CasePlaybook if Defined and lookup was successful
        if ($OutObject.Playbook.Id) {
            Write-Verbose "$(Get-Timestamp) - Begin - Adding playbook: $($OutObject.Playbook.Name) to Case: $($OutObject.CaseNumber)"
            $OutObject.Case.CasePlaybook = Add-LrCasePlaybook -Id $OutObject.CaseNumber -Playbook $($OutObject.Playbook.Id) -PassThru
            Start-Sleep $APISleep
        }

        # Set Output Object CaseTags
        $OutObject.Case.CaseTags = $CaseTags
        
        # Create meaningful tags
        # Add Technique Classification
        if ($DefaultCaseTag) {
            Write-Verbose "$(Get-Timestamp) - Begin - Add Default Tag to Case"
            $TechniqueTagStatus = Get-LrTags -Name $DefaultCaseTag -Exact
            Start-Sleep $APISleep

            if ($null -eq $TechniqueTagStatus) {
                New-LrTag -Tag $DefaultCaseTag
                Start-Sleep $APISleep
            }
            Add-LrCaseTags -Id $OutObject.CaseNumber -Tags $DefaultCaseTag
            Start-Sleep $APISleep
            Write-Verbose "$(Get-Timestamp) - End - Add Default Tag to Case"
        }



        # Create and assign HOST Tags
        # HostOrigin
        if ($TagOriginHosts -eq $true) {
            Write-Verbose "$(Get-Timestamp) - Begin - Add Host Origin Tags to Case"
            $HostTags = $CaseTags | Where-Object -Property Primary -in "HOST","IP","DNS" | Where-Object -Property Note -eq "Origin"
            ForEach ($HostTag in $HostTags) {
                Write-Verbose "$(Get-Timestamp) - Info - Host Origin: $($HostTag)"
                $TagStatus = Get-LrTags -Name $HostTag.Tag -Exact
                if ($null -eq $TagStatus) {
                    Write-Verbose "$(Get-Timestamp) - Info - Creating new tag: $($HostTag)"
                    New-LrTag -Tag $HostTag.Tag
                    Start-Sleep $APISleep
                }
                Write-Verbose "$(Get-Timestamp) - Info - Adding tag: $($HostTag) to Case: $($OutObject.CaseNumber)"
                Add-LrCaseTags -Id $OutObject.CaseNumber -Tags $HostTag.Tag
                Start-Sleep $APISleep
            }
            Write-Verbose "$(Get-Timestamp) - End - Add Host Origin Tags to Case"
        }

        # HostImpacted
        if ($TagImpactedHosts -eq $true) {
            Write-Verbose "$(Get-Timestamp) - Begin - Add Host Impacted Tags to Case"
            $HostTags = $CaseTags | Where-Object -Property Primary -in "HOST","IP","DNS" | Where-Object -Property Note -eq "Impacted"
            ForEach ($HostTag in $HostTags) {
                Write-Verbose "$(Get-Timestamp) - Info - Host Impacted: $($HostTag)"
                $TagStatus = Get-LrTags -Name $HostTag.Tag -Exact
                if ($null -eq $TagStatus) {
                    Write-Verbose "$(Get-Timestamp) - Info - Creating new tag: $($HostTag)"
                    New-LrTag -Tag $HostTag.Tag
                    Start-Sleep $APISleep
                }
                Write-Verbose "$(Get-Timestamp) - Info - Adding tag: $($HostTag) to Case: $($OutObject.CaseNumber)"
                Add-LrCaseTags -Id $OutObject.CaseNumber -Tags $HostTag.Tag
                Start-Sleep $APISleep
            }
            Write-Verbose "$(Get-Timestamp) - End - Add Host Impacted Tags to Case"
        }

        # Generate User Origin Tags
        if ($TagOriginUsers) {
            Write-Verbose "$(Get-Timestamp) - Begin - Add User Origin Tags to Case"
            $OriginUserTags = $CaseTags | Where-Object -Property Primary -in "User" | Where-Object -Property Note -in "Origin", "Sender"

            # Iterate through Origin Host tags
            ForEach ($OriginUserTag in $OriginUserTags) {
                # If the Curent Case Host Tags does not include the Origin Host Tag, add it
                if ($CurUserTags -notcontains $OriginUserTag.Tag) {
                    $TagStatus = Get-LrTags -Name $OriginUserTag.Tag -Exact
                    if ($null -eq $TagStatus) {
                        Write-Verbose "$(Get-Timestamp) - Info - Creating new tag: $($OriginUserTag.tag)"
                        New-LrTag -Tag $OriginUserTag.Tag
                        Start-Sleep $APISleep
                    }
                    Write-Verbose "$(Get-Timestamp) - Info - Adding tag: $($OriginUserTag.tag) to Case: $($OutObject.CaseNumber)"
                    Add-LrCaseTags -Id $OutObject.CaseNumber -Tags $OriginUserTag.Tag
                    $ScreenNewTags.add($OriginUserTag)
                    Start-Sleep $APISleep
                }
            }
            Write-Verbose "$(Get-Timestamp) - End - Add User Origin Tags to Case"
        }

        # General User Impacted Tags
        if ($TagImpactedUsers) {
            Write-Verbose "$(Get-Timestamp) - Begin - Add User Impacted Tags to Case"
            $ImpactUserTags = $CaseTags | Where-Object -Property Primary -eq "User" | Where-Object -Property Note -in "Impacted", "Recipient"
            ForEach ($ImpactUserTag in $ImpactUserTags) {
                # If the Curent Case User Tags does not include the Impacted User Tag, add it
                if ($CurUserTags -notcontains $ImpactUserTag.Tag) {
                    $TagStatus = Get-LrTags -Name $ImpactUserTag.Tag -Exact
                    if ($null -eq $TagStatus) {
                        Write-Verbose "$(Get-Timestamp) - Info - Creating new tag: $($ImpactUserTag.tag)"
                        New-LrTag -Tag $ImpactUserTag.Tag
                        Start-Sleep $APISleep
                    }
                    Write-Verbose "$(Get-Timestamp) - Info - Adding tag: $($ImpactUserTag.tag) to Case: $($OutObject.CaseNumber)"
                    Add-LrCaseTags -Id $OutObject.CaseNumber -Tags $ImpactUserTag.Tag
                    $ScreenNewTags.add($ImpactUserTag)
                    Start-Sleep $APISleep
                }
            }
            Write-Verbose "$(Get-Timestamp) - End - Add User Impacted Tags to Case"
        }

        # Create Tag Taxonomy Case Note Summary
        $TaxonomySummary = "-==- Case Taxonamy Summary -==-`r`nThis case incorporates Case Tagging to support automated case association, reporting, and enhance security operations.`r`n`r`n"
        $TaxonomySummary += "Prefix - Definition`r`n"
        $TaxonomySummary += "TECH_ -  The primary technical threat associated with the case.`r`n"
        $TaxonomySummary += "USER_ -  A user identifier associated with the case.`r`n"
        $TaxonomySummary += "HOST_ -  A hostname associated with the case.`r`n"
        $TaxonomySummary += "IP_ -  An IP address associated with the case.`r`n"
        $TaxonomySummary += "DNS_ - A DNS entry associated with the case.`r`n"
        $TaxonomySummary += "_Int_ - Internal - A resource that has been identified as Internal to the organization.`r`n"
        $TaxonomySummary += "_Ext_ - External - A resource that has been identified as External to the organization.`r`n"
        $TaxonomySummary += "_Login_ - A user identifier used for identification and authentication..`r`n"
        $TaxonomySummary += "_Email_ - A user identifier used for e-mail correspondence..`r`n"
        $TaxonomySummary += "_TrueId_ - TrueIdentity - An integer ID value representing an individual.`r`n"
        $TaxonomySummary += "`r`n-- Case Taxonomy Tags --`r`n"
        $CurrentCaseTags = Get-LrCaseById -Id $OutObject.CaseNumber | Select-Object -ExpandProperty tags | Select-Object -ExpandProperty text
        Start-Sleep $APISleep
        if ($CurrentCaseTags) {
            Write-Verbose "$(Get-Timestamp) - Begin - Add CaseTagTaxonomy"
            ForEach ($CurrentCaseTag in $CurrentCaseTags) {
                # Apply Regex match approach to support future modifications to case tag listing and prevent adding non-taxonomy tags to note.
                Switch -regex ($CurrentCaseTag) {
                    'tech_.*' {$TaxonomySummary +="$CurrentCaseTag`r`n"}
                    'user_.*' {$TaxonomySummary +="$CurrentCaseTag`r`n"}
                    'host_.*' {$TaxonomySummary +="$CurrentCaseTag`r`n"}
                    'ip_*' {$TaxonomySummary +="$CurrentCaseTag`r`n"}
                    'dns_*' {$TaxonomySummary +="$CurrentCaseTag`r`n"}
                }
            }
            #Add Case tag Taxonomy
            Add-LrNoteToCase -Id $OutObject.CaseNumber -Text $TaxonomySummary
            Start-Sleep $APISleep
            Write-Verbose "$(Get-Timestamp) - End - Add CaseTagTaxonomy"
        }

        Write-Verbose "$(Get-Timestamp) - End New-LrCaseHelper"
        if ($PassThru) {
            Return $OutObject
        }
    }
}