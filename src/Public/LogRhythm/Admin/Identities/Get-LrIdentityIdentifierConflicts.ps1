using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Get-LrIdentityIdentifierConflicts {
    <#
    .SYNOPSIS
        Get a list of Identifier Conflicts for LogRhythm 7.4.
    .DESCRIPTION
        A TrueIdentity "Conflict" is when two TrueIdentities share the same Identifier.

        This is common if multiple Active Directory domains are synced; any user with an account in both Domains will likely create a Conflict.

        Note that a conflict is specific to matching Identifier types.  
        Example 1: Conflict
        TrueID        Identifier                  Type
        ----          ----                        ----
        1             Bob.Jones@example.com       Login
        77            Bob.Jones@example.com       Login

        Example 2: No Conflict
        TrueID        Identifier                  Type
        ----          ----                        ----
        1             Bob.Jones@example.com       Login
        77            Bob.Jones@example.com       Email

        Example 3: Conflict
        TrueID        Identifier                  Type
        ----          ----                        ----
        1             Bob.Jones@example.com       Email
        77            Bob.Jones@example.com       Email

    .PARAMETER EntityId
        Optional long
        Only search for conflicts within this Root EntityId
        Recommended when IdentityEntitySegregation has been enabled in the Data Processor(s)
    .PARAMETER Filter
        Apply custom Identities filter
    .EXAMPLE
        PS C:\> Get-LrIdentityConflicts -Entity 1
        ----
    .EXAMPLE
        PS C:\> Get-LrIdentityConflicts
        ----
        ConflictId : 0
        Login      : marcus.burnett
        Type       : Login
        Count      : 2
        Status     : Unresolved
        Identities : {@{IdentityId=1; Identity_FirstName=Marcus; Identity_LastName=Burnett; Identity_Title=IT Helpdesk Admin; Identity_Department=IT; Identity_Manager=Nancy Smith;
             Identity_LastUpdate=2020-03-10T20:29:34.04Z; IdentifierId=1; Source=Fabrikam}, @{IdentityId=11; Identity_FirstName=Marcus; Identity_LastName=Burnett; Identity_Title=IT Helpdesk Admin;
             Identity_Department=IT; Identity_Manager=Nancy Smith; Identity_LastUpdate=2020-03-10T21:02:53.943Z; IdentifierId=40; Source=Cont0so}}
    .NOTES
        LogRhythm-API        
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>
    
    [CmdletBinding()]
    param( 
        [Parameter(Mandatory = $false, Position = 0)]
        [ValidateNotNull()]
        [pscredential] $Credential = $LrtConfig.LogRhythm.ApiKey,

        [Parameter(Mandatory = $false, ValueFromPipeline=$true, Position = 1)]
        [long]$EntityId,

        [Parameter(Mandatory = $false, ValueFromPipeline=$true, Position = 2)]
        [string] $Filter,

        [Parameter(Mandatory = $false, ValueFromPipeline=$false, Position = 9)]
        [bool] $ShowRetired = $false
    )

    Begin {
        # Request Setup
        $BaseUrl = $LrtConfig.LogRhythm.AdminBaseUrl
        $Token = $Credential.GetNetworkCredential().Password

        # Define HTTP Header
        $Headers = [Dictionary[string,string]]::new()
        $Headers.Add("Authorization", "Bearer $Token")

        # Define HTTP Method
        $Method = $HttpMethod.Get

        # Check preference requirements for self-signed certificates and set enforcement for Tls1.2 
        Enable-TrustAllCertsPolicy

        # Establish Arrays
        $Identifiers = @{}
        # Simple array - will contain the Identifier/Type combo of any conflicts
        $Conflicts = @()
    
        # Searching Scope.  
        $SearchingIdententities = $True
        $Page = 1
        $Count = 100
    }

    Process { 
        while ($SearchingIdententities -eq $True) {
            $Offset = ($Page - 1) * $Count
            $RequestUrl = $BaseUrl + "/identities?count=" + $Count + "&offset=" + $Offset
            if ($ShowRetired) { $RequestUrl += "&showRetired=true" }
            if ($Filter) { $RequestUrl += "&$Filter" }
            

            if ($PSEdition -eq 'Core'){
                try {
                    $Response = Invoke-RestMethod $RequestUrl -Headers $Headers -Method $Method -SkipCertificateCheck
                }
                catch {
                    $ExceptionMessage = ($_.Exception.Message).ToString().Trim()
                    Write-Verbose "Exception Message: $ExceptionMessage"
                    $SearchingIdententities = $False
                    break;
                }
            } else {
                try {
                    $Response = Invoke-RestMethod $RequestUrl -Headers $Headers -Method $Method
                }
                catch [System.Net.WebException] {
                    $ExceptionMessage = ($_.Exception.Message).ToString().Trim()
                    Write-Verbose "Exception Message: $ExceptionMessage"
                    $SearchingIdententities = $False
                    break;
                }
            }
 
            if ($Response.Count -eq 0) {
                $SearchingIdententities = $False
                break;
            } elseif ($Response.Count -lt $Count) {
                $SearchingIdententities = $False
            }


            foreach ($Identity in $Response)
            {
                if ($EntityId -and $Identity.entity.entityId -ne $EntityId)
                {
                    # This Identity is not in our Entity, ignore it
                    # Unfortunately, we couldn't filter by Entity as the filter in the API query params is the Entity name, not ID
                    continue;
                }
                
                foreach ($Identifier in $Identity.Identifiers)
                {
                    # Filter inactive
                    if ($Identifier.recordStatus -eq "Retired") 
                    {
                        continue;
                    }
                    
                    # Form the Value/Type key
                    $IdentifierKey = $Identifier.value + '|' + $Identifier.identifierType
                    $IdentifierMetadata = @{ "IdentityId" = $Identity.identityId; "IdentifierId" = $Identifier.identifierID; "Source" = $Identifier.source.IAMName }
                                        
                    # See if the Identifier record exists
                    if ($null -eq $Identifiers[$IdentifierKey]) {
                        # If not, create it
                        $Identifiers[$IdentifierKey] = @()

                    } elseif ($Conflicts -notcontains $IdentifierKey) {
                        # The Identifier already had a record
                        # But there's no record of a conflict
                        # We need to check if the other records contain a different IdentityId
                        $HasConflict = (@($Identifiers[$IdentifierKey] | Where-Object { $_.IdentityId -ne $Identity.identityId }).Count -gt 0)
                        if ($HasConflict) {
                            $Conflicts += $IdentifierKey
                        }
                    }
                    
                    $Identifiers[$IdentifierKey] += $IdentifierMetadata
                }
            
            }
            
            $Page = $Page + 1
        }
    }

    End {
        $IdentifiersWithConflicts = $Identifiers.GetEnumerator() | Where-Object { $Conflicts -contains $_.Name }
        $ConflictId = 0
        foreach ($IdentitiyConflict in $IdentifiersWithConflicts) {
            [array]$IdConflictDetails = $null
            For ($i=0; $i -lt $IdentitiyConflict.Value.Count; $i++) {
                # Lookup additional information based on IdentityID and append into Conflict Details
                $IdentityIdDetailResults = Get-LrIdentityById -IdentityId $IdentitiyConflict.Value[$i].IdentityId

                
                [array]$IdConflictDetails += [PSCustomObject]@{
                    IdentityId  = $IdentitiyConflict.Value[$i].IdentityId
                    Identity_FirstName = $IdentityIdDetailResults.nameFirst
                    Identity_LastName = $IdentityIdDetailResults.nameLast
                    Identity_Title = $IdentityIdDetailResults.title
                    Identity_Department = $IdentityIdDetailResults.department
                    Identity_Manager = $IdentityIdDetailResults.manager
                    Identity_LastUpdate = $IdentityIdDetailResults.dateUpdated
                    IdentifierId = $IdentitiyConflict.Value[$i].IdentifierId
                    Source = $IdentitiyConflict.Value[$i].Source
                }
            }
            
            [array]$IdConflicts += [PSCustomObject]@{
                ConflictId = $ConflictId
                Login = $IdentitiyConflict.Name.Split("|")[0]
                Type = $IdentitiyConflict.Name.Split("|")[1]
                Count = $IdentitiyConflict.Value.Count
                Status = "Unresolved"
                Identities = $IdConflictDetails
            }
            $ConflictId = $ConflictId + 1
        }
        Write-Verbose "Identifiers: $($IdConflicts | Out-String)"
        return $IdConflicts
    }

}