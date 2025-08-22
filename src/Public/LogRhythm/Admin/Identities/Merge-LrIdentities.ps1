using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Merge-LrIdentities {
    <#
    .SYNOPSIS
        Merge two TrueIdentities in LR 7.4 or greater.
    .DESCRIPTION
        This cmdlet moves all Identifiers from the Secondard TrueIdentity into the specified Primary TrueIdentity record
        The Secondary Identity will be retired.
        
        Note: Only "Active" Identifiers on the Secondary will be migrated
    .PARAMETER SourceIdentityId
        The TrueIdentity ID for the record that will have its active identifiers migrated to the DestinationIdentityId.
        
        The SourceIdentityID will be retired as a part of this cmdlet's execution.
    .PARAMETER DestinationIdentityId
        The TrueIdentity ID for the record that will have its active identifiers updated with additional identifiers
        from the the SourceIdentityId.

        The DestinationIdentityID will remain active as a part of this cmdlet's execution.
    .PARAMETER PrimaryIdentityId
        Depreciated argument.  This argument is being depreciated and will be phased out in version 2.0.0 of LogRhythm.Tools.

        This paramater is mapped to the new paramater DestinationIdentityId.

        Required integer
        The IdentityId of the TrueIdentity which will remain after merging
        Example: 
            https://WebConsole:8443/admin/identity/3208/identifiers
            -PrimaryIdentityId 3208
    .PARAMETER SecondaryIdentityId
        Depreciated argument.  This argument is being depreciated and will be phased out in version 2.0.0 of LogRhythm.Tools.

        This paramater is mapped to the new paramater SourceIdentityId.

        Required integer
        The IdentityId of the TrueIdentity which will be retired after merging
        All Identifiers will be moved from the Secondary TrueIdentity to the Primary TrueIdentity
    .EXAMPLE
        C:\> Merge-LrIdentities -PrimaryIdentity 8 -SecondaryIdentity 1
        Merge-LrIdentities -PrimaryIdentityId 8 -SecondaryIdentityId 1
        Primary Identity: 'Eric Hart (Eric.Hart)'
        Secondary Identity: 'Eric Hart (Eric.Hart)'
        Moving Identifiers:
            Identifier 'eric.hart@logrhythm.com' type 'Login' already exists in the Primary Identity
            Identifier 'eric.hart@logrhythm.com' type 'Email' already exists in the Primary Identity
            Successfully moved Identifier 'eric23hart@gmail.com' type 'Email'
        @{identityID=1; nameFirst=Eric; nameMiddle=W; nameLast=Hart; displayIdentifier=Eric.Hart; company=LogRhythm; department=Customer Success; title=; manager=Chuck Talley; addressCity=; domainName=; entity=; dateUpdated=2020-06-19T14:25:33.883Z; recordStatus=Retired; identifiers=System.Object[]; groups=System.Object[]}
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>  
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false, ValueFromPipeline = $false, Position = 0)]
        [long] $EntityId = 1,


        [Parameter(Mandatory = $false, ValueFromPipeline = $false, Position = 1)]
        [long] $SourceIdentityId,



        [Parameter(Mandatory = $false, ValueFromPipeline = $false, Position = 2)]
        [long] $DestinationIdentityId,


        [Parameter(Mandatory = $false, ValueFromPipeline = $false, Position = 3)]
        [long] $PrimaryIdentityId,


        [Parameter(Mandatory = $false, ValueFromPipeline = $false, Position = 4)]
        [long] $SecondaryIdentityId,


        [Parameter(Mandatory = $false, Position = 5)]
        [switch] $PassThru,


        [Parameter(Mandatory = $false, Position = 6)]
        [ValidateNotNull()]
        [pscredential] $Credential = $LrtConfig.LogRhythm.ApiKey
    )

    Begin {
        $Me = $MyInvocation.MyCommand.Name

        # Set migration to leverage 7.5. or 7.4 API endpoints
        if ($LrtConfig.LogRhythm.Version -match '7\.[0-4]\.\d+') {
            $Mode = "7.4"
        } else {
            $Mode = "7.5"
            # Request Setup
            $BaseUrl = $LrtConfig.LogRhythm.BaseUrl
            $Token = $Credential.GetNetworkCredential().Password

            # Define HTTP Headers
            $Headers = [Dictionary[string,string]]::new()
            $Headers.Add("Authorization", "Bearer $Token")
            

            # Define HTTP Method
            $Method = $HttpMethod.Post

            # Check preference requirements for self-signed certificates and set enforcement for Tls1.2 
            Enable-TrustAllCertsPolicy
        }
    }


    Process {
        # Establish General Error object Output
        $ErrorObject = [PSCustomObject]@{
            Code                  =   $null
            Error                 =   $false
            Type                  =   $null
            Note                  =   $null
            Value                 =   $null
            Raw                   =   $null
        }

        # Ensure Identity IDs have been provided.  Handles assigning depreciated paramaters for integration transition.
        if (!$DestinationIdentityId) {
            if ($PrimaryIdentityId) {
                Write-verbose "$(Get-Timestamp) - Warning - This cmdlet's paramater: PrimaryIdentityId is being retired.  Update to new paramater PrimaryIdentityId."
                $DestinationIdentityId = $PrimaryIdentityId
            } else {
                $ErrorObject.Error = $true
                $ErrorObject.Type = "Input"
                $ErrorObject.Note = "Merge-LrIdentites requires paramater DestinationIdentityId."
                return $ErrorObject
            }
        }

        # Ensure Identity IDs have been provided.  Handles assigning depreciated paramaters for integration transition.
        if (!$SourceIdentityId) {
            if ($SecondaryIdentityId) {
                Write-verbose "$(Get-Timestamp) - Warning - This cmdlet's paramater: SecondaryIdentityId is being retired.  Update to new paramater PrimaryIdentityId."
                $SourceIdentityId = $SecondaryIdentityId
            } else {
                $ErrorObject.Error = $true
                $ErrorObject.Type = "Input"
                $ErrorObject.Note = "Merge-LrIdentites requires paramater SourceIdentityId."
                return $ErrorObject
            }
        }

        # Check record status
        $DestinationIdentity = Get-LrIdentityById -IdentityId $DestinationIdentityId
        if (-not $DestinationIdentity) {
            $ErrorObject.Code = 404
            $ErrorObject.Error = $true
            $ErrorObject.Type = "Record Not Found"
            $ErrorObject.Note = "Unable to retrieve any details for DestinationIdentityId."
            $ErrorObject.Value = $DestinationIdentityId
            return $ErrorObject
        }

        if ($DestinationIdentity.recordStatus -eq "Retired") {
            $ErrorObject.Code = 409
            $ErrorObject.Error = $true
            $ErrorObject.Type = "Disabled Destination Identity"
            $ErrorObject.Note = "DestinationIdentityId has a record status of Retired.  Record must be active to participate in merge."
            $ErrorObject.Value = $DestinationIdentityId
            return $ErrorObject
        }
    
        $SourceIdentity = Get-LrIdentityById -IdentityId $SourceIdentityId
        if (-not $SourceIdentity) {
            $ErrorObject.Code = 404
            $ErrorObject.Error = $true
            $ErrorObject.Type = "RecordNotFound"
            $ErrorObject.Note = "Unable to retrieve any details for SourceIdentityId."
            $ErrorObject.Value = $SourceIdentityId
            return $ErrorObject
        }

        if ($Mode -like "7.4") {
            $Identifiers = $SourceIdentity.identifiers 
            foreach ($Identifier in $Identifiers)
            {
                # Check to see if the source Identifier is currently retired
                if ($Identifier.recordStatus -eq "Retired") {
                    write-verbose "$(Get-Timestamp) - Identifier '$($Identifier.value)' type '$($Identifier.identifierType)' is retired in the Source Identity"
                    continue
                }
                
                # Check to see if the source Identifier already exists in the DestinationIdentity
                $DestinationHasIdentifier = (@($DestinationIdentity.identifiers | Where-Object { $_.value -eq $Identifier.value -and $_.identifierType -eq $Identifier.identifierType }).Count -gt 0)
                if ($DestinationHasIdentifier) {
                    write-verbose "$(Get-Timestamp) - Identifier '$($Identifier.value)' type '$($Identifier.identifierType)' already exists in the Destination Identity"
                    continue
                }
                
                # Add the current Identifier to the DestinationIdentityId
                $MoveStatus = Add-LrIdentityIdentifier  -IdentityId $DestinationIdentityId -IdentifierType $Identifier.identifierType -IdentifierValue $Identifier.value -PassThru

                # Verify the Identity was successfully updated.
                if ($MoveStatus -eq $True -or $MoveStatus) {
                    write-verbose "$(Get-Timestamp) - Successfully moved Identifier '$($Identifier.value)' type '$($Identifier.identifierType)'"
                } else {
                    write-verbose "$(Get-Timestamp) - Failed to move Identifier '$($Identifier.value)' type '$($Identifier.identifierType)'"
                }
            }
            
            # Retire the SourceIdentityId
            Disable-LrIdentity -IdentityId $SourceIdentityId

            # If PassThru is enabled, retrieve the UpdatedIdentity details
            if ($PassThru) {
                $Response = Get-LrIdentityById -IdentityId $DestinationIdentityId
            }
        }

        if ($Mode -like "7.5") {
            # Define URL
            $RequestUrl = $BaseUrl + "/lr-admin-api/identities/$DestinationIdentityId/merge/"

            # Define request body
            $Body = [PSCustomObject]@{
                sourceId = $SourceIdentityId
            } | ConvertTo-Json

            Write-Verbose "[$Me]: Request URL: $RequestUrl"
            Write-Verbose "[$Me]: Request Body:`n$Body"

            # Send Request
            $Response = Invoke-RestAPIMethod -Uri $RequestUrl -Headers $Headers -Method $Method -Body $Body -Origin $Me
            if (($null -ne $Response.Error) -and ($Response.Error -eq $true)) {
                return $Response
            }
        }

        if ($PassThru) {
            return $Response
        }
    }

    End { }

}