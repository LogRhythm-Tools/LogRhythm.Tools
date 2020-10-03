using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Merge-LrIdentities {
    <#
    .SYNOPSIS
        Merge two TrueIdentity records into one.  Requires LogRhythm 7.4 or greater.
    .DESCRIPTION
        This cmdlet moves all Identifiers from the Secondard TrueIdentity into the specified Primary TrueIdentity record
        The Secondary Identity will be retired.
        
        Note: Only "Active" Identifiers on the Secondary will be migrated
    .PARAMETER PrimaryIdentityId
        Required integer
        The IdentityId of the TrueIdentity which will remain after merging
        Example: 
            https://WebConsole:8443/admin/identity/3208/identifiers
            -PrimaryIdentityId 3208
    .PARAMETER SecondaryIdentityId
        Required integer
        The IdentityId of the TrueIdentity which will be retired after merging
        All Identifiers will be moved from the Secondary TrueIdentity to the Primary TrueIdentity
    .PARAMETER IdentityObject
        Pipeline paramater that will accept an of two [int]IdentitiyId values.  
        The first value of each pair represents the PrimaryId
        The second value of each pair represents the SecondaryId

        @(1,11)
    .PARAMETER TestMode
        Enabled by default. Disabling "TestMode" will perform the TrueIdentity migration.
        
        With TestMode on the cmdlet will check for errors but not make any changes to the TrueIdentities
    .EXAMPLE
        C:\> Merge-LrIdentities -PrimaryIdentity 8 -SecondaryIdentity 1 -TestMode $false
        Merge-LrIdentities -PrimaryIdentityId 8 -SecondaryIdentityId 1 -TestMode $false
        Primary Identity: 'Eric Hart (Eric.Hart)'
        Secondary Identity: 'Eric Hart (Eric.Hart)'
        Moving Identifiers:
            Identifier 'eric.hart@logrhythm.com' type 'Login' already exists in the Primary Identity
            Identifier 'eric.hart@logrhythm.com' type 'Email' already exists in the Primary Identity
            Successfully moved Identifier 'eric23hart@gmail.com' type 'Email'
        @{identityID=1; nameFirst=Eric; nameMiddle=W; nameLast=Hart; displayIdentifier=Eric.Hart; company=LogRhythm; department=Customer Success; title=; manager=Chuck Talley; addressCity=; domainName=; entity=; dateUpdated=2020-06-19T14:25:33.883Z; recordStatus=Retired; identifiers=System.Object[]; groups=System.Object[]}
    .EXAMPLE
        C:\> Merge-LrIdentities -IdentityObject @(8,1)
        ---
        Running in Preview mode; no changes to TrueIdentities will be made
        Primary Identity: 'Eric Hart (Eric.Hart)'
        Secondary Identity: 'Eric Hart (Eric.Hart)'
        Moving Identifiers:
                Identifier 'eric.hart@logrhythm.com' type 'Login' already exists in the Primary Identity
                Identifier 'eric.hart@logrhythm.com' type 'Email' already exists in the Primary Identity
                Successfully moved Identifier 'eric23hart@gmail.com' type 'Email'
        Test Mode: Disable-LrIdentity -IdentityId 1
        identityID        : 1
        status            : Retired
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>  
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false, ValueFromPipeline = $true, Position = 0)]
        [object] $IdentityObject,


        [Parameter(Mandatory = $false, ValueFromPipeline = $false, Position = 1)]
        [long] $EntityId = 1,


        [Parameter(Mandatory = $false, ValueFromPipeline = $false, Position = 2)]
        [long] $PrimaryIdentityId,


        [Parameter(Mandatory = $false, ValueFromPipeline = $false, Position = 3)]
        [long] $SecondaryIdentityId,


        [Parameter(Mandatory = $false, ValueFromPipeline = $false, Position = 4)]
        [int] $LeadingWhitespace = 0,


        [Parameter(Mandatory = $false, ValueFromPipeline = $false, Position = 5)]
        [bool] $TestMode = $True,

                                
        [Parameter(Mandatory = $false, Position = 6)]
        [switch] $PassThru,


        [Parameter(Mandatory = $false, Position = 7)]
        [ValidateNotNull()]
        [pscredential] $Credential = $LrtConfig.LogRhythm.ApiKey
    )

    Begin {
        $LeadingWhitespaceString = "`t" * $LeadingWhitespace

        if ($TestMode) {
            write-host ($LeadingWhitespaceString + "Running in Preview mode; no changes to TrueIdentities will be made")
        }
    }


    Process {
        # Establish General Error object Output
        $ErrorObject = [PSCustomObject]@{
            Error                 =   $false
            Note                  =   $null
            IdentityId            =   $null
            IdentifierId          =   $null
            RecordStatus          =   $null
            $IdentifierStatus     =   $null
            NameFirst             =   $null
            NameLast              =   $null
        }

        # Establish General Output object
        $OutObject = [PSCustomObject]@{
            PrimaryIdentityId       = $PrimaryIdentityId
            PrimaryIdentity         = [PSCustomObject]@{
                Id                  = $null
                RecordStatus        = $null
                NameFirst           = $null
                NameLast            = $null
                DisplayIdentifier   = $null
                AddedIdentifiers    = $null
                AddedCount          = 0
            }
            SecondaryIdentityId     = $SecondaryIdentityId
            SecondaryIdentity       = [PSCustomObject]@{
                Id                  = $null
                RecordStatus        = $null
                NameFirst           = $null
                NameLast            = $null
                DisplayIdentifier   = $null
                RetiredIdentifiers  = $null
                RetiredCount        = 0
            }
            MigrationStatus         = $false
        }

        if ($IdentityObject) {
            #check int
            $PrimaryIdentityId = $IdentityObject[0]
            $OutObject.PrimaryIdentityId = $IdentityObject[0]
            $SecondaryIdentityId = $IdentityObject[1]
            $OutObject.SecondaryIdentityId = $IdentityObject[1]
        } else {
            $OutObject.PrimaryIdentityId = $PrimaryIdentityId
            $OutObject.SecondaryIdentityId = $SecondaryIdentityId
        }
        # Check record status
        $Primary = Get-LrIdentityById  -IdentityId $PrimaryIdentityId
        if (-not $Primary -or $Primary.recordStatus -eq "Retired") {
            $ErrorObject.Error = $true
            $ErrorObject.IdentityId = $($Primary.id)
            $ErrorObject.NameFirst = $($Primary.nameFirst)
            $ErrorObject.NameLast = $($Primary.nameLast)
            $ErrorObject.RecordStatus = $($Primary.recordStatus)
            $ErrorObject.Note = "The Primary Identity (ID '$PrimaryIdentityId') was not found or the record status is Retired"
            return $ErrorObject
        } else {
            Write-Verbose "$(Get-Timestamp) - PrimaryID: $($Primary.nameFirst) $($Primary.nameLast) ($($Primary.displayIdentifier))"
            $OutObject.PrimaryIdentity.NameFirst = $($Primary.nameFirst)
            $OutObject.PrimaryIdentity.NameLast = $($Primary.nameLast)
            $OutObject.PrimaryIdentity.Id = $($Primary.id)
            $OutObject.PrimaryIdentity.RecordStatus = $($Primary.recordStatus)
            $OutObject.PrimaryIdentity.DisplayIdentifier = $($Primary.displayIdentifier)
        }
    
        $Secondary = Get-LrIdentityById -IdentityId $SecondaryIdentityId
        if (-not $Secondary) {
            $ErrorObject.Error = $true
            $ErrorObject.IdentityId = $($Secondary.id)
            $ErrorObject.NameFirst = $($Secondary.nameFirst)
            $ErrorObject.NameLast = $($Secondary.nameLast)
            $ErrorObject.RecordStatus = $($Secondary.recordStatus)
            $ErrorObject.Note = "The Secondary Identity (ID '$SecondaryIdentityId') was not found"
            return $ErrorObject
        } else {
            Write-Verbose "$(Get-Timestamp) - SecondaryID: $($Secondary.nameFirst) $($Secondary.nameLast) ($($Secondary.displayIdentifier))"
            $OutObject.SecondaryIdentity.NameFirst = $($Secondary.nameFirst)
            $OutObject.SecondaryIdentity.NameLast = $($Secondary.nameLast)
            $OutObject.SecondaryIdentity.Id = $($Secondary.id)
            $OutObject.SecondaryIdentity.RecordStatus = $($Secondary.recordStatus)
            $OutObject.SecondaryIdentity.DisplayIdentifier = $($Secondary.displayIdentifier)
        }
    
        $Identifiers = $Secondary.identifiers 
        foreach ($Identifier in $Identifiers) {
            if ($Identifier.recordStatus -eq "Retired") {
                Write-Verbose "$(Get-Timestamp) - Identifier: $($Identifier.value)' type '$($Identifier.identifierType)' is disabled and will not be moved"
                continue
            }
            
            # Check to see if this Identifier already exists in the Primary Identity
            $PrimaryHasIdentifier = (@($Primary.identifiers | Where-Object { $_.value -eq $Identifier.value -and $_.identifierType -eq $Identifier.identifierType }).Count -gt 0)
            if ($PrimaryHasIdentifier) {
                Write-Verbose "$(Get-Timestamp) - Identifier '$($Identifier.value)' type '$($Identifier.identifierType)' already exists in the Primary Identity"
                continue
            }
            
            if ($TestMode) {
                $MoveStatus = $True
            } else {
                $MoveStatus = Add-LrIdentityIdentifier  -IdentityId $PrimaryIdentityId -IdentifierType $Identifier.identifierType -IdentifierValue $Identifier.value
                if ($MoveStatus.Error -eq $true ) {

                } else {
                    $OutObject.PrimaryIdentity.AddedCount += 1
                    $OutObject | Add-Member -MemberType NoteProperty -Name PrimaryIdentity.AddedIdentifiers -Value $Identifier
                }
            }
            
            if ($MoveStatus -eq $True -or !$MoveStatus) {
                Write-Verbose "$(Get-Timestamp) - Successfully moved Identifier '$($Identifier.value)' type '$($Identifier.identifierType)'"
            } else {
                Write-Verbose "$(Get-Timestamp) - Failed moved Identifier '$($Identifier.value)' type '$($Identifier.identifierType)'"
            }
        }
    
        if ($TestMode) {
            Write-Verbose "Test Mode: Retire-LrIdentity -IdentityId $SecondaryIdentityId "
            $RetireResults = "identityID        : $SecondaryIdentityId`r`nstatus            : Retired"
        } else {
            $RetireResults = Disable-LrIdentity -IdentityId $SecondaryIdentityId -PassThru
            if ($RetireResults.Error -eq $true ) {

            } else {
                $OutObject.SecondaryIdentity.RecordStatus = $RetireResults.recordStatus
                $OutObject.SecondaryIdentity.RetiredIdentifiers = $RetireResults.identifiers
                $OutObject.SecondaryIdentity.RetiredCount = $RetireResults.identifiers.count
            }

            if ($OutObject.SecondaryIdentity.RetiredCount -eq $OutObject.PrimaryIdentity.AddedCount) {
                $OutObject.MigrationStatus = $true
            } else {
                $ErrorObject.Error = $true
                $ErrorObject.Note = "Identifier Migration count mismatch. PrimaryIdentity: $($OutObject.PrimaryIdentity.Id) AddedCount $($OutObject.PrimaryIdentity.AddedCount) does not match SecondaryId: $($OutObject.SecondaryIdentity.Id) RetiredCount $($OutObject.SecondaryIdentity.RetiredCount)."
            }

        }

        # Return output object
        if ($ErrorObject.Error -eq $true) {
            return $ErrorObject
        }
        if ($PassThru) {
            return $OutObject
        }
    }

    End { }

}