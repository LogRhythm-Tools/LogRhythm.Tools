using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Merge-LrIdentities {
    <#
    .SYNOPSIS
        Merge two TrueIdentities in LR 7.4 
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
        [Parameter(Mandatory = $false, Position = 0)]
        [ValidateNotNull()]
        [pscredential] $Credential = $LrtConfig.LogRhythm.ApiKey,

        [Parameter(Mandatory = $false, ValueFromPipeline=$false, Position = 1)]
        [long]$EntityId = 1,

        [Parameter(Mandatory = $false, ValueFromPipeline=$false, Position = 2)]
        [long] $PrimaryIdentityId,

        [Parameter(Mandatory = $false, ValueFromPipeline=$false, Position = 3)]
        [long] $SecondaryIdentityId,

        [Parameter(Mandatory = $false, ValueFromPipeline=$true, Position = 4)]
        [object] $IdentityObject,

        [Parameter(Mandatory = $false, ValueFromPipeline=$false, Position = 5)]
        [int] $LeadingWhitespace = 0,

        [Parameter(Mandatory = $false, ValueFromPipeline=$false, Position = 6)]
        [bool] $TestMode = $True
    )

    Begin {
        $LeadingWhitespaceString = "`t" * $LeadingWhitespace

        if ($TestMode) {
            write-host ($LeadingWhitespaceString + "Running in Preview mode; no changes to TrueIdentities will be made")
        }
    }


    Process {
        if ($IdentityObject) {
            #check int
            $PrimaryIdentityId = $IdentityObject[0]
            $SecondaryIdentityId = $IdentityObject[1]
        }
        # Check record status
        $Primary = Get-LrIdentityById  -IdentityId $PrimaryIdentityId
        if (-not $Primary -or $Primary.recordStatus -eq "Retired") {
            write-host ($LeadingWhitespaceString + "The Primary Identity (ID '$PrimaryIdentityId') was not found or the record status was Retired")
            Exit 1
        } else {
            $PrimaryDisplay = "'$($Primary.nameFirst) $($Primary.nameLast) ($($Primary.displayIdentifier))'"
        }
    
        $Secondary = Get-LrIdentityById -IdentityId $SecondaryIdentityId
        if (-not $Secondary) {
            write-host ($LeadingWhitespaceString + "The Secondary Identity (ID '$SecondaryIdentityId') was not found")
            Exit 1
        } else {
            $SecondaryDisplay = "'$($Secondary.nameFirst) $($Secondary.nameLast) ($($Secondary.displayIdentifier))'"
        }

        write-host ($LeadingWhitespaceString + "Primary Identity: $PrimaryDisplay")
        write-host ($LeadingWhitespaceString + "Secondary Identity: $SecondaryDisplay")
        write-host ($LeadingWhitespaceString + "Moving Identifiers:")
    
        $Identifiers = $Secondary.identifiers 
        foreach ($Identifier in $Identifiers)
        {
            if ($Identifier.recordStatus -eq "Retired") {
                write-host ($LeadingWhitespaceString + "`tIdentifier '$($Identifier.value)' type '$($Identifier.identifierType)' is disabled and will not be moved")
                continue
            }
            
            # Check to see if this Identifier already exists in the Primary Identity
            $PrimaryHasIdentifier = (@($Primary.identifiers | Where-Object { $_.value -eq $Identifier.value -and $_.identifierType -eq $Identifier.identifierType }).Count -gt 0)
            if ($PrimaryHasIdentifier) {
                write-host ($LeadingWhitespaceString + "`tIdentifier '$($Identifier.value)' type '$($Identifier.identifierType)' already exists in the Primary Identity")
                continue
            }
            
            if ($TestMode) {
                $MoveStatus = $True
            } else {
                $MoveStatus = Add-LrIdentityIdentifier  -IdentityId $PrimaryIdentityId -IdentifierType $Identifier.identifierType -IdentifierValue $Identifier.value
            }
            
            if ($MoveStatus -eq $True -or $MoveStatus) {
                write-host ($LeadingWhitespaceString + "`tSuccessfully moved Identifier '$($Identifier.value)' type '$($Identifier.identifierType)'")
            } else {
                write-host ($LeadingWhitespaceString + "`tFailed to move Identifier '$($Identifier.value)' type '$($Identifier.identifierType)'")
            }
        }
    
        if ($TestMode) {
            Write-Host "Test Mode: Retire-LrIdentity -IdentityId $SecondaryIdentityId "
            $RetireResults = "identityID        : $SecondaryIdentityId`r`nstatus            : Retired"
        } else {
            $RetireResults = Disable-LrIdentity -IdentityId $SecondaryIdentityId
        }

        Write-Host $RetireResults
    }

    End { }

}