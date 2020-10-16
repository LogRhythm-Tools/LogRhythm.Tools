using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Add-LrCaseTrueIdSummary {
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
        PS C:\> Add-LrNoteToCase -Id 1780 -Text "Review of alarm 21202 indicated manual action from System Administrator." -PassThru
        ---

        number        : 4
        dateCreated   : 2020-07-17T01:49:47.0452267Z
        dateUpdated   : 2020-07-17T01:49:47.0452267Z
        createdBy     : @{number=1; name=lrtools; disabled=False}
        lastUpdatedBy : @{number=1; name=lrtools; disabled=False}
        type          : note
        status        : completed
        statusMessage :
        text          : Review of alarm 21202 indicated manual action from System Administrator.
        pinned        : False
        datePinned    :
    .EXAMPLE
        PS C:\> Add-LrNoteToCase -Id 2 -Text "This is my note for case 2!" -PassThru       
        ---

        number        : 5
        dateCreated   : 2020-07-17T01:51:45.7467156Z
        dateUpdated   : 2020-07-17T01:51:45.7467156Z
        createdBy     : @{number=1; name=lrtools; disabled=False}
        lastUpdatedBy : @{number=1; name=lrtools; disabled=False}
        type          : note
        status        : completed
        statusMessage :
        text          : This is my note for case 2!
        pinned        : False
        datePinned    :
    .NOTES
        LogRhythm-API
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, Position = 0)]
        [ValidateNotNull()]
        [object] $Id,


        [Parameter(Mandatory = $true, Position = 1)]
        [ValidateNotNullOrEmpty()]
        [object] $IdentityId,


        [Parameter(Mandatory = $false, Position = 2)]
        [switch] $PassThru
    )

    Begin {

    }

    Process {

        $IdentityResults = Get-LrIdentityById -IdentityId $IdentityId 
        
        if ($IdentityResults) {
            $IdentitySummary = "-==- TrueIdentity Summary -==-`r`nName: $($IdentityResults.nameFirst) "
            if ($IdentityResults.nameMiddle) { $IdentitySummary += "$($IdentityResults.nameMiddle) "}
            if ($IdentityResults.nameLast) { $IdentitySummary += "$($IdentityResults.nameLast)`r`n"}
            if ($IdentityResults.displayIdentifier) { $IdentitySummary += "Display Identifier: $($IdentityResults.displayIdentifier) `r`n"}
            if ($IdentityResults.company) { $IdentitySummary += "Company: $($IdentityResults.company) `r`n"}
            if ($IdentityResults.department) { $IdentitySummary += "Department: $($IdentityResults.department) `r`n"}
            if ($IdentityResults.title) { $IdentitySummary += "Title: $($IdentityResults.title) `r`n"}
            if ($IdentityResults.manager) { $IdentitySummary += "Manager: $($IdentityResults.manager) `r`n"}
            if ($IdentityResults.addressCity) { $IdentitySummary += "Manager: $($IdentityResults.addressCity) `r`n"}
            if ($IdentityResults.domainName) { $IdentitySummary += "Manager: $($IdentityResults.domainName) `r`n"}
            if ($IdentityResults.entity.name) { $IdentitySummary += "LogRhythm Entity: $($IdentityResults.entity.name) `r`n"}
            if ($IdentityResults.manager) { $IdentitySummary += "`r`n---- Identifiers ----`r`n"}
            ForEach ($Identifier in $IdentityResults.Identifiers) {
                $i += 1
                $IdentitySummary += "Identifier $i.  Type: $($Identifier.IdentifierType)  Value: $($Identifier.value)`r`n"
            }
            if ($IdentityResults.dateUpdated) { $IdentitySummary += "`r`nRecord last updated: $($IdentityResults.dateUpdated)"}
            
            $SummaryStatus = Add-LrNoteToCase -Id $Id -Text $IdentitySummary -PassThru
        } else {
            return $null
        }



        if ($PassThru) {
            return $SummaryStatus
        } else {
            return $null
        }
    }
}