using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Format-LrIdentityTextOutput {
    <#
    .SYNOPSIS
        Converts the data returned from the Administration Identities API for a single Identity into a text output.

        This output is ideal for applying to LogRhythm Case.
    .DESCRIPTION
        Typical use case would be in line with:
        Get-LrIdentityById -IdentityId 54 | Format-LrIdentityTextOutput | Add-LrNoteToCase -Id 4
    .PARAMETER Identity
        Identity object representing the data commonly returned from the Admin Identitiy API endpoint.
    .PARAMETER Type
        Sets if the summary note will be detailed or summary.  A detailed note is a note suitable to be a complete Evidence Note.

        A summary is a brief of the Identity that can be joined to additional text summaries prior to adding as an Evidence Note.

    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
        Note: You can bypass the need to provide a Credential by setting
        the preference variable $LrtConfig.LogRhythm.ApiKey
        with a valid Api Token.
    .INPUTS
        Type -> Parameter
    .OUTPUTS
        PSCustomObject representing the (new|modified) LogRhythm object.
    .EXAMPLE
        PS C:\> Get-LrIdentityById -IdentityId 54 | Format-LrIdentityTextOutput | Add-LrNoteToCase -Id 4
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
        PS C:\> Get-LrIdentityById -IdentityId 54 | Format-LrIdentityTextOutput -Type "Summary" | Add-LrNoteToCase -Id 4   
    .NOTES
        LogRhythm-API
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
        [ValidateNotNull()]
        [object] $Identity,

        [Parameter(Mandatory = $false, Position = 1)]
        [ValidateSet('detail', 'summary', ignorecase=$true)]
        [string] $Type = "Detail"
    )

    Begin {
        $Me = $MyInvocation.MyCommand.Name
    }

    Process {
        $CaseOutput = [list[String]]::new()
        if ($Identity.identityId) {
            if ($Type -like "Detail") {
                $CaseOutput.Add("-==- TrueIdentity Summary -==-")
                if ($Identity.nameMiddle) {
                    $CaseOutput.Add("Name: $($Identity.nameFirst) $($Identity.nameMiddle) $($Identity.nameLast)" )
                } else {
                    $CaseOutput.Add("Name: $($Identity.nameFirst) $($Identity.nameLast)" )
                }
                if ($Identity.displayIdentifier) { $CaseOutput.Add("Display Identifier: $($Identity.displayIdentifier) ")}
                if ($Identity.domainName) { $CaseOutput.Add("Domain: $($Identity.domainName) ")}
                if ($Identity.title) { $CaseOutput.Add("Title: $($Identity.title) ")}
                if ($Identity.department) { $CaseOutput.Add("Department: $($Identity.department) ")}
                if ($Identity.manager) { $CaseOutput.Add("Manager: $($Identity.manager) ")}
                if ($Identity.company) { $CaseOutput.Add("Company: $($Identity.company) ")}
                if ($Identity.addressCity) { $CaseOutput.Add("Address: $($Identity.addressCity) ")}
                if ($Identity.entity.name) { $CaseOutput.Add("LogRhythm Entity: $($Identity.entity.name) ")}
                if ($Identity.identifiers) { $CaseOutput.Add("`r`n---- Identifiers ----")}
                $i = 0
                ForEach ($Identifier in $Identity.Identifiers) {
                    $i += 1
                    $CaseOutput.Add("Identifier: $i  Type: $($Identifier.IdentifierType)  Value: $($Identifier.value)")
                }
                if ($Identity.dateUpdated) { $CaseOutput.Add("`r`nRecord ID: $($Identity.identityID)      Record last updated: $($Identity.dateUpdated)")}
            }
            if ($Type -like "Summary") {
                if ($Identity.nameMiddle) {
                    $NoteName = "Name: $($Identity.nameFirst) $($Identity.nameMiddle) $($Identity.nameLast)"
                    $NoteTrueId = "TrueID: $($Identity.identityId)"
                    $CaseOutput.Add("$NoteName $($NoteTrueId.PadLeft(47-($NoteName.length)+$($NoteTrueId.length)))")
                } else {
                    $NoteName = "Name: $($Identity.nameFirst) $($Identity.nameLast)"
                    $NoteTrueId = "TrueID: $($Identity.identityId)"
                    $CaseOutput.Add("$NoteName $($NoteTrueId.PadLeft(47-($NoteName.length)+$($NoteTrueId.length)))")
                }
                if ($Identity.title -and $Identity.department) {
                    $NoteDepartment = "Department: $($Identity.department)"
                    $NoteTitle = "Title: $($Identity.title)"
                    $CaseOutput.Add("$NoteDepartment $($NoteTitle.PadLeft(38-($NoteDepartment.length)+$($NoteTitle.length)))")
                } elseif ($Identity.title) {
                    $CaseOutput.Add("Title: $($Identity.title)")
                } elseif ($Identity.department) {
                    $CaseOutput.Add("Department: $($Identity.department)")
                }
                if ($Identity.manager -and $Identity.company) {
                    $NoteManager = "Manager: $($Identity.manager)"
                    $NoteCompany = "Company: $($Identity.company)"
                    $CaseOutput.Add("$NoteCompany $($NoteManager.PadLeft(40-($NoteCompany.length)+$($NoteManager.length)))")
                } elseif ($Identity.manager) {
                    $CaseOutput.Add("Manager: $($Identity.manager)")
                } elseif ($Identity.company) {
                    $CaseOutput.Add("Company: $($Identity.company)")
                }
                if ($Identity.addressCity) { $CaseOutput.Add("Address: $($Identity.addressCity)")}
            }
        } else {
            return $null
        }

        return $CaseOutput | Out-String
    }
}