using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Add-LrCaseHostSummary {
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
        [object] $HostId,


        [Parameter(Mandatory = $false, Position = 2)]
        [switch] $PassThru
    )

    Begin {

    }

    Process {
        $HostResults = Get-LrHostDetails -Id $HostId
    
        if ($HostResults) {
            $HostSummary = "-==- LogRhythm Known Host Summary -==-`r`nName: $($HostResults.Name)`r`n"
            if ($HostResults.shortDesc) {$HostSummary += "Short Description: $($HostResults.shortDesc)`r`n"}
            if ($HostResults.location.id -ne -1) {
                $LocationDetails = [list[object]]::new()
                $LocationResults = Get-LrLocations -Id $HostResults.location.id
                $ParentLocationId = $LocationResults.ParentLocationId
                $LocationDetails.Add($LocationResults)
                if ($ParentLocationId -ne 0) {
                    $TmpCounter = 0
                    do {
                        $LocationResults = Get-LrLocations -Id $ParentLocationId
                        $LocationDetails.Add($LocationResults)
                        $ParentLocationId = $LocationResults.ParentLocationId
                        $TmpCounter += 1
                    } until (($ParentLocationId -eq 0) -or ($TmpCounter -ge 4))
                }
                $LocationNote = "Location:"
                ForEach ($Location in $LocationDetails) {
                    $LocationNote += " $($Location.name),"
                }
                $LocationNote = $LocationNote.trimend(",")
                $HostSummary += "$LocationNote`r`n"
            }
            if ($HostResults.hostzone) {$HostSummary += "Zone: $($HostResults.hostZone)`r`n"}
            if ($HostResults.osType) {$HostSummary += "OS Type: $($HostResults.osType)`r`n"}
            if ($HostResults.riskLevel) {$HostSummary += "Risk Level: $($HostResults.riskLevel)`r`n"}
            if ($HostResults.threatLevel) {$HostSummary += "Threat Level: $($HostResults.threatLevel)`r`n"}
            if ($HostResults.threatLevelComments) {$HostSummary += "Threat Level Comments: $($HostResults.threatLevelComments)`r`n"}
            if ($HostResults.Entity) {$HostSummary += "LogRhythm Entity: $($HostResults.entity.name)`r`n"}
            if ($HostResults.longDesc) {$HostSummary += "Long Description: $($HostResults.longDesc)`r`n"}
            if ($HostResults.hostIdentifiers) {$HostSummary += "`r`n---- Identifiers ----`r`n"}
            ForEach ($Identifier in $HostResults.hostIdentifiers) {
                $i += 1
                $HostSummary += "Identifier $i.  Type: $($Identifier.type)  Value: $($Identifier.value)`r`n"
            }
            if ($HostResults.dateUpdated) { $HostSummary += "`r`nRecord last updated: $($HostResults.dateUpdated)"}
    
            $SummaryStatus = Add-LrNoteToCase -Id $Id -Text $HostSummary -PassThru
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