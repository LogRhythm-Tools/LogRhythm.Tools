using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Format-LrHostTextOutput {
    <#
    .SYNOPSIS
        Format-LrHostTextOutput
    .DESCRIPTION
        Format-LrHostTextOutput
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
        [Parameter(
            Mandatory = $true, 
            ValueFromPipeline = $true, 
            Position = 0
        )]
        [ValidateNotNullOrEmpty()]
        [object] $LRHost
    )

    Begin {
        $Me = $MyInvocation.MyCommand.Name
    }

    Process {
        $CaseOutput = [list[String]]::new()

        if ($LRHost.Id) {
            $CaseOutput.Add("-==- Known Host Summary -==-")
            $CaseOutput.Add("Name: $($LRHost.Name)")
            $HostSumString1 = "Zone: $($LRHost.hostZone)"
            $HostSumString2 = "OS Type: $($LRHost.osType)"
            $HostSumString3 = "Entity: $($LRHost.entity.name)"
            $CaseOutput.Add("$HostSumString1  $($HostSumString2.PadLeft(19-($HostSumString1.length)+$($HostSumString2.length))) $($HostSumString3.PadLeft(19-($HostSumString2.length)+$($HostSumString3.length)))")
            $RiskThreatString1 = "Risk Level: $($LRHost.riskLevel)"
            $RiskThreatString2 = "Threat Level: $($LRHost.threatLevel)"
            $CaseOutput.Add("$RiskThreatString1  $($RiskThreatString2.PadLeft(29-($RiskThreatString1.length)+$($RiskThreatString2.length)))")
            if ($LRHost.shortDesc) {$CaseOutput.Add("Short Description: $($LRHost.shortDesc)")}
            if ($LRHost.longDesc) {$CaseOutput.Add("Long Description:`r`n$($LRHost.longDesc)`r`n")}
            if ($LRHost.threatLevelComments) {$CaseOutput.Add("Threat Level Comments:`r`n$($LRHost.threatLevelComments)")}
            
            if ($LRHost.hostIdentifiers) {$CaseOutput.Add("`r`n---- Identifiers ----")}
            $i = 0
            ForEach ($Identifier in $LRHost.hostIdentifiers) {
                $i += 1
                $IdentifierString1 = "Identifier: $i  Type: $($Identifier.type)"
                $IdentifierString2 = "Value: $($Identifier.value)"
                $CaseOutput.Add("$IdentifierString1 $($IdentifierString2.PadLeft(45-($IdentifierString1.length)+$($IdentifierString2.length)))")
            }
            if ($LRHost.dateUpdated) { $CaseOutput.Add("`r`nRecord ID: $($LRHost.id)      Record last updated: $($LRHost.dateUpdated)")}    
        } else {
            return $null
        }

        
        return $CaseOutput | Out-String
    }
}