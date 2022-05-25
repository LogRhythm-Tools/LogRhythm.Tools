using namespace System

Function Update-LrCase {
    <#
    .SYNOPSIS
        Update case information. For example, the case name, priority, and due date.
    .DESCRIPTION
        The Update-LrCase cmdlet updates an existing case.
    .PARAMETER Id
        Unique identifier for the case, either as an RFC 4122 formatted string, or as
        a number.
    .PARAMETER ExternalId
        Externally defined identifier for the case.
    .PARAMETER Name
        Name of the case.
    .PARAMETER Priority
        Priority of the case. Valid values: 1-5
    .PARAMETER DueDate
        When the case is due, either as an Rfc3339 formatted string, or as a [DateTime]
    .PARAMETER Summary
        Note summarizing the case.
    .PARAMETER Resolution
        Description of how the case was resolved.
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
        Note: You can bypass the need to provide a Credential by setting
        the preference variable $LrtConfig.LogRhythm.ApiKey
        with a valid Api Token.
    .INPUTS
        [System.Object]   ->  Id
    .OUTPUTS
        If the PassThru switch is provided, a PSCustomObject representing the modified
        LogRhythm Case will be returned.
    .EXAMPLE
        PS C:\> Update-LrCase -Id 4481 -Summary "My New Summary"
        ---
        In this example we updated the Summary of Case number 4481 to "My New Summary".
        As we did not include the PassThru parameter, there will be no output.
    .EXAMPLE
        In this example we will use the pipeline to pass a case object to Update-LrCase
        and update every field we can.
        
        
        PS C:\> $case = Get-LrCaseById -Id 4481

        PS C:\> $case | Update-LrCase -ExternalId "Ext1212" -Name "Example Case" -Priority 3 -DueDate 2020-11-01 -Summary "Here's my summary" -Resolution "a resolution!" -PassThru

        ---
        id                      : ACAA4DF4-E810-4AF5-A3FA-2B3BA47BD237
        number                  : 4481
        externalId              : Ext1212
        dateCreated             : 2020-09-16T12:11:38.1893786Z
        dateUpdated             : 2020-09-17T09:58:21.8816109Z
        dateClosed              :
        owner                   : @{number=11; name=API, Example; disabled=False}
        lastUpdatedBy           : @{number=11; name=API, Example; disabled=False}
        name                    : Example Case
        status                  : @{name=Created; number=1}
        dueDate                 : 2020-11-01T05:00:00Z
        resolution              : a resolution!
        resolutionDateUpdated   : 2020-09-17T09:58:21.8816109Z
        resolutionLastUpdatedBy : @{number=11; name=API, Example; disabled=False}
        summary                 : Here's my summary
        entity                  : @{number=-100; name=Global Entity; fullName=Global Entity}
        collaborators           : {@{number=11; name=API, Example; disabled=False}, @{number=19; name=Smith, Bob; disabled=False}}
        tags                    : {}
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
            ValueFromPipelineByPropertyName = $true, 
            Position = 0
        )]
        [ValidateNotNull()]
        [object] $Id,

        
        [Parameter(Mandatory = $false, Position = 1)]
        [ValidateLength(0,250)]
        [string] $ExternalId,
        

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 2)]
        [ValidateLength(1,250)]
        [string] $Name,


        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 3)]
        [ValidateRange(1,5)]
        [int] $Priority,


        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 4)]
        [DateTime] $DueDate,


        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 5)]
        [ValidateLength(0,10000)]
        [string] $Summary,


        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 6)]
        [ValidateLength(0,500)]
        [string] $Resolution,


        [Parameter(Mandatory = $false, Position = 8)]
        [switch] $PassThru,


        [Parameter(Mandatory = $false, Position = 9)]
        [ValidateNotNull()]
        [pscredential] $Credential = $LrtConfig.LogRhythm.ApiKey
    )


    Begin {
        $Me = $MyInvocation.MyCommand.Name
        
        $BaseUrl = $LrtConfig.LogRhythm.BaseUrl
        $Token = $Credential.GetNetworkCredential().Password

        # Enable self-signed certificates and Tls1.2
        Enable-TrustAllCertsPolicy

        # Request Headers
        $Headers = [Dictionary[string,string]]::new()
        $Headers.Add("Authorization", "Bearer $Token")
        

        # Request Method
        $Method = $HttpMethod.Put

        # Set initial ProcessedCount
        $ProcessedCount = 0
    }


    Process {
        # Establish General Error object Output
        $ErrorObject = [PSCustomObject]@{
            Code                  =   $null
            Error                 =   $false
            Type                  =   $null
            Note                  =   $null
            Case                  =   $Id
            Raw                   =   $null
        } 
        
        # Test CaseId Format
        $IdStatus = Test-LrCaseIdFormat $Id
        if ($IdStatus.IsValid -eq $true) {
            $CaseNumber = $IdStatus.CaseNumber
        } else {
            return $IdStatus
        }

        # Request URI
        $RequestUrl = $BaseUrl + "/lr-case-api/cases/$CaseNumber/"


        #region: Create Json Body                                                                  
        $Body = [PSCustomObject]@{}
        
        # Parameter: ExternalId
        if (! [string]::IsNullOrEmpty($ExternalId)) {
            $Body | Add-Member -MemberType NoteProperty -Name "externalId" -Value $ExternalId
        }

        # Parameter: Name
        if (! [string]::IsNullOrEmpty($Name)) {
            $Body | Add-Member -MemberType NoteProperty -Name "name" -Value $Name
        }

        # Parameter: Priority
        if ($Priority -gt 0) {
            $Body | Add-Member -MemberType NoteProperty -Name "priority" -Value $Priority
        }

        # Parameter: DueDate
        if ($DueDate) {
            $_dueDate = ($DueDate.ToUniversalTime()).ToString("yyyy-MM-ddTHH:mm:ssZ")
            $Body | Add-Member -MemberType NoteProperty -Name "dueDate" -Value $_dueDate
        }

        # Parameter: Summary
        if (! [string]::IsNullOrEmpty($Summary)) {
            $Body | Add-Member -MemberType NoteProperty -Name "summary" -Value $Summary
        }

        # Parameter: Resolution
        if (! [string]::IsNullOrEmpty($Resolution)) {
            $Body | Add-Member -MemberType NoteProperty -Name "resolution" -Value $Resolution
        }

        # Important - Convert to JSON 
        $Body = $Body | ConvertTo-Json
        #endregion
        

        #region: Send Request                                                                      
        Write-Verbose "[$Me]: request body is:`n$Body"

        $Response = Invoke-RestAPIMethod -Uri $RequestUrl -Headers $Headers -Method $Method -Body $Body -Origin $Me
        if ($Response.Error) {
            return $Response
        }
        #endregion
        

        $ProcessedCount++

        # Return
        if ($PassThru) {
            return $Response
        }
    }

    
    End { 
        Write-Verbose "Updated $ProcessedCount cases."
    }
}