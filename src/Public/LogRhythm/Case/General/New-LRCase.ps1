using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function New-LrCase {
    <#
    .SYNOPSIS
        Create a new case.
    .DESCRIPTION
        The New-LrCase cmdlet creates a new case and returns the newly created case as a PSCustomObject.
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
        Note: You can bypass the need to provide a Credential by setting
        the preference variable $LrtConfig.LogRhythm.ApiKey
        with a valid Api Token.
    .PARAMETER Name
        Name of the case.
    .PARAMETER Priority
        (int 1-5) Priority of the case.
    .PARAMETER DueDate
        When the case is due, as [System.DateTime] or a date-parsable [System.String]
        If ommitted, a due date will be set for 24 hours from the current time.
    .PARAMETER Summary
        Note summarizing the case.
    .INPUTS
        Name, Priority, DueDate, and Summary can all be sent by name through the pipeline.
    .OUTPUTS
        PSCustomObject representing the newly created case.
    .EXAMPLE
        PS C:\>  New-LrCase -Name "Mock case" -Priority 5 -Summary "Mock case summary for automation validation." -DueDate "10-20-2020 14:22:11"

        id                      : E66A5D03-412F-43AB-B9B7-0459055827AF
        number                  : 2
        externalId              :
        dateCreated             : 2020-07-16T16:47:46.0395837Z
        dateUpdated             : 2020-07-16T16:47:46.0395837Z
        dateClosed              :
        owner                   : @{number=2; name=LRTools; disabled=False}
        lastUpdatedBy           : @{number=2; name=LRTools; disabled=False}
        name                    : Mock case
        status                  : @{name=Created; number=1}
        priority                : 5
        dueDate                 : 2020-10-20T14:22:11Z
        resolution              :
        resolutionDateUpdated   :
        resolutionLastUpdatedBy :
        summary                 : Mock case summary for automation validation.
        entity                  : @{number=-100; name=Global Entity; fullName=Global Entity}
        collaborators           : {@{number=2; name=LRTools; disabled=False}}
        tags                    : {}
    .NOTES
        LogRhythm-API
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, 
            ValueFromPipeline = $true, 
            ValueFromPipelineByPropertyName = $true, 
            Position = 0
        )]
        [ValidateLength(1,250)]
        [string] $Name,


        [Parameter(Mandatory = $true, 
            ValueFromPipeline = $true, 
            ValueFromPipelineByPropertyName = $true, 
            Position = 1
        )]
        [ValidateRange(1,5)]
        [int] $Priority,


        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 2
        )]
        [DateTime] $DueDate = ([DateTime]::now).AddDays(1),


        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 3
        )]
        [ValidateLength(1,10000)]
        [string] $Summary,


        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 4)]
        [int[]] $AlarmNumbers,


        [Parameter(Mandatory = $false, Position = 5)]
        [switch] $PassThru,


        [Parameter(Mandatory = $false, Position = 6)]
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
        $Headers.Add("Content-Type","application/json")
        $RequestUrl = $BaseUrl + "/lr-case-api/cases/"

        # Request Method
        $Method = $HttpMethod.Post
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

        # Request Body
        $Body = [PSCustomObject]@{
            name = $Name
            priority = $Priority
            externalId = $null
            dueDate = ($DueDate.ToUniversalTime()).ToString("yyyy-MM-ddTHH:mm:ssZ")
            summary = $Summary
        }
        $Body = $Body | ConvertTo-Json

        # Send Request
        try {
            $Response = Invoke-RestMethod $RequestUrl -Headers $Headers -Method $Method -Body $Body
            Write-Verbose "[$Me]: Created Case $($Response.id)"
        } catch [System.Net.WebException] {
            $Err = Get-RestErrorMessage $_
            $ErrorObject.Code = $Err.statusCode
            $ErrorObject.Type = "WebException"
            $ErrorObject.Note = $Err.message
            $ErrorObject.Error = $true
            $ErrorObject.Raw = $_
            return $ErrorObject
        }
        
        # Attach Alarm to Case
        if ($AlarmNumbers) {
            try {
                $UpdatedCase = Add-LrAlarmToCase -Id $Response.id -AlarmNumbers $AlarmNumbers -PassThru
                $Response = $UpdatedCase
            }
            catch {
                Write-Error "Case was created, but failed to add alarms."
                $PSCmdlet.ThrowTerminatingError($PSItem)
            }
        }

        # Done!
        if ($PassThru) {
            return $Response
        }
    }


    End { }
}