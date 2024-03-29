using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Get-LrCaseById {
    <#
    .SYNOPSIS
        Returns the summary of a case by Id.
    .DESCRIPTION
        The Get-LrCaseById cmdlet returns the LogRhythm Case specified by the ID parameter.
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
        Note: You can bypass the need to provide a Credential by setting
        the preference variable $LrtConfig.LogRhythm.ApiKey
        with a valid Api Token.
    .PARAMETER Id
        Unique identifier for the case, either as an RFC 4122 formatted string, or as a number.
    .INPUTS
        System.Object -> Id
    .OUTPUTS
        PSCustomObject representing the (new|modified) LogRhythm object.
    .EXAMPLE
        PS C:\> Get-LrCaseById -Id 1785

            id                      : 16956857-3965-4B83-AAE6-C9B33A38D15E
            number                  : 1785
            externalId              :
            dateCreated             : 2019-09-28T05:03:13.424802Z
            dateUpdated             : 2019-09-28T05:03:13.424802Z
            dateClosed              :
            owner                   : @{number=52; name=API, LogRhythm; disabled=False}
            lastUpdatedBy           : @{number=52; name=API, LogRhythm; disabled=False}
            name                    : Test Case - Pester Automated Test
            status                  : @{name=Created; number=1}
            priority                : 5
            dueDate                 : 2019-10-10T09:18:22Z
            resolution              :
            resolutionDateUpdated   :
            resolutionLastUpdatedBy :
            summary                 : Case created by Pester automation
            entity                  : @{number=-100; name=Global Entity}
            collaborators           : {@{number=52; name=API, LogRhythm; disabled=False}}
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
        

        # Request URI
        $Method = $HttpMethod.Get

        # https://docs.microsoft.com/en-us/dotnet/api/system.int32.tryparse
        $_int = 0
    }


    Process {
        # Establish General Error object Output
        $ErrorObject = [PSCustomObject]@{
            Code                  =   $null
            Error                 =   $false
            Type                  =   $null
            Note                  =   $null
            Value                 =   $Id
            Raw                   =   $null
        }

        # Check if ID value is an integer
        if ([int]::TryParse($Id, [ref]$_int)) {
            Write-Verbose "[$Me]: Id parses as integer."
        } elseif (($Id -Is [System.Guid]) -Or (Test-Guid $Id)) {
            Write-Verbose "[$Me]: Id parses as GUID."
        } else {
            $ErrorObject.Error = $true
            $ErrorObject.Type  = "DataType"
            $ErrorObject.Note  = "Id does not parse as integer or GUID."
            return $ErrorObject
        }
        
        $RequestUrl = $BaseUrl + "/lr-case-api/cases/$Id/"
        Write-Verbose "[$Me]: Request URL: $RequestUrl"


        $Response = Invoke-RestAPIMethod -Uri $RequestUrl -Headers $Headers -Method $Method -Origin $Me
        if (($null -ne $Response.Error) -and ($Response.Error -eq $true)) {
            return $Response
        }

        return $Response
    }


    End { }
}