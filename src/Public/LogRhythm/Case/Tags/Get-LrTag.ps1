using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Get-LrTag {
    <#
    .SYNOPSIS
        Get a tag by ID Number for LogRhythm case use.
    .DESCRIPTION
        The Get-LrTag cmdlet retrieves a tag that exists by its Tag #.

    .PARAMETER Number
        Unique, numeric identifier for the tag.
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
        Note: You can bypass the need to provide a Credential by setting
        the preference variable $LrtConfig.LogRhythm.ApiKey with a valid Api Token.
    .INPUTS
        [int]   -> Number
    .OUTPUTS
        PSCustomObject representing the modified LogRhythm Case.
    .EXAMPLE
        PS C:\> New-LrTag Peaches
        --- 
        
        number text    dateCreated            createdBy
        ------ ----    -----------            ---------
        1 Peaches 2020-06-06T14:03:11.4Z @{number=-100; name=LogRhythm Administrator; disabled=False}
    .NOTES
        LogRhythm-API
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools     
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
        [int32] $Number,


        [Parameter(Mandatory = $false, Position = 1)]
        [ValidateNotNull()]
        [pscredential] $Credential = $LrtConfig.LogRhythm.ApiKey
    )


    Begin {
        $Me = $MyInvocation.MyCommand.Name
        
        $BaseUrl = $LrtConfig.LogRhythm.CaseBaseUrl
        $Token = $Credential.GetNetworkCredential().Password

        # Enable self-signed certificates and Tls1.2
        Enable-TrustAllCertsPolicy

        # Request Headers
        $Headers = [Dictionary[string,string]]::new()
        $Headers.Add("Authorization", "Bearer $Token")
        $Headers.Add("Content-Type","application/json")


        # Request URI
        $Method = $HttpMethod.Get
    }


    Process {
        # Establish General Error object Output
        $ErrorObject = [PSCustomObject]@{
            Code                  =   $null
            Error                 =   $false
            Type                  =   $null
            Note                  =   $null
            Tag                   =   $Number
            Raw                   =   $null
        }

        $RequestUrl = $BaseUrl + "/tags/$Number"
        Write-Verbose "[$Me]: RequestUrl: $RequestUrl"

        # Make Request
        try {
            $Response = Invoke-RestMethod $RequestUrl -Headers $Headers -Method $Method
        } catch [System.Net.WebException] {
            $Err = Get-RestErrorMessage $_
            $ErrorObject.Code = $Err.statusCode
            $ErrorObject.Type = "WebException"
            $ErrorObject.Note = $Err.message
            $ErrorObject.Error = $true
            $ErrorObject.Raw = $_
            return $ErrorObject
        }
        
        return $Response
        #endregion
    }

    End { }
}