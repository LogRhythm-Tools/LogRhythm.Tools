using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Set-YourFunctionName {
    <#
    .SYNOPSIS
        xxxxxx
    .DESCRIPTION
        xxxxxx
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
        Note: You can bypass the need to provide a Credential by setting
        the preference variable $LrtConfig.LogRhythm.ApiKey
        with a valid Api Token.
    .PARAMETER XXXX
        xxxxxx
    .INPUTS
        Type -> Parameter
    .OUTPUTS
        PSCustomObject representing the (new|modified) LogRhythm object.
    .EXAMPLE
        PS C:\> 
    .NOTES
        LogRhythm-API
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false, Position = 0)]
        [ValidateNotNull()]
        [pscredential] $Credential = $LrtConfig.LogRhythm.ApiKey,


        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 1
        )]
        [object] $Id
    )

    Begin {
        $Me = $MyInvocation.MyCommand.Name
    
        # $BaseUrl = $LrtConfig.LogRhythm.BaseUrl
        $BaseUrl = $LrtConfig.LogRhythm.BaseUrl

        $Token = $Credential.GetNetworkCredential().Password
        
        # Request Headers
        $Headers = [Dictionary[string,string]]::new()
        $Headers.Add("Authorization", "Bearer $Token")
        $Headers.Add("Content-Type","application/json")
        
        # Request URI   
        $Method = $HttpMethod.Post

        # Enable self-signed certificates and Tls1.2
        Enable-TrustAllCertsPolicy
    }


    Process {
        # Establish General Error object Output
        $ErrorObject = [PSCustomObject]@{
            Code                  =   $null
            Error                 =   $false
            Type                  =   $null
            Note                  =   $null
            Raw                   =   $_
        }

        # Define RequestUri
        $RequestUri = $BaseUrl + "/path/"


        # Request Body
        $Body = [PSCustomObject]@{
            Name = "value"
        }
        $Body = $Body | ConvertTo-Json


        # REQUEST
        try {
            $Response = Invoke-RestMethod `
                -Uri $RequestUri `
                -Headers $Headers `
                -Method $Method `
                -Body $Body
        }
        catch {
            $Err = Get-RestErrorMessage $_
            $ErrorObject.Code = $Err.statusCode
            $ErrorObject.Type = "WebException"
            $ErrorObject.Note = $Err.message
            $ErrorObject.Raw = $_
            $ErrorObject.Error = $true
            return $ErrorObject
        }

        return $Response
    }


    End { }
}