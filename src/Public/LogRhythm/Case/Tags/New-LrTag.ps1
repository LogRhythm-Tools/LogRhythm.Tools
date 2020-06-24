using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function New-LrTag {
    <#
    .SYNOPSIS
        Create a new tag for LogRhythm case use.
    .DESCRIPTION
        The New-LrTag cmdlet creates a tag that does not currently exist.
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
        Note: You can bypass the need to provide a Credential by setting
        the preference variable $LrtConfig.LogRhythm.ApiKey
        with a valid Api Token.
    .INPUTS
        [String]   -> Tag
    .OUTPUTS
        PSCustomObject representing the modified LogRhythm Case.
    .EXAMPLE
        PS C:\> New-LrTag Peaches
        
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
        [Parameter(Mandatory = $false, Position = 0)]
        [ValidateNotNull()]
        [pscredential] $Credential = $LrtConfig.LogRhythm.ApiKey,


        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true,
            Position = 1
        )]
        [ValidateNotNull()]
        [string] $Tag
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
        $Method = $HttpMethod.Post
    }


    Process {
        # Establish General Error object Output
        $ErrorObject = [PSCustomObject]@{
            Code                  =   $null
            Error                 =   $false
            Type                  =   $null
            Note                  =   $null
            ResponseUrl           =   $null
            Tag                   =   $Tag
        }

        # Request URI
        $RequestUrl = $BaseUrl + "/tags/"
        Write-Verbose "[$Me]: RequestUrl: $RequestUrl"



        #region: Process Tags                                                            
        # Request Body - Tags
        Write-Verbose "[$Me]: Validating Tags"

        # Convert / Validate Tags to Tag Numbers array
        $_tagNumber = $Tag | Get-LrTagNumber
        if (($_tagNumber.Error -eq $true) -or ($_tagNumber)) {
            $ErrorObject.Code = "ValueExists"
            $ErrorObject.Type = "Duplicate"
            $ErrorObject.Note = "Tag exists.  ID: $_tagNumber"
            $ErrorObject.ResponseUrl = "Reference results of: Get-LrTag -number $_tagNumber"
            $ErrorObject.Error = $true
            return $ErrorObject
        }

        # Create Body
        $Body = ([PSCustomObject]@{ text = $Tag }) | ConvertTo-Json


        #region: Make Request                                                            
        Write-Verbose "[$Me]: request body is:`n$Body"

        # Make Request
        if ($PSEdition -eq 'Core'){
            try {
                $Response = Invoke-RestMethod $RequestUrl -Headers $Headers -Method $Method -Body $Body -SkipCertificateCheck
            }
            catch {
                $Err = Get-RestErrorMessage $_
                $ErrorObject.Code = $Err.statusCode
                $ErrorObject.Type = "WebException"
                $ErrorObject.Note = $Err.message
                $ErrorObject.ResponseUrl = $RequestUrl
                $ErrorObject.Error = $true
                return $ErrorObject
            }
        } else {
            try {
                $Response = Invoke-RestMethod $RequestUrl -Headers $Headers -Method $Method -Body $Body
            }
            catch [System.Net.WebException] {
                $Err = Get-RestErrorMessage $_
                $ErrorObject.Code = $Err.statusCode
                $ErrorObject.Type = "WebException"
                $ErrorObject.Note = $Err.message
                $ErrorObject.ResponseUrl = $RequestUrl
                $ErrorObject.Error = $true
                return $ErrorObject
            }
        }
        
        return $Response
        #endregion
    }

    End { }
}