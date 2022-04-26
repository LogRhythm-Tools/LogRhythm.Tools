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
        [ValidateNotNull()]
        [string] $Tag,


        [Parameter(Mandatory = $false, Position = 1)]
        [switch] $PassThru,
        

        [Parameter(Mandatory = $false, Position = 2)]
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
            Tag                   =   $Tag
            Raw                   =   $null
        }

        # Request URI
        $RequestUrl = $BaseUrl + "/lr-case-api/tags/"
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
            $ErrorObject.Error = $true
            return $ErrorObject
        }

        # Create Body
        $Body = ([PSCustomObject]@{ text = $Tag }) | ConvertTo-Json


        #region: Make Request                                                            
        Write-Verbose "[$Me]: request body is:`n$Body"

        # Make Request
        $Response = Invoke-RestAPIMethod -Uri $RequestUrl -Headers $Headers -Method $Method -Body $Body -Origin $Me
        if ($Response.Error) {
            return $Response
        }
        
        if ($PassThru) {
            return $Response
        }
        #endregion
    }

    End { }
}