using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Get-ExaSiteCollectorCerts {
    <#
    .SYNOPSIS
        Download a Site Collector Core certificate
    .DESCRIPTION
        Download the certificate for a Site Collector Core identified by its Core ID.
    .PARAMETER Path
        Location where certificates will be downloaded to.  Must be in format of full path plus file name.
    .PARAMETER CoreID
        Site Collector Core ID. To retrieve the ID, see Get Site Collector Core details.
    .EXAMPLE
        PS C:\> Get-ExaSiteCollectorCerts -Path "C:\TEMP\certs.zip" -CoreID e6696714-5555-5555-5555-6f68c675b2ea
    .NOTES
        Exabeam-API
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false, Position = 0)]
        [string] $Path = '.\ngsc_certs.zip',


        [Parameter(Mandatory = $false, Position = 1)]
        [string] $CoreID,
        

        [Parameter(Mandatory = $false, Position = 2)]
        [ValidateNotNull()]
        [pscredential] $Credential = $LrtConfig.Exabeam.ApiKey
    )
                                                                    
    Begin {
        $Me = $MyInvocation.MyCommand.Name
        Set-LrtExaToken
        # Request Setup
        $BaseUrl = $LrtConfig.Exabeam.BaseUrl
        $Token = $LrtConfig.Exabeam.Token.access_token

        # Define HTTP Headers
        $Headers = [Dictionary[string,string]]::new()
        $Headers.Add("Authorization", "Bearer $Token")
        $Headers.Add("accept", "application/json")

        # Define HTTP Method
        $Method = $HttpMethod.Get
        
        # Define HTTP URI
        $RequestUrl = $BaseUrl + "site-collectors/v1/cores/$CoreID/certificates/download"

        # Check preference requirements for self-signed certificates and set enforcement for Tls1.2
        Enable-TrustAllCertsPolicy
    }

    Process {
        Write-Verbose "[$Me]: Request URL: $RequestUrl"

        # Send Request
        $Response = Invoke-WebRequest -OutFile $Path -Uri $RequestUrl -Headers $Headers -Method $Method
        if (($null -ne $Response.Error) -and ($Response.Error -eq $true)) {
            return $Response
        }
    }

    End { }
}