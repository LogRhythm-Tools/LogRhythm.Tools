using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Start-LrEchoUseCase {
    <#
    .SYNOPSIS
        Start a LogRhythm Echo use cases.
    .DESCRIPTION
        Start-LrEchoUseCase returns a summary of the amount of logs sent and/or PCAPs replayed.
    .OUTPUTS

    .EXAMPLE
        PS C:\> Start-LrEchoUseCase -Id 5
    .EXAMPLE
        PS C:\> Start-LrEchoUseCase -Title "Use Case 5"
    .NOTES
        LogRhythm-API
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false, ValueFromPipeline=$true, Position=0)]
        [ValidateNotNull()]
        [string] $Title,

        [Parameter(Mandatory=$false, ValueFromPipeline=$true, Position=1)]
        [ValidateNotNull()]
        [int] $Id
    )

    Begin {
        # Request Setup
        $Me = $MyInvocation.MyCommand.Name
        $BaseUrl = $LrtConfig.LogRhythmEcho.BaseUrl

        # Define HTTP Headers
        $Headers = [Dictionary[string,string]]::new()
        #$Headers.Add("Authorization", "Bearer $Token")
        
        # Define HTTP Method
        $Method = $HttpMethod.Post

        # Check preference requirements for self-signed certificates and set enforcement for Tls1.2 
        Enable-TrustAllCertsPolicy
    }

    Process {      
        if ((!$Id) -and ($Title)) {
            $Id = $(Get-LrEchoUseCases -Title $Title -Exact | Select-Object -ExpandProperty Id)
        } elseif((!$Id) -and (!$Title)) {
            Return "Please provide Echo Case ID# or Title"
        }

        # Define HTTP URI
        $RequestUrl = $BaseUrl + "/execute/$Id"

        # Send Request
        if ($PSEdition -eq 'Core'){
            try {
                $Response = Invoke-RestMethod $RequestUrl -Headers $Headers -Method $Method -SkipCertificateCheck
            }
            catch {
                $Err = Get-RestErrorMessage $_
                throw [Exception] "[$Me] [$($Err.statusCode)]: $($Err.message) - $($Err.details) - $($Err.validationErrors)"
            }
        } else {
            try {
                $Response = Invoke-RestMethod $RequestUrl -Headers $Headers -Method $Method
            }
            catch [System.Net.WebException] {
                $Err = Get-RestErrorMessage $_
                throw [Exception] "[$Me] [$($Err.statusCode)]: $($Err.message) - $($Err.details) - $($Err.validationErrors)"
            }
        }

        Return $Response
    }

    End { }
}