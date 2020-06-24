using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Start-EchoUseCase {
    <#
    .SYNOPSIS
        Start a LogRhythm Echo use cases.
    .DESCRIPTION
        Start-EchoUseCase returns a , including it's details and list items.
    .OUTPUTS
        PSCustomObject representing the specified LogRhythm List and its contents.

        If parameter ListItemsOnly is specified, a string collection is returned containing the
        list's item values.
    .EXAMPLE
        PS C:\> Get-LrList -Identity "edea82e3-8d0b-4370-86f0-d96bcd4b6c19" -Credential $MyKey
    .NOTES
        LogRhythm-API
    .LINK
        https://github.com/SmartResponse-Framework/SmartResponse.Framework
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
            $Id = $(Get-EchoUseCases -Title $Title -ExactName | Select-Object -ExpandProperty Id)
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