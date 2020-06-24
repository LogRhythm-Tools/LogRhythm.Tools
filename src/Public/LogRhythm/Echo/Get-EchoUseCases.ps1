using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Get-EchoUseCases {
    <#
    .SYNOPSIS
        Retrieve list of LogRhythm Echo use cases.
    .DESCRIPTION
        Get-EchoUseCases returns a , including it's details and list items.
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
        [Parameter(Mandatory=$false, ValueFromPipeline=$false, Position=0)]
        [ValidateNotNull()]
        [string] $Title,

        [Parameter(Mandatory=$false, ValueFromPipeline=$false, Position=1)]
        [ValidateNotNull()]
        [string] $Description,

        [Parameter(Mandatory=$false, ValueFromPipeline=$true, Position=2)]
        [ValidateNotNull()]
        [int] $Id,

        [Parameter(Mandatory=$false, ValueFromPipeline=$false, Position=3)]
        [ValidateNotNull()]
        [switch] $ExactName
    )
                                                                    
    Begin {
        # Request Setup
        $Me = $MyInvocation.MyCommand.Name
        $BaseUrl = $LrtConfig.LogRhythmEcho.BaseUrl

        # Define HTTP Headers
        $Headers = [Dictionary[string,string]]::new()
        #$Headers.Add("Authorization", "Bearer $Token")
        
        # Define HTTP Method
        $Method = $HttpMethod.Get
        
        # Define HTTP URI
        $RequestUrl = $BaseUrl + "/usecases"

        # Check preference requirements for self-signed certificates and set enforcement for Tls1.2 
        Enable-TrustAllCertsPolicy
    }

    Process {      
        # Send Request
        # Make Request
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

        # Update results
        $CasesCount = $Response.numresults
        $Response = $Response.objects

        if ($Title) {
            $RegexTitle = "^.*$Title.*$"
            $Response = $($Response | Where-Object -Property "title" -Match $RegexTitle)
        }
        if ($Description) {
            $RegexDescription = "^.*$Description.*$"
            $Response = $($Response | Where-Object -Property "description" -Match $RegexDescription)
        }
        if ($Id) {
            $Response = $($Response | Where-Object -Property "id" -eq $Id)
        }


        # [Exact] Parameter
        # Search "Malware" normally returns both "Malware" and "Malware Options"
        # This would only return "Malware"
        if ($ExactName) {
            $Pattern = "^$Title$"
            $Response | ForEach-Object {
                if(($_.title -match $Pattern) -or ($_.title -eq $Title)) {
                    Write-Verbose "[$Me]: Exact title name match found."
                    $List = $_
                    return $List
                }
            }
            return $null
        } else {
            return $Response
        }
    }

    End { }
}