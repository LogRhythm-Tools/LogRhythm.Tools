using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Get-LrEchoUseCases {
    <#
    .SYNOPSIS
        Retrieve list of LogRhythm Echo use cases.
    .DESCRIPTION
        Get-LrEchoUseCases returns a list of available Echo Use Cases.
    .PARAMETER Title
        Retrieve results where the Use Case Title contains the specified string.
    .PARAMETER Description
        Retrieve results where the Use Case Description contains the specified string.
    .PARAMETER Id
        Retrieve results where the Use Case ID exactly matches the specified integer.
    .PARAMETER Exact
        Restricts the Title search results to exact matches only.
    .OUTPUTS
        PSCustomObject representing the available LogRhythm Echo use cases that are available for execution.
    .EXAMPLE
        PS C:\> Get-LrEchoUseCases
    .NOTES
        LogRhythm-API
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false, ValueFromPipeline = $false, Position = 0)]
        [ValidateNotNull()]
        [string] $Title,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false, Position = 1)]
        [ValidateNotNull()]
        [string] $Description,

        [Parameter(Mandatory = $false, ValueFromPipeline = $true, Position = 2)]
        [ValidateNotNull()]
        [int] $Id,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false, Position = 3)]
        [ValidateNotNull()]
        [switch] $Exact
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
        $Response = Invoke-RestAPIMethod -Uri $RequestUrl -Headers $Headers -Method $Method -Origin $Me
        if ($Response.Error) {
            return $Response
        }

        # Update results
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
        if ($Exact) {
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