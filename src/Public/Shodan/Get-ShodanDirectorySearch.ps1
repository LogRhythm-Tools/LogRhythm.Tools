<#
    .SYNOPSIS
        Search the Shodan directory of search queries that users have saved in Shodan.
    .DESCRIPTION
        Retrieves number of votes, description, title, timestamp, tags, and query for each matching result.
    .PARAMETER Credential
        Shodan API Key
    .PARAMETER Keyword
        Keyword for conducting Shodan Directory search
    .OUTPUTS
        PSObject representing the object lookup.  
    .EXAMPLE
        PS C:\> Get-ShodanDirectorySearch -Keyword "password"
        -----
        votes       : 1924
        description : Finds results with "default password" in the banner; the named defaults might work!
        title       : default password
        timestamp   : 1/14/2010 5:26:18 PM
        tags        : {router, default, password}
        query       : "default password"

        votes       : 508
        description : user: admin
                    pass: password
        title       : netgear
        timestamp   : 1/20/2010 12:12:47 AM
        tags        : {}
        query       : netgear

    .NOTES
        Shodan-API      
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
#>
function Get-ShodanDirectorySearch {
    [CmdLetBinding()]
    param( 
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
        [string] $Keyword,


        [Parameter(Mandatory = $false, Position = 1)]
        [ValidateNotNull()]
        [pscredential] $Credential = $LrtConfig.Shodan.ApiKey
    )
    Begin {
        # Request Setup
        $BaseUrl = $LrtConfig.Shodan.BaseUrl
        $Token = $Credential.GetNetworkCredential().Password
            
        
        [psobject]$ShodanResults = @()

        # Searching Scope.  
        $PollingShodan = $True
        $Page = 1
        $Count = 10

        # Check preference requirements for self-signed certificates and set enforcement for Tls1.2 
        Enable-TrustAllCertsPolicy
    }

    Process {
        # Establish General Error object Output
        $ErrorObject = [PSCustomObject]@{
            Error                 =   $false
            Value                 =   $null
            Code                  =   $Null
            Type                  =   $null
            Note                  =   $null
        }

        while ($PollingShodan -eq $True) {
            $RequestUrl = $BaseUrl +"/shodan/query/search?query="+ $Keyword +"&page="+ $Page +"&key="+ $Token
            Write-Verbose "[$Me]: Request URL: $RequestUrl"        
            try {
                $Response = Invoke-RestMethod $RequestUrl
            } catch {
                $Err = Get-RestErrorMessage $_
                $ErrorObject.Error = $true
                $ErrorObject.Type = "System.Net.WebException"
                $ErrorObject.Code = $($Err.statusCode)
                $ErrorObject.Note = $($Err.message)
                return $ErrorObject
            }

            $ShodanResults += $Response.Matches

            if ($Response.Matches.Count -eq 0) {
                $PollingShodan = $False
                break;
            } elseif ($Response.Matches.Count -lt $Count) {
                $PollingShodan = $False
            }
            $Page = $Page + 1
            # Shodan 1 request /second
            Start-Sleep .85
        }
    }

    End {
        return $ShodanResults
    }
}