<#
    .SYNOPSIS
        Search the Shodan directory of search queries that users have saved in Shodan.
    .DESCRIPTION
        Retrieves number of votes, description, title, timestamp, tags, and query for each matching result.
    .PARAMETER ShodanAPI
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
        [Parameter(Mandatory = $false, Position = 0)]
        [ValidateNotNull()]
        [pscredential] $Credential = $LrtConfig.Shodan.ApiKey,

        [Parameter(Mandatory=$true, ValueFromPipeline=$true, Position=1)]
        [string]$Keyword
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
    }

    Process {
        while ($PollingShodan -eq $True) {
            $RequestUrl = $BaseUrl +"/shodan/query/search?query="+ $Keyword +"&page="+ $Page +"&key="+ $Token           
            try {
                $Response = Invoke-RestMethod $RequestUrl
            }
            catch [System.Net.WebException] {
                $Err = Get-RestErrorMessage $_
                Write-Host "Exception invoking Rest Method: [$($Err.statusCode)]: $($Err.message)" -ForegroundColor Yellow
                $PSCmdlet.ThrowTerminatingError($PSItem)
                # Fragment Below
                $Message = "ERROR: Failed to call API to get Identities." + $ApiError
                write-host $Message
                $PollingShodan = $False
                break;
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