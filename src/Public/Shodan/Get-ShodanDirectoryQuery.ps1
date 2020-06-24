<#
    .SYNOPSIS
        Retrieve a list of all search queries that users have saved in Shodan.
    .DESCRIPTION
        Retrieves each queries number of votes, description, tags, timestamp, title, and Shodan query string.
    .PARAMETER ShodanAPI
        Shodan API Key
    .OUTPUTS
        PSObject representing the object lookup.  
    .EXAMPLE
        PS C:\> Get-ShodanDirectoryQuery
        -----
        votes       : 11815
        description : best ip cam search I have found yet.
        tags        : {webcam, surveillance, cams}
        timestamp   : 3/15/2010 1:32:32 PM
        title       : Webcam
        query       : Server: SQ-WEBCAM

        votes       : 4851
        description : admin admin
        tags        : {cam, webcam}
        timestamp   : 2/6/2012 9:04:16 AM
        title       : Cams
        query       : linux upnp avtech
    .NOTES
        Shodan-API      
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
#>
function Get-ShodanDirectoryQuery {
    [CmdLetBinding()]
    param( 
        [Parameter(Mandatory = $false, Position = 0)]
        [ValidateNotNull()]
        [pscredential] $Credential = $LrtConfig.Shodan.ApiKey,

        [Parameter(Mandatory = $false, Position = 1)]
        [int]$MaxPages = 10
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
            $RequestUrl = $BaseUrl + "/shodan/query?sort=votes&page=" + $Page +"&key=" + $Token          
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
            } elseif ($Page -ge $MaxPages) {
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