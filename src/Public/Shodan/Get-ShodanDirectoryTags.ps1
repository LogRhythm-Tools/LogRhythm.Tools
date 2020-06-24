<#
.SYNOPSIS
    Retrieve information about a Shodan account associated with API key.
.DESCRIPTION
    Retrieves membership status, credits, display name, and account creation date.
.PARAMETER ShodanAPI
    Shodan API Key
.OUTPUTS
    PSObject representing the object lookup.  
.EXAMPLE
    PS C:\> Get-ShodanProfile

.NOTES
    Shodan-API      
.LINK
    https://github.com/LogRhythm-Tools/LogRhythm.Tools
#>
function Get-ShodanDirectoryTags {
    [CmdLetBinding()]
    param( 
        [Parameter(Mandatory = $false, Position = 0)]
        [ValidateNotNull()]
        [pscredential] $Credential = $LrtConfig.Shodan.ApiKey,

        [int]$ReturnSize = 100
    )
    Begin {
        # Request Setup
        $BaseUrl = $LrtConfig.Shodan.BaseUrl
        $Token = $Credential.GetNetworkCredential().Password

        $RequestUrl = $BaseUrl + "/shodan/query/tags?size="+$ReturnSize +"&key=" + $Token
        Write-Verbose $RequestUrl
    }

    Process {
        
        try {
            $Results = Invoke-RestMethod $RequestUrl
        } catch {
            Write-Host "Status Code: $($_.Exception.Response.StatusCode.value__)"
            Write-Host "Status Description: $($_.Exception.Response.StatusDescription)"
        }
    }

    End {
        return $Results
    }
}