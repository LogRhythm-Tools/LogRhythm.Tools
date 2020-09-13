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
        
        try {
            $Results = Invoke-RestMethod $RequestUrl
        } catch [System.Net.WebException] {
            $Err = Get-RestErrorMessage $_
            $ErrorObject.Error = $true
            $ErrorObject.Type = "System.Net.WebException"
            $ErrorObject.Code = $($Err.statusCode)
            $ErrorObject.Note = $($Err.message)
            return $ErrorObject
        }
    }   

    End {
        return $Results
    }
}