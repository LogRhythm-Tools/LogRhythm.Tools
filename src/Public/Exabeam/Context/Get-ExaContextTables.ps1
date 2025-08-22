using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Get-ExaContextTables {
    <#
    .NOTES
        Exabeam-API
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false, ValueFromPipeline = $true, Position = 0)]
        [ValidateNotNull()]
        [string] $Name,

        [Parameter(Mandatory = $false, Position = 3)]
        [switch] $Exact,

        [Parameter(Mandatory = $false, Position = 6)]
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

        # Define HTTP Method
        $Method = $HttpMethod.Get
        
        # Define HTTP URI
        $RequestUrl = $BaseUrl + "context-management/v1/tables"

        # Check preference requirements for self-signed certificates and set enforcement for Tls1.2
        Enable-TrustAllCertsPolicy
    }

    Process {
        Write-Verbose "[$Me]: Request URL: $RequestUrl"

        # Send Request
        $Response = Invoke-RestAPIMethod -Uri $RequestUrl -Headers $Headers -Method $Method -Origin $Me
        if (($null -ne $Response.Error) -and ($Response.Error -eq $true)) {
            return $Response
        }

        if ($Name.length -gt 0) {
            $Results = [list[object]]::new()
            ForEach ($List in $Response) {
                if ($Exact) {
                    if ($List.name -like $Name) {
                        return $List
                    }
                } else {
                    if ($List.name -match "$Name.*") {
                        $Results.add($List)
                    }
                }
            }
            if ($Results) {
                return $Results
            } else {
                return
            }
        }
        return $Response
    }

    End { }
}