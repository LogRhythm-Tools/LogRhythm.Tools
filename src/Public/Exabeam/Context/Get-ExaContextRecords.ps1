using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Get-ExaContextRecords {
    <#
    .NOTES
        Exabeam-API
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>
    
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
        [ValidateNotNull()]
        [string] $id,

        [Parameter(Mandatory = $false, ValueFromPipeline = $true, Position = 1)]
        [ValidateNotNull()]
        [int32] $limit,

        [Parameter(Mandatory = $false, ValueFromPipeline = $true, Position = 2)]
        [ValidateNotNull()]
        [int32] $offset,

        [Parameter(Mandatory = $false, Position = 3)]
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
        $Headers.Add("accept", "application/json")
        $Headers.Add("Authorization", "Bearer $Token")

        # Define HTTP Method
        $Method = $HttpMethod.Get

        $RequestUrl = $BaseUrl + "context-management/v1/tables/" + $id + "/records"

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

        if ($Response.paging.next) {
            $Results = [list[object]]::new()
            ForEach($Record in $Response.records) {
                $Results.add($Record)
            }
            $Counter = 0
            DO {
                if ($Counter -eq 0) {
                    $RequestUrl = $Response.paging.next[0] -replace "^http:", "https:"
                } else {
                    $RequestUrl = $PaginationResults.paging.next[0] -replace "^http:", "https:"
                }
                Write-Verbose "[$Me]: Request URL: $RequestUrl"
                # Retrieve Query Results
                $PaginationResults = Invoke-RestAPIMethod -Uri $RequestUrl -Headers $Headers -Method $Method -Origin $Me
                if (($null -ne $PaginationResults.Error) -and ($PaginationResults.Error -eq $true)) {
                    return $PaginationResults
                }
                
                # Append results to Response
                ForEach($Record in $PaginationResults.records) {
                    $Results.add($Record)
                }
                $Counter += 1
            } While ($PaginationResults.paging.next)
            $PaginationResults.records = $Results

            return $PaginationResults
        }
        
        return $Response
    }

    End { }
}