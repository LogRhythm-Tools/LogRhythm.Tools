using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function New-ExaContextTable {
    <#
    .NOTES
        LogRhythm-API        
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false, ValueFromPipeline = $true, Position = 0)]
        [ValidateNotNull()]
        [string] $Name,


        [Parameter(Mandatory = $false, Position = 1)]
        [ValidateSet(
            'Other',
            'User', 
            ignorecase=$true
        )]
        [string] $ContextType = 'Other',
        

        [Parameter(Mandatory = $false, Position = 2)]
        [ValidateSet(
            'Custom',
            ignorecase=$true
        )]
        [string] $Source,


        [Parameter(Mandatory = $false, Position = 3)]
        [PSCustomObject[]] $Attributes = @(),


        [Parameter(Mandatory = $false, Position = 4)]
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
        $Method = $HttpMethod.Post
        
        # Define HTTP URI
        $RequestUrl = $BaseUrl + "context-management/v1/tables"

        # Check preference requirements for self-signed certificates and set enforcement for Tls1.2
        Enable-TrustAllCertsPolicy
    }

    Process {
        Write-Verbose "[$Me]: Request URL: $RequestUrl"

        # Validate Attributes
        foreach ($Attribute in $Attributes) {
            if (-not (Test-ExaAttributeSchema $Attribute)) {
                throw "Invalid attribute schema detected: $($Attribute | ConvertTo-Json -Depth 10 -Compress)"
            }
        }
        

        # Build the JSON Body
        $Body = @{
            name        = $Name
            contextType = $ContextType
            source      = $Source
            attributes  = $Attributes
        } | ConvertTo-Json -Depth 3 -Compress

        # Send Request
        $Response = Invoke-RestAPIMethod -Uri $RequestUrl -Headers $Headers -Method $Method -Body $Body -Origin $Me
        
        if (($null -ne $Response.Error) -and ($Response.Error -eq $true)) {
            return $Response
        }
        
        return $Response
    }

    End { }
}