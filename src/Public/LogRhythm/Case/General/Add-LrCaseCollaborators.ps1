using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Add-LrCaseCollaborators {
    <#
    .SYNOPSIS
        Add collaborators to a case.
    .DESCRIPTION
        The Add-LrCaseCollaborators cmdlet adds case collaborators to an existing case.
    .PARAMETER Id
        Unique identifier for the case, either as an RFC 4122 formatted string, or as a number.
    .PARAMETER Numbers
        List of numeric person identifiers.
    .PARAMETER Names
        List of person names.  Each name should match the person record explicitly.

        Example: "jones, steven"
    .PARAMETER GroupNumbers
        List of numeric notification group identifiers.
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
        Note: You can bypass the need to provide a Credential by setting
        the preference variable $LrtConfig.LogRhythm.ApiKey
        with a valid Api Token.
    .INPUTS
        [System.Object]     ->  Id
        [System.Int32[]]    ->  Numbers
        [System.String[]]   ->  Names
        [System.Int32[]]    ->  GroupNumbers
    .OUTPUTS
        PSCustomObject representing the modified LogRhythm Case.
    .EXAMPLE
        PS C:\> Add-LrCaseCollaborators -Id 5 -Numbers @{5, 7, 22}
    .NOTES
        LogRhythm-API
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools     
    #>

    [CmdletBinding()]
    Param(
        [Parameter(
            Mandatory = $true, 
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true, 
            Position = 0)]
        [ValidateNotNull()]
        [object] $Id,
        
        [Parameter(Mandatory = $false, Position = 1)]
        [ValidateNotNull()]
        [int32[]] $Numbers,

        [Parameter(Mandatory = $false, Position = 2)]
        [ValidateNotNull()]
        [string[]] $Names,

        [Parameter(Mandatory = $false, Position = 3)]
        [ValidateNotNull()]
        [int32[]] $GroupNumbers,


        [Parameter(Mandatory = $false, Position = 4)]
        [switch] $PassThru,


        [Parameter(Mandatory = $false, Position = 5)]
        [ValidateNotNull()]
        [pscredential] $Credential = $LrtConfig.LogRhythm.ApiKey
    )


    Begin {
        $Me = $MyInvocation.MyCommand.Name
        
        $BaseUrl = $LrtConfig.LogRhythm.BaseUrl
        $Token = $Credential.GetNetworkCredential().Password

        # Enable self-signed certificates and Tls1.2
        Enable-TrustAllCertsPolicy

        # Request Headers
        $Headers = [Dictionary[string,string]]::new()
        $Headers.Add("Authorization", "Bearer $Token")
        


        # Request URI
        $Method = $HttpMethod.Put
    }


    Process {
        # Test CaseID Format
        $IdStatus = Test-LrCaseIdFormat $Id
        if ($IdStatus.IsValid -eq $true) {
            $CaseNumber = $IdStatus.CaseNumber
        } else {
            return $IdStatus
        }                                                      

        $RequestUrl = $BaseUrl + "/lr-case-api/cases/$CaseNumber/actions/addCollaborators/"

        [int32[]]$ValidUserID = @()
        if ($Names) {
            ForEach ($Name in $Names) {
                $UserStatus = Get-LrUserNumber -User $Name
                if ($UserStatus) {
                    $ValidUserId += $UserStatus
                }
            }
        }

        if ($Numbers) {
            ForEach ($Number in $Numbers) {
                $UserStatus = Get-LrUserNumber -User $Number
                if ($UserStatus) {
                    $ValidUserId += $UserStatus
                }
            }
        }

        # Create request body with people numbers
        if (!($ValidUserId -Is [System.Array])) {
            # only one tag, use simple json
            Write-Verbose "Here"
            $Body = "{ `"numbers`": [$ValidUserId] }"
        } else {
            # multiple values, create an object
            $Body = ([PSCustomObject]@{ numbers = $ValidUserId }) | ConvertTo-Json
        }
        #endregion



        #region: Make Request                                                            
        Write-Verbose "[$Me]: Request URL: $RequestUrl"
        Write-Verbose "[$Me]: Request Body:`n$Body"

        # Make Request
        $Response = Invoke-RestAPIMethod -Uri $RequestUrl -Headers $Headers -Method $Method -Body $Body -Origin $Me
        if (($null -ne $Response.Error) -and ($Response.Error -eq $true)) {
            return $Response
        }
        
        # Only return the case if PassThru was requested.
        if ($PassThru) {
            return $Response    
        }
    }


    End { }
}