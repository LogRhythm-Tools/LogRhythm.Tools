using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Get-LrCaseAssociatedCases {
    <#
    .SYNOPSIS
        Return a list of cases assocaited with a specific case.
    .DESCRIPTION
        The Get-LrCaseAssociatedCases cmdlet returns an object containing all the cases
        that has been associated to a specific case.

        If a match is not found, this cmdlet will return null.
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
        Note: You can bypass the need to provide a Credential by setting
        the preference variable $SrfPreferences.LrDeployment.LrApiToken
        with a valid Api Token.
    .PARAMETER Id
        Unique identifier for the case, either as an RFC 4122 formatted string, or as a number.
    .INPUTS
        [System.Object]   ->  Id
    .OUTPUTS
        System.Object representing the returned LogRhythm playbooks on the applicable case.

        If a match is not found, this cmdlet will throw exception
        [System.Collections.Generic.KeyNotFoundException]
    .EXAMPLE
        PS C:\> Get-LrCaseAssociatedCases -Id 4
        ---
        id         : C5B41873-CE0D-41D9-9C03-BF3B0D8310F3
        number     : 5
        externalId :
        private    : False
        summary    : @{id=C5B41873-CE0D-41D9-9C03-BF3B0D8310F3; number=5; externalId=; dateCreated=2020-07-24T20:45:05.9814956Z; dateUpdated=2020-07-25T23:46:29.4980008Z; dateClosed=; owner=;
                    lastUpdatedBy=; name=Concurrent VPN Connection from Disparate Locations; status=; priority=2; dueDate=2020-07-25T20:45:05.9774965Z; resolution=; resolutionDateUpdated=;
                    resolutionLastUpdatedBy=; summary=Remote Access VPN authenticating from multiple geographic locations within close time proximity.  Time between authentications: Days: 0 Hours: 0
                    Secs: 30.  The distance between the two locations is greater than 2000 miles.; entity=; collaborators=System.Object[]; tags=System.Object[]}
    .NOTES
        LogRhythm-API
    .LINK
        https://github.com/SmartResponse-Framework/SmartResponse.Framework        
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false, Position = 0)]
        [ValidateNotNull()]
        [pscredential] $Credential = $LrtConfig.LogRhythm.ApiKey,


        [Parameter(Mandatory = $true,ValueFromPipeline = $true,Position = 1)]
        [ValidateNotNullOrEmpty()]
        [object] $Id
    )

    Begin {
        $Me = $MyInvocation.MyCommand.Name
        
        $BaseUrl = $LrtConfig.LogRhythm.CaseBaseUrl
        $Token = $Credential.GetNetworkCredential().Password

        # Enable self-signed certificates and Tls1.2
        Enable-TrustAllCertsPolicy 
        
        # Request Headers
        $Headers = [Dictionary[string,string]]::new()
        $Headers.Add("Authorization", "Bearer $Token")
        
        # Request Method
        $Method = $HttpMethod.Get
    }


    Process {
        # Test CaseID Format
        $IdStatus = Test-LrCaseIdFormat $Id
        if ($IdStatus.IsValid -eq $true) {
            $CaseNumber = $IdStatus.CaseNumber
        } else {
            return $IdStatus
        }  

        
        $RequestUrl = $BaseUrl + "/cases/$CaseNumber/associated/"
        Write-Verbose "[$Me]: RequestUrl: $RequestUrl"

        # REQUEST
        try {
            $Response = Invoke-RestMethod $RequestUrl -Headers $Headers -Method $Method
        }
        catch [System.Net.WebException] {
            $Err = Get-RestErrorMessage $_

            switch ($Err.statusCode) {
                "404" {
                    throw [KeyNotFoundException] `
                        "[404]: Playbook Id $Id not found, or you do not have permission to view it."
                    }
                    "401" {
                        throw [UnauthorizedAccessException] `
                        "[401]: Credential '$($Credential.UserName)' is unauthorized to access 'lr-case-api'"
                    }
                Default {
                    throw [Exception] "[$Me] [$($Err.statusCode)]: $($Err.message) $($Err.details)`n$($Err.validationErrors)`n"
                }
            }
        }

        # Return all responses.
        return $Response
    }


    End { }
}