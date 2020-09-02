using namespace System

Function Get-InputTenantId {
    <#
    .SYNOPSIS
        Determine if a user entered a valid guid.
    .PARAMETER Value
        String to evaluate as a guid.
    .EXAMPLE
        PS C:\> Get-InputGuid -Value 3da80399-a3a9-4e2f-91fc-809064cc33c7 -OldValue cbb3790d-b8c4-4102-8cbd-81b284639511

        Value                                Valid Changed
        -----                                ----- -------
        cbb3790d-b8c4-4102-8cbd-81b284639511  True    True
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string] $Value,

        [Parameter(Mandatory = $false, Position = 1)]
        [string] $OldValue
    )


    # Return object 
    $Return = [PSCustomObject]@{
        Value = $null
        Valid = $false
        Changed = $false
    }


    # Parsing OAuth2 URL for TenantId: Group 4 would contain the TenantId/Guid
        # Group #  Description          Example
        # -------  -----------          ----------------
        # Group 1: Full match           "https://login.microsoftonline.com/{GUID}/oauth2/token"
        # Group 2: Only if Https        "s"
        # Group 3: Host                 "login.microsoftonline.com"
    #--># Group 4: Tenant Id            {GUID}
        # Group 5: Remainder of URL     "/oauth2/token"
    $Extract = [regex]::new("(^http(s)?:\/\/(.*?)\/([0-9A-Fa-f]{8}[-][0-9A-Fa-f]{4}[-][0-9A-Fa-f]{4}[-][0-9A-Fa-f]{4}[-][0-9A-Fa-f]{12})(.*?)$)")


    # Parse the old value for TenantId
    $ExtractResult = $Extract.Match($OldValue)


    # If we could not parse a valid Url + TenantId, then source data is bad.
    if (! $ExtractResult.Success) {
        Write-Host "    [!] Warning: Value found in current configuration file is invalid, so it cannot be updated." -ForegroundColor Red
        Write-Host "    Update this field directly in the configuration." -ForegroundColor Red
        # set valid to true because user input won't help change it.
        $Return.Valid = $true
        return $Return
    }


    # Extract Old TenantId, used to find/replace
    if ($ExtractResult.Groups[4].Success) {
        $Find = $ExtractResult.Groups[4].Value
        Write-Verbose "Tenant Id Extracted from Url: $Find"
    }


    # Test new TenantId/guid entered by user
    $ValidGuid = [guid]::Empty
    if ([guid]::TryParse($Value, [ref]$ValidGuid)) {

        # All tests passed, return new Url + TenantId combination
        $Return.Valid = $true

        # Create URL with the provided guid
        $Return.Value = $OldValue.Replace($Find, $Value)

        # Is Value different than OldValue
        if ($Return.Value -ne $OldValue) {
            $Return.Changed = $true
        }
    }
    
    return $Return
}