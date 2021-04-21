Function Get-InputApiUrl {
    <#
    .SYNOPSIS 
        Determine if a user entered a valid IP Address
    .PARAMETER Value
        String to evaluate as an IP Address or hostname.
    .EXAMPLE
        PS C:\> Get-InputIpAddress -Value 1.2.3.4

        Value   Valid
        -----   -----
        1.2.3.4  True
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string] $Value,

        [Parameter(Mandatory = $false, Position = 1)]
        [string] $OldValue
    )

    # Accept Hostname or IPAddress
    $ValidRegex = [regex]::new("^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$")
    # Parses hostname from a URL in group 4 (with port) or 6 (without port)
    $Extract = [regex]::new("^(http(?:s)?:\/\/)?((?<host>[^:\/]+)(((:)?(?<port>\d{2,4})?)))(?:\/?.*?)$")

    # Return object
    $Return = [PSCustomObject]@{
        Value = $null
        Valid = $false
        Changed = $false
    }


    # Parse the old value so we can find the hostname part
    $ExtractResult = $Extract.Match($OldValue)


    # If OldValue wasn't a valid match for https://host/ or https://host:9999/ then we have a source data problem
    if (! $ExtractResult.Success) {
        Write-Host "    [!] Warning: Value found in current configuration file is invalid, so it cannot be updated." -ForegroundColor Red
        Write-Host "    Update this field directly in the configuration." -ForegroundColor Red
        # set valid to true because user input won't help change it.
        $Return.Valid = $true
        return $Return
    }


    # Our $Find will either be in group 4 or 6.
    # First condition: Hosts with a port definition (https://host.com:8080/blah)
    # Second condition: Hosts without a port (https://host.com/blah)
    if ($ExtractResult.Groups["port"].Success -and $ExtractResult.Groups["host"].Success) {
        $Find = $ExtractResult.Groups["host"].Value + ':' + $ExtractResult.Groups["port"].Value
        Write-Verbose "Extraction with port."
    } elseif ($ExtractResult.Groups["host"].Success) {
        $Find = $ExtractResult.Groups["host"].Value
        Write-Verbose "Extraction without port."
    }
    # If we couldn't find a host to replace:
    if ([string]::IsNullOrEmpty($Find)) {
        Write-Verbose "No extraction point found in existing Api Url."
        Write-Verbose "Old Value: $OldValue | New Value: $NewValue"
    }


    # Extract the parsed details for the user submitted value
    $ExtractValue = $Extract.Match($Value)
    
    # If Value wasn't a valid match for https://host/ or https://host:9999/ then we have a source data problem
    if (! $ExtractValue.Success) {
        Write-Host "    [!] Warning: Value found in current configuration file is invalid, so it cannot be updated." -ForegroundColor Red
        Write-Host "    Update this field directly in the configuration." -ForegroundColor Red
        # set valid to true because user input won't help change it.
        $Return.Valid = $false
        return $Return
    }

    # We need a valid hostname to use for replacement
    if ($ExtractValue.Groups["host"].Success -match $ValidRegex) {
        $Return.Valid = $true
        if ($ExtractValue.Groups["port"].Success -and $ExtractValue.Groups["host"].Success) {
            $Replace = $ExtractValue.Groups["host"].Value + ':' + $ExtractValue.Groups["port"].Value
            Write-Verbose "Extraction with port."
        } elseif ($ExtractValue.Groups["host"].Success) {
            Write-Verbose "Extraction without port."
            if ($ExtractValue.Groups["host"] -like "*.cloud") {
                Write-Verbose "LogRhythm Cloud Host."
                $Replace = $ExtractValue.Groups["host"].Value
                $Return.Valid = $true
            } else {
                # If the User Value does not contain Port and the Old Value does contain Port, retain Old Value Port
                if ($ExtractResult.Groups["port"].Success) {
                    Write-Verbose "Retaining Old Value Port"
                    $Replace = $ExtractValue.Groups["host"].Value + ':' + $ExtractResult.Groups["port"].Value
                    $Return.Valid = $true
                } else {
                    # Default to setting Find = Value Host
                    $Replace = $ExtractValue.Groups["host"].Value
                    $Return.Valid = $true
                }
            }
        }
    }

    # Create URL from OldValue
    $Return.Value = $OldValue.Replace($Find, $Replace)

    # Update URL if Return.Value is not equal to OldValue
    if ($Return.Value -ne $OldValue) {
        $Return.Changed = $true
    }

    return $Return
}